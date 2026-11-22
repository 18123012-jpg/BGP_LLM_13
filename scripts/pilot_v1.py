#!/usr/bin/env python3
"""Pilot: one LLM writes an FRR config for a V1 scenario, then we grade it in two tiers.

  step 1  prompt   scenario intent (plain language) -> prompt text
  step 2  LLM      Ollama writes a config (temperature 0.6, top_p 0.95, <=512 tokens, fixed seed)
  step 3  Tier 1   vtysh -C inside the frr-eval container (exit 0 = syntax valid)
  step 4  Tier 2   Batfish testRoutePolicies on every test vector, labelled TP/TN/FP/FN
  step 5  save     every prompt, raw answer, extracted config and result under results/pilot_v1/

Special model name "reference" skips the LLM and uses our hand-written reference config.
Run that first: it must give all TP/TN, which proves the plumbing before a real model is used.

Usage (venv active, run from ~/bgp-llm-eval):
  python scripts/pilot_v1.py --model reference --only SEC-V1-01
  python scripts/pilot_v1.py --model qwen2.5-coder:7b --only SEC-V1-01 --trials 2
  python scripts/pilot_v1.py --model mistral:7b-instruct          # all 10 V1 scenarios, 1 trial
"""
import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests
from pybatfish.client.session import Session
from pybatfish.datamodel.route import BgpRoute

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_batfish import label, policy_for, wrap_cumulus  # reuse the proven Tier-2 helpers
from normalize_frr import normalize  # neighbor prefix-list -> equivalent route-map before Tier 2

OLLAMA = "http://localhost:11434/api/generate"
NUM_CTX = 4096  # same for every model so the runs are comparable


def build_prompt(sc):
    return (
        "You are a network engineer writing FRRouting (FRR 8.5.2) configuration.\n\n"
        f"{sc['intent']}\n\n"
        "Write the complete BGP configuration for AS 65000 that implements this policy, "
        f"including the neighbor {sc['peer_ip']} (remote-as {sc['peer_as']}) and everything "
        "needed so the policy is actually applied to that neighbor.\n"
        "Output only FRR configuration commands. No explanations, no markdown."
    )


def call_ollama(model, prompt, seed):
    body = {"model": model, "prompt": prompt, "stream": False,
            "options": {"temperature": 0.6, "top_p": 0.95, "num_predict": 512,
                        "num_ctx": NUM_CTX, "seed": seed}}
    t0 = time.time()
    r = requests.post(OLLAMA, json=body, timeout=600)
    r.raise_for_status()
    return r.json()["response"], round(time.time() - t0, 1)


def extract_config(text):
    """Take the content of the first ``` fence if there is one, else the raw text."""
    m = re.search(r"```[a-zA-Z]*\n(.*?)```", text, re.S)
    cfg = m.group(1) if m else text
    return cfg.strip("\n") + "\n"


def vtysh_check(cfg, container="frr-eval"):
    r = subprocess.run(["docker", "exec", "-i", container, "vtysh", "-C", "-f", "/dev/stdin"],
                       input=cfg, capture_output=True, text=True)
    msg = [l for l in (r.stdout + r.stderr).splitlines() if "vtysh.conf" not in l and l.strip()]
    return r.returncode, "; ".join(msg[:3])


def find_binding(cfg, ip, d):
    """How is a filter attached to the neighbor in this direction? route-map or prefix-list."""
    for kind in ("route-map", "prefix-list"):
        m = re.search(rf"neighbor {re.escape(ip)} {kind} (\S+) {d}\b", cfg)
        if m:
            return kind, m.group(1)
    return None


def tier2(bf, cfg, sc, tag):
    """Load into Batfish and test every vector. Returns (labels, parse_status, unrecognized, note)."""
    d = "in" if sc["direction"] == "inbound" else "out"
    bind = find_binding(cfg, sc["peer_ip"], d)
    if bind is None:
        return None, "UNBOUND", [], "no route-map or prefix-list is attached to the neighbor"
    host = "pilot-" + tag
    snap = Path(tempfile.mkdtemp(prefix="bfsnap_"))
    (snap / "configs").mkdir()
    (snap / "configs" / f"{host}.cfg").write_text(wrap_cumulus(cfg, host, sc["peer_ip"]))
    try:
        bf.init_snapshot(str(snap), name=tag, overwrite=True)
    finally:
        shutil.rmtree(snap, ignore_errors=True)
    status = bf.q.fileParseStatus().answer().frame().iloc[0]["Status"]
    warn = bf.q.parseWarning().answer().frame()
    unrec = [f"{r['Text']} {str(r['Parser_Context'])}" for _, r in warn.iterrows()]
    note = f"{bind[0]} {bind[1]}"
    if bind[0] == "route-map":
        pol = bind[1]
    else:
        # a neighbor-level prefix-list has no route-map name; Batfish builds an internal
        # per-peer policy. Find it by listing the policies of this node.
        fr = bf.q.bgpPeerConfiguration(nodes=host).answer().frame()
        col = "Import_Policy" if d == "in" else "Export_Policy"
        pol = None
        if col in fr.columns:
            for _, r in fr.iterrows():
                if str(r.get("Remote_IP")) == sc["peer_ip"]:
                    v = r[col]
                    v = list(v) if isinstance(v, (list, tuple, set)) else [v]
                    v = [str(x) for x in v if x is not None and str(x) not in ("", "nan", "None")]
                    pol = v[0] if v else None
        if pol is None:
            print("    bgpPeerConfiguration columns:", list(fr.columns))
            print(fr.to_string()[:1500])
            return None, status, unrec, f"{note} (Batfish policy for this peer not found)"
        note += f" -> Batfish policy {pol}"
    labels = []
    for t in sc["test_vectors"]:
        route = BgpRoute(network=t["prefix"], originatorIp=sc["peer_ip"], originType="igp",
                         protocol="bgp", asPath=t["as_path"])
        fr = bf.q.testRoutePolicies(policies=pol, direction=d, inputRoutes=[route]).answer().frame()
        if fr.empty:
            labels.append((t["prefix"], t["expected_action"], "NO_RESULT", "?"))
            continue
        act = fr.iloc[0]["Action"]
        labels.append((t["prefix"], t["expected_action"], act, label(t["expected_action"], act)))
    return labels, status, unrec, note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help='Ollama model name, or "reference"')
    ap.add_argument("--dataset", default="dataset/bgp_security_dataset.json")
    ap.add_argument("--refs", default="dataset/reference_configs/V1")
    ap.add_argument("--only", help="one scenario id, e.g. SEC-V1-01")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--seed", type=int, default=1000, help="trial n uses seed+n")
    ap.add_argument("--out", default="results/pilot_v1")
    a = ap.parse_args()

    scs = [s for s in json.loads(Path(a.dataset).read_text()) if s["id"].startswith("SEC-V1-")]
    if a.only:
        scs = [s for s in scs if s["id"] == a.only]
    if not scs:
        sys.exit("no scenario selected")

    bf = Session(host="localhost")
    bf.set_network("bgp_llm_eval_pilot")
    safe = a.model.replace(":", "_").replace("/", "_")
    outdir = Path(a.out) / safe
    outdir.mkdir(parents=True, exist_ok=True)
    rows, tot = [], {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

    for sc in scs:
        for n in range(1, a.trials + 1):
            run = f"{sc['id']}_t{n}"
            print(f"\n=== {run}  model={a.model}")
            prompt = build_prompt(sc)
            if a.model == "reference":
                raw, secs = (Path(a.refs) / f"{sc['id']}.conf").read_text(), 0.0
            else:
                raw, secs = call_ollama(a.model, prompt, a.seed + n)
            cfg = extract_config(raw)
            (outdir / f"{run}.prompt.txt").write_text(prompt)
            (outdir / f"{run}.raw.txt").write_text(raw)
            (outdir / f"{run}.conf").write_text(cfg)
            print(f"  LLM answer: {len(cfg.splitlines())} lines in {secs}s  (saved {run}.conf)")

            code, msg = vtysh_check(cfg)
            print(f"  Tier 1 vtysh -C: exit {code}" + (f" | {msg}" if msg else ""))
            row = {"run": run, "model": a.model, "seconds": secs, "vtysh_exit": code,
                   "vtysh_msg": msg, "batfish_parse": "", "unrecognized": "", "TP": 0, "TN": 0,
                   "FP": 0, "FN": 0, "verdict": "", "normalized": 0, "norm_log": ""}
            if code != 0:
                row["verdict"] = "SYNTAX_FAIL"
                print("  -> stops here: Tier 2 is only run for configs that pass Tier 1")
            else:
                # Tier 1 judged the model's own text. Before Tier 2, rewrite neighbor-level
                # prefix-lists into equivalent route-maps (Batfish grades named route policies).
                cfg2, norm_log = normalize(cfg)
                rewritten = sum(1 for x in norm_log if x["action"].startswith("rewritten"))
                row["normalized"] = rewritten
                row["norm_log"] = json.dumps(norm_log, separators=(",", ":")) if norm_log else ""
                if norm_log:
                    (outdir / f"{run}.norm.conf").write_text(cfg2)
                    print(f"  normalizer: {rewritten} rewritten, {len(norm_log) - rewritten} kept (see {run}.norm.conf)")
                labels, status, unrec, note = tier2(bf, cfg2, sc, run.lower().replace("_", "-"))
                row["batfish_parse"] = status
                row["unrecognized"] = " | ".join(unrec)
                if labels is None:
                    row["verdict"] = "UNBOUND" if status == "UNBOUND" else "UNRESOLVED"
                    print(f"  Tier 2 not graded: {note}")
                else:
                    print(f"  Tier 2 attached via: {note}")
                    print(f"  Tier 2 Batfish parse: {status}" + (f"  unrecognized: {unrec}" if unrec else ""))
                    for prefix, exp, act, lab in labels:
                        print(f"    {'[+]' if lab in ('TP', 'TN') else '[-]'} {prefix:<20} "
                              f"expected={exp:<9} batfish={act:<6} {lab}")
                        if lab in tot:
                            tot[lab] += 1
                            row[lab] += 1
                    row["verdict"] = "CORRECT" if row["FP"] + row["FN"] == 0 else "WRONG_POLICY"
            print(f"  verdict: {row['verdict']}")
            rows.append(row)

    csv_path = outdir / "summary.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    kinds = {}
    for r in rows:
        kinds[r["verdict"]] = kinds.get(r["verdict"], 0) + 1
    print("\nSUMMARY", a.model, "| runs:", len(rows), "| verdicts:", kinds, "| route labels:", tot)
    print("saved to", outdir)


if __name__ == "__main__":
    main()
