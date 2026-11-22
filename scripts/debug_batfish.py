#!/usr/bin/env python3
"""Diagnose how Batfish reads a config, in its original form and in an address-family form.

Question answered: does Batfish only see neighbor-level filters when they are written inside
`address-family ipv4 unicast` (with `neighbor X activate`)?  FRR accepts both forms.

Usage (venv active, from ~/bgp-llm-eval):
  python scripts/debug_batfish.py results/pilot_v1/qwen2.5-coder_7b/SEC-V1-01_t1.conf SEC-V1-01
"""
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

from pybatfish.client.session import Session
from pybatfish.datamodel.route import BgpRoute

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_batfish import label, wrap_cumulus

POL = re.compile(r"^\s*neighbor (\S+) (prefix-list|route-map) (\S+) (in|out)\s*$")


def afi_variant(cfg, ip):
    """Move neighbor-level prefix-list/route-map lines into an address-family block."""
    lines = cfg.splitlines()
    moved = [l.strip() for l in lines if (m := POL.match(l)) and m.group(1) == ip]
    if not moved:
        return None
    rest = [l for l in lines if not ((m := POL.match(l)) and m.group(1) == ip)]
    if any(l.strip().startswith("address-family ipv4 unicast") for l in rest):
        return None  # already has the block; nothing to move
    i = next((k for k, l in enumerate(rest) if l.startswith("router bgp")), None)
    if i is None:
        return None
    j = i + 1
    while j < len(rest) and (rest[j].startswith(" ") or rest[j].startswith("!")):
        j += 1
    block = [" address-family ipv4 unicast", f"  neighbor {ip} activate"] + \
            ["  " + m for m in moved] + [" exit-address-family"]
    return "\n".join(rest[:j] + block + rest[j:]) + "\n"


def run(bf, name, cfg, sc):
    d = "in" if sc["direction"] == "inbound" else "out"
    host = "dbg-" + name
    snap = Path(tempfile.mkdtemp(prefix="bfdbg_"))
    (snap / "configs").mkdir()
    (snap / "configs" / f"{host}.cfg").write_text(wrap_cumulus(cfg, host, sc["peer_ip"]))
    try:
        bf.init_snapshot(str(snap), name=name, overwrite=True)
    finally:
        shutil.rmtree(snap, ignore_errors=True)
    print(f"\n----- variant: {name}")
    print("parse status  :", bf.q.fileParseStatus().answer().frame()[["File_Name", "Status"]].to_dict("records"))
    w = bf.q.parseWarning().answer().frame()
    for _, r in w.iterrows():
        print("parse warning :", r["Line"], "|", r["Text"], "|", r["Comment"])
    pc = bf.q.bgpPeerConfiguration(nodes=host).answer().frame()
    col = "Import_Policy" if d == "in" else "Export_Policy"
    row = pc[pc["Remote_IP"].astype(str) == sc["peer_ip"]]
    pols = []
    if len(row):
        v = row.iloc[0][col]
        pols = [str(x) for x in (list(v) if isinstance(v, (list, tuple, set)) else [v]) if x not in (None, "")]
    print(f"{col:<14}:", pols)
    if not pols:
        print("=> Batfish sees NO filter on this peer in this form")
        return
    tot = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for t in sc["test_vectors"]:
        route = BgpRoute(network=t["prefix"], originatorIp=sc["peer_ip"], originType="igp",
                         protocol="bgp", asPath=t["as_path"])
        fr = bf.q.testRoutePolicies(policies=pols[0], direction=d, inputRoutes=[route]).answer().frame()
        act = fr.iloc[0]["Action"] if len(fr) else "NO_RESULT"
        lab = label(t["expected_action"], act)
        tot[lab] = tot.get(lab, 0) + 1
        print(f"   {'[+]' if lab in ('TP', 'TN') else '[-]'} {t['prefix']:<20} expected={t['expected_action']:<9} batfish={act:<6} {lab}")
    print("labels:", tot)


def main():
    conf, sid = Path(sys.argv[1]), sys.argv[2]
    ds = sys.argv[3] if len(sys.argv) > 3 else "dataset/bgp_security_dataset.json"
    sc = {s["id"]: s for s in json.loads(Path(ds).read_text())}[sid]
    cfg = conf.read_text()
    bf = Session(host="localhost")
    bf.set_network("bgp_llm_eval_debug")
    run(bf, "original", cfg, sc)
    v = afi_variant(cfg, sc["peer_ip"])
    if v is None:
        print("\n(no address-family variant: config has no neighbor-level filter line to move, "
              "or already has an address-family block)")
    else:
        print("\n===== address-family variant of the same config =====")
        print(v)
        run(bf, "addrfam", v, sc)


if __name__ == "__main__":
    main()
