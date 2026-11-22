#!/usr/bin/env python3
"""Tier-2 feasibility test: can Batfish read an FRR config and answer testRoutePolicies?

Batfish has no standalone frr.conf format. It reads Cumulus Linux devices, one
concatenated file per device in <snapshot>/configs/<hostname>.cfg, built as:
    hostname line
    /etc/network/interfaces        (marker: "# This file describes the network interfaces")
    /etc/cumulus/ports.conf        (marker: "# ports.conf --")
    /etc/frr/frr.conf              (marker: "frr version")
This script wraps each reference config into that layout, loads it into a running
Batfish service, replays every test vector with testRoutePolicies, and labels the
result TP/TN/FP/FN against expected_action.

Label convention (matches T20): positive = route that SHOULD be permitted.
  TP permitted & expected PERMITTED   TN denied & expected DENIED
  FP permitted & expected DENIED (leak)   FN denied & expected PERMITTED (blackhole)

Usage (venv active, batfish container up):
  python scripts/test_batfish.py --dataset dataset/bgp_security_dataset.json \
      --configs dataset/reference_configs/V1 --only SEC-V1-01
  python scripts/test_batfish.py --dataset ... --configs ...            # all scenarios
"""
import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

from pybatfish.client.session import Session
from pybatfish.datamodel.route import BgpRoute

LOCAL_AS = 65000


def wrap_cumulus(frr_text, hostname, peer_ip):
    """Return one concatenated Cumulus-style file that Batfish can split into parts."""
    body = "\n".join(l for l in frr_text.splitlines() if not l.startswith(("hostname ", "frr defaults", "frr version")))
    return (
        f"{hostname}\n"
        "# This file describes the network interfaces\n"
        "auto lo\n"
        "iface lo inet loopback\n"
        "    address 192.0.2.250/32\n"
        "\n"
        "auto swp1\n"
        "iface swp1\n"
        "    address 192.0.2.250/24\n"
        "\n"
        "# ports.conf --\n"
        "\n"
        "frr version 8.5.2\n"
        "frr defaults traditional\n"
        f"hostname {hostname}\n"
        f"{body}\n"
    )


def policy_for(frr_text, peer_ip, direction):
    m = re.search(rf"neighbor {re.escape(peer_ip)} route-map (\S+) {direction}\b", frr_text)
    return m.group(1) if m else None


def label(expected, action):
    permitted = action == "PERMIT"
    if expected == "PERMITTED":
        return "TP" if permitted else "FN"
    return "FP" if permitted else "TN"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--configs", required=True)
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--only", help="run one scenario id, e.g. SEC-V1-01")
    a = ap.parse_args()

    scenarios = {s["id"]: s for s in json.loads(Path(a.dataset).read_text())}
    files = sorted(Path(a.configs).glob("SEC-*.conf"))
    if a.only:
        files = [f for f in files if f.stem == a.only]
    if not files:
        sys.exit("no config files selected")

    bf = Session(host=a.host)
    bf.set_network("bgp_llm_eval")
    totals = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    failed = 0

    for f in files:
        sc = scenarios[f.stem]
        text = f.read_text()
        host = "ref-" + f.stem.lower()
        d = "in" if sc["direction"] == "inbound" else "out"
        pol = policy_for(text, sc["peer_ip"], d)
        print(f"\n=== {f.stem}  policy={pol}  direction={d}")

        snap = Path(tempfile.mkdtemp(prefix="bfsnap_"))
        (snap / "configs").mkdir()
        (snap / "configs" / f"{host}.cfg").write_text(wrap_cumulus(text, host, sc["peer_ip"]))
        try:
            bf.init_snapshot(str(snap), name=f.stem, overwrite=True)
        finally:
            shutil.rmtree(snap, ignore_errors=True)

        parse = bf.q.fileParseStatus().answer().frame()
        print("parse status:", parse[["File_Name", "Status"]].to_dict("records"))
        issues = bf.q.initIssues().answer().frame()
        if len(issues):
            print("init issues:")
            for _, r in issues.iterrows():
                print("   ", str(r.get("Details", r.to_dict()))[:200])

        if pol is None:
            print("[-] no neighbor route-map binding found in config")
            failed += 1
            continue

        bad = 0
        for t in sc["test_vectors"]:
            route = BgpRoute(network=t["prefix"], originatorIp=sc["peer_ip"],
                             originType="igp", protocol="bgp", asPath=t["as_path"])
            fr = bf.q.testRoutePolicies(policies=pol, direction=d,
                                        inputRoutes=[route]).answer().frame()
            if fr.empty:
                print(f"  [-] {t['prefix']}: no result (policy not found or not parsed)")
                bad += 1
                continue
            action = fr.iloc[0]["Action"]
            lab = label(t["expected_action"], action)
            totals[lab] += 1
            ok = lab in ("TP", "TN")
            bad += 0 if ok else 1
            print(f"  [{'+' if ok else '-'}] {t['prefix']:<20} expected={t['expected_action']:<9} "
                  f"batfish={action:<6} {lab}")
        failed += 1 if bad else 0

    print("\nTOTAL", totals, f"| scenarios with problems: {failed}/{len(files)}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
