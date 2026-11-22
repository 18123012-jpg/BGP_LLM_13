#!/usr/bin/env python3
"""Verify reference configs against the dataset.

Two independent checks per scenario:
  1. LOCAL  - a small Python evaluator (prefix-list + route-map, first match wins,
              implicit deny, neighbor binding) replays every test vector.
              It supports ONLY: ip prefix-list, route-map match ip address prefix-list,
              neighbor ... route-map ... in|out.  It is NOT FRR and NOT Batfish.
  2. VTYSH  - (--vtysh) pipes the config into `docker exec -i <container> vtysh -C`
              and requires exit code 0 (real FRR syntax check).

Usage:
  python verify_reference.py                      # local check only
  python verify_reference.py --vtysh              # local + FRR syntax check
  python verify_reference.py --dataset X.json --configs reference_configs/V1
"""
import argparse
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path


def parse_conf(text):
    pls, rms, binds = {}, {}, {}
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        if not raw.startswith(" "):
            cur = None
        m = re.match(r"ip prefix-list (\S+) seq (\d+) (permit|deny) (\S+?)(?: ge (\d+))?(?: le (\d+))?$", line)
        if m:
            name, seq, act, net, ge, le = m.groups()
            pls.setdefault(name, []).append(
                (int(seq), act, ipaddress.ip_network(net), int(ge) if ge else None, int(le) if le else None))
            continue
        m = re.match(r"route-map (\S+) (permit|deny) (\d+)$", line)
        if m:
            name, act, seq = m.groups()
            entry = (int(seq), act, [])
            rms.setdefault(name, []).append(entry)
            cur = entry
            continue
        m = re.match(r"match ip address prefix-list (\S+)$", line)
        if m and cur is not None:
            cur[2].append(m.group(1))
            continue
        m = re.match(r"neighbor (\S+) route-map (\S+) (in|out)$", line)
        if m:
            binds[(m.group(1), m.group(3))] = m.group(2)
    return pls, rms, binds


def pl_permits(entries, prefix):
    p = ipaddress.ip_network(prefix)
    for _seq, act, net, ge, le in sorted(entries, key=lambda e: e[0]):
        if ge is None and le is None:
            lo = hi = net.prefixlen
        else:
            lo = ge if ge is not None else net.prefixlen
            hi = le if le is not None else 32
        if p.network_address in net and lo <= p.prefixlen <= hi:
            return act == "permit"
    return False  # implicit deny


def rm_permits(entries, pls, prefix):
    for _seq, act, matches in sorted(entries, key=lambda e: e[0]):
        if all(pl_permits(pls.get(n, []), prefix) for n in matches):  # no match clause -> matches all
            return act == "permit"
    return False  # implicit deny


def vtysh_ok(text, container):
    r = subprocess.run(["docker", "exec", "-i", container, "vtysh", "-C", "-f", "/dev/stdin"],
                       input=text, capture_output=True, text=True)
    msg = [l for l in (r.stdout + r.stderr).splitlines() if "vtysh.conf" not in l and l.strip()]
    return r.returncode == 0, "; ".join(msg[:2])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="bgp_security_dataset.json")
    ap.add_argument("--configs", default="reference_configs/V1")
    ap.add_argument("--vtysh", action="store_true", help="also run vtysh -C inside the FRR container")
    ap.add_argument("--container", default="frr-eval")
    a = ap.parse_args()

    scenarios = {s["id"]: s for s in json.loads(Path(a.dataset).read_text())}
    files = sorted(Path(a.configs).glob("SEC-*.conf"))
    if not files:
        sys.exit(f"no SEC-*.conf in {a.configs}")

    tot = ok_vec = bad_sc = 0
    for f in files:
        sid = f.stem
        sc = scenarios.get(sid)
        if sc is None:
            print(f"[-] {sid}: not in dataset")
            bad_sc += 1
            continue
        text = f.read_text()
        pls, rms, binds = parse_conf(text)
        d = "in" if sc["direction"] == "inbound" else "out"
        rm_name = binds.get((sc["peer_ip"], d))
        problems = []
        if rm_name is None or rm_name not in rms:
            problems.append(f"no route-map bound to neighbor {sc['peer_ip']} {d}")
        else:
            for t in sc["test_vectors"]:
                got = PERMIT if rm_permits(rms[rm_name], pls, t["prefix"]) else DENY
                tot += 1
                if got == t["expected_action"]:
                    ok_vec += 1
                else:
                    problems.append(f"{t['prefix']} expected {t['expected_action']} got {got}")
        if a.vtysh:
            good, msg = vtysh_ok(text, a.container)
            if not good:
                problems.append(f"vtysh -C failed: {msg}")
        n = len(sc["test_vectors"])
        if problems:
            bad_sc += 1
            print(f"[-] {sid}: " + " | ".join(problems))
        else:
            print(f"[+] {sid}: {n}/{n} vectors" + (" + vtysh OK" if a.vtysh else ""))
    print(f"\nvectors correct: {ok_vec}/{tot} | scenarios failing: {bad_sc}/{len(files)}"
          + ("" if a.vtysh else " | vtysh NOT run (use --vtysh)"))
    sys.exit(1 if bad_sc else 0)


PERMIT, DENY = "PERMITTED", "DENIED"

if __name__ == "__main__":
    main()
