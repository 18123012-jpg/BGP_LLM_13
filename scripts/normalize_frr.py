#!/usr/bin/env python3
"""Normalize FRR neighbor-level prefix-lists into equivalent route-maps.

Why: FRR applies `neighbor X prefix-list P in|out` as "permit iff P permits the prefix,
implicit deny otherwise". A route-map with one `permit 10` clause that matches P, bound with
`neighbor X route-map R in|out`, behaves identically (no match -> implicit deny). Batfish's
testRoutePolicies grades named route policies, so a bare neighbor prefix-list leaves the
Tier-2 grader with nothing to run (Import_Policy == []).

Scope (deliberately narrow):
  * rewrites ONLY `neighbor <x> prefix-list <P> in|out` lines
  * if the same neighbor+direction ALSO has a route-map, FRR applies both (prefix-list first);
    that case is left untouched and reported, never merged
  * every rewrite is logged so the number of normalized answers per model can be reported
    in threats to validity

Usage:
  python normalize_frr.py in.conf                 # normalized config to stdout, log to stderr
  python normalize_frr.py in.conf -o out.conf     # write file
  from normalize_frr import normalize; text, log = normalize(raw)
"""
import argparse
import json
import re
import sys
from pathlib import Path

NB_PL = re.compile(r"^(\s*)neighbor\s+(\S+)\s+prefix-list\s+(\S+)\s+(in|out)\s*$")
NB_RM = re.compile(r"^\s*neighbor\s+(\S+)\s+route-map\s+(\S+)\s+(in|out)\s*$")
RM_DEF = re.compile(r"^route-map\s+(\S+)\s+(?:permit|deny)\s+\d+\s*$")


def normalize(text):
    lines = text.splitlines()
    rm_bound = {(m.group(1), m.group(3)) for l in lines if (m := NB_RM.match(l))}
    used = {m.group(1) for l in lines if (m := RM_DEF.match(l))}
    made = {}          # (prefix_list, direction) -> generated route-map name
    out, new_maps, log = [], [], []
    for l in lines:
        m = NB_PL.match(l)
        if not m:
            out.append(l)
            continue
        ind, nb, pl, d = m.groups()
        if (nb, d) in rm_bound:
            out.append(l)
            log.append({"neighbor": nb, "direction": d, "prefix_list": pl,
                        "action": "kept: route-map also bound, not merged"})
            continue
        if (pl, d) not in made:
            name = f"AUTO-{pl}-{d.upper()}"
            while name in used:
                name += "_"
            used.add(name)
            made[(pl, d)] = name
            new_maps.append(f"route-map {name} permit 10\n match ip address prefix-list {pl}")
        name = made[(pl, d)]
        out.append(f"{ind}neighbor {nb} route-map {name} {d}")
        log.append({"neighbor": nb, "direction": d, "prefix_list": pl,
                    "action": f"rewritten to route-map {name}"})
    result = "\n".join(out).rstrip("\n") + "\n"
    if new_maps:
        result += "!\n" + "\n".join(new_maps) + "\n"
    return result, log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("conf")
    ap.add_argument("-o", "--output")
    a = ap.parse_args()
    text, log = normalize(Path(a.conf).read_text())
    if a.output:
        Path(a.output).write_text(text)
    else:
        sys.stdout.write(text)
    print(json.dumps(log, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()
