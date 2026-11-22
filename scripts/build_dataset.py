#!/usr/bin/env python3
"""Phase 2 - Scenario dataset generator + validator.

Output:
  bgp_security_dataset.json        ground truth (40 scenarios, 92 test vectors)
  output/dataset_summary.json      validation report (status PASSED / FAILED)

Design (see slides 26-27):
  * 4 vector categories x 10 scenarios; 2-5 test routes per scenario
  * V1 bogon = 28 vectors, V2 AS-path = 23, V3 max-prefix = 21, V4 communities = 20
  * Every test vector has expected_action (PERMITTED / DENIED) and, where useful, a reason
  * Intent prompts are plain language: NO CLI keywords, so the model must choose constructs
  * Scenario numbering is global: V1 = 01-10, V2 = 11-20, V3 = 21-30, V4 = 31-40
  * peer_as = 65000 + n, peer_ip = 192.0.2.n  (unique per scenario; local AS is always 65000)

Conventions inside as_path:
  "P"  -> the peer's own ASN        "P1" -> peer ASN with a digit appended (look-alike ASN)
  []   -> locally originated route (used for outbound / egress tests)
"""
import hashlib
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path

LOCAL_AS = 65000
DATASET_FILE = Path("dataset/bgp_security_dataset.json")
OUT_DIR = Path("output")
PERMITTED, DENIED = "PERMITTED", "DENIED"

EXPECTED_VECTORS = {1: 28, 2: 23, 3: 21, 4: 20}
CATEGORY = {
    1: "bogon_rfc1918_prefix_filtering",
    2: "as_path_origin_regex",
    3: "max_prefix_restart_throttling",
    4: "community_scrubbing_tagging",
}


def v(prefix, path, action, reason=None, comm=None, exp_comm=None, exp_lp=None):
    d = {"prefix": prefix, "as_path": path, "expected_action": action}
    if reason:
        d["reason"] = reason
    if comm is not None:
        d["communities"] = comm
    if exp_comm is not None:
        d["expected_communities"] = exp_comm
    if exp_lp is not None:
        d["expected_local_pref"] = exp_lp
    return d


# Each entry: (name, peering_type, direction, invariant, intent, vectors[, extra])
# extra = {"extra_peer_ips": [...], "static_assertions": [regex, ...]}
RAW = {1: [], 2: [], 3: [], 4: []}

# ------------------------------------------------------------------ V1 bogon (28)
RAW[1] += [
    ("RFC 1918 Private IPv4 Inbound Filtering", "customer", "inbound",
     "Nothing inside 10.0.0.0/8 or longer than /24 is accepted from AS {peer}; 203.0.113.0/24 is accepted.",
     "You operate AS {local}. Customer AS {peer} connects over eBGP at {ip} and owns 203.0.113.0/24. "
     "Accept only the customer's own block. Reject private RFC 1918 space and any route more specific than a /24.",
     [v("10.10.1.0/24", ["P"], DENIED, "RFC 1918 (10.0.0.0/8)"),
      v("203.0.113.0/24", ["P"], PERMITTED),
      v("198.51.100.0/25", ["P"], DENIED, "Longer than /24")]),
    ("CGNAT and 172.16/12 Inbound Filtering", "customer", "inbound",
     "Nothing in 100.64.0.0/10 or 172.16.0.0/12 is accepted from AS {peer}; 198.51.100.0/24 is accepted.",
     "You operate AS {local}. Customer AS {peer} at {ip} owns 198.51.100.0/24. Accept that block only. "
     "Shared carrier-grade NAT space and the middle private range must never be accepted.",
     [v("100.64.10.0/24", ["P"], DENIED, "RFC 6598 (100.64.0.0/10)"),
      v("198.51.100.0/24", ["P"], PERMITTED),
      v("172.16.5.0/24", ["P"], DENIED, "RFC 1918 (172.16.0.0/12)")]),
    ("Loopback and Link-Local Inbound Filtering", "peer", "inbound",
     "Nothing in 127.0.0.0/8 or 169.254.0.0/16 is accepted from AS {peer}; 203.0.113.0/24 is accepted.",
     "You operate AS {local} and peer settlement-free with AS {peer} at {ip}. The peer announces 203.0.113.0/24. "
     "Accept that, but reject loopback and link-local address space.",
     [v("127.0.0.0/24", ["P"], DENIED, "Loopback 127.0.0.0/8"),
      v("169.254.1.0/24", ["P"], DENIED, "Link-local 169.254.0.0/16"),
      v("203.0.113.0/24", ["P"], PERMITTED)]),
    ("Multicast and Class E Inbound Filtering", "transit", "inbound",
     "No multicast (224.0.0.0/4) or reserved class E (240.0.0.0/4) prefix is accepted from transit AS {peer}.",
     "You operate AS {local} and buy transit from AS {peer} at {ip}. Take ordinary unicast routes up to a /24 "
     "but never accept multicast or reserved experimental space.",
     [v("224.0.0.0/24", ["P"], DENIED, "Multicast 224.0.0.0/4"),
      v("240.0.0.0/24", ["P"], DENIED, "Reserved class E 240.0.0.0/4"),
      v("203.0.113.0/24", ["P", 15169], PERMITTED)]),
    ("Benchmarking and Protocol-Assignment Ranges", "ixp", "inbound",
     "Nothing in 198.18.0.0/15 or 192.0.0.0/24 is accepted from AS {peer} at the exchange.",
     "You operate AS {local} at an internet exchange and receive routes from AS {peer} at {ip}. "
     "Reject the network-benchmarking range and the IETF protocol-assignment block; accept ordinary customer space.",
     [v("198.18.4.0/24", ["P"], DENIED, "RFC 2544 (198.18.0.0/15)"),
      v("192.0.0.0/24", ["P"], DENIED, "RFC 6890 IETF protocol assignments"),
      v("203.0.113.0/24", ["P"], PERMITTED)]),
    ("Prefix Length Boundary /24 versus /25", "customer", "inbound",
     "Only the exact /24 203.0.113.0/24 is accepted from AS {peer}; any more-specific is rejected.",
     "You operate AS {local}. Customer AS {peer} at {ip} is assigned 203.0.113.0/24. "
     "Accept the whole block as announced but refuse any smaller pieces of it.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("203.0.113.0/25", ["P"], DENIED, "Longer than /24"),
      v("203.0.113.128/25", ["P"], DENIED, "Longer than /24")]),
    ("Default Route Rejection", "peer", "inbound",
     "The default route and private space are never accepted from AS {peer}.",
     "You operate AS {local} and peer with AS {peer} at {ip}. The peer must not hand you a default route "
     "or any private space; accept its real customer block 203.0.113.0/24.",
     [v("0.0.0.0/0", ["P"], DENIED, "Default route"),
      v("203.0.113.0/24", ["P"], PERMITTED),
      v("10.0.0.0/8", ["P"], DENIED, "RFC 1918 (10.0.0.0/8)")]),
    ("Customer Allocation Whitelist", "customer", "inbound",
     "Only 203.0.113.0/24 and 198.51.100.0/24 are accepted from AS {peer}; all other space is rejected.",
     "You operate AS {local}. Customer AS {peer} at {ip} holds exactly two blocks: 203.0.113.0/24 and "
     "198.51.100.0/24. Accept those and nothing else, even if the prefix looks legitimate.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("198.51.100.0/24", ["P"], PERMITTED),
      v("8.8.8.0/24", ["P"], DENIED, "Not in customer allocation")]),
    ("Private Space Egress to Transit", "transit", "outbound",
     "Only 203.0.113.0/24 is announced to transit AS {peer}; private space is never announced.",
     "You operate AS {local} and announce routes to your upstream AS {peer} at {ip}. Announce only your own "
     "block 203.0.113.0/24 and never leak internal private space.",
     [v("10.20.0.0/16", [], DENIED, "RFC 1918 (10.0.0.0/8)"),
      v("203.0.113.0/24", [], PERMITTED)]),
    ("Exchange Bogon Sweep", "ixp", "inbound",
     "No 192.168.0.0/16 prefix is accepted from AS {peer}; 198.51.100.0/24 is accepted.",
     "You operate AS {local} at an exchange. AS {peer} at {ip} announces 198.51.100.0/24. "
     "Accept it, and reject the home-network private range if it ever appears.",
     [v("192.168.50.0/24", ["P"], DENIED, "RFC 1918 (192.168.0.0/16)"),
      v("198.51.100.0/24", ["P"], PERMITTED)]),
]

# ------------------------------------------------------------------ V2 AS-path (23)
RAW[2] += [
    ("Stub Customer Origin Only", "customer", "inbound",
     "Only a path consisting solely of AS {peer} is accepted from {ip}.",
     "You operate AS {local}. AS {peer} is a stub customer at {ip}. Accept a route only if the customer "
     "originated it itself with nothing else in the path; reject anything else.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("203.0.113.0/24", [3356, "P"], DENIED, "Path transits another AS")]),
    ("Prepending Customer", "customer", "inbound",
     "Paths made only of AS {peer}, repeated any number of times, are accepted; paths originated elsewhere are rejected.",
     "You operate AS {local}. Customer AS {peer} at {ip} sometimes repeats its own AS number for traffic "
     "engineering. Allow that, but reject any route the customer did not originate.",
     [v("203.0.113.0/24", ["P", "P"], PERMITTED),
      v("203.0.113.0/24", ["P", 3356], DENIED, "Origin is not the customer")]),
    ("Customer Cone", "customer", "inbound",
     "Routes originated by AS {peer} or its downstream customer AS 65100 are accepted; other origins are rejected.",
     "You operate AS {local}. Customer AS {peer} at {ip} also provides transit to its own customer AS 65100. "
     "Accept routes originated by either, and reject routes originated by anyone else.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("203.0.113.0/24", ["P", 65100], PERMITTED),
      v("203.0.113.0/24", ["P", 3356], DENIED, "Origin outside customer cone")]),
    ("Lateral Peer Without Tier-1", "peer", "inbound",
     "Any path from AS {peer} containing AS 701, 174 or 3356 is rejected.",
     "You operate AS {local} and peer settlement-free with AS {peer} at {ip}. A lateral peer must never "
     "carry the large tier-1 transit networks 701, 174 or 3356; reject any route whose path mentions them.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("203.0.113.0/24", ["P", 174], DENIED, "Tier-1 ASN 174 via lateral peer"),
      v("203.0.113.0/24", ["P", 701, 65200], DENIED, "Tier-1 ASN 701 mid-path")]),
    ("Look-Alike ASN Rejection", "customer", "inbound",
     "Only the exact path AS {peer} is accepted; an ASN that merely starts with the same digits is rejected.",
     "You operate AS {local}. Customer AS {peer} at {ip} must be the sole AS in the path. "
     "Be careful: a different network whose AS number begins with the same digits must not be accepted.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("203.0.113.0/24", ["P1"], DENIED, "Look-alike ASN (peer ASN + extra digit)")]),
    ("Private ASN in Transit Path", "transit", "inbound",
     "Paths from transit AS {peer} containing a private ASN in 64512-65534 are rejected.",
     "You operate AS {local} and buy transit from AS {peer} at {ip}. Reject any route whose path "
     "contains an AS number from the private-use range.",
     [v("203.0.113.0/24", ["P", 15169], PERMITTED),
      v("203.0.113.0/24", ["P", 64600], DENIED, "Private ASN 64600 in path")]),
    ("Excessive Path Length", "transit", "inbound",
     "Paths longer than 10 hops from AS {peer} are rejected.",
     "You operate AS {local} and receive routes from transit AS {peer} at {ip}. Reject any route whose "
     "AS path is longer than ten hops; normal short paths are fine.",
     [v("203.0.113.0/24", ["P", 3356, 174, 701, 1299, 2914], PERMITTED),
      v("203.0.113.0/24", ["P", 3356, 174, 701, 1299, 2914, 6453, 6762, 3257, 1273, 4134], DENIED,
        "11 hops, longer than 10")]),
    ("Egress Own Routes Only", "peer", "outbound",
     "Only locally originated routes (empty AS path) are announced to AS {peer}.",
     "You operate AS {local} and announce routes to lateral peer AS {peer} at {ip}. Send only routes that "
     "your own network originated; never re-announce routes learned from a provider.",
     [v("203.0.113.0/24", [], PERMITTED),
      v("198.51.100.0/24", [3356], DENIED, "Learned from provider, must not leak")]),
    ("AS Loop Prevention", "transit", "inbound",
     "Paths from AS {peer} that already contain AS {local} are rejected.",
     "You operate AS {local} and receive routes from transit AS {peer} at {ip}. Reject any route whose "
     "path already includes your own AS number.",
     [v("203.0.113.0/24", ["P", 15169], PERMITTED),
      v("203.0.113.0/24", ["P", LOCAL_AS, 15169], DENIED, "Own ASN in path (loop)")]),
    ("Exchange First-AS Enforcement", "ixp", "inbound",
     "The first AS in every path from {ip} must be AS {peer}.",
     "You operate AS {local} at an internet exchange. Neighbor AS {peer} at {ip} must be the leftmost AS "
     "in every path it sends. Reject routes whose first AS is anyone else.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("203.0.113.0/24", ["P", 13335], PERMITTED),
      v("203.0.113.0/24", [13335, "P"], DENIED, "First AS is not the neighbor")]),
]

# ------------------------------------------------------------------ V3 max-prefix (21)
RAW[3] += [
    ("Stub Customer Hard Limit with Restart", "customer", "inbound",
     "Neighbor {ip} is limited to 100 prefixes, warns at 80%, restarts after 15 minutes; only the /24 203.0.113.0/24 is accepted.",
     "You operate AS {local}. Stub customer AS {peer} at {ip} should only ever send tens of routes. "
     "Cap how many prefixes it may send at 100: log a warning at 80 percent, tear the session down above 100, "
     "and let it retry after 15 minutes. Also accept only its block 203.0.113.0/24 and nothing more specific.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("203.0.113.0/25", ["P"], DENIED, "Longer than /24")],
     {"static_assertions": [r"neighbor {ip} maximum-prefix 100 80 restart 15\b"]}),
    ("Peer Warning-Only Monitoring", "peer", "inbound",
     "Neighbor {ip} is limited to 500 prefixes with warning only at 90%; session is never torn down.",
     "You operate AS {local} and peer with AS {peer} at {ip}. Allow up to 500 prefixes and log a warning at "
     "90 percent, but never tear the session down. Reject private space from this peer.",
     [v("198.51.100.0/24", ["P"], PERMITTED),
      v("10.0.0.0/8", ["P"], DENIED, "RFC 1918 (10.0.0.0/8)")],
     {"static_assertions": [r"neighbor {ip} maximum-prefix 500 90 warning-only\b"]}),
    ("Transit Full-Table Limit", "transit", "inbound",
     "Neighbor {ip} is limited to 1,000,000 prefixes, warns at 85%, restarts after 30 minutes; default route rejected.",
     "You operate AS {local} and buy a full table from transit AS {peer} at {ip}. Set the ceiling at one million "
     "prefixes, warn at 85 percent, tear down above the ceiling and retry after 30 minutes. Do not accept a default route.",
     [v("203.0.113.0/24", ["P", 15169], PERMITTED),
      v("0.0.0.0/0", ["P"], DENIED, "Default route")],
     {"static_assertions": [r"neighbor {ip} maximum-prefix 1000000 85 restart 30\b"]}),
    ("Exchange Peer Limit with Long Restart", "ixp", "inbound",
     "Neighbor {ip} is limited to 2000 prefixes, warns at 75%, restarts after 60 minutes; CGNAT space rejected.",
     "You operate AS {local} at an exchange. AS {peer} at {ip} may send at most 2000 prefixes: warn at 75 percent, "
     "tear down above the limit and wait an hour before retrying. Reject shared carrier-grade NAT space.",
     [v("198.51.100.0/24", ["P"], PERMITTED),
      v("100.64.0.0/10", ["P"], DENIED, "RFC 6598 (100.64.0.0/10)")],
     {"static_assertions": [r"neighbor {ip} maximum-prefix 2000 75 restart 60\b"]}),
    ("Peer-Group Inheritance", "customer", "inbound",
     "Every member of peer group CUSTOMERS ({ip} and 192.0.2.200) is limited to 50 prefixes with warning at 80%.",
     "You operate AS {local}. Two customer sessions, {ip} and 192.0.2.200, both belong to AS {peer} and share one "
     "template named CUSTOMERS. Put the prefix ceiling of 50 with an 80 percent warning on that template so both "
     "sessions inherit it. Reject multicast space.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("224.0.0.0/24", ["P"], DENIED, "Multicast 224.0.0.0/4")],
     {"extra_peer_ips": ["192.0.2.200"],
      "static_assertions": [r"neighbor CUSTOMERS maximum-prefix 50 80\b",
                            r"neighbor {ip} peer-group CUSTOMERS\b",
                            r"neighbor 192\.0\.2\.200 peer-group CUSTOMERS\b"]}),
    ("Per-Neighbor Override of Group Limit", "peer", "inbound",
     "Group PEERS has a 100-prefix limit; neighbor {ip} overrides it to 500.",
     "You operate AS {local}. A template named PEERS carries a default ceiling of 100 prefixes. Neighbor {ip} "
     "(AS {peer}) is a bigger peer that is a member of PEERS but needs its own ceiling of 500. "
     "Reject link-local space from it.",
     [v("198.51.100.0/24", ["P"], PERMITTED),
      v("169.254.0.0/16", ["P"], DENIED, "Link-local 169.254.0.0/16")],
     {"static_assertions": [r"neighbor PEERS maximum-prefix 100\b",
                            r"neighbor {ip} peer-group PEERS\b",
                            r"neighbor {ip} maximum-prefix 500\b"]}),
    ("Route-Flap Damping", "customer", "inbound",
     "Flap damping is configured with half-life 15, reuse 750, suppress 2000, max-suppress 60; only the /24 is accepted.",
     "You operate AS {local}. Customer AS {peer} at {ip} has an unstable link that keeps flapping its route. "
     "Enable route-flap damping with a 15 minute half-life, reuse threshold 750, suppress threshold 2000 and a "
     "maximum suppress time of 60 minutes. Accept only its /24 block and nothing smaller.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("203.0.113.0/26", ["P"], DENIED, "Longer than /24")],
     {"static_assertions": [r"bgp dampening 15 750 2000 60\b"]}),
    ("Tiny Stub Strict Cap", "customer", "inbound",
     "Neighbor {ip} is limited to 10 prefixes with the default warning and no automatic restart.",
     "You operate AS {local}. Customer AS {peer} at {ip} announces a single small block. Allow no more than 10 prefixes "
     "and tear the session down above that without any automatic retry. Reject private space.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("172.20.0.0/16", ["P"], DENIED, "RFC 1918 (172.16.0.0/12)")],
     {"static_assertions": [r"(?m)neighbor {ip} maximum-prefix 10$"]}),
    ("Peer Limit with 30 Minute Restart", "peer", "inbound",
     "Neighbor {ip} is limited to 250 prefixes with a 30-minute restart; /25s and link-local rejected.",
     "You operate AS {local} and peer with AS {peer} at {ip}. Allow at most 250 prefixes; if exceeded, drop the session "
     "and let it come back after 30 minutes. Accept ordinary /24 space but reject anything more specific and link-local space.",
     [v("198.51.100.0/24", ["P"], PERMITTED),
      v("198.51.100.0/25", ["P"], DENIED, "Longer than /24"),
      v("169.254.0.0/16", ["P"], DENIED, "Link-local 169.254.0.0/16")],
     {"static_assertions": [r"neighbor {ip} maximum-prefix 250( \d+)? restart 30\b"]}),
    ("Large Customer Cone Limit", "customer", "inbound",
     "Neighbor {ip} is limited to 5000 prefixes, warns at 70%, restarts after 15 minutes; class E space rejected.",
     "You operate AS {local}. Customer AS {peer} at {ip} has a large downstream cone. Allow up to 5000 prefixes, warn "
     "at 70 percent, tear down above the limit and retry after 15 minutes. Reject reserved experimental space.",
     [v("203.0.113.0/24", ["P"], PERMITTED),
      v("240.0.0.0/24", ["P"], DENIED, "Reserved class E 240.0.0.0/4")],
     {"static_assertions": [r"neighbor {ip} maximum-prefix 5000 70 restart 15\b"]}),
]

# ------------------------------------------------------------------ V4 communities (20)
RAW[4] += [
    ("Ingress Replace Customer Communities", "customer", "inbound",
     "Routes accepted from AS {peer} carry exactly community 65000:1001; the customer's own tags are discarded.",
     "You operate AS {local}. Customer AS {peer} at {ip} owns 203.0.113.0/24 and attaches its own control tags. "
     "On import, throw away whatever tags the customer set and mark the route only with your internal customer tag 65000:1001. "
     "Reject private space.",
     [v("203.0.113.0/24", ["P"], PERMITTED, comm=["65001:120", "65000:80"], exp_comm=["65000:1001"]),
      v("10.5.0.0/16", ["P"], DENIED, "RFC 1918 (10.0.0.0/8)", comm=[])]),
    ("Egress Scrub of Internal Communities", "transit", "outbound",
     "Routes announced to transit AS {peer} carry no 65000:* community.",
     "You operate AS {local} and announce routes to your upstream AS {peer} at {ip}. Strip every community in your "
     "own 65000 namespace before the route leaves. Never announce private space.",
     [v("203.0.113.0/24", [], PERMITTED, comm=["65000:1001", "65000:200"], exp_comm=[]),
      v("10.20.0.0/16", [], DENIED, "RFC 1918 (10.0.0.0/8)", comm=["65000:1001"])]),
    ("NO_EXPORT Tagging for Peer Routes", "peer", "inbound",
     "Routes accepted from AS {peer} carry the well-known no-export community 65535:65281.",
     "You operate AS {local} and peer with AS {peer} at {ip}. Mark everything learned from this peer so it stays "
     "inside your network and is never passed to other neighbors. Reject shared carrier-grade NAT space.",
     [v("198.51.100.0/24", ["P"], PERMITTED, comm=[], exp_comm=["65535:65281"]),
      v("100.64.0.0/10", ["P"], DENIED, "RFC 6598 (100.64.0.0/10)", comm=[])]),
    ("Customer Blackhole Request", "customer", "inbound",
     "A /32 inside 203.0.113.0/24 tagged 65535:666 is accepted and also tagged 65535:65281; other /32s are rejected.",
     "You operate AS {local}. Customer AS {peer} at {ip} owns 203.0.113.0/24 and may ask you to drop traffic to a single "
     "host by sending that /32 with the standard blackhole community. Accept such requests only for addresses inside its "
     "own block, keep the blackhole community, and make sure the route cannot leave your network.",
     [v("203.0.113.55/32", ["P"], PERMITTED, comm=["65535:666"], exp_comm=["65535:666", "65535:65281"]),
      v("198.51.100.55/32", ["P"], DENIED, "Not in customer allocation", comm=["65535:666"])]),
    ("Large Community Replacement", "customer", "inbound",
     "Routes accepted from AS {peer} carry only large community 65000:1:100; customer large communities are discarded.",
     "You operate AS {local}. Customer AS {peer} at {ip} attaches 3-part large communities of its own. "
     "Discard them on import and mark the route with your large community 65000:1:100. Reject the home-network private range.",
     [v("203.0.113.0/24", ["P"], PERMITTED, comm=["65001:100:1"], exp_comm=["65000:1:100"]),
      v("192.168.7.0/24", ["P"], DENIED, "RFC 1918 (192.168.0.0/16)", comm=[])]),
    ("Customer Local-Preference Control", "customer", "inbound",
     "Only community 65000:80 is honored from AS {peer} and sets local-preference 80; 65000:200 is discarded.",
     "You operate AS {local}. Customer AS {peer} at {ip} may ask for a backup role by sending community 65000:80, which "
     "lowers the route's local preference to 80. It may not ask for anything higher: discard any other community in your "
     "namespace, such as 65000:200. Reject routes more specific than a /24.",
     [v("203.0.113.0/24", ["P"], PERMITTED, comm=["65000:80", "65000:200"], exp_comm=["65000:80"], exp_lp=80),
      v("203.0.113.0/25", ["P"], DENIED, "Longer than /24", comm=[])]),
    ("Additive Region Tag", "customer", "inbound",
     "Routes accepted from AS {peer} keep the customer's informational tag 65001:777 and gain region tag 65000:2001.",
     "You operate AS {local}. Customer AS {peer} at {ip} attaches an informational tag 65001:777 that you want to keep. "
     "Add your own region tag 65000:2001 without removing the customer's tag. Reject the upper private range.",
     [v("203.0.113.0/24", ["P"], PERMITTED, comm=["65001:777"], exp_comm=["65001:777", "65000:2001"]),
      v("172.31.0.0/16", ["P"], DENIED, "RFC 1918 (172.16.0.0/12)", comm=[])]),
    ("Scrub Internal Tags but Keep Upstream Signal", "transit", "outbound",
     "Routes announced to AS {peer} lose all 65000:* communities except 65000:9999, which is meant for the upstream.",
     "You operate AS {local} and announce routes to upstream AS {peer} at {ip}. Remove your internal communities from the 65000 "
     "namespace before announcing, but keep the single tag 65000:9999 because the upstream acts on it. Never announce private space.",
     [v("203.0.113.0/24", [], PERMITTED, comm=["65000:1001", "65000:9999"], exp_comm=["65000:9999"]),
      v("10.30.0.0/16", [], DENIED, "RFC 1918 (10.0.0.0/8)", comm=[])]),
    ("Graceful Shutdown Handling", "peer", "inbound",
     "Routes from AS {peer} carrying 65535:0 are accepted with local-preference 0 and keep the community.",
     "You operate AS {local} and peer with AS {peer} at {ip}. When the peer announces that it is going down for maintenance "
     "using the standard graceful-shutdown community, make that route the least preferred and keep the community. "
     "Reject multicast space.",
     [v("198.51.100.0/24", ["P"], PERMITTED, comm=["65535:0"], exp_comm=["65535:0"], exp_lp=0),
      v("224.1.0.0/24", ["P"], DENIED, "Multicast 224.0.0.0/4", comm=[])]),
    ("Customer-Only Tag Must Not Reach Transit", "transit", "outbound",
     "Routes tagged 65000:3 are never announced to AS {peer}; untagged own routes are announced unchanged.",
     "You operate AS {local} and announce routes to upstream AS {peer} at {ip}. Routes carrying your internal customer-only "
     "tag 65000:3 must never be sent to the upstream. All other own routes go out unchanged.",
     [v("203.0.113.0/24", [], PERMITTED, comm=[], exp_comm=[]),
      v("198.51.100.0/24", [], DENIED, "Tagged customer-only, must not go to transit", comm=["65000:3"])]),
]

# ------------------------------------------------------------------ build + validate
def resolve_path(path, peer_as):
    out = []
    for x in path:
        if x == "P":
            out.append(peer_as)
        elif x == "P1":
            out.append(int(f"{peer_as}1"))
        else:
            out.append(x)
    return out


def build():
    scenarios, n = [], 0
    for vec in (1, 2, 3, 4):
        for entry in RAW[vec]:
            name, ptype, direction, invariant, intent, vectors = entry[:6]
            extra = entry[6] if len(entry) > 6 else {}
            n += 1
            peer_as, peer_ip = LOCAL_AS + n, f"192.0.2.{n}"
            fmt = {"local": LOCAL_AS, "peer": peer_as, "ip": peer_ip}
            sc = {
                "id": f"SEC-V{vec}-{n:02d}",
                "name": name,
                "vector_category": CATEGORY[vec],
                "peering_type": ptype,
                "direction": direction,
                "local_as": LOCAL_AS,
                "peer_as": peer_as,
                "peer_ip": peer_ip,
                "invariant": invariant.format(**fmt),
                "intent": intent.format(**fmt),
                "test_vectors": [dict(tv, as_path=resolve_path(tv["as_path"], peer_as)) for tv in vectors],
            }
            if extra.get("extra_peer_ips"):
                sc["extra_peer_ips"] = extra["extra_peer_ips"]
            if extra.get("static_assertions"):
                sc["static_assertions"] = [a.replace("{ip}", re.escape(peer_ip)) for a in extra["static_assertions"]]
            scenarios.append(sc)
    return scenarios


COMM_RE = re.compile(r"^\d+:\d+(:\d+)?$")


def validate(scenarios):
    errs = []
    ids, asns, ips = set(), set(), set()
    per_vec = Counter()
    for sc in scenarios:
        sid = sc["id"]
        if sid in ids:
            errs.append(f"{sid}: duplicate id")
        ids.add(sid)
        vec = int(sid.split("-")[1][1])
        if not 64512 <= sc["peer_as"] <= 65534 or sc["peer_as"] == sc["local_as"]:
            errs.append(f"{sid}: peer_as {sc['peer_as']} invalid or equals local_as")
        if sc["peer_as"] in asns:
            errs.append(f"{sid}: duplicate peer_as {sc['peer_as']}")
        asns.add(sc["peer_as"])
        for ip in [sc["peer_ip"]] + sc.get("extra_peer_ips", []):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errs.append(f"{sid}: bad ip {ip}")
            if ip in ips:
                errs.append(f"{sid}: duplicate peer ip {ip}")
            ips.add(ip)
        if sc["peering_type"] not in {"customer", "peer", "transit", "ixp"}:
            errs.append(f"{sid}: bad peering_type")
        if sc["direction"] not in {"inbound", "outbound"}:
            errs.append(f"{sid}: bad direction")
        tvs = sc["test_vectors"]
        if not 2 <= len(tvs) <= 5:
            errs.append(f"{sid}: needs 2-5 vectors, has {len(tvs)}")
        acts = {t["expected_action"] for t in tvs}
        if acts != {PERMITTED, DENIED}:
            errs.append(f"{sid}: must mix PERMITTED and DENIED")
        seen = set()
        for t in tvs:
            try:
                ipaddress.ip_network(t["prefix"], strict=True)
            except ValueError:
                errs.append(f"{sid}: bad prefix {t['prefix']}")
            if t["expected_action"] not in {PERMITTED, DENIED}:
                errs.append(f"{sid}: bad action")
            if t["expected_action"] == DENIED and not t.get("reason"):
                errs.append(f"{sid}: DENIED vector {t['prefix']} lacks reason")
            if not all(isinstance(a, int) and 1 <= a <= 4294967295 for a in t["as_path"]):
                errs.append(f"{sid}: bad as_path {t['as_path']}")
            for c in t.get("communities", []) + t.get("expected_communities", []):
                if not COMM_RE.match(c):
                    errs.append(f"{sid}: bad community {c}")
            if vec == 4 and t["expected_action"] == PERMITTED and "expected_communities" not in t:
                errs.append(f"{sid}: PERMITTED V4 vector lacks expected_communities")
            key = (t["prefix"], tuple(t["as_path"]), tuple(t.get("communities", [])))
            if key in seen:
                errs.append(f"{sid}: duplicate vector {key}")
            seen.add(key)
            per_vec[vec] += 1
        if vec == 3:
            for pat in sc.get("static_assertions", []):
                try:
                    re.compile(pat)
                except re.error as e:
                    errs.append(f"{sid}: bad regex {pat}: {e}")
            if not sc.get("static_assertions"):
                errs.append(f"{sid}: V3 scenario lacks static_assertions")
    for vec, want in EXPECTED_VECTORS.items():
        if per_vec[vec] != want:
            errs.append(f"V{vec}: expected {want} vectors, got {per_vec[vec]}")
    if len(scenarios) != 40:
        errs.append(f"expected 40 scenarios, got {len(scenarios)}")
    return errs, per_vec


def main():
    scenarios = build()
    errs, per_vec = validate(scenarios)
    blob = json.dumps(scenarios, indent=2, ensure_ascii=False)
    DATASET_FILE.write_text(blob + "\n", encoding="utf-8")
    OUT_DIR.mkdir(exist_ok=True)
    allv = [t for sc in scenarios for t in sc["test_vectors"]]
    summary = {
        "status": "PASSED" if not errs else "FAILED",
        "errors": errs,
        "scenarios": len(scenarios),
        "test_vectors": len(allv),
        "vectors_per_category": {f"V{k}": per_vec[k] for k in sorted(per_vec)},
        "expected_action_split": dict(Counter(t["expected_action"] for t in allv)),
        "peering_types": dict(Counter(sc["peering_type"] for sc in scenarios)),
        "directions": dict(Counter(sc["direction"] for sc in scenarios)),
        "dataset_sha256": hashlib.sha256(blob.encode("utf-8")).hexdigest(),
    }
    (OUT_DIR / "dataset_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    sys.exit(0 if not errs else 1)


if __name__ == "__main__":
    main()


