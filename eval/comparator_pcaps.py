#!/usr/bin/env python3
"""
Write one small capture per traffic class, for running other tools on the
same packets the detector is scored on (Zeek, Suricata, tshark).

Each class gets its own pcap of Ethernet frames, built with the corpus
builders in attacker/ and, by default, the PDU Session Container outer header
real N3 traffic carries (see eval/heldout.py). The IP-wrapped nested form,
which the corpus does not contain, is included so tools can be compared on
both nested forms.

    python3 eval/comparator_pcaps.py --out captures/comparators
"""
from __future__ import annotations

import argparse
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.path.insert(0, os.path.join(ROOT, "attacker"))
sys.path.insert(0, os.path.join(ROOT, "detector"))

from scapy.all import ICMP, IP, UDP, Ether, wrpcap  # noqa: E402
from scapy.contrib.gtp import GTP_U_Header  # noqa: E402

import generate_attacks as ga  # noqa: E402
from benign_traffic import benign_corpus  # noqa: E402
from heldout import with_session_container  # noqa: E402

UPF, SMF, GNB, ATT = "10.10.10.10", "10.10.10.11", "10.10.10.20", "10.10.10.66"


def ip_wrapped_nested(teid):
    return ga.outer(UPF, teid, GNB) / IP(src="10.45.0.2", dst="10.45.0.1") / \
        UDP(sport=2152, dport=2152) / GTP_U_Header(gtp_type=0xFF, teid=teid + 1) / \
        IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=50, help="packets per class")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--plain-outer", action="store_true", help="omit the PDU Session Container")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    os.makedirs(a.out, exist_ok=True)

    classes = {
        "bare_nested": [ga.mk_gtp_in_gtp(UPF, 0x100 + i, GNB) for i in range(a.n)],
        "ip_wrapped_nested": [ip_wrapped_nested(0x200 + 2 * i) for i in range(a.n)],
        "pfcp_smuggle": [ga.mk_pfcp_smuggle(UPF, 0x400 + i, GNB, rng) for i in range(a.n)],
        "ngap_smuggle": [ga.mk_ngap_smuggle(UPF, 0x500 + i, GNB) for i in range(a.n)],
        "inner_to_core": [ga.mk_inner_to_core(UPF, 0x600 + i, GNB, SMF) for i in range(a.n)],
        # owner first, then the re-sourced packet, per TEID
        "teid_spoof": [p for i in range(a.n) for p in
                       (ga.mk_benign(UPF, 0x700 + i, GNB), ga.mk_teid_spoof(UPF, 0x700 + i, ATT))],
        "benign": [p for p, _cat in benign_corpus(a.n, a.seed)],
    }
    for name, pkts in classes.items():
        if not a.plain_outer:
            pkts = [with_session_container(p, rng) for p in pkts]
        frames = [Ether(src="02:00:00:00:00:20", dst="02:00:00:00:00:10") / p for p in pkts]
        path = os.path.join(a.out, f"{name}.pcap")
        wrpcap(path, frames)
        print(f"{len(frames):4d} {path}")


if __name__ == "__main__":
    main()
