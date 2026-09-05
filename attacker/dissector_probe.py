#!/usr/bin/env python3
"""
Dissector cross-check probe  --  LAB / EVALUATION USE ONLY.

Writes a tiny, Ethernet-framed pcap that isolates the R1 dissector blind spot
so it can be reproduced against any packet dissector, not just Scapy. It holds
three GTP-U packets sharing one outer 5-tuple:

  1. bare-nested   outer GTP-U whose payload is a second (bare) GTP-U header,
                   then an inner IP/ICMP packet. This is the abuse case; the
                   nested header's first byte (0x30-0x3f) matches neither the
                   IPv4 nor the IPv6 nibble, so a dissector that selects the
                   inner protocol from that byte returns it opaque.
  2. benign        outer GTP-U carrying a normal inner IP/ICMP packet.
  3. cp_smuggle    outer GTP-U carrying an inner IP/UDP packet to the PFCP port.

A correct-but-naive dissector decodes packets 2 and 3 to their inner IP but
returns packet 1's inner as undissected bytes. Scapy, Wireshark/tshark and Zeek
all behave this way (see PAPER Section 7.3 / manuscript). Usage:

    python3 attacker/dissector_probe.py --write captures/dissector_probe.pcap

Then, from the repository root:

    # tshark: the nested frame does not match the gtp filter and shows no message
    tshark -r captures/dissector_probe.pcap -Y gtp -T fields -e frame.number -e gtp.message

    # Zeek (via the official container): one GTPv1 tunnel, no nested tunnel,
    # and no inner connection for the bare-nested packet
    docker run --rm -v "$PWD/captures":/d -w /d zeek/zeek:latest \
        zeek -C -r dissector_probe.pcap
    cat conn.log tunnel.log
"""
from __future__ import annotations

import argparse

from scapy.all import Ether, IP, UDP, ICMP, wrpcap
from scapy.contrib.gtp import GTP_U_Header
from scapy.contrib.pfcp import PFCP

GTPU_PORT = 2152
PFCP_PORT = 8805


def _frame(pkt):
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / pkt


def _outer(gnb, upf, teid):
    return IP(src=gnb, dst=upf) / UDP(sport=GTPU_PORT, dport=GTPU_PORT) / \
        GTP_U_Header(teid=teid)


def build(gnb="10.10.10.20", upf="10.10.10.10", ue="10.45.0.2"):
    return [
        _frame(_outer(gnb, upf, 0x101) / GTP_U_Header(teid=0x101) /
               IP(src=ue, dst="10.45.0.1") / ICMP()),          # bare-nested (R1)
        _frame(_outer(gnb, upf, 0x102) / IP(src=ue, dst="8.8.8.8") / ICMP()),  # benign
        _frame(_outer(gnb, upf, 0x103) / IP(src=ue, dst=upf) /
               UDP(sport=40000, dport=PFCP_PORT) / PFCP()),    # cp smuggle
    ]


def main():
    p = argparse.ArgumentParser(description="Dissector cross-check probe (lab only)")
    p.add_argument("--gnb", default="10.10.10.20")
    p.add_argument("--upf", default="10.10.10.10")
    p.add_argument("--write", default="captures/dissector_probe.pcap")
    a = p.parse_args()
    pkts = build(a.gnb, a.upf)
    wrpcap(a.write, pkts)
    print(f"[+] wrote {len(pkts)} packets -> {a.write}")
    for i, pk in enumerate(pkts, 1):
        print(f"    pkt{i}: {pk.summary()}")


if __name__ == "__main__":
    main()
