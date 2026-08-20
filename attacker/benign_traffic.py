#!/usr/bin/env python3
"""
Realistic benign 5G user-plane traffic generator  --  LAB / EVALUATION USE.

The original evaluation used a single benign shape (ICMP to 8.8.8.8). A false-
positive rate measured against one trivial flow says almost nothing: it cannot
exercise the detector's heuristics against the *diversity* of real N3 traffic.

This module synthesises a broad, deliberately adversarial-for-the-detector
benign corpus so that the reported false-positive rate is meaningful. Every
packet here is legitimate user-plane traffic that a correct detector MUST leave
un-flagged. Categories:

  web_tls        TCP 443 flows with realistic TLS-record-shaped payloads
  web_http       TCP 80 GET/response with options (MSS/SACK/WS/timestamps)
  dns            UDP 53 query/response
  quic           UDP 443 QUIC long-header datagrams
  ntp            UDP 123
  rtp_voip       small UDP on high ports (VoIP/RTP-like)
  icmp           echo request/reply
  ipv6           IPv6 inner PDU (v6 UE to v6 DNS)
  fragmented     fragmented inner IP datagram
  ip_options     inner IP carrying IP options
  unstructured   Unstructured-PDU-session bytes (non-IP inner) -- the hard case
  handover       a legitimate Xn handover: same UL TEID, new gNB source IP

The last two categories are the ones that genuinely stress the detector:

  * `unstructured` exercises `_looks_like_gtp`: a 5G Unstructured PDU session
    carries arbitrary bytes with no inner IP header, so the detector's nested-
    GTP re-parse heuristic can be provoked into a false positive. We include
    payloads specifically crafted to begin with a GTP-v1-looking byte pair.

  * `handover` exercises R2 (TEID spoofing): after an Xn handover the UPF's
    uplink TEID is unchanged but user-plane packets now legitimately arrive
    from a *different* gNB IP -- structurally identical to a TEID-spoof attack.

Both are real limitations of stateless passive heuristics and are reported
honestly in the evaluation rather than defined away.
"""
from __future__ import annotations

import argparse
import json
import random
from typing import Callable

from scapy.all import (
    IP, IPv6, UDP, TCP, ICMP, Raw, wrpcap, fragment,
)
from scapy.contrib.gtp import GTP_U_Header

GTPU_PORT = 2152

# A pool of UE addresses so flows are not all from one host.
UE_V4 = [f"10.45.0.{i}" for i in range(2, 40)]
UE_V6 = [f"2001:db8:45::{i:x}" for i in range(2, 20)]
# Public data-network destinations (never a core NF).
DN_V4 = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "142.250.72.14", "151.101.1.140"]
DN_V6 = ["2001:4860:4860::8888", "2606:4700:4700::1111"]


def _outer(gnb: str, upf: str, teid: int) -> "Packet":
    return IP(src=gnb, dst=upf) / UDP(sport=GTPU_PORT, dport=GTPU_PORT) / \
        GTP_U_Header(teid=teid)


def _tcp_opts(rng: random.Random):
    return [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (rng.randint(1, 2**31), 0)),
            ("NOP", None), ("WScale", 7)]


# --------------------------------------------------------------------------- #
# Per-category builders. Each returns a list of one or more packets.
# --------------------------------------------------------------------------- #
def b_web_tls(a, rng) -> list:
    ue, dn = rng.choice(UE_V4), rng.choice(DN_V4)
    teid = rng.randint(0x1000, 0xFFFF)
    sport = rng.randint(1024, 65535)
    # TLS ClientHello-ish record: type=0x16(handshake) ver=0x0303 len ...
    tls = b"\x16\x03\x03" + bytes(rng.randint(0, 255) for _ in range(rng.randint(40, 200)))
    syn = _outer(a.gnb, a.upf, teid) / IP(src=ue, dst=dn) / \
        TCP(sport=sport, dport=443, flags="S", options=_tcp_opts(rng))
    data = _outer(a.gnb, a.upf, teid) / IP(src=ue, dst=dn) / \
        TCP(sport=sport, dport=443, flags="PA") / Raw(load=tls)
    return [syn, data]


def b_web_http(a, rng) -> list:
    ue, dn = rng.choice(UE_V4), rng.choice(DN_V4)
    teid = rng.randint(0x1000, 0xFFFF)
    sport = rng.randint(1024, 65535)
    get = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
           b"User-Agent: curl/8.0\r\nAccept: */*\r\n\r\n")
    return [
        _outer(a.gnb, a.upf, teid) / IP(src=ue, dst=dn) /
        TCP(sport=sport, dport=80, flags="S", options=_tcp_opts(rng)),
        _outer(a.gnb, a.upf, teid) / IP(src=ue, dst=dn) /
        TCP(sport=sport, dport=80, flags="PA") / Raw(load=get),
    ]


def b_dns(a, rng) -> list:
    ue, dn = rng.choice(UE_V4), rng.choice(["8.8.8.8", "1.1.1.1"])
    teid = rng.randint(0x1000, 0xFFFF)
    # Minimal DNS query wire bytes for "example.com A"
    q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x07example\x03com\x00\x00\x01\x00\x01")
    return [_outer(a.gnb, a.upf, teid) / IP(src=ue, dst=dn) /
            UDP(sport=rng.randint(1024, 65535), dport=53) / Raw(load=q)]


def b_quic(a, rng) -> list:
    ue, dn = rng.choice(UE_V4), rng.choice(DN_V4)
    teid = rng.randint(0x1000, 0xFFFF)
    # QUIC long header: first byte has high bit set (0xc0..0xff), then version.
    payload = bytes([rng.randint(0xc0, 0xff)]) + b"\x00\x00\x00\x01" + \
        bytes(rng.randint(0, 255) for _ in range(rng.randint(30, 200)))
    return [_outer(a.gnb, a.upf, teid) / IP(src=ue, dst=dn) /
            UDP(sport=rng.randint(1024, 65535), dport=443) / Raw(load=payload)]


def b_ntp(a, rng) -> list:
    ue = rng.choice(UE_V4)
    teid = rng.randint(0x1000, 0xFFFF)
    ntp = b"\x1b" + b"\x00" * 47
    return [_outer(a.gnb, a.upf, teid) / IP(src=ue, dst="129.6.15.28") /
            UDP(sport=rng.randint(1024, 65535), dport=123) / Raw(load=ntp)]


def b_rtp_voip(a, rng) -> list:
    ue, dn = rng.choice(UE_V4), rng.choice(DN_V4)
    teid = rng.randint(0x1000, 0xFFFF)
    rtp = b"\x80\x00" + bytes(rng.randint(0, 255) for _ in range(rng.randint(20, 160)))
    return [_outer(a.gnb, a.upf, teid) / IP(src=ue, dst=dn) /
            UDP(sport=rng.randint(16384, 32767), dport=rng.randint(16384, 32767)) /
            Raw(load=rtp)]


def b_icmp(a, rng) -> list:
    ue, dn = rng.choice(UE_V4), rng.choice(DN_V4)
    teid = rng.randint(0x1000, 0xFFFF)
    return [_outer(a.gnb, a.upf, teid) / IP(src=ue, dst=dn) /
            ICMP() / Raw(load=b"\x00" * rng.randint(8, 56))]


def b_ipv6(a, rng) -> list:
    ue, dn = rng.choice(UE_V6), rng.choice(DN_V6)
    teid = rng.randint(0x1000, 0xFFFF)
    return [_outer(a.gnb, a.upf, teid) / IPv6(src=ue, dst=dn) /
            UDP(sport=rng.randint(1024, 65535), dport=443) /
            Raw(load=bytes(rng.randint(0, 255) for _ in range(rng.randint(20, 100))))]


def b_fragmented(a, rng) -> list:
    """A fragmented inner IP datagram carried in GTP-U (legitimate large UDP)."""
    ue, dn = rng.choice(UE_V4), rng.choice(DN_V4)
    teid = rng.randint(0x1000, 0xFFFF)
    big = IP(src=ue, dst=dn) / UDP(sport=rng.randint(1024, 65535), dport=443) / \
        Raw(load=bytes(rng.randint(0, 255) for _ in range(2000)))
    frags = fragment(big, fragsize=1200)
    return [_outer(a.gnb, a.upf, teid) / f for f in frags]


def b_ip_options(a, rng) -> list:
    """Inner IP carrying an IP option (Router Alert) -- legal but unusual."""
    ue, dn = rng.choice(UE_V4), rng.choice(DN_V4)
    teid = rng.randint(0x1000, 0xFFFF)
    inner = IP(src=ue, dst=dn, options=b"\x94\x04\x00\x00") / ICMP()  # Router Alert
    return [_outer(a.gnb, a.upf, teid) / inner]


def b_unstructured(a, rng) -> list:
    """Unstructured PDU session: arbitrary non-IP bytes inside GTP-U.

    Crafted to include the worst case for `_looks_like_gtp`: a first byte in
    0x30-0x3f and a second byte that collides with a real GTP message type.
    A robust detector must NOT flag these as GTP-in-GTP.
    """
    teid = rng.randint(0x1000, 0xFFFF)
    # Half plain random, half adversarially GTP-looking prefixes.
    if rng.random() < 0.5:
        payload = bytes(rng.randint(0, 255) for _ in range(rng.randint(16, 120)))
    else:
        # top nibble 0x3 + a byte that is a valid GTP msg type -> tries to fool R1
        payload = bytes([rng.choice([0x30, 0x34, 0x3e, 0x3f])]) + \
            bytes([rng.choice([0x01, 0xff, 0x1a])]) + \
            bytes(rng.randint(0, 255) for _ in range(rng.randint(14, 100)))
    return [_outer(a.gnb, a.upf, teid) / Raw(load=payload)]


def b_handover(a, rng) -> list:
    """A legitimate Xn/N2 handover.

    The same uplink TEID keeps flowing to the UPF, but the source gNB IP
    changes from the serving gNB to the target gNB. Structurally this is
    indistinguishable, on the N3 user plane alone, from a TEID-spoof attack --
    a real limitation of stateless R2 that we surface rather than hide.
    """
    ue, dn = rng.choice(UE_V4), rng.choice(DN_V4)
    teid = rng.randint(0x1000, 0xFFFF)
    target_gnb = "10.10.10.21"  # a second, legitimate gNB
    before = _outer(a.gnb, a.upf, teid) / IP(src=ue, dst=dn) / ICMP()
    after = _outer(target_gnb, a.upf, teid) / IP(src=ue, dst=dn) / ICMP()
    return [before, after]


# Category -> (builder, weight). Weights approximate a realistic traffic mix;
# the two hard categories are present but not dominant.
CATEGORIES: dict[str, tuple[Callable, float]] = {
    "web_tls": (b_web_tls, 22),
    "web_http": (b_web_http, 10),
    "dns": (b_dns, 14),
    "quic": (b_quic, 16),
    "ntp": (b_ntp, 3),
    "rtp_voip": (b_rtp_voip, 8),
    "icmp": (b_icmp, 6),
    "ipv6": (b_ipv6, 8),
    "fragmented": (b_fragmented, 4),
    "ip_options": (b_ip_options, 3),
    "unstructured": (b_unstructured, 4),
    "handover": (b_handover, 2),
}


def benign_corpus(n: int, seed: int = 1337, args=None) -> list:
    """Return a list of (packet, category) tuples, all benign (label False).

    `n` is an approximate target packet count; because some builders emit
    multi-packet flows the returned length is close to but not exactly `n`.
    """
    rng = random.Random(seed)
    if args is None:
        args = argparse.Namespace(gnb="10.10.10.20", upf="10.10.10.10")
    names = list(CATEGORIES)
    weights = [CATEGORIES[k][1] for k in names]
    out: list = []
    while len(out) < n:
        cat = rng.choices(names, weights=weights, k=1)[0]
        for pkt in CATEGORIES[cat][0](args, rng):
            out.append((pkt, cat))
    return out


def main():
    p = argparse.ArgumentParser(description="Realistic benign N3 traffic generator")
    p.add_argument("--upf", default="10.10.10.10")
    p.add_argument("--gnb", default="10.10.10.20")
    p.add_argument("--count", type=int, default=400)
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--write", help="write pcap here")
    p.add_argument("--labels-out", help="write aligned all-False labels JSON here")
    p.add_argument("--categories-out", help="write per-packet category JSON here")
    a = p.parse_args()

    pairs = benign_corpus(a.count, a.seed, a)
    pkts = [pk for pk, _ in pairs]
    cats = [c for _, c in pairs]
    if a.write:
        wrpcap(a.write, pkts)
        print(f"[+] wrote {len(pkts)} benign packets -> {a.write}")
    if a.labels_out:
        with open(a.labels_out, "w") as fh:
            json.dump([False] * len(pkts), fh)
    if a.categories_out:
        with open(a.categories_out, "w") as fh:
            json.dump(cats, fh)
    # quick category tally to stdout
    tally: dict = {}
    for c in cats:
        tally[c] = tally.get(c, 0) + 1
    print("[+] category mix:", json.dumps(tally))


if __name__ == "__main__":
    main()
