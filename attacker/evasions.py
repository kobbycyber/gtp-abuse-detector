#!/usr/bin/env python3
"""
Evasion suite  --  LAB / EVALUATION USE ONLY.

A detector that is only ever tested against attacks built to match its own
rules will always score 100%. That number is meaningless. This module builds
the *adversarial* case: packets crafted specifically to slip past the detector,
so the evaluation can report an honest robustness picture -- which evasions the
detector catches, and which it does not (and therefore what its documented
blind spots are).

Each entry is (name, packet, target_rule, expected_detect, rationale):

  expected_detect = True   the detector SHOULD still catch this (robustness win)
  expected_detect = False  a known, documented blind spot of a stateless
                           passive heuristic (reported as a limitation, not hidden)

The benchmark scores every entry and asserts the detector's behaviour matches
`expected_detect`, so a regression in either direction (a new blind spot, or a
claimed catch that silently breaks) fails the build.
"""
from __future__ import annotations

from scapy.all import IP, IPv6, UDP, TCP, ICMP, Raw
from scapy.contrib.gtp import GTP_U_Header, GTPHeader

UPF = "10.10.10.10"
SMF = "10.10.10.11"
GNB = "10.10.10.20"
ATT = "10.10.10.66"
GTPU = 2152
PFCP_PORT = 8805
SCTP_PROTO = 132


def _outer(teid, src=GNB, dst=UPF):
    return IP(src=src, dst=dst) / UDP(sport=GTPU, dport=GTPU) / GTP_U_Header(teid=teid)


# --------------------------------------------------------------------------- #
# R1 (GTP-in-GTP) evasion attempts
# --------------------------------------------------------------------------- #
def e_gtp_in_gtp_ipv6_inner():
    """Nested GTP tunnel forwarding an inner IPv6 packet (not IPv4).

    The robust detector validates the nested header carries a routable inner
    IP -- it must accept IPv6, not just IPv4. Expected: still detected.
    """
    pkt = _outer(0x11) / GTP_U_Header(teid=0x11) / IPv6(src="2001:db8::2", dst="2001:db8::1") / ICMP()
    return ("r1_ipv6_inner", pkt, "R1_GTP_IN_GTP", True,
            "nested tunnel carries IPv6 inner; robust reparse must handle v6")


def e_gtp_in_gtp_with_ext_header():
    """Nested GTP-U whose OUTER carries an extension header (S/PN/E flags set).

    Shifts the payload offset by 4 bytes; a length/offset-naive parser could
    miss the nested header. Expected: still detected.
    """
    outer = IP(src=GNB, dst=UPF) / UDP(sport=GTPU, dport=GTPU) / \
        GTP_U_Header(teid=0x12, S=1, seq=0x1234)
    pkt = outer / GTP_U_Header(teid=0x12) / IP(src="10.45.0.2", dst="10.45.0.1") / ICMP()
    return ("r1_outer_ext_header", pkt, "R1_GTP_IN_GTP", True,
            "outer GTP-U extension header shifts inner offset")


def e_gtp_in_gtp_generic_header():
    """Nest a generic GTPHeader (control-plane style) rather than GTP_U_Header."""
    pkt = _outer(0x13) / GTPHeader(gtp_type=0xff, teid=0x13) / \
        IP(src="10.45.0.2", dst="10.45.0.1") / ICMP()
    return ("r1_generic_gtp_nested", pkt, "R1_GTP_IN_GTP", True,
            "nested header dissects as generic GTP, not GTP-U")


def e_gtp_in_gtp_noise_prefix():
    """Benign-looking noise that starts like GTP but carries no inner IP.

    This is an EVASION of the naive heuristic in the *false-positive* direction
    turned around: the robust detector must NOT flag it (no routable inner).
    Expected: not detected (correctly), i.e. expected_detect=False for R1.
    """
    pkt = _outer(0x14) / Raw(load=b"\x30\xff" + b"\x99" * 40)
    return ("r1_noise_no_inner_ip", pkt, "R1_GTP_IN_GTP", False,
            "GTP-looking bytes but no routable inner IP -> must NOT flag")


# --------------------------------------------------------------------------- #
# R2 (TEID spoof) evasion attempts
# --------------------------------------------------------------------------- #
def e_teid_spoof_first_seen():
    """Spoofer transmits on a TEID the detector has never seen before.

    Stateless first-seen ownership means the rogue simply becomes the owner and
    no conflict is raised. Known blind spot. Expected: not detected.
    """
    pkt = _outer(0x7777, src=ATT) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    return ("r2_unseen_teid", pkt, "R2_TEID_SPOOF", False,
            "rogue owns a never-before-seen TEID; nothing to conflict with")


def e_teid_spoof_source_ip_spoofed():
    """Rogue also spoofs the legitimate gNB source IP.

    If the attacker forges the gNB's IP, R2's (TEID, src-IP) invariant holds
    and no alarm fires. Known blind spot of IP-based attribution. Expected:
    not detected (this sample re-uses the legit gNB IP, so no owner change).
    """
    pkt = _outer(0x5, src=GNB) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    return ("r2_spoofed_source_ip", pkt, "R2_TEID_SPOOF", False,
            "attacker forges gNB source IP -> (TEID,src) invariant preserved")


# --------------------------------------------------------------------------- #
# R3 (control-plane smuggling) evasion attempts
# --------------------------------------------------------------------------- #
def e_cp_smuggle_nonstandard_port():
    """PFCP payload sent to a non-standard UDP port inside the tunnel.

    R3 keys on well-known control-plane ports. Moving PFCP off 8805 evades a
    port-based rule. Known blind spot. Expected: not detected.
    """
    pkt = _outer(0x21) / IP(src="10.45.0.2", dst=UPF) / UDP(dport=18805) / Raw(load=b"\x21" * 16)
    return ("r3_nonstandard_port", pkt, "R3_CP_SMUGGLING", False,
            "PFCP moved off port 8805 -> port heuristic misses it")


def e_cp_smuggle_pfcp_standard():
    """PFCP on its standard port -- the detector must still catch this."""
    pkt = _outer(0x22) / IP(src="10.45.0.2", dst=UPF) / UDP(dport=PFCP_PORT) / Raw(load=b"\x21" * 16)
    return ("r3_pfcp_standard", pkt, "R3_CP_SMUGGLING", True,
            "PFCP on standard port -> must be detected")


def e_cp_smuggle_sctp_inner():
    """SCTP/NGAP smuggled inside the tunnel -- must still be caught."""
    inner = IP(src="10.45.0.2", dst=UPF, proto=SCTP_PROTO) / Raw(load=b"\x00" * 16)
    pkt = _outer(0x23) / inner
    return ("r3_sctp_inner", pkt, "R3_CP_SMUGGLING", True,
            "SCTP inner -> must be detected")


# --------------------------------------------------------------------------- #
# R4 (inner-to-core) evasion attempts
# --------------------------------------------------------------------------- #
def e_inner_to_core_unlisted_nf():
    """Inner packet targets a core NF whose IP is NOT in the configured set.

    R4 only knows the core IPs it was told about. An NF outside that set is
    invisible. Known blind spot / config-completeness dependency. Expected:
    not detected.
    """
    pkt = _outer(0x31) / IP(src="10.45.0.2", dst="10.10.10.99") / TCP(dport=80)
    return ("r4_unlisted_core_nf", pkt, "R4_INNER_TO_CORE", False,
            "targets a core NF IP not in the configured core set")


def e_inner_to_core_listed_nf():
    """Inner packet targets a known core NF -- must be detected."""
    pkt = _outer(0x32) / IP(src="10.45.0.2", dst=SMF) / TCP(dport=80)
    return ("r4_listed_core_nf", pkt, "R4_INNER_TO_CORE", True,
            "targets a known core NF -> must be detected")


EVASIONS = [
    e_gtp_in_gtp_ipv6_inner,
    e_gtp_in_gtp_with_ext_header,
    e_gtp_in_gtp_generic_header,
    e_gtp_in_gtp_noise_prefix,
    e_teid_spoof_first_seen,
    e_teid_spoof_source_ip_spoofed,
    e_cp_smuggle_nonstandard_port,
    e_cp_smuggle_pfcp_standard,
    e_cp_smuggle_sctp_inner,
    e_inner_to_core_unlisted_nf,
    e_inner_to_core_listed_nf,
]


def all_evasions() -> list:
    """Return list of (name, packet, target_rule, expected_detect, rationale)."""
    return [fn() for fn in EVASIONS]


if __name__ == "__main__":
    for name, pkt, rule, exp, why in all_evasions():
        print(f"{name:28} target={rule:16} expect_detect={exp!s:5}  {why}")
