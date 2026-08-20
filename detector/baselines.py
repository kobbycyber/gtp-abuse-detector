"""
Baseline detectors, for quantifying the contribution of the robust detector.

The headline claim of this project is that a passive GTP-U abuse detector must
*actively re-parse* the inner payload, because Scapy's default GTP-U binding
renders a nested GTP header (and other non-IP inner content) as ``Raw``. To
show that this matters -- rather than merely asserting it -- we implement the
obvious naive detector that a competent engineer would write first, and score
it on the identical corpus.

`naive_evaluate` uses ONLY Scapy's default dissection: it relies on
``haslayer`` / ``getlayer`` over whatever layers Scapy produced at capture
time, with no byte-level re-interpretation of ``Raw`` payloads. Every other
design decision (the four rule ideas, the state model) is held constant, so the
delta between `naive_evaluate` and `rules.evaluate` isolates exactly one
variable: the inner re-parse.
"""
from __future__ import annotations

from scapy.all import IP, IPv6, UDP, Packet
from scapy.contrib.gtp import GTP_U_Header, GTPHeader

from rules import (
    DetectorState, Finding,
    PFCP_PORT, GTPC_PORT, GTPU_PORT, SCTP_PROTO,
)


def _naive_inner(pkt: Packet):
    """Inner payload as Scapy dissected it -- no re-parse of Raw."""
    if not pkt.haslayer(GTP_U_Header):
        return None
    inner = pkt[GTP_U_Header].payload
    return inner if inner else None


def naive_gtp_in_gtp(pkt: Packet, state: DetectorState) -> list:
    inner = _naive_inner(pkt)
    if inner is None:
        return []
    # Default dissection: a nested tunnel only appears as a GTP layer if Scapy
    # already parsed it as one -- which it does NOT for a G-PDU payload, so this
    # is exactly the miss the robust detector fixes.
    if inner.haslayer(GTP_U_Header) or inner.haslayer(GTPHeader):
        outer = pkt[GTP_U_Header]
        return [Finding("R1_GTP_IN_GTP", "critical",
                        pkt[IP].src if pkt.haslayer(IP) else "?",
                        pkt[IP].dst if pkt.haslayer(IP) else "?",
                        int(outer.teid), "naive: nested GTP via default dissection")]
    return []


def naive_teid_spoof(pkt: Packet, state: DetectorState) -> list:
    # R2 needs no inner re-parse -- it works on the outer header only, so the
    # naive and robust versions are identical here (kept for a fair comparison).
    if not pkt.haslayer(GTP_U_Header) or not pkt.haslayer(IP):
        return []
    teid = int(pkt[GTP_U_Header].teid)
    src = pkt[IP].src
    owner = state.teid_owner.get(teid)
    if owner is None:
        state.teid_owner[teid] = src
        return []
    if owner != src:
        state.teid_owner[teid] = src
        if state.known_gnb_ips and state.is_known_gnb(src) and state.is_known_gnb(owner):
            return []
        return [Finding("R2_TEID_SPOOF", "high", src, pkt[IP].dst, teid,
                        "naive: TEID owner change")]
    return []


def naive_cp_smuggling(pkt: Packet, state: DetectorState) -> list:
    inner = _naive_inner(pkt)
    if inner is None:
        return []
    proto = None
    if inner.haslayer(IP) and int(inner[IP].proto) == SCTP_PROTO:
        proto = "SCTP/NGAP"
    elif inner.haslayer(UDP):
        dport = int(inner[UDP].dport)
        if dport == PFCP_PORT:
            proto = "PFCP"
        elif dport == GTPC_PORT:
            proto = "GTP-C"
        elif dport == GTPU_PORT:
            proto = "GTP-U"
    if proto:
        outer = pkt[GTP_U_Header]
        return [Finding("R3_CP_SMUGGLING", "critical",
                        pkt[IP].src if pkt.haslayer(IP) else "?",
                        pkt[IP].dst if pkt.haslayer(IP) else "?",
                        int(outer.teid), f"naive: CP proto {proto}")]
    return []


def naive_inner_to_core(pkt: Packet, state: DetectorState) -> list:
    inner = _naive_inner(pkt)
    if inner is None or not inner.haslayer(IP):
        return []
    if state.is_core_ip(inner[IP].dst):
        outer = pkt[GTP_U_Header]
        return [Finding("R4_INNER_TO_CORE", "high",
                        pkt[IP].src if pkt.haslayer(IP) else "?",
                        pkt[IP].dst if pkt.haslayer(IP) else "?",
                        int(outer.teid), "naive: inner dst is core NF")]
    return []


NAIVE_RULES = [naive_gtp_in_gtp, naive_teid_spoof,
               naive_cp_smuggling, naive_inner_to_core]


def naive_evaluate(pkt: Packet, state: DetectorState) -> list:
    findings: list = []
    for rule in NAIVE_RULES:
        try:
            findings.extend(rule(pkt, state))
        except Exception:
            continue
    return findings
