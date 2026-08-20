"""
GTP-U tunnel-abuse detection rules.

Each rule is a pure function: it takes a parsed Scapy packet plus a shared
DetectorState and returns a list of Finding objects (possibly empty). Keeping
rules pure and stateless-where-possible makes them unit-testable against
synthetic packets without a live core, which is what lets us report detection
rate / FPR / latency as thesis metrics.

Covered abuse classes:
  R1  GTP-in-GTP        - a GTP-U header nested inside the inner payload
  R2  TEID spoofing     - same TEID observed from a new source IP
  R3  CP smuggling      - control-plane protocol (PFCP/NGAP/GTP-C/SCTP)
                          encapsulated inside a GTP-U user-plane tunnel
  R4  Inner-to-core     - inner IP destination targets a core NF address
                          (UPF/SMF/AMF) instead of the external data network
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import time

from scapy.all import IP, IPv6, UDP, TCP, ICMP, Packet, Raw
from scapy.contrib.gtp import GTP_U_Header, GTPHeader

# GTP-U G-PDU / echo message types we treat as "a real GTP header".
_GTP_MSG_TYPES = {0x01, 0x02, 0x1a, 0x1b, 0xfe, 0xff}


def _gtp_header_len(flags: int) -> int:
    """Mandatory 8 bytes, plus the 4-byte optional field iff any of E/S/PN set."""
    return 8 + (4 if (flags & 0x07) else 0)


def _looks_like_gtp(buf: bytes) -> bool:
    """Heuristic: do these raw bytes start with a *credible* GTPv1 header?

    First byte: version(3b)=001, PT(1b)=1  -> top nibble is 0x3.
    Second byte is the message type. This lets the detector see nested
    tunnels that Scapy's default GTP-U payload binding parses as Raw,
    because that binding only expects IPv4/IPv6 inside a G-PDU.

    Beyond the version/PT/type gate we also validate the 16-bit length field
    (bytes 2-3): for a real GTP header the total datagram is
    ``8 + length`` bytes. Random Unstructured-PDU-session bytes that merely
    happen to start 0x3X with a plausible message-type byte almost never
    satisfy this, which is what removes the false-positive class that the
    naive version of this heuristic produced on benign non-IP payloads.
    """
    if len(buf) < 8:
        return False
    if (buf[0] >> 5) != 0b001:          # not GTP version 1
        return False
    if not (buf[0] & 0x10):             # PT bit must be set for GTP (not GTP')
        return False
    if buf[1] not in _GTP_MSG_TYPES:
        return False
    declared = (buf[2] << 8) | buf[3]   # payload length after the mandatory 8B
    # The declared length must be consistent with the bytes actually present.
    # Allow trailing padding (<=4B) but reject headers that claim a length the
    # buffer cannot back, and reject a zero-length G-PDU (carries no inner pkt).
    total = 8 + declared
    if total > len(buf) or total < len(buf) - 4:
        return False
    if buf[1] in (0xff, 0xfe) and declared < 20:   # G-PDU must carry >=1 IP hdr
        return False
    return True


def _carries_inner_ip(gtp) -> bool:
    """Does a (re-parsed) nested GTP header actually carry a routable inner IP?

    A tunnel-in-tunnel used for abuse forwards a real inner packet, so the
    bytes after the nested GTP header begin with an IPv4 (nibble 4) or IPv6
    (nibble 6) version field. Pure noise that passed the byte-level gate above
    will not, so this is the final guard against flagging benign Unstructured
    payloads as GTP-in-GTP.
    """
    try:
        if gtp.haslayer(IP) or gtp.haslayer(IPv6):
            return True
        payload = bytes(gtp.payload) if gtp.payload else b""
        return len(payload) >= 1 and (payload[0] >> 4) in (4, 6)
    except Exception:
        return False


def _reparse_inner(inner: Packet):
    """If inner arrived as Raw but is actually a GTP header, re-dissect it."""
    if inner is None:
        return inner
    if isinstance(inner, Raw) or inner.__class__.__name__ == "Raw":
        buf = bytes(inner.load) if hasattr(inner, "load") else bytes(inner)
        if _looks_like_gtp(buf):
            try:
                return GTP_U_Header(buf)
            except Exception:
                return inner
    return inner

# Well-known control-plane UDP ports that must NEVER ride inside GTP-U user data.
PFCP_PORT = 8805      # N4  (SMF <-> UPF)
GTPC_PORT = 2123      # GTP-C control plane
GTPU_PORT = 2152      # GTP-U user plane (the outer tunnel itself)
SCTP_PROTO = 132      # NGAP/S1AP ride over SCTP


@dataclass
class Finding:
    rule: str          # e.g. "R1_GTP_IN_GTP"
    severity: str      # "critical" | "high" | "medium"
    src: str
    dst: str
    teid: Optional[int]
    detail: str
    ts: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return {
            "type": "finding",
            "rule": self.rule, "severity": self.severity, "src": self.src,
            "dst": self.dst, "teid": self.teid, "detail": self.detail,
            "ts": round(self.ts, 6),
        }


@dataclass
class DetectorState:
    """Cross-packet memory. Deliberately small so it survives long captures."""
    # teid -> first source IP seen carrying it
    teid_owner: dict = field(default_factory=dict)
    # set of IPs belonging to core network functions (UPF/SMF/AMF/...)
    core_nf_ips: set = field(default_factory=set)
    # UE address pool prefix (traffic to here is legitimate user data)
    ue_pool_prefix: str = "10.45."
    # Known legitimate gNB source IPs. When populated, R2 suppresses TEID-owner
    # changes *between* known gNBs (a legitimate Xn/N2 handover) and only flags
    # a TEID re-sourced from an IP OUTSIDE this pool -- i.e. an actual rogue
    # endpoint. Leave empty to keep the stricter "flag any owner change" mode.
    known_gnb_ips: set = field(default_factory=set)

    def is_core_ip(self, ip: str) -> bool:
        return ip in self.core_nf_ips

    def is_known_gnb(self, ip: str) -> bool:
        return ip in self.known_gnb_ips


def _inner_of_gtpu(pkt: Packet) -> Optional[Packet]:
    """Return the payload carried *inside* the outer GTP-U header, or None.

    Actively re-parses Raw payloads that are really nested GTP headers, so
    the rules see tunnel-in-tunnel abuse that default dissection hides.
    """
    if not pkt.haslayer(GTP_U_Header):
        return None
    inner = pkt[GTP_U_Header].payload
    if not inner:
        return None
    return _reparse_inner(inner)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
def rule_gtp_in_gtp(pkt: Packet, state: DetectorState) -> list[Finding]:
    """R1: a GTP header appears nested inside the GTP-U payload."""
    inner = _inner_of_gtpu(pkt)
    if inner is None:
        return []
    # Look for any GTP header (U or generic) nested below the outer one, and
    # confirm the nested tunnel actually forwards a routable inner IP packet.
    # The second condition rejects benign Unstructured-PDU bytes that merely
    # collide with the GTP byte pattern (see _looks_like_gtp / _carries_inner_ip).
    nested = None
    if inner.haslayer(GTP_U_Header):
        nested = inner[GTP_U_Header]
    elif inner.haslayer(GTPHeader):
        nested = inner[GTPHeader]
    if nested is not None and _carries_inner_ip(nested):
        outer = pkt[GTP_U_Header]
        return [Finding(
            rule="R1_GTP_IN_GTP", severity="critical",
            src=pkt[IP].src if pkt.haslayer(IP) else "?",
            dst=pkt[IP].dst if pkt.haslayer(IP) else "?",
            teid=int(outer.teid),
            detail="GTP header nested inside GTP-U payload (tunnel-in-tunnel).",
        )]
    return []


def rule_teid_spoof(pkt: Packet, state: DetectorState) -> list[Finding]:
    """R2: a TEID previously seen from IP A now arrives from IP B."""
    if not pkt.haslayer(GTP_U_Header) or not pkt.haslayer(IP):
        return []
    teid = int(pkt[GTP_U_Header].teid)
    src = pkt[IP].src
    owner = state.teid_owner.get(teid)
    if owner is None:
        state.teid_owner[teid] = src
        return []
    if owner != src:
        # Suppress legitimate handovers: if an allowlist of gNB IPs is
        # configured and BOTH the old and new source are known gNBs, this is a
        # normal Xn/N2 handover, not a spoof. Track the latest owner either way.
        state.teid_owner[teid] = src
        if state.known_gnb_ips and state.is_known_gnb(src) and state.is_known_gnb(owner):
            return []
        return [Finding(
            rule="R2_TEID_SPOOF", severity="high",
            src=src, dst=pkt[IP].dst, teid=teid,
            detail=f"TEID {hex(teid)} first bound to {owner}, now sourced from {src}.",
        )]
    return []


def rule_cp_smuggling(pkt: Packet, state: DetectorState) -> list[Finding]:
    """R3: control-plane protocol encapsulated inside GTP-U user data."""
    inner = _inner_of_gtpu(pkt)
    if inner is None:
        return []
    proto = None
    # SCTP inside GTP-U -> almost always NGAP/S1AP smuggling
    if inner.haslayer(IP) and int(inner[IP].proto) == SCTP_PROTO:
        proto = "SCTP/NGAP"
    elif inner.haslayer(UDP):
        dport = int(inner[UDP].dport)
        if dport == PFCP_PORT:
            proto = "PFCP (N4)"
        elif dport == GTPC_PORT:
            proto = "GTP-C"
        elif dport == GTPU_PORT:
            proto = "GTP-U"  # also caught by R1, kept for defence-in-depth
    if proto:
        outer = pkt[GTP_U_Header]
        return [Finding(
            rule="R3_CP_SMUGGLING", severity="critical",
            src=pkt[IP].src if pkt.haslayer(IP) else "?",
            dst=pkt[IP].dst if pkt.haslayer(IP) else "?",
            teid=int(outer.teid),
            detail=f"Control-plane payload ({proto}) encapsulated in GTP-U tunnel.",
        )]
    return []


def rule_inner_to_core(pkt: Packet, state: DetectorState) -> list[Finding]:
    """R4: inner IP destination is a core NF, not the external data network."""
    inner = _inner_of_gtpu(pkt)
    if inner is None or not inner.haslayer(IP):
        return []
    inner_dst = inner[IP].dst
    if state.is_core_ip(inner_dst):
        outer = pkt[GTP_U_Header]
        return [Finding(
            rule="R4_INNER_TO_CORE", severity="high",
            src=pkt[IP].src if pkt.haslayer(IP) else "?",
            dst=pkt[IP].dst if pkt.haslayer(IP) else "?",
            teid=int(outer.teid),
            detail=f"Inner packet targets core NF {inner_dst} instead of data network.",
        )]
    return []


ALL_RULES = [
    rule_gtp_in_gtp,
    rule_teid_spoof,
    rule_cp_smuggling,
    rule_inner_to_core,
]


def evaluate(pkt: Packet, state: DetectorState) -> list[Finding]:
    """Run every rule over one packet; return the union of findings."""
    findings: list[Finding] = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule(pkt, state))
        except Exception:
            # A malformed packet must never crash the detector.
            continue
    return findings
