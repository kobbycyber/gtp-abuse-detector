"""
Unit tests: every abuse class must be detected, and benign traffic must not
raise a finding. Run with:  pytest -q   (from the detector/ directory)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, IPv6, UDP, ICMP, TCP, Raw
from scapy.contrib.gtp import GTP_U_Header
from scapy.contrib.pfcp import PFCP

from rules import DetectorState, evaluate

UPF = "10.10.10.10"
SMF = "10.10.10.11"
GNB = "10.10.10.20"
ATT = "10.10.10.66"
GTPU = 2152


def _outer(teid, src=GNB, dst=UPF):
    return IP(src=src, dst=dst) / UDP(sport=GTPU, dport=GTPU) / GTP_U_Header(teid=teid)


def fresh_state():
    st = DetectorState()
    st.core_nf_ips = {UPF, SMF}
    return st


def rules_hit(findings):
    return {f.rule for f in findings}


def test_benign_clean():
    st = fresh_state()
    pkt = _outer(0x1) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    assert evaluate(pkt, st) == []


def test_gtp_in_gtp():
    st = fresh_state()
    pkt = _outer(0x1) / GTP_U_Header(teid=0x1) / IP(dst="10.45.0.1") / ICMP()
    assert "R1_GTP_IN_GTP" in rules_hit(evaluate(pkt, st))


def test_teid_spoof():
    st = fresh_state()
    benign = _outer(0x5, src=GNB) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    assert evaluate(benign, st) == []            # establishes ownership
    spoof = _outer(0x5, src=ATT) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    assert "R2_TEID_SPOOF" in rules_hit(evaluate(spoof, st))


def test_pfcp_smuggle():
    st = fresh_state()
    pkt = _outer(0x1) / IP(src="10.45.0.2", dst=UPF) / UDP(dport=8805) / PFCP()
    assert "R3_CP_SMUGGLING" in rules_hit(evaluate(pkt, st))


def test_ngap_smuggle():
    st = fresh_state()
    inner = IP(src="10.45.0.2", dst=UPF, proto=132) / Raw(load=b"\x00" * 16)
    pkt = _outer(0x1) / inner
    assert "R3_CP_SMUGGLING" in rules_hit(evaluate(pkt, st))


def test_inner_to_core():
    st = fresh_state()
    pkt = _outer(0x1) / IP(src="10.45.0.2", dst=SMF) / TCP(dport=80)
    assert "R4_INNER_TO_CORE" in rules_hit(evaluate(pkt, st))


def test_detector_survives_garbage():
    st = fresh_state()
    junk = IP(src=GNB, dst=UPF) / UDP(sport=GTPU, dport=GTPU) / \
        GTP_U_Header(teid=0x9) / Raw(load=b"\xff\x00\xde\xad")
    evaluate(junk, st)  # must not raise


def test_gtp_in_gtp_gpdu_outer():
    """Nested tunnel inside a realistic G-PDU (0xFF) outer that a UPF would
    decapsulate. Scapy guesses the nested bytes as a non-Raw class (PPP), so the
    re-parse must key on the raw bytes, not on the 'Raw' class. This is the case
    R1 originally missed until the corpus used a realistic outer message type."""
    st = fresh_state()
    outer = IP(src=GNB, dst=UPF) / UDP(sport=GTPU, dport=GTPU) / \
        GTP_U_Header(gtp_type=0xFF, teid=0x1)
    pkt = IP(bytes(outer / GTP_U_Header(gtp_type=0xFF, teid=0x1) /
                   IP(src="10.45.0.2", dst="10.45.0.1") / ICMP()))
    assert "R1_GTP_IN_GTP" in rules_hit(evaluate(pkt, st))


def test_benign_gpdu_inner_ip_clean():
    """A valid G-PDU carrying a real inner IP packet must not trip R1."""
    st = fresh_state()
    pkt = IP(bytes(IP(src=GNB, dst=UPF) / UDP(sport=GTPU, dport=GTPU) /
                   GTP_U_Header(gtp_type=0xFF, teid=0x1) /
                   IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()))
    assert "R1_GTP_IN_GTP" not in rules_hit(evaluate(pkt, st))


def test_teid_spoof_rogue_cannot_take_ownership():
    """Spoofs interleaved with the owner's traffic on one TEID: every spoof is
    flagged and the legitimate owner never is. Regression for the defect the
    live corpus exposed: R2 used to hand the TEID to whichever source sent
    last, so the owner's next packet was flagged and a repeated spoof from the
    same rogue went unseen."""
    st = fresh_state()
    st.known_gnb_ips = {GNB, "10.10.10.21"}
    legit = _outer(0x7, src=GNB) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    spoof = _outer(0x7, src=ATT) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    assert evaluate(legit, st) == []
    for _ in range(3):
        assert "R2_TEID_SPOOF" in rules_hit(evaluate(spoof, st))
        assert "R2_TEID_SPOOF" in rules_hit(evaluate(spoof, st))   # repeated spoof
        assert evaluate(legit, st) == []                           # owner stays clean
    # The rogue is seen first (e.g. after a detector restart): with the
    # allowlist, the legitimate gNB reclaims the tunnel silently and the
    # rogue's next packet is flagged, rather than the roles staying reversed.
    legit8 = _outer(0x8, src=GNB) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    spoof8 = _outer(0x8, src=ATT) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    assert evaluate(spoof8, st) == []
    assert evaluate(legit8, st) == []
    assert evaluate(legit8, st) == []
    assert "R2_TEID_SPOOF" in rules_hit(evaluate(spoof8, st))


def test_teid_scoped_by_receiving_endpoint():
    """A TEID is unique only within its receiving endpoint (TS 29.281), and
    each endpoint allocates its own, so one number can name two tunnels. In
    the live run the session's downlink TEID was 0x1 (UPF -> gNB) while the
    attack corpus sent uplink traffic on TEID 0x1 (gNB -> UPF). Downlink
    traffic on 0x1 must not make the UPF the owner of the uplink tunnel 0x1,
    and a spoof of that uplink tunnel must still fire. Ownership must also
    come from the outer header that carries the tunnel, including over IPv6
    transport, never from the subscriber's inner packet."""
    st = fresh_state()
    st.known_gnb_ips = {GNB, "10.10.10.21"}
    uplink = _outer(0x1, src=GNB, dst=UPF) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    downlink = _outer(0x1, src=UPF, dst=GNB) / IP(src="8.8.8.8", dst="10.45.0.2") / ICMP()
    assert evaluate(downlink, st) == []
    assert evaluate(uplink, st) == []
    assert evaluate(downlink, st) == []
    spoof = _outer(0x1, src=ATT, dst=UPF) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP()
    assert "R2_TEID_SPOOF" in rules_hit(evaluate(spoof, st))
    # IPv6 N3 transport carrying IPv4 user traffic: varying inner sources on
    # one tunnel are legitimate, a different outer source is a spoof.
    def v6(src, inner_src):
        return IPv6(bytes(IPv6(src=src, dst="fd00::20") / UDP(sport=GTPU, dport=GTPU) /
                          GTP_U_Header(teid=0x9) / IP(src=inner_src, dst="10.45.0.2") / ICMP()))
    for inner_src in ("8.8.8.8", "1.1.1.1", "8.8.8.8", "9.9.9.9"):
        assert evaluate(v6("fd00::10", inner_src), st) == []
    assert "R2_TEID_SPOOF" in rules_hit(evaluate(v6("fd00::66", "8.8.8.8"), st))

def test_live_attack_corpus_scores_clean():
    """The exact corpus `make attack` sends live (seed 1337, 400 malicious, 100
    benign, every packet on TEID 0x1) must score with no false positive and no
    false negative under the live detector's configuration."""
    import argparse
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))), "attacker"))
    import generate_attacks as ga
    args = argparse.Namespace(upf=UPF, smf=SMF, gnb=GNB, attacker=ATT, teid=0x1,
                              count=400, benign=100, seed=1337, classes=None)
    pkts, labels = ga.build_corpus(args)
    st = fresh_state()
    st.known_gnb_ips = {GNB, "10.10.10.21"}
    flagged = [bool(evaluate(IP(bytes(p)), st)) for p in pkts]
    assert flagged == labels
