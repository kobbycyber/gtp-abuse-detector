"""
Unit tests: every abuse class must be detected, and benign traffic must not
raise a finding. Run with:  pytest -q   (from the detector/ directory)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, UDP, ICMP, TCP, Raw
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
