"""
Adversarial-robustness tests: the detector's behaviour on every crafted
evasion must match its documented expectation (a robustness win stays won, a
blind spot stays a known blind spot). A drift in either direction fails here.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))                       # detector/
sys.path.insert(0, os.path.join(HERE, "..", "..", "attacker"))  # attacker/

from scapy.all import IP, UDP, ICMP
from scapy.contrib.gtp import GTP_U_Header
from rules import DetectorState, evaluate
from evasions import all_evasions

CORE = {"10.10.10.10", "10.10.10.11"}
GNBS = {"10.10.10.20", "10.10.10.21"}


def _primed_state():
    st = DetectorState()
    st.core_nf_ips = set(CORE)
    st.known_gnb_ips = set(GNBS)
    # Establish a legit owner for TEID 0x5 so the 'spoofed source IP' evasion
    # (which reuses the gNB IP) has an owner to (not) conflict with.
    evaluate(IP(src="10.10.10.20", dst="10.10.10.10") / UDP(sport=2152, dport=2152) /
             GTP_U_Header(teid=0x5) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP(), st)
    return st


def test_every_evasion_matches_expectation():
    st = _primed_state()
    mismatches = []
    for name, pkt, rule, expected, _why in all_evasions():
        got = rule in {f.rule for f in evaluate(IP(bytes(pkt)), st)}
        if got != expected:
            mismatches.append((name, expected, got))
    assert not mismatches, f"evasion drift: {mismatches}"


def test_at_least_the_expected_robustness_wins():
    st = _primed_state()
    wins = 0
    for name, pkt, rule, expected, _why in all_evasions():
        if expected and rule in {f.rule for f in evaluate(IP(bytes(pkt)), st)}:
            wins += 1
    assert wins >= 6   # ipv6-inner, ext-header, generic-nested, pfcp, sctp, listed-nf
