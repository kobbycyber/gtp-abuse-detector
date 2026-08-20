"""
False-positive tests against a realistic, diverse benign corpus.

The point of these tests is that the reported false-positive rate is earned
against traffic that actually exercises the heuristics (TLS/QUIC/DNS/IPv6/
fragments/Unstructured-PDU/handover), not a single trivial flow.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))                       # detector/
sys.path.insert(0, os.path.join(HERE, "..", "..", "attacker"))  # attacker/

from scapy.all import IP
from rules import DetectorState, evaluate
from benign_traffic import benign_corpus, b_unstructured, b_handover
import argparse
import random

CORE = {"10.10.10.10", "10.10.10.11"}
GNBS = {"10.10.10.20", "10.10.10.21"}


def _state(allowlist=True):
    st = DetectorState()
    st.core_nf_ips = set(CORE)
    if allowlist:
        st.known_gnb_ips = set(GNBS)
    return st


def _fp_count(pairs, allowlist=True):
    st = _state(allowlist)
    fp = 0
    for pkt, _cat in pairs:
        rt = IP(bytes(pkt))          # round-trip through the wire format
        if evaluate(rt, st):
            fp += 1
    return fp


def test_realistic_benign_zero_fp_with_allowlist():
    pairs = benign_corpus(600, seed=1337)
    assert _fp_count(pairs, allowlist=True) == 0


def test_benign_fp_only_from_handover_without_allowlist():
    """Without the gNB allowlist, any FP must come solely from handover flows."""
    pairs = benign_corpus(600, seed=1337)
    st = _state(allowlist=False)
    offending_categories = set()
    for pkt, cat in pairs:
        if evaluate(IP(bytes(pkt)), st):
            offending_categories.add(cat)
    assert offending_categories <= {"handover"}


def test_unstructured_pdu_never_flagged():
    """Unstructured PDU bytes, including GTP-looking prefixes, must not fire R1."""
    a = argparse.Namespace(gnb="10.10.10.20", upf="10.10.10.10")
    st = _state()
    for i in range(200):
        for pkt in b_unstructured(a, random.Random(i)):
            assert evaluate(IP(bytes(pkt)), st) == []


def test_handover_suppressed_with_allowlist_flagged_without():
    a = argparse.Namespace(gnb="10.10.10.20", upf="10.10.10.10")
    pkts = b_handover(a, random.Random(1))
    st_on = _state(allowlist=True)
    assert all(evaluate(IP(bytes(p)), st_on) == [] for p in pkts)
    st_off = _state(allowlist=False)
    hits = [f.rule for p in pkts for f in evaluate(IP(bytes(p)), st_off)]
    assert "R2_TEID_SPOOF" in hits
