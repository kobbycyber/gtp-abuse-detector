"""
Baseline-comparison tests: the naive default-dissection detector must miss
GTP-in-GTP that the robust detector catches. This locks in the quantified
contribution -- if a refactor accidentally made the naive path 'work', the
central claim would be false, and this test would catch it.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))                       # detector/
sys.path.insert(0, os.path.join(HERE, "..", "..", "attacker"))  # attacker/

from scapy.all import IP
from rules import DetectorState, evaluate
from baselines import naive_evaluate
import generate_attacks as ga

CORE = {"10.10.10.10", "10.10.10.11"}
UPF, GNB = "10.10.10.10", "10.10.10.20"


def _state():
    st = DetectorState()
    st.core_nf_ips = set(CORE)
    return st


def _wire(pkt):
    return IP(bytes(pkt))


def test_naive_misses_gtp_in_gtp():
    pkt = _wire(ga.mk_gtp_in_gtp(UPF, 0x1, GNB))
    assert naive_evaluate(pkt, _state()) == []          # default dissection: Raw
    assert "R1_GTP_IN_GTP" in {f.rule for f in evaluate(pkt, _state())}


def test_robust_beats_naive_on_recall():
    """Over a small mixed set, robust recall must exceed naive recall."""
    builders = [
        lambda t: ga.mk_gtp_in_gtp(UPF, t, GNB),
        lambda t: ga.mk_pfcp_smuggle(UPF, t, GNB),
        lambda t: ga.mk_ngap_smuggle(UPF, t, GNB),
        lambda t: ga.mk_inner_to_core(UPF, t, GNB, "10.10.10.11"),
    ]
    pkts = [_wire(b(0x10 + i)) for i, b in enumerate(builders)]
    robust_hits = sum(1 for p in pkts if evaluate(p, _state()))
    naive_hits = sum(1 for p in pkts if naive_evaluate(p, _state()))
    assert robust_hits == len(pkts)
    assert naive_hits < robust_hits


def test_naive_and_robust_agree_on_non_reparse_rules():
    """R3 (SCTP inner) needs no re-parse, so both detectors must agree."""
    pkt = _wire(ga.mk_ngap_smuggle(UPF, 0x2, GNB))
    assert "R3_CP_SMUGGLING" in {f.rule for f in evaluate(pkt, _state())}
    assert "R3_CP_SMUGGLING" in {f.rule for f in naive_evaluate(pkt, _state())}
