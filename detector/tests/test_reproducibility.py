"""Regression tests for corpus reproducibility.

The corpus seed is load-bearing: the paper claims every reported number can be
regenerated from it. That claim was false for one build because
`mk_pfcp_smuggle` drew its inner source port from the *module-level*
`random`, which is never seeded, rather than from the caller's seeded
`Random`. The corpus therefore differed byte-for-byte between two runs with
the same seed, even though the detection outcome happened not to change.

These tests fail if that regresses.
"""
from __future__ import annotations

import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.path.insert(0, os.path.join(ROOT, "attacker"))
sys.path.insert(0, os.path.join(ROOT, "detector"))

import benchmark  # noqa: E402


def _digest(pkts) -> str:
    return hashlib.sha256(b"".join(bytes(p) for p in pkts)).hexdigest()


def test_corpus_is_byte_reproducible_across_runs():
    """Same seed twice must give byte-identical packets, not merely equal scores."""
    a, _, _ = benchmark.build_corpus(1337, 60, 12)
    b, _, _ = benchmark.build_corpus(1337, 60, 12)
    assert _digest(a) == _digest(b), (
        "corpus is not byte-reproducible under a fixed seed; check that every "
        "generator draws from the caller's seeded Random, not module-level random"
    )


def test_different_seeds_give_different_corpora():
    """Guard against the opposite failure: a seed that is silently ignored."""
    a, _, _ = benchmark.build_corpus(1337, 60, 12)
    b, _, _ = benchmark.build_corpus(1, 60, 12)
    assert _digest(a) != _digest(b)


def test_latency_timer_covers_dissection():
    """The reported per-packet cost must include Scapy dissection.

    Dissection is roughly 70% of the true cost of a passive tap. A harness that
    starts its timer after `IP(bytes(pkt))` reports rule-evaluation cost only and
    overstates sustained throughput by about 3x. This test reads the source
    rather than timing, because a timing assertion would be flaky on shared CI.
    """
    src = open(os.path.join(ROOT, "eval", "benchmark.py")).read()
    body = src.split("def score_corpus", 1)[1]
    t0 = body.index("t0 = time.perf_counter()")
    dissect = body.index("IP(wire)")
    assert dissect > t0, (
        "packet dissection happens before the latency timer starts; move it "
        "inside the timed region or the reported throughput is not a tap rate"
    )
