#!/usr/bin/env python3
"""
Per-packet processing cost, repeated so one noisy run cannot set the figure.

Times dissection plus rule evaluation for every packet of the seed-1337
corpus (each packet is serialised to bytes before its timer starts, as in
eval/benchmark.py), repeats the pass --reps times, and reports the pooled
percentiles together with the spread of the per-run means.

    python3 eval/latency.py --reps 5 --out results/latency.json
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.path.insert(0, os.path.join(ROOT, "detector"))
sys.path.insert(0, os.path.join(ROOT, "attacker"))

import scapy  # noqa: E402
from scapy.all import IP  # noqa: E402

import benchmark  # noqa: E402
from rules import evaluate  # noqa: E402


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    pkts, _labels, _classes = benchmark.build_corpus(a.seed, 600, 120)
    wires = [bytes(p) for p in pkts]
    pooled, means = [], []
    for _ in range(a.reps):
        st = benchmark._fresh_state(use_allowlist=True)
        run = []
        for wire in wires:
            t0 = time.perf_counter()
            evaluate(IP(wire), st)
            run.append((time.perf_counter() - t0) * 1e6)
        pooled += run
        means.append(statistics.fmean(run))
    out = {
        "reps": a.reps, "packets_per_rep": len(wires),
        "mean_us": round(statistics.fmean(pooled), 1),
        "mean_of_runs_sd_us": round(statistics.stdev(means), 1) if len(means) > 1 else 0.0,
        "run_means_us": [round(m, 1) for m in means],
        "p50_us": round(pct(pooled, 50), 1), "p95_us": round(pct(pooled, 95), 1),
        "p99_us": round(pct(pooled, 99), 1), "max_us": round(max(pooled), 1),
        "pkts_per_s": round(1e6 / statistics.fmean(pooled)),
        "python": platform.python_version(), "scapy": scapy.__version__,
        "cpu": platform.processor() or platform.machine(),
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
