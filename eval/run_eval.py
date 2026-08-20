#!/usr/bin/env python3
"""
Reproducible, no-network evaluation entry point.

Runs the comprehensive benchmark (eval/benchmark.py) and renders the results
document (eval/report.py). Needs only Python + Scapy -- no 5G core, no root.
This is the path that produces the thesis numbers.

  python eval/run_eval.py --seeds 1337,1,2,3,4 --benign 600 --per-class 120
"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL = os.path.join(ROOT, "eval")


def run(cmd):
    print("»", " ".join(cmd))
    subprocess.run(cmd, check=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", default="1337,1,2,3,4")
    p.add_argument("--benign", type=int, default=600)
    p.add_argument("--per-class", type=int, default=120)
    a = p.parse_args()

    metrics = os.path.join(EVAL, "metrics.json")
    results = os.path.join(EVAL, "RESULTS.md")

    run([sys.executable, os.path.join(EVAL, "benchmark.py"),
         "--seeds", a.seeds, "--benign", str(a.benign),
         "--per-class", str(a.per_class), "--metrics-out", metrics,
         "--write-pcap"])

    with open(results, "w") as fh:
        subprocess.run([sys.executable, os.path.join(EVAL, "report.py"), metrics],
                       stdout=fh, check=True)

    print(f"\n[+] metrics -> {metrics}")
    print(f"[+] results -> {results}")


if __name__ == "__main__":
    main()
