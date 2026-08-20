#!/usr/bin/env python3
"""
Comprehensive, reproducible evaluation harness for the GTP-U abuse detector.

Everything here runs offline with only Python + Scapy -- no 5G core, no root.
It produces the full evidence set a defensible evaluation needs, rather than a
single headline F1 on a self-generated corpus:

  1. Main metrics on a REALISTIC mixed corpus (diverse benign + all attacks)
  2. Per-attack-class recall breakdown
  3. Per-benign-category false-positive breakdown (where FPs actually come from)
  4. Naive-baseline vs robust-detector comparison (isolates the re-parse win)
  5. R2 ablation: with vs without the known-gNB allowlist (handover handling)
  6. Evasion suite: which crafted evasions are caught vs documented blind spots
  7. Multi-seed stability: mean +/- std of the headline metrics across seeds
  8. Latency / single-core throughput

Writes eval/metrics.json (machine-readable) and is consumed by report.py to
render eval/RESULTS.md.

  python eval/benchmark.py --seeds 1337,1,2,3,4 --benign 600 --per-class 120
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "detector"))
sys.path.insert(0, os.path.join(ROOT, "attacker"))

from scapy.all import IP, wrpcap  # noqa: E402
from rules import DetectorState, evaluate  # noqa: E402
from baselines import naive_evaluate  # noqa: E402
from metrics import Scoreboard  # noqa: E402
import generate_attacks as ga  # noqa: E402
from benign_traffic import benign_corpus  # noqa: E402
from evasions import all_evasions  # noqa: E402

CORE_IPS = {"10.10.10.10", "10.10.10.11"}
KNOWN_GNBS = {"10.10.10.20", "10.10.10.21"}   # serving + target gNB (handover)
UPF, SMF, GNB, ATT = "10.10.10.10", "10.10.10.11", "10.10.10.20", "10.10.10.66"
ATTACK_CLASSES = ["gtp_in_gtp", "pfcp_smuggle", "ngap_smuggle", "inner_to_core", "teid_spoof"]


def _mal_args(teid):
    return argparse.Namespace(upf=UPF, smf=SMF, gnb=GNB, attacker=ATT, teid=teid)


def build_corpus(seed: int, benign_n: int, per_class: int):
    """Return (packets, labels, classes) time-ordered for causal R2 correctness.

    classes[i] is the attack class for malicious packets, the benign category
    for benign packets, or 'spoof_victim' for the legit flow a spoof reuses.
    Baseline (benign + spoof victims) is emitted first so a spoof always has a
    prior owner to conflict with -- mirroring a real capture where the victim
    tunnel is already active when the rogue re-sources its TEID.
    """
    rng = random.Random(seed)
    pkts, labels, classes = [], [], []

    # --- baseline block: realistic benign + one legit victim flow per spoof ---
    benign = benign_corpus(benign_n, seed)  # list[(pkt, category)]
    baseline = [(pk, False, cat) for pk, cat in benign]

    victim_teids = []
    for i in range(per_class):
        vt = 0x900000 + i          # disjoint from benign random TEID range
        victim_teids.append(vt)
        baseline.append((ga.mk_benign(UPF, vt, GNB), False, "spoof_victim"))
    rng.shuffle(baseline)

    # --- attack block ---
    attacks = []
    for _ in range(per_class):
        t = rng.randint(0x1, 0xffff)
        attacks.append((ga.mk_gtp_in_gtp(UPF, t, GNB), True, "gtp_in_gtp"))
        attacks.append((ga.mk_pfcp_smuggle(UPF, t, GNB), True, "pfcp_smuggle"))
        attacks.append((ga.mk_ngap_smuggle(UPF, t, GNB), True, "ngap_smuggle"))
        attacks.append((ga.mk_inner_to_core(UPF, t, GNB, SMF), True, "inner_to_core"))
    for vt in victim_teids:
        attacks.append((ga.mk_teid_spoof(UPF, vt, ATT), True, "teid_spoof"))
    rng.shuffle(attacks)

    for pk, lab, cls in baseline + attacks:
        pkts.append(pk)
        labels.append(lab)
        classes.append(cls)
    return pkts, labels, classes


def _fresh_state(use_allowlist: bool) -> DetectorState:
    st = DetectorState()
    st.core_nf_ips = set(CORE_IPS)
    if use_allowlist:
        st.known_gnb_ips = set(KNOWN_GNBS)
    return st


def score_corpus(pkts, labels, classes, evaluator, use_allowlist=True, latency=False):
    """Run an evaluator over a corpus; return a rich result dict."""
    st = _fresh_state(use_allowlist)
    board = Scoreboard()
    per_class_total, per_class_hit = {}, {}
    per_cat_fp = {}
    for pkt, truth, cls in zip(pkts, labels, classes):
        # round-trip through raw bytes so we test real dissection, not the
        # in-memory object graph (the R1 finding is precisely about this).
        rt = IP(bytes(pkt))
        board.packets_seen += 1
        t0 = time.perf_counter()
        findings = evaluator(rt, st)
        if latency:
            board.latency.record(time.perf_counter() - t0)
        board.add_findings(findings)
        pred = bool(findings)
        board.score(pred, truth)
        if truth:
            per_class_total[cls] = per_class_total.get(cls, 0) + 1
            if pred:
                per_class_hit[cls] = per_class_hit.get(cls, 0) + 1
        elif pred:
            per_cat_fp[cls] = per_cat_fp.get(cls, 0) + 1

    cl = board.classification()
    recall_by_class = {c: round(per_class_hit.get(c, 0) / per_class_total[c], 4)
                       for c in sorted(per_class_total)}
    return {
        "classification": cl,
        "recall_by_class": recall_by_class,
        "class_totals": per_class_total,
        "fp_by_benign_category": per_cat_fp,
        "rule_hits": board.rule_hits,
        "latency": board.latency.summary() if latency else {"count": 0},
        "packets": board.packets_seen,
    }


def run_evasions():
    """Score the evasion suite; assert observed == documented expectation."""
    st = _fresh_state(use_allowlist=True)
    # Prime R2 owner for the 'spoofed source IP' case (legit gNB owns TEID 0x5).
    from scapy.all import UDP, ICMP
    from scapy.contrib.gtp import GTP_U_Header
    evaluate(IP(src=GNB, dst=UPF) / UDP(sport=2152, dport=2152) /
             GTP_U_Header(teid=0x5) / IP(src="10.45.0.2", dst="8.8.8.8") / ICMP(), st)
    rows, mismatches = [], 0
    for name, pkt, rule, expected, why in all_evasions():
        rt = IP(bytes(pkt))
        got = rule in {f.rule for f in evaluate(rt, st)}
        ok = (got == expected)
        mismatches += 0 if ok else 1
        rows.append({"name": name, "target_rule": rule, "expected_detect": expected,
                     "detected": got, "consistent": ok, "rationale": why})
    caught = sum(1 for r in rows if r["expected_detect"] and r["detected"])
    blind = sum(1 for r in rows if not r["expected_detect"] and not r["detected"])
    return {"rows": rows, "mismatches": mismatches,
            "robustness_wins": caught, "documented_blind_spots": blind}


def main():
    p = argparse.ArgumentParser(description="Comprehensive GTP-U detector benchmark")
    p.add_argument("--seeds", default="1337,1,2,3,4")
    p.add_argument("--benign", type=int, default=600)
    p.add_argument("--per-class", type=int, default=120)
    p.add_argument("--metrics-out", default=os.path.join(ROOT, "eval", "metrics.json"))
    p.add_argument("--write-pcap", action="store_true",
                   help="also write the seed-0 corpus to captures/ for inspection")
    a = p.parse_args()
    seeds = [int(s) for s in a.seeds.split(",")]

    # ---- primary run on the first seed, full detail + latency ----
    p0, l0, c0 = build_corpus(seeds[0], a.benign, a.per_class)
    robust = score_corpus(p0, l0, c0, evaluate, use_allowlist=True, latency=True)
    robust_noallow = score_corpus(p0, l0, c0, evaluate, use_allowlist=False)
    naive = score_corpus(p0, l0, c0, naive_evaluate, use_allowlist=True)

    if a.write_pcap:
        caps = os.path.join(ROOT, "captures")
        os.makedirs(caps, exist_ok=True)
        wrpcap(os.path.join(caps, "mixed.pcap"), p0)
        with open(os.path.join(caps, "mixed.labels.json"), "w") as fh:
            json.dump(l0, fh)
        with open(os.path.join(caps, "mixed.classes.json"), "w") as fh:
            json.dump(c0, fh)

    # ---- multi-seed stability of the headline metrics (robust, allowlist) ----
    agg = {"precision": [], "recall": [], "f1": [], "false_positive_rate": []}
    for s in seeds:
        ps, ls, cs = build_corpus(s, a.benign, a.per_class)
        r = score_corpus(ps, ls, cs, evaluate, use_allowlist=True)["classification"]
        for k in agg:
            agg[k].append(r[k])

    def stat(v):
        return {"mean": round(statistics.mean(v), 4),
                "std": round(statistics.pstdev(v), 4),
                "min": round(min(v), 4), "max": round(max(v), 4)}
    stability = {k: stat(v) for k, v in agg.items()}

    evasion = run_evasions()

    metrics = {
        "config": {"seeds": seeds, "benign": a.benign, "per_class": a.per_class,
                   "primary_seed": seeds[0], "corpus_packets": robust["packets"]},
        "packets_seen": robust["packets"],
        "gtpu_packets": robust["packets"],
        "rule_hits": robust["rule_hits"],
        "latency": robust["latency"],
        "classification": robust["classification"],
        "recall_by_class": robust["recall_by_class"],
        "fp_by_benign_category": robust["fp_by_benign_category"],
        "baseline_naive": {
            "classification": naive["classification"],
            "recall_by_class": naive["recall_by_class"],
        },
        "r2_ablation": {
            "with_gnb_allowlist": {
                "false_positive_rate": robust["classification"]["false_positive_rate"],
                "fp": robust["classification"]["fp"],
                "fp_by_benign_category": robust["fp_by_benign_category"],
            },
            "without_gnb_allowlist": {
                "false_positive_rate": robust_noallow["classification"]["false_positive_rate"],
                "fp": robust_noallow["classification"]["fp"],
                "fp_by_benign_category": robust_noallow["fp_by_benign_category"],
            },
        },
        "stability_across_seeds": stability,
        "evasion_suite": evasion,
    }

    with open(a.metrics_out, "w") as fh:
        json.dump(metrics, fh, indent=2)

    cl = robust["classification"]
    nb = naive["classification"]
    print(f"[+] corpus: {robust['packets']} packets  "
          f"({sum(l0)} malicious / {len(l0)-sum(l0)} benign)")
    print(f"[+] robust : P={cl['precision']} R={cl['recall']} F1={cl['f1']} "
          f"FPR={cl['false_positive_rate']}")
    print(f"[+] naive  : P={nb['precision']} R={nb['recall']} F1={nb['f1']}  "
          f"(R1 recall {naive['recall_by_class'].get('gtp_in_gtp')})")
    print(f"[+] evasions: {evasion['robustness_wins']} caught, "
          f"{evasion['documented_blind_spots']} documented blind spots, "
          f"{evasion['mismatches']} mismatches")
    print(f"[+] metrics -> {a.metrics_out}")
    if evasion["mismatches"]:
        print("[!] WARNING: evasion suite mismatch -- detector behaviour drifted")
        sys.exit(1)


if __name__ == "__main__":
    main()
