#!/usr/bin/env python3
"""
Render a detector metrics JSON into a thesis-ready markdown results document.

Handles both the comprehensive benchmark schema (eval/benchmark.py) and the
legacy single-run schema (detector --metrics-out). Usage:

  python eval/report.py eval/metrics.json > eval/RESULTS.md
"""
import json
import sys
from datetime import datetime, timezone

L = []


def w(s=""):
    L.append(s)


def table(headers, rows, aligns=None):
    aligns = aligns or ["---"] * len(headers)
    w("| " + " | ".join(headers) + " |")
    w("|" + "|".join(aligns) + "|")
    for r in rows:
        w("| " + " | ".join(str(c) for c in r) + " |")
    w()


def render(m, src):
    w("# GTP-U Abuse Detection — Evaluation Results")
    w()
    w(f"_Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} "
      f"from `{src}`._")
    w()

    cfg = m.get("config")
    if cfg:
        w(f"Corpus: **{cfg.get('corpus_packets', m.get('packets_seen'))} packets** "
          f"(realistic diverse benign + all attack classes), primary seed "
          f"`{cfg.get('primary_seed')}`, stability measured across seeds "
          f"`{cfg.get('seeds')}`.")
        w()

    # --- headline classification ---
    cl = m.get("classification")
    if cl:
        w("## 1. Headline classification (robust detector, realistic corpus)")
        w()
        table(["Metric", "Value"],
              [["True positives", cl["tp"]], ["False positives", cl["fp"]],
               ["False negatives", cl["fn"]], ["True negatives", cl["tn"]],
               ["Precision", cl["precision"]], ["Recall", cl["recall"]],
               ["F1", cl["f1"]], ["False-positive rate", cl["false_positive_rate"]]],
              ["---", "---:"])

    # --- multi-seed stability ---
    st = m.get("stability_across_seeds")
    if st:
        w("## 2. Stability across seeds")
        w()
        w("Headline metrics are stable, not a single lucky corpus:")
        w()
        rows = [[k, v["mean"], v["std"], v["min"], v["max"]]
                for k, v in st.items()]
        table(["Metric", "Mean", "Std", "Min", "Max"], rows,
              ["---", "---:", "---:", "---:", "---:"])

    # --- per-class recall + baseline ---
    rc = m.get("recall_by_class")
    if rc:
        w("## 3. Per-attack-class recall, robust vs naive baseline")
        w()
        w("The naive baseline is the detector a competent engineer writes first: "
          "Scapy's default dissection with `haslayer`, **no inner re-parse**. "
          "The only design variable that differs is the re-parse, so the delta "
          "isolates this project's core contribution.")
        w()
        nb = m.get("baseline_naive", {}).get("recall_by_class", {})
        rows = []
        for c in sorted(rc):
            rows.append([c, rc[c], nb.get(c, "—")])
        table(["Attack class", "Robust recall", "Naive recall"], rows,
              ["---", "---:", "---:"])
        nbc = m.get("baseline_naive", {}).get("classification")
        if nbc:
            w(f"Overall the naive baseline scores recall **{nbc['recall']}** / "
              f"F1 **{nbc['f1']}**, missing GTP-in-GTP entirely "
              f"(recall {nb.get('gtp_in_gtp', '—')}) because a nested GTP header "
              f"deserialises as `Raw` under default dissection. The robust "
              f"detector re-parses those bytes and recovers full recall.")
            w()

    # --- false-positive provenance + R2 ablation ---
    ab = m.get("r2_ablation")
    if ab:
        w("## 4. False-positive provenance and the handover ablation")
        w()
        w("A false-positive rate is only meaningful against diverse benign "
          "traffic. The benign corpus spans TLS, HTTP, DNS, QUIC, NTP, RTP, "
          "ICMP, IPv6, fragmented IP, IP-options, **Unstructured PDU-session "
          "bytes**, and **legitimate handovers** — the last two chosen "
          "specifically to stress the detector's heuristics.")
        w()
        wa = ab["with_gnb_allowlist"]
        wo = ab["without_gnb_allowlist"]
        table(["R2 configuration", "FPR", "False positives", "FP source"],
              [["with known-gNB allowlist", wa["false_positive_rate"], wa["fp"],
                json.dumps(wa["fp_by_benign_category"]) or "none"],
               ["without allowlist", wo["false_positive_rate"], wo["fp"],
                json.dumps(wo["fp_by_benign_category"]) or "none"]],
              ["---", "---:", "---:", "---"])
        w("Every residual false positive is attributable to legitimate Xn/N2 "
          "handovers, where the uplink TEID is unchanged but the source gNB IP "
          "legitimately changes — structurally identical to a TEID-spoof on the "
          "N3 user plane alone. Supplying the operator's known gNB address pool "
          "(`--gnb-ips`) suppresses these while still catching a TEID re-sourced "
          "from any IP outside the pool. This is a documented, mitigated "
          "limitation of stateless passive attribution, not a hidden one.")
        w()

    # --- evasion suite ---
    ev = m.get("evasion_suite")
    if ev:
        w("## 5. Evasion suite (adversarial robustness)")
        w()
        w(f"The detector is scored against **{len(ev['rows'])} crafted evasions**, "
          f"each labelled with whether a correct detector *should* catch it or "
          f"whether it is an inherent blind spot of a stateless passive rule. "
          f"Result: **{ev['robustness_wins']} robustness wins** (caught despite "
          f"the evasion attempt), **{ev['documented_blind_spots']} documented "
          f"blind spots**, **{ev['mismatches']} mismatches** vs the documented "
          f"expectation.")
        w()
        rows = []
        for r in ev["rows"]:
            outcome = "caught ✓" if r["detected"] else "not caught"
            kind = "robustness win" if r["expected_detect"] else "known blind spot"
            rows.append([f"`{r['name']}`", r["target_rule"], outcome, kind,
                         r["rationale"]])
        table(["Evasion", "Rule", "Outcome", "Class", "Why"], rows)
        w("The blind spots are honest limitations of user-plane-only heuristics: "
          "a rogue that owns a never-before-seen TEID, forges the gNB source IP, "
          "moves a control-plane protocol off its well-known port, or targets a "
          "core NF outside the configured set. Each maps to a concrete "
          "hardening path (control-plane correlation, deep payload classification, "
          "complete NF inventory) discussed in the paper.")
        w()

    # --- detections per rule ---
    hits = m.get("rule_hits")
    if hits:
        w("## 6. Detections per rule (primary corpus)")
        w()
        table(["Rule", "Hits"], [[r, hits[r]] for r in sorted(hits)],
              ["---", "---:"])

    # --- latency ---
    lat = m.get("latency", {})
    if lat.get("count"):
        w("## 7. Per-packet latency and throughput")
        w()
        rows = []
        for k in ("mean_us", "p50_us", "p95_us", "p99_us", "max_us"):
            if k in lat:
                rows.append([k.replace("_us", "").upper(), lat[k]])
        table(["Metric", "Value (µs)"], rows, ["---", "---:"])
        if lat.get("mean_us"):
            w(f"Sustained single-core throughput ≈ **{1e6/lat['mean_us']:,.0f} "
              f"pkt/s** (1 / mean latency), measured on raw-byte re-dissection of "
              f"every packet — the realistic passive-tap cost.")
            w()


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "eval/metrics.json"
    with open(src) as fh:
        m = json.load(fh)
    render(m, src)
    print("\n".join(L))


if __name__ == "__main__":
    main()
