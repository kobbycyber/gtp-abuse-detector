"""
Metrics collection for the detector.

Produces the numbers your thesis needs:
  - per-packet processing latency (mean / p50 / p95 / p99)
  - detection counts per rule
  - when ground-truth labels are supplied (eval mode): TP/FP/FN,
    precision, recall, F1, and false-positive rate.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from statistics import mean


@dataclass
class LatencyTracker:
    samples: list = field(default_factory=list)

    def record(self, seconds: float) -> None:
        self.samples.append(seconds * 1e6)  # store as microseconds

    def _pct(self, p: float) -> float:
        if not self.samples:
            return 0.0
        s = sorted(self.samples)
        k = int(round((p / 100.0) * (len(s) - 1)))
        return s[k]

    def summary(self) -> dict:
        if not self.samples:
            return {"count": 0}
        return {
            "count": len(self.samples),
            "mean_us": round(mean(self.samples), 2),
            "p50_us": round(self._pct(50), 2),
            "p95_us": round(self._pct(95), 2),
            "p99_us": round(self._pct(99), 2),
            "max_us": round(max(self.samples), 2),
        }


@dataclass
class Scoreboard:
    packets_seen: int = 0
    gtpu_packets: int = 0
    rule_hits: dict = field(default_factory=dict)
    latency: LatencyTracker = field(default_factory=LatencyTracker)

    # eval-mode confusion counts (need labelled input)
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add_findings(self, findings: list) -> None:
        for f in findings:
            self.rule_hits[f.rule] = self.rule_hits.get(f.rule, 0) + 1

    def score(self, predicted_malicious: bool, truth_malicious: bool) -> None:
        if predicted_malicious and truth_malicious:
            self.tp += 1
        elif predicted_malicious and not truth_malicious:
            self.fp += 1
        elif not predicted_malicious and truth_malicious:
            self.fn += 1
        else:
            self.tn += 1

    def classification(self) -> dict:
        tp, fp, fn, tn = self.tp, self.fp, self.fn, self.tn
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        return {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "false_positive_rate": round(fpr, 4),
        }

    def report(self, labelled: bool = False) -> dict:
        r = {
            "packets_seen": self.packets_seen,
            "gtpu_packets": self.gtpu_packets,
            "rule_hits": self.rule_hits,
            "latency": self.latency.summary(),
        }
        if labelled:
            r["classification"] = self.classification()
        return r

    def dump(self, path: str, labelled: bool = False) -> None:
        with open(path, "w") as fh:
            json.dump(self.report(labelled), fh, indent=2)
