"""Redraw the two evaluation figures whose numbers changed.

Usage: python3 paper/figures/make_eval_figures.py

fig5_findings_per_rule.png  offline per-rule findings (primary seed 1337) next to
                            the labelled 500-packet live run before and after the
                            R2 ownership fix (paper/RESULTS.md section 4).
fig7_latency.png            published per-packet latency, dissection and rule
                            evaluation timed together (paper/RESULTS.md 3.5).

The numbers are the published ones, not re-measured here: latency is
host-dependent, and the live counts come from the live lab.
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
BLUE, ORANGE, RED = "#1f4e9c", "#e08214", "#c62828"
plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False})

RULES = ["R1", "R2", "R3", "R4"]
OFFLINE = [120, 120, 240, 360]          # make eval, seed 1337 (840 findings)
LIVE_BEFORE = [82, 146, 150, 230]       # live run, R2 code before the fix (608)
LIVE_AFTER = [82, 88, 150, 230]         # live run, R2 fixed (550)

LATENCY = [("Mean", 686.46), ("P50", 626.70), ("P95", 1186.59),
           ("P99", 1615.94), ("Max", 2332.44)]


def fig5():
    fig, ax = plt.subplots(figsize=(4.275, 2.65), dpi=200)
    x = np.arange(len(RULES))
    w = 0.27
    series = [(OFFLINE, BLUE, "Offline (1,320 pkt)"),
              (LIVE_BEFORE, ORANGE, "Live, before R2 fix (500 pkt)"),
              (LIVE_AFTER, RED, "Live, after R2 fix (500 pkt)")]
    for k, (vals, col, lab) in enumerate(series):
        pos = x + (k - 1) * w
        ax.bar(pos, vals, w, color=col, label=lab)
        for p, v in zip(pos, vals):
            ax.text(p, v + 4, str(v), ha="center", fontsize=5.6)
    ax.set_xticks(x)
    ax.set_xticklabels(RULES)
    ax.set_ylabel("Findings raised")
    ax.set_ylim(0, 400)
    ax.legend(frameon=False, fontsize=6.2, loc="upper left")
    fig.tight_layout(pad=0.3)
    fig.savefig(os.path.join(HERE, "fig5_findings_per_rule.png"), dpi=200)
    plt.close(fig)


def fig7():
    fig, ax = plt.subplots(figsize=(4.2, 2.57), dpi=200)
    labels = [k for k, _ in LATENCY]
    vals = [v for _, v in LATENCY]
    ax.bar(labels, vals, color=BLUE, width=0.6)
    for i, v in enumerate(vals):
        ax.text(i, v + 25, f"{v:,.0f}", ha="center", fontsize=7)
    ax.set_ylabel("Latency (µs)")
    ax.set_ylim(0, 2600)
    fig.tight_layout(pad=0.3)
    fig.savefig(os.path.join(HERE, "fig7_latency.png"), dpi=200)
    plt.close(fig)


if __name__ == "__main__":
    fig5()
    fig7()
    print("wrote fig5_findings_per_rule.png and fig7_latency.png to", HERE)
