#!/usr/bin/env python3
"""
Held-out evaluation on seeds never used during development.

Development used seeds 1337, 1, 2, 3 and 4. This script scores the frozen
engine on fresh seeds (default 101-110), pools the packets, and reports
precision, recall and false-positive rate with Wilson 95% intervals, so the
interval reflects how many packets were scored rather than how many seeds.

With --realistic-outer every outer GTP-U header is rewritten to carry a PDU
Session Container extension header (E flag set, random QFI), which is how a
real gNB frames every N3 G-PDU. The packets inside the tunnel are unchanged.

    python3 eval/heldout.py --out results/heldout.json
    python3 eval/heldout.py --realistic-outer --out results/heldout_ext.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.path.insert(0, os.path.join(ROOT, "detector"))
sys.path.insert(0, os.path.join(ROOT, "attacker"))

from scapy.all import IP, IPv6, UDP  # noqa: E402
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer  # noqa: E402

import benchmark  # noqa: E402
from baselines import naive_evaluate  # noqa: E402
from external_eval import wilson  # noqa: E402
from rules import evaluate  # noqa: E402


def with_session_container(pkt, rng: random.Random):
    """Same packet, with a PDU Session Container on its outer GTP-U header."""
    raw = bytes(pkt)
    net = IP(raw) if raw[0] >> 4 == 4 else IPv6(raw)
    gtp = net[GTP_U_Header]
    hdr = bytes(gtp)
    assert hdr[0] & 0x07 == 0, "corpus outer headers carry no optional fields"
    payload = hdr[8:]
    outer = net.copy()
    outer[UDP].remove_payload()
    del outer[UDP].len, outer[UDP].chksum
    if outer.haslayer(IP):
        del outer[IP].len, outer[IP].chksum
    else:
        del outer[IPv6].plen
    new = outer / GTP_U_Header(gtp_type=gtp.gtp_type, teid=gtp.teid, E=1, next_ex=0x85) / \
        GTPPDUSessionContainer(type=1, QFI=rng.randint(1, 9)) / payload
    return new


def score(seeds, benign_n, per_class_n, realistic):
    tot = {"robust": dict(tp=0, fp=0, fn=0, tn=0), "naive": dict(tp=0, fp=0, fn=0, tn=0)}
    per_class = {}
    per_seed = []
    for seed in seeds:
        pkts, labels, classes = benchmark.build_corpus(seed, benign_n, per_class_n)
        if realistic:
            rng = random.Random(seed ^ 0x5EED)
            pkts = [with_session_container(p, rng) for p in pkts]
        for name, fn in (("robust", evaluate), ("naive", naive_evaluate)):
            st = benchmark._fresh_state(use_allowlist=True)
            c = dict(tp=0, fp=0, fn=0, tn=0)
            for pkt, truth, cls in zip(pkts, labels, classes):
                pred = bool(fn(IP(bytes(pkt)), st))
                key = ("tp" if pred else "fn") if truth else ("fp" if pred else "tn")
                c[key] += 1
                if name == "robust" and truth:
                    h = per_class.setdefault(cls, [0, 0])
                    h[0] += pred
                    h[1] += 1
            for k in c:
                tot[name][k] += c[k]
            if name == "robust":
                per_seed.append({"seed": seed, **c})
    return tot, per_class, per_seed


def summarise(c):
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    return {
        **c,
        "precision": tp / (tp + fp) if tp + fp else None,
        "precision_wilson95": wilson(tp, tp + fp),
        "recall": tp / (tp + fn) if tp + fn else None,
        "recall_wilson95": wilson(tp, tp + fn),
        "fpr": fp / (fp + tn) if fp + tn else None,
        "fpr_wilson95": wilson(fp, fp + tn),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seeds", default=",".join(str(s) for s in range(101, 111)))
    ap.add_argument("--benign", type=int, default=600)
    ap.add_argument("--per-class", type=int, default=120)
    ap.add_argument("--realistic-outer", action="store_true")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(",")]
    assert not set(seeds) & {1337, 1, 2, 3, 4}, "held-out seeds must not overlap development seeds"
    tot, per_class, per_seed = score(seeds, args.benign, args.per_class, args.realistic_outer)
    out = {
        "seeds": seeds,
        "realistic_outer": args.realistic_outer,
        "robust": summarise(tot["robust"]),
        "naive": summarise(tot["naive"]),
        "robust_recall_by_class": {k: {"hit": v[0], "total": v[1], "wilson95": wilson(v[0], v[1])}
                                   for k, v in sorted(per_class.items())},
        "per_seed_robust": per_seed,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=2)
    r, n = out["robust"], out["naive"]
    print(f"robust: P={r['precision']:.4f} R={r['recall']:.4f} FPR={r['fpr']:.4f} "
          f"recall95={[round(x, 4) for x in r['recall_wilson95']]} fpr95={[round(x, 4) for x in r['fpr_wilson95']]}")
    print(f"naive : P={n['precision']:.4f} R={n['recall']:.4f} FPR={n['fpr']:.4f}")


if __name__ == "__main__":
    main()
