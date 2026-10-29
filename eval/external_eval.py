#!/usr/bin/env python3
"""
Score the detector on captures it was not built against.

Every GTP-U packet in a capture gets the capture's label (attack or benign);
that label comes from the dataset's own scenario split, never from the rules.
Captures are read as files or streamed straight out of .tar.xz archives, so a
multi-gigabyte archive is never unpacked to disk.

    python3 eval/external_eval.py --label benign --core-ips 10.42.0.64 \
        --source oulu/benign_traffic.tar.xz --out results/oulu_benign.json

The output JSON holds packet counts, per-rule finding counts, the number of
GTP-U packets flagged by the engine and by the naive baseline, Wilson 95%
intervals for the flagged fraction, any exceptions, and up to 20 example
findings for inspection.
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import math
import os
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "detector"))

from scapy.all import Ether, RawPcapReader  # noqa: E402
from scapy.contrib.gtp import GTP_U_Header  # noqa: E402
from scapy.layers.l2 import CookedLinux  # noqa: E402

from baselines import naive_evaluate  # noqa: E402
from rules import DetectorState, evaluate  # noqa: E402


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval for a proportion k/n (95% by default)."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centre - half), min(1.0, centre + half))


def _frames(source: str):
    """Yield (name, raw frame bytes, linktype) from a pcap, glob or .tar.xz."""
    def from_reader(name, reader):
        linktype = getattr(reader, "linktype", 1)
        for raw, _meta in reader:
            yield name, raw, linktype

    if source.endswith((".tar.xz", ".tar.gz", ".tar")):
        with tarfile.open(source, "r|*") as tar:
            for member in tar:
                if not member.isfile() or not member.name.endswith((".pcap", ".pcapng", ".cap")):
                    continue
                fh = tar.extractfile(member)
                yield from from_reader(member.name, RawPcapReader(fh))
        return
    for path in sorted(glob.glob(source)):
        yield from from_reader(path, RawPcapReader(path))


def _decode(raw: bytes, linktype: int):
    if linktype == 113:
        return CookedLinux(raw)
    return Ether(raw)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", action="append", required=True,
                    help="pcap path, glob or .tar.xz archive (repeatable)")
    ap.add_argument("--label", choices=["attack", "benign"], required=True)
    ap.add_argument("--core-ips", default="", help="comma-separated core NF addresses (R4)")
    ap.add_argument("--gnb-ips", default="", help="comma-separated gNB allowlist (R2); empty = strict")
    ap.add_argument("--limit", type=int, default=0, help="stop after N frames (0 = all)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    def state():
        st = DetectorState()
        st.core_nf_ips = {x for x in args.core_ips.split(",") if x}
        st.known_gnb_ips = {x for x in args.gnb_ips.split(",") if x}
        return st

    robust_state, naive_state = state(), state()
    frames = gtpu = flagged = naive_flagged = errors = 0
    rule_hits = collections.Counter()
    naive_rule_hits = collections.Counter()
    per_file = collections.Counter()
    examples = []
    t_start = time.time()

    for source in args.source:
        for name, raw, linktype in _frames(source):
            frames += 1
            if args.limit and frames > args.limit:
                break
            try:
                pkt = _decode(raw, linktype)
                if not pkt.haslayer(GTP_U_Header):
                    continue
                gtpu += 1
                per_file[os.path.basename(name)] += 1
                found = evaluate(pkt, robust_state)
                naive = naive_evaluate(pkt, naive_state)
            except Exception as exc:  # the engine itself must never raise
                errors += 1
                if errors <= 5:
                    examples.append({"error": repr(exc), "file": name})
                continue
            if found:
                flagged += 1
                for f in found:
                    rule_hits[f.rule] += 1
                if len(examples) < 20:
                    examples.append({"file": os.path.basename(name), "frame": frames,
                                     "rules": sorted({f.rule for f in found}),
                                     "detail": found[0].detail})
            if naive:
                naive_flagged += 1
                for f in naive:
                    naive_rule_hits[f.rule] += 1
            if frames % 200000 == 0:
                print(f"[{time.time() - t_start:7.0f}s] {frames} frames, {gtpu} GTP-U, "
                      f"{flagged} flagged", file=sys.stderr, flush=True)

    lo, hi = wilson(flagged, gtpu)
    nlo, nhi = wilson(naive_flagged, gtpu)
    out = {
        "sources": args.source,
        "label": args.label,
        "config": {"core_ips": args.core_ips, "gnb_ips": args.gnb_ips or "(none: strict R2)"},
        "frames": frames,
        "gtpu_packets": gtpu,
        "flagged": flagged,
        "flagged_fraction": flagged / gtpu if gtpu else None,
        "flagged_wilson95": [lo, hi],
        "rule_hits": dict(rule_hits),
        "naive_flagged": naive_flagged,
        "naive_flagged_fraction": naive_flagged / gtpu if gtpu else None,
        "naive_flagged_wilson95": [nlo, nhi],
        "naive_rule_hits": dict(naive_rule_hits),
        "errors": errors,
        "files": len(per_file),
        "seconds": round(time.time() - t_start, 1),
        "examples": examples,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps({k: v for k, v in out.items() if k != "examples"}, indent=2))


if __name__ == "__main__":
    main()
