#!/usr/bin/env python3
"""
Passive GTP-U tunnel-abuse detector.

Modes:
  live    sniff an interface (default N3) and flag abuse in real time
  pcap    replay a capture file offline (reproducible, for the thesis)

Both modes share the same rule engine (rules.py) and metrics (metrics.py),
so live and offline numbers are directly comparable.

Examples:
  python gtpu_detector.py live --iface eth1 --core-ips 10.10.10.10
  python gtpu_detector.py pcap --file /captures/mixed.pcap --labels /captures/mixed.labels.json
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time

from scapy.all import sniff, rdpcap, PcapReader, IP
from scapy.contrib.gtp import GTP_U_Header  # noqa: F401  (registers layer)

from rules import DetectorState, evaluate
from metrics import Scoreboard


def build_state(args) -> DetectorState:
    st = DetectorState()
    if args.core_ips:
        st.core_nf_ips = set(args.core_ips.split(","))
    if getattr(args, "gnb_ips", None):
        st.known_gnb_ips = set(args.gnb_ips.split(","))
    if args.ue_prefix:
        st.ue_pool_prefix = args.ue_prefix
    return st


def handle_packet(pkt, state: DetectorState, board: Scoreboard, emit) -> list:
    board.packets_seen += 1
    if pkt.haslayer(GTP_U_Header):
        board.gtpu_packets += 1
    t0 = time.perf_counter()
    findings = evaluate(pkt, state)
    board.latency.record(time.perf_counter() - t0)
    board.add_findings(findings)
    for f in findings:
        emit(f)
    return findings


def make_emitter(json_lines: bool):
    def emit(f):
        if json_lines:
            print(json.dumps(f.as_dict()), flush=True)
        else:
            sev = f.severity.upper()
            teid = hex(f.teid) if f.teid is not None else "-"
            print(f"[{sev:8}] {f.rule:18} src={f.src:15} teid={teid:12} {f.detail}",
                  flush=True)
    return emit


def run_live(args):
    state = build_state(args)
    board = Scoreboard()
    emit = make_emitter(args.json)
    bpf = f"udp port {args.port}"
    print(f"[*] Sniffing {args.iface} filter='{bpf}'  (Ctrl-C to stop)",
          file=sys.stderr)

    # A periodic stats line on stdout, separate from per-finding lines, so a
    # downstream consumer (e.g. viz/server.py) can show "still alive, N
    # packets seen" between findings rather than only at shutdown, when the
    # final summary block below is printed to stderr.
    stop_heartbeat = threading.Event()

    def heartbeat():
        while not stop_heartbeat.wait(2.0):
            if args.json:
                print(json.dumps({
                    "type": "heartbeat",
                    "packets_seen": board.packets_seen,
                    "gtpu_packets": board.gtpu_packets,
                    "ts": round(time.time(), 6),
                }), flush=True)

    hb_thread = threading.Thread(target=heartbeat, daemon=True)
    hb_thread.start()

    def cb(pkt):
        handle_packet(pkt, state, board, emit)

    try:
        sniff(iface=args.iface, filter=bpf, prn=cb, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        stop_heartbeat.set()
        print(json.dumps(board.report(labelled=False), indent=2), file=sys.stderr)
        if args.metrics_out:
            board.dump(args.metrics_out)


def run_pcap(args):
    state = build_state(args)
    board = Scoreboard()
    emit = make_emitter(args.json)

    labels = None
    if args.labels:
        with open(args.labels) as fh:
            labels = json.load(fh)  # list[bool] aligned to packet index

    idx = 0
    for pkt in PcapReader(args.file):
        findings = handle_packet(pkt, state, board, emit)
        if labels is not None and idx < len(labels):
            board.score(predicted_malicious=bool(findings),
                        truth_malicious=bool(labels[idx]))
        idx += 1

    report = board.report(labelled=labels is not None)
    print(json.dumps(report, indent=2))
    if args.metrics_out:
        board.dump(args.metrics_out, labelled=labels is not None)


def main():
    p = argparse.ArgumentParser(description="Passive GTP-U tunnel-abuse detector")
    sub = p.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--core-ips", help="comma-separated core NF IPs (UPF,SMF,AMF)")
    common.add_argument("--gnb-ips", help="comma-separated known gNB IPs (suppresses R2 on legit handovers)")
    common.add_argument("--ue-prefix", default="10.45.", help="UE pool prefix")
    common.add_argument("--json", action="store_true", help="emit JSON lines")
    common.add_argument("--metrics-out", help="write metrics JSON to this path")

    lv = sub.add_parser("live", parents=[common])
    lv.add_argument("--iface", default="eth1")
    lv.add_argument("--port", type=int, default=2152)

    pc = sub.add_parser("pcap", parents=[common])
    pc.add_argument("--file", required=True)
    pc.add_argument("--labels", help="JSON list of ground-truth labels per packet")

    args = p.parse_args()
    if args.mode == "live":
        run_live(args)
    else:
        run_pcap(args)


if __name__ == "__main__":
    main()
