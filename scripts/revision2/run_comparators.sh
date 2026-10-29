#!/usr/bin/env bash
# Run Zeek, Suricata (ET Open rules) and tshark over one capture per class,
# using the official container images, so nothing needs installing locally.
#
#   scripts/revision2/run_comparators.sh [OUT_DIR]     (default: comparators/)
#
# Versions used in the paper: zeek/zeek:8.2.2, Suricata 8.0.7
# (jasonish/suricata), tshark 4.6.6 (nicolaka/netshoot).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
OUT=$(realpath -m "${1:-comparators}")
mkdir -p "$OUT/rules"
python3 eval/comparator_pcaps.py --out "$OUT/pcaps"

docker run --rm -v "$OUT/rules":/var/lib/suricata --entrypoint suricata-update jasonish/suricata:latest -q 2>/dev/null || true
for p in "$OUT"/pcaps/*.pcap; do
  n=$(basename "$p" .pcap); d="$OUT/$n"; mkdir -p "$d/zeek" "$d/suricata"
  cp "$p" "$d/zeek/"
  docker run --rm -v "$d/zeek":/d -w /d zeek/zeek:8.2.2 zeek -C -r "$n.pcap" >/dev/null 2>&1 || true
  cp "$p" "$d/suricata/"
  docker run --rm -v "$d/suricata":/d -v "$OUT/rules":/var/lib/suricata --entrypoint suricata \
    jasonish/suricata:latest -r "/d/$n.pcap" -l /d -k none >/dev/null 2>&1 || true
  docker run --rm -v "$OUT/pcaps":/d nicolaka/netshoot \
    tshark -r "/d/$n.pcap" -T fields -e frame.protocols 2>/dev/null | sort | uniq -c > "$d/tshark.txt"
  zv=$( (grep -v '^#' "$d/zeek/analyzer.log" 2>/dev/null || true) | cut -f 11 | sort -u | paste -sd, -)
  sa=$(cat "$d/suricata/fast.log" 2>/dev/null | wc -l)
  printf '%-20s zeek violations: %-28s suricata alerts: %s\n' "$n" "${zv:--}" "$sa"
done
