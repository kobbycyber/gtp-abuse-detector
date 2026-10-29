#!/usr/bin/env bash
# Score the engine and the naive baseline on the University of Oulu 5G-CGAD
# captures (doi:10.23729/fd-b9459ea4-88a7-35c2-992e-f178a294c12d).
#
#   scripts/revision2/run_external.sh /path/to/5g-cgad benign
#   scripts/revision2/run_external.sh /path/to/5g-cgad attacks
#
# The benign archive is read as .tar.xz without unpacking (about 6.6 GB); the
# attack archives are expected unpacked under their dataset folder names.
set -u
O=$1 WHICH=$2
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
R=${RESULTS:-$ROOT/eval/results/external}; mkdir -p "$R"
CORE=10.42.0.64,10.42.0.208
run() { python3 eval/external_eval.py --label "$1" --core-ips $CORE --source "$2" --out "$R/oulu_$3.json"; }
if [ "$WHICH" = benign ]; then
  run benign "$O/benign_traffic.tar.xz" benign
else
  run attack "$O/gtp_encapsulation/**/*.pcap" encapsulation
  run attack "$O/gtp_malformed/**/*.pcap" malformed
  run attack "$O/brute_force_attack/pcap_files_g_pdu_messages/*.pcap" bruteforce_gpdu
  run attack "$O/brute_force_attack/pcap_files_multi_gtp_u_messages/*.pcap" bruteforce_multi
  run attack "$O/intra_upf_dos_attack/**/*.pcap" intraupf
  run attack "$O/ddos_attack/**/*.pcap" ddos
fi
