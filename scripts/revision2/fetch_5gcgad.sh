#!/usr/bin/env bash
# Download the University of Oulu 5G-CGAD dataset (CC BY 4.0,
# doi:10.23729/fd-b9459ea4-88a7-35c2-992e-f178a294c12d) and unpack the attack
# archives. About 6.9 GB in total, 6.6 GB of it the benign archive, which is
# kept packed (eval/external_eval.py reads .tar.xz directly).
#
#   scripts/revision2/fetch_5gcgad.sh ~/5g-cgad            # everything
#   SKIP_BENIGN=1 scripts/revision2/fetch_5gcgad.sh ~/5g-cgad   # attacks only (~300 MB)
set -euo pipefail
DEST=${1:?usage: fetch_5gcgad.sh DEST_DIR}
ID=5dad463d-0306-455f-b47a-bef771b819fc
mkdir -p "$DEST"; cd "$DEST"
FILES=(/pcap_files/gtp_encapsulation.tar.xz /pcap_files/gtp_malformed.tar.xz
       /pcap_files/brute_force_attack.tar.xz /pcap_files/intra_upf_dos_attack.tar.xz
       /pcap_files/ddos_attack.tar.xz)
[ "${SKIP_BENIGN:-0}" = 1 ] || FILES+=(/pcap_files/benign_traffic.tar.xz)
for f in "${FILES[@]}"; do
  out=$(basename "$f")
  if [ -s "$out" ]; then echo "have $out"; continue; fi
  url=$(curl -s -m 60 -X POST https://etsin.fairdata.fi/api/v3/download/authorize \
        -H 'Content-Type: application/json' -d "{\"cr_id\":\"$ID\",\"file\":\"$f\"}" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')
  echo "downloading $out"
  curl -fL -o "$out" "$url"
done
for a in gtp_encapsulation gtp_malformed brute_force_attack intra_upf_dos_attack ddos_attack; do
  [ -d "$a" ] || { echo "unpacking $a"; tar -xJf "$a.tar.xz"; }
done
echo "done: $DEST"
