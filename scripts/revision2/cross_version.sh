#!/usr/bin/env bash
# Score the same capture under two Scapy releases and compare the ordered
# finding streams (wall-clock timestamps excluded).
#
#   scripts/revision2/cross_version.sh PYTHON_A PYTHON_B
#
# e.g. Ubuntu 22.04's packaged Scapy 2.4.4 against a venv with 2.7.0:
#   sudo apt install python3-scapy                     # 2.4.4 at /usr/bin/python3
#   python3 -m venv /tmp/s27 && /tmp/s27/bin/pip install scapy==2.7.0
#   scripts/revision2/cross_version.sh /usr/bin/python3 /tmp/s27/bin/python
set -euo pipefail
A=${1:?python with first Scapy}; B=${2:?python with second Scapy}
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
T=$(mktemp -d)
"$A" attacker/generate_attacks.py --seed 1337 --count 400 --benign 100 \
  --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20 --write "$T/c.pcap" --labels-out "$T/c.labels.json" >/dev/null
for py in "$A" "$B"; do
  v=$("$py" -c 'import scapy; print(scapy.__version__)')
  "$py" detector/gtpu_detector.py pcap --file "$T/c.pcap" --core-ips 10.10.10.10,10.10.10.11 \
    --gnb-ips 10.10.10.20,10.10.10.21 --json 2>/dev/null | grep '"type": "finding"' > "$T/$v.jsonl"
  echo "Scapy $v: $(wc -l < "$T/$v.jsonl") findings"
done
python3 - "$T" <<'PY'
import glob, json, sys
fs = sorted(glob.glob(sys.argv[1] + "/*.jsonl"))
load = lambda f: [{k: v for k, v in json.loads(l).items() if k != "ts"} for l in open(f)]
print("identical finding streams:", load(fs[0]) == load(fs[-1]))
PY
