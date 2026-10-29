#!/usr/bin/env bash
# One labelled live run with real subscriber traffic on every UE tunnel.
#
#   UE_COUNT=3 make lab-up            # bring the lab up with three UEs first
#   scripts/revision2/run_live.sh L1 2026 0x2 400 100
#
# Sends the seeded corpus onto N3 while the UEs ping through their tunnels,
# saves the live findings, then writes the same sequence to a labelled pcap
# and scores it offline so the two finding streams can be compared.
set -u
TAG=$1 SEED=$2 TEID=$3 COUNT=$4 BENIGN=$5
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
R=${RESULTS:-$ROOT/eval/results/live}/$TAG; mkdir -p "$R"
UES=$(grep -E '^UE_COUNT=' .env | cut -d= -f2); UES=${UES:-1}
nfind() { docker compose logs --no-log-prefix detector 2>&1 | grep -c '"type": "finding"'; }

docker compose up -d --force-recreate detector >/dev/null 2>&1; sleep 8
for i in $(seq 0 $((UES - 1))); do
  echo "uesimtun$i: $(docker compose exec -T ran ping -I uesimtun$i -c2 -W3 8.8.8.8 | grep -o '[0-9]* received')"
done
echo "findings after data-path check: $(nfind)"
for i in $(seq 0 $((UES - 1))); do
  docker compose exec -T -d ran sh -c "ping -I uesimtun$i -i 0.5 8.8.8.8 > /tmp/bg$i.log 2>&1"
done
docker compose run --rm attacker --send --iface eth0 --seed "$SEED" --teid "$TEID" --count "$COUNT" \
  --benign "$BENIGN" --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20 > "$R/attacker.log" 2>&1
docker compose exec -T ran sh -c 'pkill ping; sleep 1; for f in /tmp/bg*.log; do tail -2 $f | head -1; done' > "$R/bg_ping.txt"
sleep 6
docker compose logs --no-log-prefix detector 2>&1 | grep '"type": "finding"' > "$R/findings.jsonl"

python3 attacker/generate_attacks.py --seed "$SEED" --teid "$TEID" --count "$COUNT" --benign "$BENIGN" \
  --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20 \
  --write "$R/corpus.pcap" --labels-out "$R/corpus.labels.json" >/dev/null
python3 detector/gtpu_detector.py pcap --file "$R/corpus.pcap" --labels "$R/corpus.labels.json" \
  --core-ips 10.10.10.10,10.10.10.11 --gnb-ips 10.10.10.20,10.10.10.21 \
  --metrics-out "$R/offline_metrics.json" --json 2>/dev/null | grep '"type": "finding"' > "$R/offline_findings.jsonl"

python3 - "$R" <<'PY'
import json, sys
r = sys.argv[1]
load = lambda f: [{k: v for k, v in json.loads(l).items() if k != "ts"} for l in open(f) if l.strip()]
a, b = load(r + "/findings.jsonl"), load(r + "/offline_findings.jsonl")
print(f"live {len(a)} findings, offline {len(b)}, identical: {a == b}")
PY
