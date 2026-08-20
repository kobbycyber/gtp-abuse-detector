#!/usr/bin/env bash
# Start the simulated gNB, wait for NG setup, then start the UE.
set -euo pipefail

AMF_IP="${AMF_IP:-10.10.10.10}"
GNB_IP="${GNB_IP:-10.10.10.20}"

# Patch config addresses from env so compose stays the single source of truth.
sed -i "s/^\(\s*ngapIp:\s*\).*/\1${GNB_IP}/"  config/gnb.yaml
sed -i "s/^\(\s*gtpIp:\s*\).*/\1${GNB_IP}/"   config/gnb.yaml
sed -i "s/^\(\s*linkIp:\s*\).*/\1${GNB_IP}/"  config/gnb.yaml
sed -i "s/\(-\s*address:\s*\).*/\1${AMF_IP}/" config/gnb.yaml

if [ ! -c /dev/net/tun ]; then mkdir -p /dev/net && mknod /dev/net/tun c 10 200 || true; fi

echo "[ran] starting gNB -> AMF ${AMF_IP}"
./build/nr-gnb -c config/gnb.yaml &
GNB_PID=$!

sleep 6
echo "[ran] starting UE"
./build/nr-ue -c config/ue.yaml &
UE_PID=$!

# Keep both alive; if either dies, exit so compose can restart.
wait -n "$GNB_PID" "$UE_PID"
