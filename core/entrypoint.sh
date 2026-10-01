#!/usr/bin/env bash
# Open5GS all-in-one core bootstrap for the GTP-U abuse lab.
# - waits for MongoDB
# - registers a single test subscriber (IMSI/K/OPc from env)
# - applies bind-address / PLMN overrides
# - launches the core NFs (AMF, SMF, UPF, and support NFs)
set -euo pipefail

DB_URI="${DB_URI:-mongodb://mongo/open5gs}"
CORE_IP="${CORE_IP:-10.10.10.10}"
MCC="${MCC:-999}"
MNC="${MNC:-70}"
TAC="${TAC:-1}"
IMSI="${IMSI:-999700000000001}"
KI="${KI:-465B5CE8B199B49FAA5F0A2EE238A6BC}"
OPC="${OPC:-E8ED289DEBA952E4283B54E88E6183CA}"
APN="${APN:-internet}"

echo "[core] waiting for MongoDB at ${DB_URI} ..."
until mongosh "${DB_URI}" --quiet --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q 1; do
    sleep 1
done
echo "[core] MongoDB is up."

# --- register the test subscriber (idempotent) ---
export DB_URI
if ! open5gs-dbctl showall 2>/dev/null | grep -q "${IMSI}"; then
    echo "[core] registering subscriber ${IMSI}"
    open5gs-dbctl add "${IMSI}" "${KI}" "${OPC}" || true
else
    echo "[core] subscriber ${IMSI} already present"
fi

# --- apply address / PLMN overrides onto the packaged configs ---
# UPF: bind GTP-U (N3) on the core IP so the detector can tap it.
sed -i "s/  gtpu:/  gtpu:/" /etc/open5gs/upf.yaml
python3 - "$CORE_IP" "$MCC" "$MNC" "$TAC" <<'PY'
import sys, glob, re
core_ip, mcc, mnc, tac = sys.argv[1:5]
# Rebind the addresses that matter for the lab: NGAP (AMF) and GTP-U (UPF).
def patch(path, repls):
    try:
        s = open(path).read()
    except FileNotFoundError:
        return
    for pat, rep in repls:
        s, n = re.subn(pat, rep, s)
        if n == 0:
            print(f"[core] WARNING: pattern did not match in {path}: {pat}")
    open(path, "w").write(s)

# "- address: X" under ngap/gtpu server blocks -- the leading "- " list-item
# marker is not whitespace, so it must be matched explicitly or the regex
# silently no-ops (re.sub does not raise on zero matches).
patch("/etc/open5gs/amf.yaml", [
    (r"(ngap:\s*\n(?:.*\n)*?\s*-\s*address:\s*)[0-9.]+", r"\g<1>"+core_ip),
])
patch("/etc/open5gs/upf.yaml", [
    (r"(gtpu:\s*\n(?:.*\n)*?\s*-\s*address:\s*)[0-9.]+", r"\g<1>"+core_ip),
])
print(f"[core] bound NGAP+GTP-U to {core_ip} (PLMN {mcc}/{mnc} TAC {tac})")
PY

# --- start the NFs; UPF needs the TUN device ---
mkdir -p /dev/net || true
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200 || true
fi

# --- UE data path: give the UPF's TUN device the UE-pool gateway address and
# NAT the pool out of eth0. Outside a container the packaged systemd-networkd
# unit does this; here nothing does, and without it the UPF decapsulates
# uplink GTP-U and then fails ogs_tun_write(), so no UE packet reaches the
# data network and no reply comes back.
UE_SUBNET="${UE_SUBNET:-10.45.0.0/16}"
UE_GW="${UE_GW:-10.45.0.1/16}"
ip tuntap add name ogstun mode tun 2>/dev/null || true
ip addr replace "${UE_GW}" dev ogstun
ip link set ogstun up
iptables -t nat -C POSTROUTING -s "${UE_SUBNET}" ! -o ogstun -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "${UE_SUBNET}" ! -o ogstun -j MASQUERADE
echo "[core] ogstun ${UE_GW} up, NAT for ${UE_SUBNET}"

echo "[core] starting NFs"
open5gs-nrfd  & sleep 1
open5gs-scpd  & sleep 1
open5gs-ausfd & open5gs-udmd & open5gs-udrd & open5gs-pcfd & open5gs-bsfd & open5gs-nssfd &
sleep 1
open5gs-upfd  & sleep 1
open5gs-smfd  & sleep 1
open5gs-amfd  &

echo "[core] all NFs launched; tailing logs"
tail -F /var/log/open5gs/*.log 2>/dev/null || sleep infinity
