# Lab guide

## Prerequisites (live path)

- A Linux host  - a Ubuntu 22.04 is ideal.
- `docker` + `docker compose` plugin.
- `/dev/net/tun` present (default on Ubuntu). The core and RAN containers get
  `NET_ADMIN` and the tun device via compose.

## Bring-up sequence

```bash
cp .env .env.local   # optional: edit PLMN / keys
make build
make lab-up
make logs
```

Healthy signs:
- `core` logs show each NF starting and the subscriber being registered.
- `ran` logs show `NG Setup successful` then a UE registration and a PDU session,
  and a `uesimtun0` interface with a `10.45.0.x` address.
- `detector` prints JSON lines only when abuse is present (benign traffic is quiet).

Generate user traffic (proves N3 is live), from inside the RAN container:

```bash
docker compose exec ran ./build/nr-binder 10.45.0.2 ping -c3 8.8.8.8
```

Fire abuse and watch detections:

```bash
make attack
make logs
```

## Offline path (always works)

```bash
make test
make eval
cat eval/RESULTS.md
```

Vary the corpus:

```bash
python3 eval/run_eval.py --classes gtp_in_gtp,pfcp_smuggle --count 1000 --benign 1000
python3 attacker/generate_attacks.py --class ngap_smuggle   # inspect one packet
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ran` never reaches NG Setup | AMF address mismatch — check `AMF_IP` in `.env` and that `core` is up (`make logs`). |
| No `uesimtun0` on UE | subscriber keys differ — `ue.yaml` `key/op` must equal `.env` `KI/OPC`, and `supi` must equal `imsi-<IMSI>`. |
| UPF fails to start | `/dev/net/tun` missing or no `NET_ADMIN`; both are set in compose — confirm the host exposes tun. |
| detector sees nothing on live | it must share the core netns (`network_mode: service:core`) and sniff `eth0`; benign traffic legitimately produces no findings. |
| Open5GS config schema changed | pin known-good YAMLs into `core/configs/` and mount them over `/etc/open5gs`. |
| Can't pull base images | pull `mongo:7`, `ubuntu:22.04`, `python:3.12-slim` on the host first, or mirror them. |

## Suggested experiments for the thesis

1. **Detection completeness** — per-class recall as corpus size scales.
2. **False positives under load** — replay a long benign-only capture; confirm FPR stays 0.
3. **Latency vs. throughput** — mean/p95 latency across packet sizes and rule counts.
4. **Robustness** — fragmented / malformed GTP-U; the detector must never crash (see
   `test_detector_survives_garbage`).
5. **Live vs. offline parity** — compare `make eval` numbers to live `make attack` runs.
