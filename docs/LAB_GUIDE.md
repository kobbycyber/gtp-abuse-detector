# Lab guide

## Prerequisites (live path)

- A Linux host with a real kernel; Ubuntu 22.04 is ideal.
- `docker` + `docker compose` plugin.
- `/dev/net/tun` present (default on Ubuntu). The core and RAN containers get
  `NET_ADMIN` and the tun device via compose.

## Bring-up sequence

```bash
# optional: edit PLMN / keys directly in .env (keep ran/ue.yaml key/op in step with KI/OPC)
make build
make lab-up
make logs
```

Healthy signs:
- `core` logs show each NF starting and the subscriber being registered.
- `core` logs show `[core] ogstun 10.45.0.1/16 up, NAT for 10.45.0.0/16` and no
  `ogs_tun_write() failed` lines.
- `ran` logs show `NG Setup procedure is successful` then a UE registration and a PDU session,
  and a `uesimtun0` interface with a `10.45.0.x` address.
- `detector` prints a JSON heartbeat line every two seconds (with a running
  `packets_seen`) and a JSON finding line only when abuse is present; benign
  traffic raises no findings.

Generate user traffic (proves N3 is live), from inside the RAN container:

```bash
docker compose exec ran ping -I uesimtun0 -c3 8.8.8.8
```

The uplink leaves the gNB as GTP-U (10.10.10.20 to the UPF at 10.10.10.10), the
UPF writes the inner packet to `ogstun`, the core's NAT rule (added by
`core/entrypoint.sh`) masquerades it out, and the replies come back as downlink
GTP-U. The detector counts these packets and raises no
findings. `(DUP!)` replies can appear; they come from the host's own network,
not from the lab. An older version of this check used `./build/nr-binder`. It
still got replies, but `nr-binder` preloads `./libdevbnd.so` by a relative
path, and run from `/ueransim` the loader cannot find it: it prints
`ERROR: ld.so: object './libdevbnd.so' from LD_PRELOAD cannot be preloaded`
and runs `ping` unbound, so the ping left `eth0` without ever entering the
tunnel.

Fire abuse and watch detections:

```bash
make attack
make logs
```

The attacker shares the core's network namespace. It is not a UE and holds no
PDU session: it writes crafted GTP-U with a raw socket onto the core's `eth0`
(the N3 interface), addressed to the UPF. The run sends 500 packets (400
malicious, 100 benign, seed 1337) and takes about 17 minutes. Scapy prints
`MAC address to reach destination not found. Using broadcast.` and sends each
frame as a broadcast; this is expected. The detector should report 550
findings: R1 82, R2 88, R3 150, R4 230 (608 before the R2 ownership fix, when R2
gave 146). Findings exceed malicious packets because rules overlap: every PFCP
and NGAP smuggling packet raises both R3 and R4.

To score the same corpus per packet against its labels, without Docker:

```bash
make live-score
```

It writes `captures/live_corpus.pcap` and its labels, then scores them. Expect
precision, recall and F1 1.0 with FPR 0.0. Before the R2 fix the same corpus
scored 16 false positives and 15 false negatives.

## Offline path (always works)

```bash
make test
make eval
cat eval/RESULTS.md
```

Vary the corpus:

```bash
python3 eval/run_eval.py --seeds 1337,1,2 --benign 1000 --per-class 200
python3 attacker/generate_attacks.py --classes gtp_in_gtp,pfcp_smuggle --count 1000 --benign 1000 \
    --write captures/custom.pcap --labels-out captures/custom.labels.json
python3 attacker/generate_attacks.py --class ngap_smuggle   # inspect one packet
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ran` never reaches NG Setup | AMF address mismatch — check `AMF_IP` in `.env` and that `core` is up (`docker compose logs core`, look for `[core] all NFs launched`). |
| No `uesimtun0` on UE | subscriber keys differ — `ue.yaml` `key/op` must equal `.env` `KI/OPC`, and `supi` must equal `imsi-<IMSI>`. |
| UPF fails to start | `/dev/net/tun` missing or no `NET_ADMIN`; both are set in compose — confirm the host exposes tun. |
| UE ping gets no replies, or `core` logs `ogs_tun_write() failed` | the UPF's `ogstun` has no address or is down. `core/entrypoint.sh` gives it 10.45.0.1/16, brings it up and adds the NAT rule; rebuild (`make build`) and bring the lab up again if the core image predates that. |
| detector sees nothing on live | it must share the core netns (`network_mode: service:core`) and sniff `eth0`; benign traffic legitimately produces no findings. |
| Open5GS config schema changed | pin known-good YAMLs into `core/configs/` and mount them over `/etc/open5gs`. |
| Can't pull base images | pull `mongo:7`, `ubuntu:22.04`, `python:3.12-slim` on the host first, or mirror them. |

## Suggested experiments for the thesis

1. **Detection completeness** — per-class recall as corpus size scales.
2. **False positives under load** — replay a long benign-only capture; confirm FPR stays 0.
3. **Latency vs. throughput** — mean/p95 latency across packet sizes and rule counts.
4. **Robustness** — fragmented / malformed GTP-U; the detector must never crash (see
   `test_detector_survives_garbage`).
5. **Live vs. offline parity** — compare live `make attack` findings with
   `make live-score`, which writes and scores the identical corpus offline. On
   both live runs, all 608 findings before the R2 fix and all 550 after it, the
   live stream matched the offline pass in order and content (rule, source,
   destination, TEID, detail).
