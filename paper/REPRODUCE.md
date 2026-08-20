# Manual Reproduction Guide

This document gives the exact, manual, command-by-command procedure to reproduce
every result in `PAPER.md` and `RESULTS.md` from a clean checkout of
`gtpu-abuse-lab`. It intentionally does **not** rely on `make` targets — every
command is spelled out so you can see (and adapt) exactly what runs. `make` is
still the fast path day-to-day (`make test`, `make eval`, `make build`,
`make lab-up`, `make attack`); this guide exists so results are reproducible
even without trusting the Makefile as a black box, and so every operational
gotcha we hit is written down in one place.

All commands assume your shell is at the repo root:
`cd gtpu-abuse-lab`

---

## Part A — Offline path (no Docker, no root, ~2 minutes)

This is the path that produces reproducible thesis-grade numbers. It needs
only Python 3 + two pip packages.

### A.1 Install dependencies

```bash
python3 --version          # tested on 3.10.12; anything 3.9+ should work
sudo apt install -y python3-pip python3-venv     # if pip/venv are missing
pip3 install scapy pytest                         # or: python3 -m pip install --user scapy pytest
```

On this host, `apt install python3-scapy python3-pytest` was used instead of
pip, which installs **scapy 2.4.4** system-wide (vs. `scapy==2.7.0` pinned in
`detector/requirements.txt` for the Docker images — see `RESULTS.md` §5 for
why this version gap matters and why both were verified independently).

### A.2 Run the unit tests

```bash
cd detector
python3 -m pytest tests/ -q
cd ..
```

Expected: `19 passed` across five files. Every abuse class (`R1`–`R4`) is
detected, `test_detector_survives_garbage` confirms a malformed GTP-U packet
never raises, the realistic benign corpus produces no false positives, all
eleven crafted evasions behave as documented, the naive baseline provably
misses GTP-in-GTP, and the seeded corpus is byte-reproducible.

### A.3 Run the offline benchmark

```bash
python3 eval/run_eval.py
```

This one command produces every offline number in the paper. It builds the
seeded 1,320-packet corpus (600 malicious spread evenly across the five attack
classes, plus 720 benign across twelve traffic categories and 120 legitimate
victim flows), scores it through the exact same `rules.py` engine used live,
then runs the naive-baseline comparison, the false-positive ablation, the
five-seed stability check and the evasion suite. It writes `eval/metrics.json`
and `eval/RESULTS.md`. Everything is seeded, so the classification numbers are
byte-for-byte reproducible.

### A.4 Read the results

```bash
cat eval/RESULTS.md
```

Expected: precision **1.0**, recall **1.0**, F1 **1.0**, false-positive rate
**0.0**, each stable (standard deviation 0.0) across seeds `{1337, 1, 2, 3, 4}`;
the naive baseline misses 100% of nested tunnels (F1 **0.889**); the evasion
suite reports **6 caught / 5 documented blind spots / 0 mismatches**. Latency is
host-dependent: about **686 µs**, roughly **1,450 pkt/s** single core on the
evaluation VM, timed over dissection and rule evaluation together. Regenerate it
on your own hardware before quoting it; the classification numbers do not move.

### A.5 (Optional) vary the corpus, or inspect a single packet

```bash
# Smaller/larger corpus, different seeds (args: --seeds, --benign, --per-class):
python3 eval/run_eval.py --seeds 1337,1,2 --benign 400 --per-class 200

# Print one packet of a given attack class:
python3 attacker/generate_attacks.py --class ngap_smuggle

# Write a standalone legacy pcap for manual inspection in Wireshark:
python3 attacker/generate_attacks.py --count 200 --benign 200 --seed 1337 \
    --write captures/mixed.pcap --labels-out captures/mixed.labels.json
```

---

## Part B — Live path (Docker, full 5G core + RAN, ~15–20 minutes)

Needs a Linux host with a real kernel, `/dev/net/tun`, and Docker Compose v2.
This was run on Ubuntu with `docker compose` v5.3.1.

### B.1 Docker group membership (one-time host setup)

If `docker ps` fails with `permission denied ... docker.sock`, your user isn't
in the `docker` group:

```bash
sudo usermod -aG docker "$USER"
```

Group membership changes require a new login session to take effect. Rather
than logging out, you can adopt the new group in the *current* shell with:

```bash
sg docker -c "docker ps"      # sanity check — should list containers, not error
```

Every `docker` / `docker compose` command below can be run either after a
fresh login, or prefixed with `sg docker -c "..."` in the current shell.

### B.2 Build all images

```bash
docker compose build                          # core, ran, detector (default profile)
docker compose --profile tools build attacker # attacker is profile-gated, build it too
```

Expect this to take several minutes the first time: `core` installs Open5GS
from its PPA (~2 min), `ran` compiles UERANSIM v3.2.6 from source (~2–3 min).
Subsequent builds reuse Docker layer cache and take seconds unless you touch
`entrypoint.sh`/`run.sh`/`generate_attacks.py`, in which case only the late
layers rebuild.

### B.3 Bring up the lab

```bash
docker compose up -d mongo core ran detector
```

Wait for the core to finish registering its NFs:

```bash
docker compose logs -f core
# Ctrl-C once you see: "[core] all NFs launched; tailing logs"
```

Then check the RAN completed its full bring-up sequence:

```bash
docker compose logs ran | tail -20
```

You are looking for, in order: `SCTP connection established`,
`NG Setup procedure is successful`, `Initial Registration is successful`,
`PDU Session establishment is successful`, and finally:

```
[app] [info] Connection setup for PDU session[1] is successful, TUN interface[uesimtun0, 10.45.0.x] is up.
```

If instead you see `SCTP could not connect: Connection refused` repeating
forever, `ran` started its NGAP handshake before `core`'s AMF was listening —
see **Gotcha B.5** below (this is what happened during our own first run).

### B.4 Prove N3 is carrying real user-plane traffic

```bash
docker compose exec ran ./build/nr-binder 10.45.0.2 ping -c3 8.8.8.8
```

(Use whatever `10.45.0.x` address your own `uesimtun0` line reported — it
increments on every UE re-registration.) A successful `3 packets transmitted,
3 received, 0% packet loss` proves ICMP is traversing gNB → N3/GTP-U → UPF →
data network and back, for real, through the simulated 5G stack.

### B.5 Gotcha: `network_mode: service:core` goes stale if you recreate `core`

`detector` and `attacker` both declare `network_mode: "service:core"` in
`docker-compose.yml` so they share the UPF's actual network namespace — the
realistic passive-tap point. **If you ever recreate the `core` container**
(e.g. after editing `entrypoint.sh` and rebuilding), any container still
attached to the *old* core's namespace silently breaks: its raw socket
reports `Network is down` and its interface is simply gone. `ran` similarly
needs restarting if it started its NGAP handshake before AMF was reachable.

The fix is always the same shape — after any `core` rebuild/recreate:

```bash
docker compose up -d core                          # recreate core first
# then, once core is healthy again:
docker compose up -d --force-recreate detector ran  # re-attach dependents
```

We hit this twice in our own run (once after fixing the `mongosh` bug, once
after fixing the NGAP/GTP-U bind-address regex) — see `FINDINGS.md` for the
full timeline. This is not currently automated by the Makefile; if you're
iterating on `core/`, expect to manually recreate `detector` and `ran`
afterward every time.

### B.6 Watch the detector

```bash
docker compose logs -f detector
```

It prints nothing while traffic is benign (this is by design — see
`PAPER.md` §4), and one JSON line per finding when it isn't.

### B.7 Fire the live attack corpus

```bash
docker compose run --rm attacker --send --iface eth0 \
    --count 400 --benign 100 --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20
```

You will see `WARNING: MAC address to reach destination not found. Using
broadcast.` for packets addressed to hosts with no real ARP entry (e.g.
`8.8.8.8`, benign UE-pool addresses) — this is expected and harmless; the
frames still traverse the shared namespace and reach the detector (see
`FINDINGS.md` finding #4 for why this matters and what it looked like
*before* the fix).

Then re-check the detector:

```bash
docker compose logs detector | grep '"rule"' | tail -30
```

You should see a live mix of `R1_GTP_IN_GTP`, `R2_TEID_SPOOF`,
`R3_CP_SMUGGLING`, and `R4_INNER_TO_CORE` findings, each carrying real
`src`/`dst`/`teid` values from the lab bridge.

### B.8 Tally a full run

```bash
docker compose logs detector | python3 -c '
import sys, json
from collections import Counter
c = Counter()
n = 0
for line in sys.stdin:
    line = line.split("detector-1  |", 1)[-1].strip()
    if line.startswith("{") and "\"rule\"" in line:
        try:
            d = json.loads(line); c[d["rule"]] += 1; n += 1
        except Exception:
            pass
print("total findings:", n)
for k, v in sorted(c.items()):
    print(f"  {k}: {v}")
'
```

### B.9 Tear down

```bash
docker compose down          # stop and remove containers, keep volumes
docker compose down -v       # also remove mongo-data / captures volumes
```

---

## Part C — Full offline ↔ live parity check

To confirm both paths detect the same abuse classes with the same rule
engine (not two divergent code paths):

```bash
# Offline
python3 eval/run_eval.py
cat eval/RESULTS.md

# Live (Part B above), then compare which rules fired in both runs —
# they should be the same four rule IDs, R1–R4, in both.
```

Rule-hit *counts* will not match exactly between the two runs (different
random seed / packet mix / live ARP-driven timing), but rule *coverage*
should: every class the offline corpus exercises should also appear at least
once in a live run of comparable size. See `RESULTS.md` §4 for the actual
numbers from both runs used in this paper.
