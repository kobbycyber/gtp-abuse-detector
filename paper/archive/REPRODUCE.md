# Manual Reproduction Guide

This document gives the exact, manual, command-by-command procedure to reproduce
every result in `PAPER.md` and `RESULTS.md` from a clean checkout of
`gtp-abuse-detector`. It intentionally does **not** rely on `make` targets — every
command is spelled out so you can see (and adapt) exactly what runs. `make` is
still the fast path day-to-day (`make test`, `make eval`, `make build`,
`make lab-up`, `make attack`, `make live-score`); this guide exists so results are reproducible
even without trusting the Makefile as a black box, and so every operational
gotcha we hit is written down in one place.

All commands assume your shell is at the repo root:
`cd gtp-abuse-detector`

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

Expected: `24 passed` across five files. Every abuse class (`R1`–`R4`) is
detected, `test_detector_survives_garbage` confirms a malformed GTP-U packet
never raises, the realistic benign corpus produces no false positives, all
eleven crafted evasions behave as documented, the naive baseline provably
misses GTP-in-GTP, and the seeded corpus is byte-reproducible. Three R2 tests
cover the TEID-ownership fix: a spoofing source never takes a TEID over, a TEID
is scoped by the endpoint that receives it, and the exact corpus that
`make attack` sends scores with no false positive and no false negative.

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
suite reports **6 caught / 1 correct silence / 4 documented blind spots / 0 mismatches**. Latency is
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

## Part B — Live path (Docker, full 5G core + RAN, ~15–20 minutes, plus about 17 minutes for the attack send)

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

Earlier in the same log the core prints
`[core] ogstun 10.45.0.1/16 up, NAT for 10.45.0.0/16`. That line means the
UPF's tunnel device has its address and the UE pool is NATed out. If it is
missing, the core image predates that fix: the UPF then decapsulates uplink
GTP-U, logs `ogs_tun_write() failed` for every packet, and no UE packet reaches
the data network. Rebuild `core` (B.2) and recreate it (B.5).

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

To see the tunnel at work, start a capture on the core's N3 interface in a
second terminal first (the `core` image ships `tcpdump`):

```bash
docker compose exec core tcpdump -ni eth0 udp port 2152
```

Then send the ping out of the UE's tunnel interface:

```bash
docker compose exec ran ping -I uesimtun0 -c3 8.8.8.8
```

Expected: `3 packets transmitted, 3 received` and `0% packet loss` (the line may
also show `+N duplicates`; see the note on `(DUP!)` below). The capture
shows each echo request as uplink GTP-U from the gNB (`10.10.10.20`) to the UPF
(`10.10.10.10`), and each reply coming back as downlink GTP-U from
`10.10.10.10` to `10.10.10.20`. A second capture on the UPF's tunnel device
(`docker compose exec core tcpdump -ni ogstun icmp`) shows the decapsulated
ICMP between the UE address and `8.8.8.8`, which the core then NATs out of
`eth0`. In our run the session's uplink TEID was `0xb2aa` and its downlink TEID
`0x1`; yours can differ. The detector counts these packets (its heartbeat's
`packets_seen` rises, see B.6) and raises no finding. Together this proves ICMP
traversed UE → gNB → N3/GTP-U → UPF → data network and back through the
simulated 5G stack.

You may also see `(DUP!)` replies. They come from the host's own network (each
reply reaches the core's `eth0` more than once), not from the lab.

Do not use `docker compose exec ran ./build/nr-binder 10.45.0.2 ping -c3 8.8.8.8`,
the check earlier versions of this guide gave. It returns replies even when the
UE data path is broken. `nr-binder` works by preloading `./libdevbnd.so`, a
path relative to the current directory; run from `/ueransim`, the loader cannot
find it, prints `ERROR: ld.so: object './libdevbnd.so' from LD_PRELOAD cannot be
preloaded ... ignored.`, and runs `ping` unbound. That ping leaves `ran`'s `eth0` with source
`10.10.10.20` by the Docker default route and never touches the tunnel; a
capture on the core shows zero GTP-U while it runs. If your capture shows no
GTP-U but the ping still gets replies, the ping did not use the tunnel.

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

While traffic is benign it prints only a heartbeat line every two seconds,
carrying a running `packets_seen` count, and no findings (this is by design,
see `PAPER.md` §4). It prints one JSON line per finding when traffic is not
benign.

### B.7 Fire the live attack corpus

```bash
docker compose run --rm attacker --send --iface eth0 \
    --count 400 --benign 100 --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20
```

The `attacker` container is not a UE and holds no PDU session. It shares the
core's network namespace (`network_mode: service:core`) and writes crafted
GTP-U with a raw socket onto the core's `eth0` (the N3 interface), addressed to
the UPF. UERANSIM does not encapsulate these packets. This stands in for the
on-path position of the threat model. The corpus is the same 500 packets on
every run (seed 1337: 100 benign, 88 `teid_spoof`, 82 `gtp_in_gtp`,
80 `inner_to_core`, 79 `pfcp_smuggle`, 71 `ngap_smuggle`). Every packet uses
TEID `0x1` and outer destination `10.10.10.10`; the outer source is
`10.10.10.20` except for `teid_spoof`, which uses `10.10.10.66`.

The send takes about 17 minutes. Every packet is addressed to the UPF, and from
inside the core's own namespace Scapy cannot resolve a MAC address for that
address, so it prints `WARNING: MAC address to reach destination not found.
Using broadcast.` and sends each frame as a broadcast. This is expected and
harmless: the frames still reach `eth0` and the detector sees every one (see
`FINDINGS.md` finding #4 for why the send path matters and what it looked like
*before* that fix).

Then re-check the detector:

```bash
docker compose logs detector | grep '"rule"' | tail -30
```

You should see a live mix of `R1_GTP_IN_GTP`, `R2_TEID_SPOOF`,
`R3_CP_SMUGGLING`, and `R4_INNER_TO_CORE` findings, each carrying real
`src`/`dst`/`teid` values from the lab bridge. Every `R2_TEID_SPOOF` line should
have `"src": "10.10.10.66"`. An R2 line with `"src": "10.10.10.20"` means the
detector image predates the R2 ownership fix: it is flagging the gNB's own
packet after a spoof (see `RESULTS.md` §4.3).

### B.8 Tally a full run

```bash
docker compose logs detector | python3 -c '
import sys, json
from collections import Counter
c = Counter()
n = 0
for line in sys.stdin:
    i = line.find("{")
    if i < 0 or "\"rule\"" not in line:
        continue
    try:
        d = json.loads(line[i:]); c[d["rule"]] += 1; n += 1
    except Exception:
        pass
print("total findings:", n)
for k, v in sorted(c.items()):
    print(f"  {k}: {v}")
'
```

Expected, for one `make attack` run on a freshly started detector:

```
total findings: 550
  R1_GTP_IN_GTP: 82
  R2_TEID_SPOOF: 88
  R3_CP_SMUGGLING: 150
  R4_INNER_TO_CORE: 230
```

There are more findings than the 400 malicious packets because rules overlap:
every `pfcp_smuggle` and `ngap_smuggle` packet raises both R3 and R4, since its
inner destination is the UPF. R2 fires once per `teid_spoof` packet, and the
100 benign packets and the B.4 tunnel ping raise nothing. The log accumulates,
so a second `make attack` adds its findings to the same count. For a clean
tally, recreate the detector first
(`docker compose up -d --force-recreate detector`): that starts a new log and
empty detector state, while a plain restart keeps the old log. For comparison,
a detector image from before the R2 ownership fix gave 608 findings on the same
packets in a freshly started lab (R1 82, R2 146, R3 150, R4 230).

### B.9 Score the live corpus per packet

The live tally counts findings, not packets. To score the same 500 packets
against their labels, rebuild the identical seeded corpus with its labels and
replay it through the detector with the live settings. No Docker is needed;
`make live-score` runs exactly these two commands:

```bash
python3 attacker/generate_attacks.py --count 400 --benign 100 \
    --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20 \
    --write captures/live_corpus.pcap --labels-out captures/live_corpus.labels.json
python3 detector/gtpu_detector.py pcap --file captures/live_corpus.pcap \
    --labels captures/live_corpus.labels.json \
    --core-ips 10.10.10.10,10.10.10.11 --gnb-ips 10.10.10.20,10.10.10.21 \
    --metrics-out captures/live_corpus.metrics.json
```

It prints one line per finding, then a JSON report (also written to
`captures/live_corpus.metrics.json`). Expected, ignoring the host-dependent
`latency` block:

```
"rule_hits": {
  "R4_INNER_TO_CORE": 230,
  "R2_TEID_SPOOF": 88,
  "R1_GTP_IN_GTP": 82,
  "R3_CP_SMUGGLING": 150
},
"classification": {
  "tp": 400,
  "fp": 0,
  "fn": 0,
  "tn": 100,
  "precision": 1.0,
  "recall": 1.0,
  "f1": 1.0,
  "false_positive_rate": 0.0
}
```

The per-rule counts match the live tally in B.8. Part C shows how to check that
the two runs produce the same findings one for one.

### B.10 Tear down

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

Rule-hit *counts* will not match between `run_eval.py` and a live run (the two
corpora differ in size and composition), but rule *coverage* should: every
class the offline corpus exercises should also appear at least once in a live
run of comparable size. See `RESULTS.md` §4 for the actual numbers from both
runs used in this paper.

For the identical corpus the match is exact. After one `make attack` on a
freshly started detector (B.8) and the B.9 scoring commands, compare the live
findings with an offline pass over `captures/live_corpus.pcap`, field by field
and in order. Run this before B.10, while the detector container still exists,
because the first command reads its log:

```bash
docker compose logs detector > captures/live_detector.log
python3 detector/gtpu_detector.py pcap --file captures/live_corpus.pcap --json \
    --core-ips 10.10.10.10,10.10.10.11 --gnb-ips 10.10.10.20,10.10.10.21 \
    > captures/live_corpus.offline.log
python3 - captures/live_detector.log captures/live_corpus.offline.log <<'EOF'
import json, sys
def load(path):
    out = []
    for line in open(path):
        i = line.find("{")
        if i >= 0 and '"type": "finding"' in line:
            d = json.loads(line[i:])
            out.append((d["rule"], d["src"], d["dst"], d["teid"], d["detail"]))
    return out
live, offline = load(sys.argv[1]), load(sys.argv[2])
print("live:", len(live), "offline:", len(offline), "identical:", live == offline)
EOF
```

Expected: `live: 550 offline: 550 identical: True`. Only the timestamps differ.

---

## Part D — Cross-dissector check (the R1 blind spot is not one library's defect)

The nested-tunnel blind spot is a property of how tunnelled payloads are
dispatched, not a Scapy bug. This reproduces it against Wireshark/tshark and
Zeek from one small probe capture.

Write the probe (three GTP-U packets over one outer 5-tuple: a bare-nested
abuse packet, a benign inner-IP packet, and a control-plane-smuggle packet):

```bash
python3 attacker/dissector_probe.py --write captures/dissector_probe.pcap
```

**tshark** (Wireshark). If tshark is not installed locally, run it through a
container by prefixing the command with
`docker run --rm -v "$PWD/captures":/d nicolaka/netshoot ` and reading `/d/dissector_probe.pcap`.
All three frames are recognised as GTP-U on the outer G-PDU, but the bare-nested
frame's protocol stack **ends at that outer `gtp` layer**, while the benign and
smuggle frames continue into their inner IP:

```bash
tshark -r captures/dissector_probe.pcap -T fields \
    -e frame.number -e frame.protocols -e gtp.message
```

Expected:

```
1   eth:ethertype:ip:udp:gtp              0xff
2   eth:ethertype:ip:udp:gtp:ip:icmp      0xff
3   eth:ethertype:ip:udp:gtp:ip:udp:pfcp  0xff
```

Every frame carries `gtp.message` `0xff` (a user-data G-PDU) and matches the
`gtp` filter, so "does the frame contain a GTP-U layer" is not a sufficient
check. What marks the abuse is that frame 1's stack stops at `gtp`: its nested
inner tunnel is absorbed as an opaque T-PDU, with no second GTP layer and no
inner IP, whereas frames 2 and 3 decode their inner IP natively.

**Zeek** (run via the official container, so no local install is needed):

```bash
docker run --rm -v "$PWD/captures":/d -w /d zeek/zeek:latest \
    zeek -C -r dissector_probe.pcap
grep -c 'Tunnel::GTPv1.*DISCOVER' captures/tunnel.log     # -> 1 (the outer tunnel only)
grep -v '^#' captures/conn.log | awk '{print $3" -> "$5":"$6" ("$7")"}'
```

Expected Zeek result: exactly **one** GTPv1 tunnel (the outer one, never a
nested second tunnel); `conn.log` surfaces the inner connections of the benign
packet (ICMP to `8.8.8.8`) and the smuggle packet (UDP to `8805`) via
`tunnel_parents`, but the bare-nested packet's inner address (`10.45.0.1`)
never appears and no `weird.log` is written. Zeek's GTPv1 analyzer finds that
the decapsulated payload is neither IPv4 nor IPv6, records one analyzer
violation in `analyzer.log`, `non-IP packet in GTPv1`, and does not pass the
payload on, so no inner connection or second tunnel appears. The violation does
not identify the payload as a tunnel. Scapy, tshark and Zeek, three
independently written implementations, therefore all miss the bare-nested form,
which is the evidence behind `PAPER.md` §6.4 and manuscript Section 4.7.
