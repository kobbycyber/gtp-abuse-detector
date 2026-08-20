# GTP-U Abuse Lab: complete setup guide (start from nothing)

This guide takes a person with no prior knowledge of 5G, Docker, or Python from
a fresh Linux box to a working GTP-U abuse-detection lab. Every command is
copy-paste. After each important step there is a "You should see" checkpoint so
you always know whether it worked.

There are two ways to run this project, and you do not need both:

- Offline path: pure Python and Scapy. No Docker, no root, no 5G core. It
  produces the research numbers and always works. Start here. (~5 minutes.)
- Live path: a real (simulated) 5G core and radio in Docker, with the detector
  tapping live traffic. It is heavier, but it proves the detector works on the
  wire. (~20 minutes, mostly downloads.)

If you only have 5 minutes, do Part 3 and Part 4 and stop. That is enough to
reproduce the headline results.

---

## Part 0: what this project is, the gap it fills, and what was solved

The one-sentence version: mobile networks carry all subscriber data inside
"GTP-U" tunnels on a link called N3 (between the radio and the core). If an
attacker can inject packets onto N3, they can hide a second tunnel inside the
first, smuggle control-plane messages, spoof tunnel IDs, or aim traffic at
internal core systems. Commercial "GTP firewalls" detect this, but they are
closed black boxes. This project is an open, reproducible detector for that
abuse, plus a lab to prove it works.

### The gap

1. No open, reproducible tooling existed that combines (a) a real 5G core, (b) a
   traffic generator for GTP-U abuse, and (c) a passive detector, all runnable
   and measurable by anyone. Prior work is either closed commercial appliances
   or papers with no runnable code.
2. A subtle detection trap. The most dangerous abuse, a GTP tunnel nested inside
   another GTP tunnel ("GTP-in-GTP"), is invisible to the obvious detector. The
   standard packet-parsing library (Scapy) hands you the inner payload as opaque
   bytes, so a naive `haslayer()` check misses 100% of real nested tunnels while
   still passing in-memory unit tests. You only catch it if you actively
   re-parse the raw bytes.

### What was solved (this is the contribution)

- A four-rule passive detector (`detector/rules.py`) that catches GTP-in-GTP
  (R1), TEID spoofing (R2), control-plane smuggling (R3), and inner-traffic-to-
  core (R4).
- The re-parse fix for R1, plus hardening so it does not false-positive on
  legitimate non-IP payloads (5G "Unstructured" sessions).
- A rigorous, honest evaluation rather than a single self-congratulatory score.
  It includes:
  - a realistic benign corpus of 11 traffic types (TLS, DNS, QUIC, IPv6,
    fragments, handovers, and more) so the false-positive rate actually means
    something;
  - a naive-baseline comparison that proves the contribution: the naive detector
    scores 0% recall on GTP-in-GTP where this one scores 100%;
  - a false-positive ablation showing every residual false alarm comes from
    legitimate handovers, and a mitigation (a known-gNB allowlist) that removes
    them;
  - an evasion suite that documents, honestly, which attacks the detector
    catches and which are inherent blind spots.
- Five real deployment bugs found and fixed by actually running the live lab (a
  missing dependency that hung bring-up forever, a config-patch that silently
  did nothing, a lost file permission, a traffic generator emitting malformed
  frames, and a Docker networking trap). These are documented in
  `paper/FINDINGS.md`. They are a case study in why "passes every test" is not
  the same as "works on the wire".

You do not need to understand all of this to run the lab. Come back to it after
you have seen the numbers.

---

## Part 1: what you need

- A computer running Linux (this guide assumes Ubuntu 22.04 or 24.04; other
  distros work with equivalent package commands).
  - The offline path also works on a laptop, a VM, or WSL2.
  - The live path needs a real Linux kernel with `/dev/net/tun` (any normal
    Ubuntu install or VM has this; some restricted containers do not).
- `sudo` / administrator access to install software.
- An internet connection (to download packages and container images).
- ~5 GB free disk for the live path.

Check your basics:

```bash
uname -a           # should print "Linux ... x86_64"
whoami             # your username
sudo echo ok       # should print "ok" (confirms you have sudo)
```

---

## Part 2: install the prerequisites

### 2a. Base tools (needed for everything)

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-pip python3-venv
```

**You should see** the commands finish without red `E:` errors. Verify:

```bash
git --version        # e.g. git version 2.43.0
python3 --version    # e.g. Python 3.10.12 or newer
```

### 2b. Docker (live path only; skip for offline)

Install Docker Engine and the Compose plugin using Docker's official script:

```bash
curl -fsSL https://get.docker.com | sudo sh
```

Let your user run Docker without `sudo` every time:

```bash
sudo usermod -aG docker "$USER"
newgrp docker        # applies the new group to THIS shell immediately
```

**You should see** both of these print versions:

```bash
docker --version                 # e.g. Docker version 27.x
docker compose version           # e.g. Docker Compose version v2.x
```

Confirm the Docker service is running and `/dev/net/tun` exists (the 5G stack
needs it):

```bash
docker info >/dev/null && echo "docker daemon OK"
test -e /dev/net/tun && echo "tun OK"
```

> If `docker info` fails with a permission error, close and reopen your
> terminal (so the `docker` group takes effect) and try again.

---

## Part 3: get the code

```bash
cd ~
git clone https://github.com/kobbycyber/gtpu-abuse-lab.git
cd gtpu-abuse-lab
git checkout v1.0          # the tested, released version this guide describes
```

**You should see** the project files:

```bash
ls
# attacker  captures  core  detector  docs  eval  Makefile  paper  ran  README.md  SETUP.md  viz ...
```

---

## Part 4: offline path (recommended first; no Docker, no root)

This is the path that produces the research numbers.

### 4a. Install the two Python libraries

```bash
pip3 install scapy pytest
```

(If `pip3` warns about a "managed environment", use a virtualenv instead:
`python3 -m venv .venv && source .venv/bin/activate && pip install scapy pytest`.)

### 4b. Run the test suite

```bash
make test
```

**You should see:**

```
16 passed
```

That means: every attack class is detected, the realistic benign traffic stays
clean, all 11 evasion cases behave exactly as documented, and the naive
baseline provably misses GTP-in-GTP.

### 4c. Run the full evaluation

```bash
make eval
```

**You should see** a summary ending roughly like:

```
[+] robust : P=1.0 R=1.0 F1=1.0 FPR=0.0
[+] naive  : P=1.0 R=0.8 F1=0.8889  (R1 recall 0.0)
[+] evasions: 6 caught, 5 documented blind spots, 0 mismatches
```

### 4d. Read the results

```bash
cat eval/RESULTS.md      # or open it in any text editor
```

This is the full, thesis-ready results document: headline metrics, stability
across five random seeds, the naive-vs-robust comparison, the false-positive
ablation, and the evasion table. This is the core deliverable; at this point you
are done with the minimum path.

### 4e. (Optional) look at the moving parts

```bash
make evasions                              # list every crafted evasion + verdict
python3 attacker/generate_attacks.py --class gtp_in_gtp   # print one attack packet
python3 attacker/benign_traffic.py --count 40            # show the benign traffic mix
```

---

## Part 5: live path (real 5G stack in Docker)

This brings up a real Open5GS 5G core and a UERANSIM simulated radio/phone, then
taps the live traffic with the detector. Everything runs in an isolated private
network (`10.10.10.0/24`) using a test mobile network code (`999/70`). It never
touches a real operator.

### 5a. Build the container images (first time only, ~10 to 15 min of downloads)

```bash
make build
```

**You should see** it end with:

```
 Image gtpu-abuse-lab-ran Built
 Image gtpu-abuse-lab-core Built
 Image gtpu-abuse-lab-detector Built
```

### 5b. Start the lab

```bash
make lab-up
```

This starts four containers: `mongo` (database), `core` (5G core), `ran`
(radio + phone), `detector` (the tap).

### 5c. IMPORTANT: the one manual step everyone hits

The simulated radio (`ran`) tries to connect to the core once at startup. On a
fresh boot it usually starts a second or two before the core is ready, gets
"connection refused", and by design of the UERANSIM software it does not retry.
This is expected. The fix is to restart the radio once the core is up:

```bash
sleep 20            # give the core time to finish starting
docker compose restart ran
```

> This is documented as Finding 5 in `paper/FINDINGS.md`. It is not a bug in
> this project; it is how the upstream radio simulator behaves. Always
> `restart ran` after the core is healthy.

### 5d. Confirm the phone registered and got a data session

Watch the radio's log:

```bash
docker compose logs ran | grep -iE "NG Setup|Registration|PDU Session|uesimtun0"
```

**You should see** these four lines (the full 5G attach sequence):

```
[ngap] NG Setup procedure is successful
[nas]  Initial Registration is successful
[nas]  PDU Session establishment is successful PSI[1]
[app]  Connection setup for PDU session[1] is successful, TUN interface[uesimtun0, 10.45.0.2] is up.
```

The phone now has IP `10.45.0.2` and a working tunnel.

### 5e. Prove real data flows through the tunnel

```bash
docker compose exec ran ./build/nr-binder 10.45.0.2 ping -c3 8.8.8.8
```

**You should see** `0% packet loss` (you may also see harmless `DUP!` lines, an
artifact of the virtual network, safe to ignore). This confirms real traffic
went phone, radio, N3/GTP-U, core, internet, and back.

### 5f. Fire the attack traffic and watch the detector catch it

In one terminal, follow the detector:

```bash
make logs        # this streams the detector's findings; leave it running
```

In a second terminal (same folder), fire the attack corpus:

```bash
cd ~/gtpu-abuse-lab
make attack
```

> Note: `make attack` can take a couple of minutes, because Scapy resolves each
> synthetic destination before sending. That is normal.

**You should see**, in the first terminal, JSON findings streaming past, e.g.:

```json
{"rule": "R1_GTP_IN_GTP", "severity": "critical", ...}
{"rule": "R2_TEID_SPOOF", "severity": "high", ...}
{"rule": "R3_CP_SMUGGLING", "severity": "critical", ...}
{"rule": "R4_INNER_TO_CORE", "severity": "high", ...}
```

All four rule types firing on real transmitted traffic is the live proof that
the detector works. The most important is `R1_GTP_IN_GTP`, the nested-tunnel
case that a naive detector misses entirely.

### 5g. The live browser dashboard

Instead of reading raw JSON, you can watch detections in a browser: a network
topology that flashes when the N3 link is attacked, live packet counters, a
per-rule tally, and a scrolling findings feed.

Start it (from the project folder, with the lab up):

```bash
python3 viz/server.py        # prints: Dashboard: http://localhost:8090
```

Then open the dashboard in a browser. Which address to use depends on where your
browser is:

| Your browser is on | Open this URL |
|---|---|
| the same machine as the lab | `http://localhost:8090` |
| a VM host reaching its guest (VMware/VirtualBox NAT) | `http://<guest-NAT-IP>:8090`, e.g. `http://192.168.112.128:8090` |
| another computer on your LAN | `http://<lab-machine-LAN-IP>:8090` |

To find the lab machine's IPs: `ip -4 addr show | grep inet`.

How it actually works (important for troubleshooting): `viz/server.py` is a
plain Python process that runs on the host, not inside a container. It binds to
`0.0.0.0:8090`, meaning all network interfaces, and it works by tailing the
detector container's log (`docker logs -f`) and re-publishing each JSON line to
the browser over Server-Sent Events. Because it binds `0.0.0.0`, it is reachable
on every IP the host has, with no firewall rule or port-forward needed. Verify
the listener any time with:

```bash
ss -tlnp | grep :8090        # LISTEN 0.0.0.0:8090  ->  reachable on all IPs
```

"Waiting for detector" on the page is normal and means one of two things: the
lab is not up yet, or you started the browser before the detector container
existed. The server retries resolving the detector every few seconds, so the
page comes alive on its own once the lab is running, and you do not need to
reload. To make packets actually flow, fire an attack (Part 5f): the packet
counters climb on every 2-second heartbeat and findings scroll in as they are
decoded.

If you cannot reach `http://<ip>:8090`, it is almost always because the server
is not running (start `python3 viz/server.py`). It is not a container or
firewall issue, since the server lives on the host and binds all interfaces. On
a VM, also remember that a NAT IP (e.g. `192.168.112.x`) is reachable from the
VM and its host, but not from other physical machines on your real LAN. For
those, use the lab machine's bridged or real-LAN IP instead.

### 5h. Shut the lab down

```bash
make lab-down       # stop and remove the containers
# or, to also wipe the database/volumes:
docker compose down -v
# stop the dashboard (if running) with Ctrl-C in its terminal, or:
pkill -f viz/server.py
```

---

## Part 6: success checklist

You have fully reproduced the project if:

- [ ] `make test` gives **16 passed**
- [ ] `make eval` gives **P=1.0 R=1.0 F1=1.0 FPR=0.0**, and naive **R1 recall 0.0**
- [ ] `eval/RESULTS.md` shows the baseline comparison, ablation, and evasion tables
- [ ] (live) the radio log shows NG Setup, Registration, PDU Session, and uesimtun0
- [ ] (live) the tunnel ping shows **0% packet loss**
- [ ] (live) `make attack` makes the detector emit R1 to R4 findings
- [ ] (live) the dashboard at `http://<ip>:8090` leaves "waiting for detector" and shows counters climbing and findings scrolling during an attack

---

## Part 7: troubleshooting

| Symptom | Cause and fix |
|---|---|
| `docker: permission denied` | You are not in the `docker` group yet. Run `newgrp docker`, or log out and back in. |
| `ran` log shows `Connection refused` / `Cell selection failure` | The startup race in Part 5c. Run `docker compose restart ran` after the core is up. This is normal, not a failure. |
| No `uesimtun0` / registration fails | The subscriber keys must match: `ran/ue.yaml` `key`/`op` must equal `.env` `KI`/`OPC`, and `supi` must be `imsi-<IMSI>`. The defaults already match; only an edit breaks this. |
| `make attack` seems to hang | Expected. Scapy resolves each destination before sending, which can take a couple of minutes. Watch `make logs` to see findings arrive. |
| detector shows only heartbeats, no findings | It only speaks up for abuse; benign traffic is silent by design. Run `make attack` to generate findings. |
| Dashboard unreachable at `http://<ip>:8090` | The server is not running. Start `python3 viz/server.py` from the project folder. It binds `0.0.0.0` (all interfaces), so it is not a container or firewall issue. Confirm with `ss -tlnp \| grep :8090`. |
| Dashboard stuck on "waiting for detector" | The lab is not up, or the detector container does not exist yet. Bring the lab up (Part 5b to 5c); the page recovers on its own. |
| Dashboard reachable on the VM but not from another PC | A NAT IP (`192.168.112.x`) only reaches the VM and its host. From other machines use the lab's bridged/real-LAN IP. |
| `pip3 install` refuses ("externally managed") | Use a virtualenv: `python3 -m venv .venv && source .venv/bin/activate && pip install scapy pytest`. |
| `Cannot pull base images` | Pre-pull them: `docker pull mongo:7 ; docker pull ubuntu:22.04 ; docker pull python:3.12-slim`. |
| `/dev/net/tun` missing | You are in a restricted environment. Use the offline path (Part 4), which needs none of this. |

---

## Part 8: where everything lives

| Path | What it is |
|---|---|
| `detector/rules.py` | The four detection rules, the main contribution |
| `detector/baselines.py` | The naive detector, used to prove the contribution |
| `detector/gtpu_detector.py` | The runnable detector (live sniff or offline replay) |
| `attacker/generate_attacks.py` | The GTP-U abuse traffic generator (lab-only) |
| `attacker/benign_traffic.py` | The realistic 11-category benign traffic generator |
| `attacker/evasions.py` | The crafted evasion suite |
| `eval/benchmark.py` | The full evaluation harness (`make eval` runs this) |
| `eval/RESULTS.md` | The generated results document |
| `viz/server.py` + `viz/index.html` | The live browser dashboard (host process + page) |
| `paper/PAPER.md` | The full research write-up |
| `paper/FINDINGS.md` | The five deployment bugs, with root-cause analysis |
| `docs/ARCHITECTURE.md` | How the pieces fit together and why |
| `docs/LAB_GUIDE.md` | A shorter operator-oriented lab reference |

---

## Part 9: the detection, explained (reference)

You can run everything above without this section, but here is what each piece
actually means, so the project is fully self-contained in this one file.

### 9.1 How the detector is positioned

The detector is a passive tap: it only observes the N3 link (gNB to core) and
raises findings. It never blocks or alters traffic. In the live lab it runs
inside the core's own network namespace (`network_mode: service:core` in
`docker-compose.yml`) so it sees the exact packets arriving at the UPF, the same
place a production GTP firewall sits. It reads packets with Scapy, runs four
rules over each one, and prints a JSON finding per hit.

### 9.2 The four rules (`detector/rules.py`)

| ID | Name | Severity | What it catches |
|---|---|---|---|
| R1 | `GTP_IN_GTP` | critical | A second GTP header nested inside the GTP-U payload (a tunnel hidden inside a tunnel). |
| R2 | `TEID_SPOOF` | high | A tunnel ID (TEID) first seen from one gNB IP now arriving from a different IP (a rogue reusing a victim's tunnel). |
| R3 | `CP_SMUGGLING` | critical | A control-plane protocol (PFCP/GTP-C/SCTP-NGAP) carried inside user-plane GTP-U, where only user data belongs. |
| R4 | `INNER_TO_CORE` | high | An inner packet addressed to a core system (UPF/SMF/AMF) instead of the external internet. |

Why R1 is the headline. When Scapy parses a GTP-U packet it decides how to read
the inner payload by looking at the first 4 bits: `4` means IPv4, `6` means
IPv6. A nested GTP header starts with neither, so Scapy gives up and hands you
the inner bytes as opaque `Raw`. A detector that just calls `haslayer()` misses
100% of real nested tunnels. R1 fixes this by re-reading those raw bytes as a
GTP header, but only if they pass a length-consistency check and actually carry
a routable inner IP, so it does not false-alarm on legitimate non-IP
("Unstructured") payloads. `detector/baselines.py` implements the naive version
so `make eval` can show the difference (naive R1 recall 0.0 vs robust 1.0).

R2 and handovers. A legitimate handover moves a phone between two base stations:
the tunnel ID stays the same but the source IP changes, which looks exactly like
a spoof. Supplying the operator's known base-station IPs (`--gnb-ips`) tells R2
to treat a change between known gNBs as a handover and stay quiet, while still
flagging a tunnel re-sourced from an unknown IP.

### 9.3 The traffic (`attacker/`)

- `generate_attacks.py` builds the five abuse classes: `gtp_in_gtp`,
  `teid_spoof`, `pfcp_smuggle`, `ngap_smuggle`, `inner_to_core`, plus a trivial
  benign class. It can write a labelled pcap (`--write`) or send live
  (`--send`). Everything is seeded for byte-for-byte reproducibility.
- `benign_traffic.py` builds the realistic benign corpus: eleven traffic types
  (TLS, HTTP, DNS, QUIC, NTP, RTP/VoIP, ICMP, IPv6, fragmented IP, IP-options,
  plus the two deliberately hard ones: Unstructured-PDU bytes and legitimate
  handovers). This is what makes the measured false-positive rate meaningful
  rather than a formality.
- `evasions.py` enumerates 11 crafted evasions, each tagged with whether the
  detector should catch it or whether it is an inherent blind spot of a passive
  user-plane-only rule.

### 9.4 The evaluation: how to read `eval/RESULTS.md`

`make eval` runs `eval/benchmark.py` and writes `eval/RESULTS.md`. Its sections:

1. Headline classification: precision, recall, F1, and false-positive rate on
   the realistic mixed corpus. Target: all 1.0, FPR 0.0.
2. Stability across seeds: the same metrics over five random seeds; mean should
   be 1.0 with standard deviation 0, i.e. not a lucky corpus.
3. Naive-baseline comparison: per-attack-class recall for the robust vs the
   naive detector. The important cell is `gtp_in_gtp`: robust 1.0, naive 0.0.
   This is the contribution, quantified.
4. False-positive ablation: with vs without the known-gNB allowlist. Shows every
   residual false alarm comes from legitimate handovers, and that the allowlist
   removes them.
5. Evasion suite: 6 caught, 5 documented blind spots, 0 surprises.
6. Latency and throughput: per-packet cost and single-core packet rate.

An examiner's natural questions ("did you test realistic benign traffic?", "what
does a naive detector score?", "what are the false positives?", "what can evade
it?") are each answered by one of these sections on purpose.

### 9.5 The five deployment findings (`paper/FINDINGS.md`)

Bringing the live lab up for the first time exposed five real bugs that the
offline tests structurally could not catch: a missing `mongosh` dependency
(bring-up hung forever), a config-patch regex that silently did nothing while
logging success, a lost executable bit, a traffic sender emitting malformed
Ethernet frames, and a Docker-networking trap where recreating the core orphans
the detector. They are written up as a case study in why "passes every test" is
not the same as "works on the wire": the same lesson as R1, one layer down in
deployment. If your live bring-up misbehaves, read this file first.

---

## Part 10: command cheat-sheet

```bash
# --- offline (no Docker/root) ---
make test            # 16 unit tests
make eval            # full benchmark -> eval/RESULTS.md
make evasions        # list the evasion suite and verdicts
cat eval/RESULTS.md  # read the results

# --- live lab (Docker) ---
make build           # build images (first time only)
make lab-up          # start mongo + core + ran + detector
sleep 20 && docker compose restart ran   # REQUIRED: fix the startup race
make logs            # follow detector findings
make attack          # fire the abuse corpus at the lab
python3 viz/server.py    # dashboard at http://<ip>:8090
make lab-down        # stop the lab   (docker compose down -v to wipe volumes)

# --- prove real tunnel traffic ---
docker compose exec ran ./build/nr-binder 10.45.0.2 ping -c3 8.8.8.8
```

---

Safety and ethics. Everything here runs on a private lab network with a test
mobile-network code. The attack generator exists only to exercise the detector
in this lab. Never point it at any network you are not authorised to test.
Generating GTP-U abuse against a live operator is illegal in most countries.
