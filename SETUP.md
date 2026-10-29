# GTP-U Abuse Lab: step-by-step guide for everything

This guide starts from a fresh Linux machine and reproduces every result in the
paper, *Detecting bare-nested GTP-U tunnels that packet dissectors do not
decode* (`paper/manuscript_rev2.pdf`). Every command is copy-paste, and each
important step has a **You should see** checkpoint.

Follow the parts in order, or jump to the one you need:

| Part | What it does | Needs | Time |
|---|---|---|---|
| [1](#part-1-what-you-need) – [3](#part-3-get-the-code) | Install and get the code | Linux, internet | 10 min |
| [4](#part-4-unit-tests-and-development-benchmark) | Unit tests and development benchmark | Python only | 2 min |
| [5](#part-5-held-out-seeds) | Held-out seeds 101–110 (Table 7) | Python only | 5 min |
| [6](#part-6-processing-cost) | Per-packet cost (Fig. 6) | Python only | 1 min |
| [7](#part-7-cross-version-check-scapy-244-vs-270) | Scapy 2.4.4 vs 2.7.0 | Python only | 3 min |
| [8](#part-8-independent-data-oulu-5g-cgad) | Oulu 5G-CGAD captures (Table 12) | 8 GB disk | 2 h download + ~5 h scoring |
| [9](#part-9-zeek-suricata-and-tshark) | Zeek, Suricata, tshark (Table 10) | Docker | 10 min |
| [10](#part-10-dissector-probe) | Three-packet dissector probe | Docker | 2 min |
| [11](#part-11-live-5g-lab) | Live 5G lab, single run and three-UE runs (Table 13) | Docker, `/dev/net/tun` | 30 min + 17–30 min per run |
| [12](#part-12-figures-manuscript-and-result-files) | Figures, manuscript, result files | Python | 1 min |
| [13](#part-13-success-checklist) – [16](#part-16-how-the-detector-works) | Checklist, troubleshooting, layout, how it works | – | – |

Parts 4 to 7 need no Docker and no root, and they reproduce the core numbers.

---

## Part 0: what this project is

5G networks carry all subscriber data inside **GTP-U tunnels** on the N3 link
between the radio (gNB) and the core (UPF). GTP-U has no authentication, so a
packet placed on N3 can carry abuse: a second tunnel inside the first,
control-plane messages smuggled inside user data, a stolen tunnel ID (TEID), or
traffic aimed at internal core functions.

The main finding: Scapy, Wireshark and Zeek decide what a GTP-U data packet
(G-PDU) carries by looking at the first byte of its payload (4 = IPv4,
6 = IPv6). A second GTP-U header placed **directly** after the outer one (the
*bare-nested* form) starts with `0x3X`, so none of them decodes it, and a
detector built on them misses it silently. The *IP-wrapped* form, which an
ordinary phone can send, is decoded normally. This project's detector recovers
the payload bytes itself, after any outer extension headers, checks them
against a strict GTP plausibility gate, and raises rule **R1**. Three more
rules cover TEID re-sourcing (**R2**), control-plane smuggling (**R3**) and
inner traffic aimed at the core (**R4**).

---

## Part 1: what you need

- Linux (this guide uses Ubuntu 22.04 or 24.04). Parts 4–7 also work on a VM or WSL2.
- `sudo` access and an internet connection.
- Disk: about 1 GB for Parts 4–7, about 5 GB more for Docker (Parts 9–11), and
  about 8 GB more for the 5G-CGAD data (Part 8).
- For the live lab (Part 11): a real Linux kernel with `/dev/net/tun`. Any normal
  Ubuntu install, VM or cloud instance has one; some restricted containers do not.
  The paper's live runs used an AWS EC2 instance with 2 vCPUs and Ubuntu.

```bash
uname -a          # Linux ... x86_64
sudo echo ok      # ok
df -h ~           # check free space
```

---

## Part 2: install the prerequisites

### 2a. Base tools (everything needs these)

```bash
sudo apt-get update
sudo apt-get install -y git make curl python3 python3-pip python3-venv
```

**You should see** no `E:` errors. Check:

```bash
git --version && python3 --version      # Python 3.10 or newer
```

### 2b. Docker (Parts 9, 10 and 11 only)

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
newgrp docker                      # use the new group in this shell
docker --version && docker compose version
docker info >/dev/null && echo "docker daemon OK"
test -e /dev/net/tun && echo "tun OK"
```

If `docker info` fails with a permission error, log out and back in, then retry.

---

## Part 3: get the code

```bash
cd ~
git clone https://github.com/kobbycyber/gtp-abuse-detector.git
cd gtp-abuse-detector
python3 -m venv .venv
source .venv/bin/activate          # run this again in every new terminal
pip install scapy pytest matplotlib
```

**You should see** `Successfully installed ... scapy-2.x ...`. `make help` lists
every target used below.

All later commands are run from `~/gtp-abuse-detector` with the virtualenv active.

---

## Part 4: unit tests and development benchmark

### 4a. Unit tests

```bash
make test
```

**You should see** `25 passed`. These cover every rule, the benign corpus, the
11 evasion cases, the naive baseline, byte-for-byte reproducibility, and an
outer header with a PDU Session Container (the regression test for the
extension-header handling).

### 4b. Development benchmark (seeds 1337, 1, 2, 3, 4)

```bash
make eval
```

**You should see:**

```
[+] corpus: 1320 packets  (600 malicious / 720 benign)
[+] robust : P=1.0 R=1.0 F1=1.0 FPR=0.0
[+] naive  : P=1.0 R=0.8 F1=0.8889  (R1 recall 0.0)
[+] evasions: 6 caught, 1 correct silence, 4 documented blind spots, 0 mismatches
```

The naive baseline is the same engine without the re-parse: it misses every
bare-nested packet (R1 recall 0.0), which is Fig. 5 in the paper.

### 4c. Read the results

```bash
less eval/RESULTS.md
```

It has the headline metrics, per-class recall, the baseline comparison, the
false-positive ablation with and without the gNB allowlist, the evasion table
(paper Table 9) and timing. These seeds were used during development, so the
paper reports them for continuity only. The held-out evidence starts in Part 5.

### 4d. Optional: look at the moving parts

```bash
make evasions                                             # every evasion case and its verdict
make live-score                                           # the exact `make attack` corpus, scored per packet
python3 attacker/generate_attacks.py --class gtp_in_gtp   # print one attack packet
python3 attacker/benign_traffic.py --count 40             # show the benign mix
```

---

## Part 5: held-out seeds

Seeds 101–110 were never used while the code was being changed. The script
refuses development seeds.

```bash
make heldout
```

**You should see** (twice, once for the plain outer header and once with a
PDU Session Container on every outer header, as real N3 traffic has):

```
robust: P=1.0000 R=1.0000 FPR=0.0000 recall95=[0.9994, 1.0] fpr95=[0.0, 0.0005]
naive : P=1.0000 R=0.8000 FPR=0.0000
```

Results go to `eval/results/heldout_plain.json` and `eval/results/heldout_ext.json`.
They match `eval/results/revision2/` exactly, apart from run time. Fields to look at:

```bash
python3 -c "import json; d=json.load(open('eval/results/heldout_ext.json')); \
print(d['robust']); print(d['robust_at_risk_benign'])"
```

`robust_at_risk_benign` shows the 334 unstructured and handover packets, the only
benign packets that could plausibly fire a rule: 0 flagged, upper bound 0.0114.

**What the engine without the extension-header fix scores** (Table 7, last
engine row). The previous engine is in git history, so you can check out a
copy and run the same script against it:

```bash
git worktree add /tmp/oldengine 7c9029c
cp eval/heldout.py eval/external_eval.py /tmp/oldengine/eval/
(cd /tmp/oldengine && python3 eval/heldout.py --realistic-outer --out /tmp/old.json)
git worktree remove --force /tmp/oldengine
```

**You should see** `robust: ... R=0.8000`: all 1,200 bare-nested packets are missed.

---

## Part 6: processing cost

```bash
make latency
```

**You should see** a JSON summary with `mean_us` (a few hundred µs) and
`pkts_per_s`. Absolute values depend on the machine: the paper's development
host measured 716 µs and ~1,400 pkt/s (`eval/results/revision2/latency_local.json`),
and a 2-vCPU cloud host measured about 320 µs and ~3,100 pkt/s.

---

## Part 7: cross-version check (Scapy 2.4.4 vs 2.7.0)

This scores the same capture under two Scapy releases and compares the finding
streams.

```bash
sudo apt-get install -y python3-scapy                # Ubuntu 22.04 packages Scapy 2.4.4
python3 -m venv /tmp/s27 && /tmp/s27/bin/pip install -q scapy==2.7.0
scripts/revision2/cross_version.sh /usr/bin/python3 /tmp/s27/bin/python
```

**You should see:**

```
Scapy 2.4.4: 550 findings
Scapy 2.7.0: 550 findings
identical finding streams: True
```

Use the Ubuntu package for 2.4.4. A pip-installed 2.4.4 crashes on Python 3.10
with `liblibc.a` (an old Scapy bug unrelated to this project).

---

## Part 8: independent data (Oulu 5G-CGAD)

The 5G Core GTP-U Attack Dataset was produced by the University of Oulu on its
own testbed (30 UEs, 3 gNBs). It is licensed CC BY 4.0:
doi:10.23729/fd-b9459ea4-88a7-35c2-992e-f178a294c12d. It is not stored in this
repository; you download it.

### 8a. Download (about 6.9 GB)

```bash
make fetch-data DATA=~/5g-cgad
```

To fetch only the attack captures (~300 MB) first:

```bash
SKIP_BENIGN=1 scripts/revision2/fetch_5gcgad.sh ~/5g-cgad
```

**You should see** `downloading ...` for each archive, then `unpacking ...`, then
`done`. The benign archive stays packed (`benign_traffic.tar.xz`, 6.6 GB) because
the scorer reads it directly.

### 8b. Score

```bash
make external DATA=~/5g-cgad
```

The attack captures take about 3.5 hours and the benign archive about 2 hours
on one core. To run in the background and log out safely:

```bash
nohup make external DATA=~/5g-cgad > external.log 2>&1 &
```

Results go to `eval/results/external/oulu_*.json`.

**You should see** (compare with Table 12 and `eval/results/revision2/`):

| File | `gtpu_packets` | `flagged` | `rule_hits` |
|---|---|---|---|
| `oulu_benign.json` | 6,218,456 | 0 | – |
| `oulu_encapsulation.json` | 290,225 | 290,225 | R1, R3 |
| `oulu_malformed.json` | 353,136 | 176,903 | R2 |
| `oulu_bruteforce_gpdu.json` | 878,333 | 56,002 | R2 |
| `oulu_bruteforce_multi.json` | 10,054,554 | 123,931 | R2 |
| `oulu_intraupf.json` | 426,949 | 1 | R3 |
| `oulu_ddos.json` | 11,561,011 | 109 | R3 |

How to read it: the labels are per scenario, so the flagged fraction of an
attack capture is not a recall. The nested scenario uses the IP-wrapped form, so
the naive baseline (`naive_flagged`) catches it too. TEID brute force is not
detected; that is a documented blind spot.

---

## Part 9: Zeek, Suricata and tshark

This runs the three open tools in their official containers over one capture
per class. Nothing is installed locally.

```bash
make comparators
```

The first run pulls `zeek/zeek:8.2.2`, `jasonish/suricata` and `nicolaka/netshoot`
(about 2 GB) and downloads the ET Open ruleset.

**You should see:**

```
bare_nested          zeek violations: non-IP packet in GTPv1       suricata alerts: 0
benign               zeek violations: -                            suricata alerts: 0
inner_to_core        zeek violations: -                            suricata alerts: 0
ip_wrapped_nested    zeek violations: GTP-in-GTP                   suricata alerts: 0
ngap_smuggle         zeek violations: -                            suricata alerts: 0
pfcp_smuggle         zeek violations: -                            suricata alerts: 0
teid_spoof           zeek violations: -                            suricata alerts: 0
```

Zeek recognises only the IP-wrapped form as nested; for the bare form it reports
only that the payload is "non-IP". Suricata has no GTP-U decoder and raises
nothing. Per-class outputs land in `comparators/<class>/`: Zeek's `conn.log`,
`tunnel.log` and `analyzer.log`; Suricata's `fast.log` and `eve.json`; and
`tshark.txt`, where the bare-nested packets stop at `...:udp:gtp`.

---

## Part 10: dissector probe

A three-packet capture shows the blind spot in one screen: frame 1 is bare-nested,
frame 2 is ordinary user data, and frame 3 smuggles PFCP. The committed
`captures/dissector_probe.pcap` is the probe; to regenerate it, run
`python3 attacker/dissector_probe.py --write captures/dissector_probe.pcap`.

```bash
docker run --rm -v "$PWD/captures":/d nicolaka/netshoot \
  tshark -r /d/dissector_probe.pcap -T fields -e frame.number -e frame.protocols -e gtp.message
```

**You should see:**

```
1   eth:ethertype:ip:udp:gtp              0xff
2   eth:ethertype:ip:udp:gtp:ip:icmp      0xff
3   eth:ethertype:ip:udp:gtp:ip:udp:pfcp  0xff
```

Frame 1 stops at the outer `gtp`: the nested tunnel is shown as opaque T-PDU data.

```bash
mkdir -p /tmp/zk && cp captures/dissector_probe.pcap /tmp/zk/
docker run --rm -v /tmp/zk:/d -w /d zeek/zeek:8.2.2 zeek -C -r dissector_probe.pcap
grep -v '^#' /tmp/zk/analyzer.log | cut -f 11      # non-IP packet in GTPv1
grep -v '^#' /tmp/zk/tunnel.log | wc -l            # 1  (the outer tunnel only)
```

The source-code lines behind this behaviour, in Scapy, Wireshark 4.6.6 and Zeek
8.2.2, are listed in `eval/results/revision2/dissector_sources.md`.

---

## Part 11: live 5G lab

This brings up a real Open5GS core and UERANSIM radio and phones on a private
network (`10.10.10.0/24`, test PLMN `999/70`). The detector taps N3 inside the
core's network namespace. The attacker container is not a phone: it writes
crafted GTP-U onto N3 with a raw socket, standing in for an on-path attacker.

### 11a. Choose the number of phones

Edit `.env`. Use 1 for the single-run walkthrough, or 3 to repeat the paper's
live runs:

```bash
sed -i 's/^UE_COUNT=.*/UE_COUNT=3/' .env
grep UE_COUNT .env
```

Compose reads this file. Setting `UE_COUNT` in your shell has no effect.

### 11b. Build the images (first time, 10–15 min)

```bash
make build
```

**You should see** `Image gtp-abuse-detector-core Built` (and ran, detector, attacker).

### 11c. Start the lab and fix the radio start-up race

```bash
make lab-up
sleep 20 && docker compose restart ran
```

The radio connects to the core once at start-up. If the core is not ready yet,
it does not retry, so one restart is always needed. `scripts/lab_up.sh` does
both steps for you.

### 11d. Confirm the phones registered

```bash
docker compose logs ran | grep -iE "NG Setup|Registration is successful|uesimtun"
```

**You should see** `NG Setup procedure is successful`, then one
`Initial Registration is successful` and one `TUN interface[uesimtunN, 10.45.0.x] is up`
per phone.

### 11e. Prove real traffic flows through each tunnel

```bash
for i in 0 1 2; do docker compose exec ran ping -I uesimtun$i -c2 8.8.8.8 | tail -2; done
```

**You should see** `0% packet loss` for each phone (only `uesimtun0` with one
phone). `-I uesimtunN` makes the ping go through the phone's tunnel. `(DUP!)`
replies come from the host network and are harmless.

### 11f. Single attack run (the original 500-packet sequence)

Terminal 1:

```bash
make logs
```

Terminal 2:

```bash
make attack           # ~17 minutes for 500 packets
```

The attacker prints `MAC address to reach destination not found. Using broadcast.`
for each packet. That is expected and slow, but every packet arrives. When it
finishes:

```bash
docker compose logs detector | grep -o '"rule": "R[1-4]_[A-Z_]*"' | sort | uniq -c
make live-score       # same 500 packets from a file, scored per packet
```

**You should see** 550 findings (R1 82, R2 88, R3 150, R4 230), and
`live-score` reports `"tp": 400, "fp": 0, "fn": 0, "tn": 100`. These counts
assume a freshly started detector; a second `make attack` adds to the log.

### 11g. Labelled live runs with real UE traffic (paper Table 13)

With `UE_COUNT=3`, this reproduces the two held-out live runs. Each run pings
through all three tunnels during the attack, saves the live findings, rebuilds
the same sequence offline with labels, and compares the two:

```bash
make live-run TAG=L1 SEED=2026 TEID=0x2 COUNT=400 BENIGN=100     # ~17 min
make live-run TAG=L2 SEED=4242 TEID=0x7 COUNT=600 BENIGN=200     # ~27 min
```

**You should see**, at the end of each run:

```
live 565 findings, offline 565, identical: True        # L1
live 853 findings, offline 853, identical: True        # L2
```

The scores are in `eval/results/live/<TAG>/offline_metrics.json`: L1 has
precision and recall 1.0; L2 has recall 0.9967, because its first two packets are
re-sourcing packets sent before the real gNB used that TEID (R2 binds a TEID to
the first source it sees; the paper discusses this). `bg_ping.txt` shows the
real phone traffic that ran alongside. For a quick test, use small numbers such
as `make live-run TAG=T SEED=777 TEID=0x3 COUNT=20 BENIGN=10` (about 2 minutes).

### 11h. Live dashboard (optional)

```bash
python3 viz/server.py     # Dashboard: http://localhost:8090
```

Open `http://localhost:8090` on the same machine, or `http://<machine-IP>:8090`
from another one. It tails the detector log and shows the topology, counters,
per-rule totals and a findings feed. "Waiting for detector" means the lab is not
up yet; the page recovers on its own.

### 11i. Shut down

```bash
make lab-down              # or: docker compose down -v   to also wipe the database
pkill -f viz/server.py     # if the dashboard is running
```

On a cloud instance, stop the instance when you are done to avoid charges.

---

## Part 12: figures, manuscript and result files

```bash
make figures      # regenerates paper/figures/manuscript/image1-6.png
```

The content is the same on any machine, but the PNG bytes depend on the
matplotlib version and fonts, so `git status` may show the images as modified.
`git checkout paper/figures/manuscript` restores the committed ones.

| Paper item | Produced by | Result file |
|---|---|---|
| Table 7, held-out | `make heldout` | `eval/results/revision2/heldout_*.json` |
| Table 8 and Fig. 5, naive baseline | `make eval`, `make heldout` | `eval/RESULTS.md`, `heldout_*.json` (`naive`) |
| Table 9, evasions | `make eval` | `eval/RESULTS.md` |
| Table 10, comparators | `make comparators` | `eval/results/revision2/comparators/` |
| Table 11, benign mix | `make eval` | `eval/RESULTS.md` |
| Table 12, 5G-CGAD | `make external` | `eval/results/revision2/oulu_*.json` |
| Table 13, live runs | `make live-run` | `eval/results/revision2/live_L1/`, `live_L2/` |
| Fig. 6, cost | `make latency` | `eval/results/revision2/latency_local.json` |
| Section 7.3, versions | `cross_version.sh` | `eval/results/revision2/xversion/` |
| Section 7.3, source code | reading | `eval/results/revision2/dissector_sources.md` |

The manuscript is `paper/manuscript_rev2.docx` (and `.pdf`), and the response to
the reviewers is `paper/response_to_reviewers_rev2.md`. Earlier drafts and their
companion documents are kept for the record in `paper/archive/`.

---

## Part 13: success checklist

- [ ] `make test`: **25 passed**
- [ ] `make eval`: robust **P=1.0 R=1.0 FPR=0.0**; naive **R1 recall 0.0**; evasions **0 mismatches**
- [ ] `make heldout`: recall **1.0 (0.9994–1.0)**, FPR **0.0 (0–0.0005)**, both runs
- [ ] old engine on realistic outer headers: recall **0.8**
- [ ] `cross_version.sh`: **identical finding streams: True**
- [ ] `make external`: benign **0 flagged of 6,218,456**; encapsulation **290,225 of 290,225**
- [ ] `make comparators`: Zeek **non-IP packet in GTPv1** on bare_nested, **GTP-in-GTP** on ip_wrapped; Suricata **0** everywhere
- [ ] live: every phone's ping through `uesimtunN` shows **0% loss**
- [ ] live: `make attack` gives **550 findings** and `make live-score` **tp 400, fp 0, fn 0, tn 100**
- [ ] live, 3 UEs: L1 **565 = 565**, L2 **853 = 853**, `identical: True`

---

## Part 14: troubleshooting

| Symptom | Cause and fix |
|---|---|
| `pip install` refuses ("externally managed") | Use the virtualenv from Part 3. |
| `make heldout` says seeds overlap development | Held-out seeds must not include 1337, 1, 2, 3 or 4. This check is deliberate. |
| Scapy 2.4.4 from pip crashes with `liblibc.a` | Use Ubuntu's `python3-scapy` for 2.4.4 (Part 7). |
| `fetch_5gcgad.sh` fails at `json.load` | The Fairdata service is busy or the link expired. Rerun: finished files are skipped. |
| `make external` is slow | Expected (about 5.5 hours for all captures). Use `nohup` (Part 8b). |
| `docker: permission denied` | Run `newgrp docker`, or log out and back in. |
| `make build` fails with `Temporary failure resolving` | The Docker build network has no DNS. Add `{"dns":["8.8.8.8"]}` to `/etc/docker/daemon.json` and restart Docker, or build with `--network=host`: `for s in core ran detector attacker; do docker build --network=host -t gtp-abuse-detector-$s ./$s; done`. |
| `ran` logs `Connection refused` or `Cell selection failure` | The start-up race. Run `docker compose restart ran` once the core is up. |
| Fewer `uesimtun` interfaces than `UE_COUNT` | `UE_COUNT` was changed after the core started. Run `docker compose up -d --force-recreate core`, then `docker compose up -d --force-recreate detector`, wait 20 s, and run `docker compose restart ran`. |
| No registration or no `uesimtun0` | `ran/ue.yaml` `key`/`op` must equal `KI`/`OPC` in `.env`. The defaults match. |
| Tunnel ping gets no replies, and the core logs `ogs_tun_write() failed` | The core image is old. Run `docker compose build core && docker compose up -d core && docker compose up -d --force-recreate detector && sleep 20 && docker compose restart ran`. |
| Detector stopped seeing packets after the core was recreated | The detector joins the core's namespace at its own start. Run `docker compose up -d --force-recreate detector`. |
| `make attack` seems to hang | Expected: about 2 seconds per packet (broadcast fallback). Watch `make logs`. |
| Detector shows only heartbeats | Benign traffic is silent by design. Run an attack. |
| Dashboard unreachable | Start `python3 viz/server.py` on the lab host. It listens on all interfaces; check with `ss -tlnp \| grep 8090`. |
| `/dev/net/tun` missing | Restricted environment. Parts 4–10 still work. |

---

## Part 15: where everything lives

| Path | What it is |
|---|---|
| `detector/rules.py` | The four rules and the extension-header walk and re-parse (the contribution) |
| `detector/baselines.py` | The naive baseline (no re-parse) |
| `detector/gtpu_detector.py` | Runnable detector: `live` sniff or `pcap` replay |
| `detector/tests/` | 25 unit tests |
| `attacker/generate_attacks.py` | Seeded abuse generator, lab only (`--write` pcap, `--send` live) |
| `attacker/benign_traffic.py` | 12-category benign generator |
| `attacker/evasions.py` | The 11-case evasion suite |
| `attacker/dissector_probe.py` | The three-packet probe of Part 10 |
| `eval/benchmark.py`, `run_eval.py`, `report.py` | Development benchmark (`make eval`) |
| `eval/heldout.py` | Held-out seeds with Wilson intervals (`make heldout`) |
| `eval/external_eval.py` | Scores external captures, including `.tar.xz` (`make external`) |
| `eval/comparator_pcaps.py` | Per-class captures for the comparators |
| `eval/latency.py` | Repeated timing (`make latency`) |
| `eval/results/revision2/` | Result files for every number in the manuscript |
| `scripts/lab_up.sh`, `lab_down.sh` | One-command lab bring-up and tear-down |
| `scripts/revision2/` | `fetch_5gcgad.sh`, `run_external.sh`, `run_comparators.sh`, `run_live.sh`, `cross_version.sh` |
| `paper/` | Manuscript, response to reviewers, figure script; `archive/` holds earlier drafts |
| `docs/ARCHITECTURE.md`, `docs/LAB_GUIDE.md` | Design notes and a short operator reference |

---

## Part 16: how the detector works

**Placement.** A passive tap on N3. In the lab it shares the core's network
namespace (`network_mode: service:core`), so it sees exactly what reaches the
UPF. It never blocks anything. On a real network the tap must see N3 in clear:
on a segment without IPsec, or behind the point where IPsec ends.

**R1, nested tunnel.** The engine walks the outer header's extension-header
chain (real N3 packets carry a PDU Session Container) to find the payload. If
the dissector already decoded the payload as IP or GTP, that decoding is used.
Otherwise the raw bytes must pass the gate: GTP version 1 with the protocol-type
bit, message type 0x01, 0x02, 0x1A, 0x1B, 0xFE or 0xFF, a self-consistent length
(up to 4 bytes of padding), and at least 20 bytes for a G-PDU. Then the
recovered header must forward IPv4 or IPv6. The gate keeps 5G Unstructured-session
payloads that happen to start like GTP from raising false alarms.

**R2, TEID re-sourcing.** A TEID is unique only at the endpoint that receives
it, so ownership is keyed on (receiving address, TEID). The first source seen
owns it, and a packet from another source raises R2 without taking ownership.
With the gNB allowlist (`--gnb-ips`), an allowlisted gNB always takes ownership
silently, which covers handovers. Limits: a rogue seen first becomes the owner,
there is no ageing, and TEID brute force is not detected.

**R3, control-plane smuggling.** Inner SCTP (protocol 132), or inner UDP to
port 8805 (PFCP), 2123 (GTP-C) or 2152 (GTP-U). It keys on ports, so PFCP on
another port evades it. The SCTP check is IPv4-only.

**R4, inner-to-core.** The inner destination is in the configured core address
list (`--core-ips`). An address missing from the list is invisible. IPv4-only.

---

## Command cheat-sheet

```bash
# offline (no Docker, no root)
make test                    # 25 passed
make eval                    # development benchmark -> eval/RESULTS.md
make heldout                 # held-out seeds 101-110
make latency                 # per-packet cost
scripts/revision2/cross_version.sh /usr/bin/python3 /tmp/s27/bin/python

# independent data
make fetch-data DATA=~/5g-cgad
make external   DATA=~/5g-cgad

# comparators (Docker)
make comparators

# live lab (Docker)
make build && make lab-up && sleep 20 && docker compose restart ran
docker compose exec ran ping -I uesimtun0 -c3 8.8.8.8
make attack && make live-score
make live-run TAG=L1 SEED=2026 TEID=0x2 COUNT=400 BENIGN=100
make lab-down

# paper
make figures
```

---

**Safety and ethics.** Everything here runs on a private lab network with a test
PLMN. The attack generator exists only to exercise the detector in this lab.
Never point it at a network you are not authorised to test; generating GTP-U
abuse against a live operator is illegal in most countries.
