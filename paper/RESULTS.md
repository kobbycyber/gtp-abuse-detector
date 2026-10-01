# Results

All numbers below were produced on this host following the exact commands in
`REPRODUCE.md`. The offline numbers (§3) were first produced on 2026-07-14 and
re-run on 2026-10-01 after the R2 ownership fix (§6, defect 7), with seeds
`{1337, 1, 2, 3, 4}`: every non-timing metric came out identical. The unit-test
count (§2) and the live results (§4) are from 2026-10-01. Raw artifacts are
regenerated, not committed: `../eval/metrics.json` and `../eval/RESULTS.md`
(written by `make eval`), `../captures/live_corpus.metrics.json` (written by
`make live-score`), and the container logs captured during the live run
(excerpted verbatim in §4).

## 1. Environment

| Component | Version |
|---|---|
| Host OS | Ubuntu (kernel 6.8.0-134-generic on 2026-07-14, 6.8.0-138-generic on 2026-10-01) |
| Docker Compose | v5.3.1 |
| Python (host, offline path) | 3.10.12 |
| scapy (host, offline path) | 2.4.4 (apt `python3-scapy`) |
| scapy (containers, live path) | 2.7.0 (`detector/requirements.txt`, pip) |
| Python (detector container) | 3.12.13 (earlier build); 3.12.14 (2026-10-01 rebuild used for §4) |
| Open5GS | 2.8.0~jammy5 (via `ppa:open5gs/latest`) |
| UERANSIM | v3.2.6 (pinned, `.env: UERANSIM_REF`) |
| MongoDB | 7 (`mongo:7` image + `mongodb-org/7.0` client repo) |
| Test PLMN | MCC 999 / MNC 70 / TAC 1 |

The scapy version gap between the offline host path (2.4.4) and the
Dockerized live path (2.7.0) is intentional evidence, not an oversight: it
lets §5 below argue that the R1 nested-GTP re-parsing logic (`rules.py`)
gives identical results across two different scapy minor versions, which
matters because the underlying bug class this project's headline finding
addresses (dissection heuristics changing behavior across library versions)
is exactly what you'd want to know is *not* happening here.

## 2. Unit tests

```
cd detector && python3 -m pytest tests/ -q
24 passed
```

All 24 tests pass across five files:

- `test_rules.py` (12 tests): one per attack class (`test_gtp_in_gtp`,
  `test_teid_spoof`, `test_pfcp_smuggle`, `test_ngap_smuggle`,
  `test_inner_to_core`), a benign negative (`test_benign_clean`),
  malformed-packet robustness (`test_detector_survives_garbage`), R1 on a
  nested tunnel inside a realistic G-PDU outer and its benign G-PDU counterpart
  (`test_gtp_in_gtp_gpdu_outer`, `test_benign_gpdu_inner_ip_clean`), and three
  R2 tests added with the ownership fix:
  `test_teid_spoof_rogue_cannot_take_ownership` (spoofs interleaved with the
  owner's traffic on one TEID are all flagged and the owner never is),
  `test_teid_scoped_by_receiving_endpoint` (the same TEID number in uplink and
  downlink does not conflict, and a spoof of the uplink tunnel still fires), and
  `test_live_attack_corpus_scores_clean` (the exact corpus `make attack` sends
  scores with no false positive and no false negative).
- `test_benign.py` (4 tests): zero false positives on the realistic corpus;
  every residual FP without the gNB allowlist attributable only to handovers;
  Unstructured-PDU bytes never flagged across 200 adversarial payloads; a
  handover suppressed with the allowlist and flagged without it.
- `test_evasions.py` (2 tests): the detector's behaviour matches its documented
  expectation on all 11 crafted evasions, with at least six robustness wins.
- `test_baseline.py` (3 tests): the naive default-dissection detector provably
  misses GTP-in-GTP that the robust detector catches, robust recall beats naive
  recall on a mixed set, and the two agree on rules that need no re-parse.
  That last test, `test_naive_and_robust_agree_on_non_reparse_rules`, now also
  checks R2 on interleaved spoofs.
- `test_reproducibility.py` (3 tests): the seeded corpus is byte-identical
  across runs, a different seed produces a different corpus, and the latency
  timer covers dissection rather than starting after it.

The three new R2 tests and the extended baseline test fail on the old R2 code
and pass on the fixed code.

## 3. Offline evaluation (comprehensive benchmark)

Command: `python3 eval/run_eval.py` (equivalently `make eval`). One invocation
produces headline metrics, multi-seed stability, the naive-baseline
comparison, the false-positive ablation, and the evasion suite.

**Corpus (primary seed 1337):** 1,320 packets, 600 malicious spread evenly
across the five attack classes, plus 720 benign: 600 packets spanning twelve categories
(TLS, HTTP, DNS, QUIC, NTP, RTP/VoIP, ICMP, IPv6, fragmented IP, IP-options,
Unstructured-PDU, handover) plus 120 legitimate victim flows that establish
TEID ownership before a spoof reuses it. The trivial single-shape benign of the
earlier evaluation is replaced entirely.

### 3.1 Headline classification (robust detector)

| Metric | Value |
|---|---:|
| True positives | 600 |
| False positives | 0 |
| False negatives | 0 |
| True negatives | 720 |
| **Precision** | **1.0** |
| **Recall** | **1.0** |
| **F1** | **1.0** |
| **False-positive rate** | **0.0** |

Stable across seeds `{1337, 1, 2, 3, 4}`: each metric has mean 1.0 and standard
deviation 0.0.

### 3.2 Naive-baseline comparison (contribution, quantified)

Identical corpus, identical rule ideas, the only difference being no inner
re-parse (`detector/baselines.py`):

| Attack class | Robust recall | Naive recall |
|---|---:|---:|
| gtp_in_gtp | **1.0** | **0.0** |
| pfcp_smuggle | 1.0 | 1.0 |
| ngap_smuggle | 1.0 | 1.0 |
| inner_to_core | 1.0 | 1.0 |
| teid_spoof | 1.0 | 1.0 |
| **overall (F1)** | **1.0** | **0.889** |

The naive baseline misses 100% of GTP-in-GTP; the re-parse recovers it.

### 3.3 False-positive ablation (handover handling)

| R2 configuration | FPR | FP | Source |
|---|---:|---:|---|
| with `--gnb-ips` allowlist | **0.0** | 0 | none |
| without allowlist | 0.0083 | 6 | 100% handover |

Every residual false positive is a legitimate Xn/N2 handover; the operator's
known-gNB allowlist suppresses these while still catching a TEID re-sourced
from outside the pool. R2 keys ownership on (receiving address, TEID), read from
the outer header that carries the tunnel, and the first source seen owns the
pair. With the allowlist, an allowlisted gNB always takes ownership and nothing
is raised: that covers a handover, and the real gNB reclaiming a tunnel a rogue
was seen on first. Any other change raises R2 and leaves ownership where it is, so a rogue
never takes the pair over.
Without the allowlist every change is flagged and ownership never moves, so a
handed-over session keeps alerting for as long as it sends from the new gNB.

### 3.4 Evasion suite

11 crafted evasions: **6 robustness wins** (still caught despite the evasion),
**1 correct-silence case** (GTP-looking noise the detector rightly ignores),
**4 documented blind spots** (inherent to a stateless user-plane-only rule), and
**0 mismatches** against the documented expectation.

### 3.5 Per-packet latency (single core, 1,320 packets, dissection included)

| Metric | Value (µs) |
|---|---:|
| Mean | 686.46 |
| P50 | 626.70 |
| P95 | 1186.59 |
| P99 | 1615.94 |
| Max | 2332.44 |

Implied sustained single-core throughput ≈ **1,450 pkt/s**.

The timed region spans dissection and rule evaluation: each packet is serialized
to bytes first, then the timer starts immediately before `IP(wire)`.
Three throughput figures have appeared in this project's history:

1. The current harness times dissection and rule evaluation together (it
   serializes each packet before starting the timer): 686 µs mean, ≈1,450 pkt/s. This is the figure a passive tap must
   actually pay.
2. An earlier harness started its timer after `IP(bytes(pkt))`, so it timed
   rule evaluation only: ≈206 µs, ≈4,850 pkt/s. This was a measurement, but of
   the wrong region.
3. An earlier `README.md` quoted about 8,000 pkt/s with no recorded measurement
   behind it. That figure is withdrawn.

Dissection is about 76% of per-packet cost on this host. The remaining 24% of
686 µs, ≈165 µs (≈6,000 pkt/s), is the rule-evaluation share; it is derived
from that split, not measured. `test_reproducibility.py` now fails the build if
the timer is moved back outside the dissection.

These absolute values are host-dependent and were produced on the offline
evaluation host; the classification numbers are not host-dependent.
Regenerate with `make eval` before quoting them.

## 4. Live full-stack validation

Unlike §3, this traffic was not written to a pcap and replayed. A UERANSIM UE
completed a real NGAP/NAS registration and an IPv4 PDU session against an
Open5GS 5G core, all inside Docker, and the detector sniffed `eth0` passively
(filter `udp port 2152`) inside the core's own network namespace.

The attack traffic does not come from the UE. A separate `attacker` container
shares the core's network namespace (`network_mode: service:core`); it is not a
UE and holds no PDU session. It writes crafted GTP-U with a raw socket onto the
core's `eth0` (the N3 interface), addressed to the UPF, and UERANSIM does not
encapsulate these packets. This stands in for the on-path position of the
threat model. Whether the UPF acts on the crafted frames was not measured; the
detector observes them on `eth0` as a tap would. Only an IPv4 PDU session was
exercised; Unstructured and Ethernet session types were not.

### 4.1 Core/RAN bring-up (excerpted, see `FINDINGS.md` for the full story
including two bugs fixed to get here)

```
ran-1  | [sctp] [info] SCTP connection established (10.10.10.10:38412)
ran-1  | [ngap] [info] NG Setup procedure is successful
ran-1  | [nas]  [info] Initial Registration is successful
ran-1  | [nas]  [info] PDU Session establishment is successful PSI[1]
ran-1  | [app]  [info] Connection setup for PDU session[1] is successful,
                        TUN interface[uesimtun0, 10.45.0.2] is up.
```

### 4.2 Real N3 dataflow proof

```
$ docker compose exec ran ping -I uesimtun0 -c3 8.8.8.8
```

All 3 echo requests were answered. A `tcpdump` on the core's `eth0` during the
ping showed each request as uplink GTP-U from the gNB (`10.10.10.20`) to the
UPF (`10.10.10.10`) and each reply returning as downlink GTP-U from
`10.10.10.10` to `10.10.10.20`. The ICMP itself appeared decapsulated on the
UPF's tunnel device `ogstun` and left through NAT. The session's TEIDs were
`0xb2aa` uplink (gNB to UPF) and `0x1` downlink (UPF to gNB). The detector
counted these packets and raised zero findings: this is the traffic class it
must stay silent on. `(DUP!)` replies can appear; they come from the host's own
network (each reply arrives several times at the core's `eth0`), not from the
lab.

This check replaces `docker compose exec ran ./build/nr-binder 10.45.0.2 ping
-c3 8.8.8.8`, whose replies an earlier version of this section reported as
proof of N3 dataflow. That ping never used the tunnel. `nr-binder` preloads
`./libdevbnd.so` by a path relative to the current directory; run from
`/ueransim` as documented, the loader cannot find it, prints `ERROR: ld.so:
object './libdevbnd.so' from LD_PRELOAD cannot be preloaded ... ignored.`, and
runs ping unbound. The ping left
`ran`'s `eth0` with source `10.10.10.20` by the Docker default route, and a
`tcpdump` on the core showed zero GTP-U while it ran. At the time the UE data
path did not work at all (§6, defect 6).

### 4.3 Live attack corpus

Command: `docker compose run --rm attacker --send --iface eth0 --count 400
--benign 100 --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20`
(500 packets total, sent as real raw-socket traffic in the core's network
namespace, this is the code path fixed in `FINDINGS.md` Finding 4).

The corpus is seeded (1337) and identical on every run: 100 benign,
88 `teid_spoof`, 82 `gtp_in_gtp`, 80 `inner_to_core`, 79 `pfcp_smuggle` and
71 `ngap_smuggle`. Every packet uses TEID `0x1` and outer destination
`10.10.10.10` (the UPF); the outer source is `10.10.10.20` except for
`teid_spoof`, which uses `10.10.10.66`. The send takes about 17 minutes:
from inside the core's own namespace Scapy cannot resolve a MAC address for
the UPF address, prints `MAC address to reach destination not found. Using
broadcast.`, and sends each frame as a broadcast. The detector saw all 500
packets, with zero crashes.

The same 500 packets are written to a pcap with per-packet labels and scored
offline with `make live-score` (`REPRODUCE.md` B.9). The live findings stream
is identical, in order and content (rule, source, destination, TEID and
detail), to that offline pass over the same corpus; this was checked for all
608 findings of the run before the fix and all 550 of the run after it. Only
the timestamps differ. Per-packet scores therefore come from the labelled
offline pass.

| | Before the R2 fix | After the R2 fix |
|---|---:|---:|
| R1_GTP_IN_GTP | 82 | 82 |
| R2_TEID_SPOOF | 146 | 88 |
| R3_CP_SMUGGLING | 150 | 150 |
| R4_INNER_TO_CORE | 230 | 230 |
| **Total findings** | **608** | **550** |
| True positives | 385 | 400 |
| False positives | 16 | 0 |
| False negatives | 15 | 0 |
| True negatives | 84 | 100 |
| **Precision** | **0.960** | **1.0** |
| **Recall** | **0.9625** | **1.0** |
| **F1** | **0.961** | **1.0** |
| **False-positive rate** | **0.16** | **0.0** |

*Before the R2 fix:* live run on a freshly started lab, 2026-10-01. *After the
R2 fix:* live run on a freshly recreated detector, 2026-10-01, 500 of 500
attack packets seen; four UE pings through the tunnel before the attack and
four after it (40 GTP-U packets) raised no finding, and `packets_seen` ended at
540. Per-packet scores for both columns come from `make live-score`;
`test_live_attack_corpus_scores_clean` locks the after-fix per-packet verdicts.

Findings exceed the 400 malicious packets because rules overlap: every
`pfcp_smuggle` and `ngap_smuggle` packet raises both R3 and R4, since its inner
destination is the UPF. R1, R3 and R4 are unchanged by the fix.

Every error in the before run came from R2 (defect 7, §6). R2 used to move
ownership of a TEID to whichever source sent last. All 16 false positives were
a benign packet immediately after a `teid_spoof`: ownership had moved to the
rogue, so the gNB's own packet looked like the spoof. All 15 false negatives
were a `teid_spoof` immediately after another `teid_spoof`: the rogue already
owned the TEID, so nothing changed. With first-source-wins ownership, R2 fires
exactly once per `teid_spoof` packet (88) and never on the gNB.

The live figure published earlier in this document, 131 findings (R1 22, R2 17,
R3 37, R4 55), did not reproduce and is withdrawn.

Sample raw findings (verbatim JSON lines from `docker compose logs detector`
for the run before the fix, log prefix removed). R1, R3 and R4 are unaffected
by the fix, and the R2 line is a real spoof from the rogue source
`10.10.10.66`, which both versions flag the same way:

```json
{"type": "finding", "rule": "R1_GTP_IN_GTP", "severity": "critical", "src": "10.10.10.20", "dst": "10.10.10.10", "teid": 1, "detail": "GTP header nested inside GTP-U payload (tunnel-in-tunnel).", "ts": 1790848547.466536}
{"type": "finding", "rule": "R2_TEID_SPOOF", "severity": "high", "src": "10.10.10.66", "dst": "10.10.10.10", "teid": 1, "detail": "TEID 0x1 first bound to 10.10.10.20, now sourced from 10.10.10.66.", "ts": 1790848541.416248}
{"type": "finding", "rule": "R3_CP_SMUGGLING", "severity": "critical", "src": "10.10.10.20", "dst": "10.10.10.10", "teid": 1, "detail": "Control-plane payload (SCTP/NGAP) encapsulated in GTP-U tunnel.", "ts": 1790848567.638227}
{"type": "finding", "rule": "R4_INNER_TO_CORE", "severity": "high", "src": "10.10.10.20", "dst": "10.10.10.10", "teid": 1, "detail": "Inner packet targets core NF 10.10.10.11 instead of data network.", "ts": 1790848537.380705}
```

### 4.4 Offline vs. live: coverage parity

| Rule | Fired offline (§3.1)? | Fired on the live corpus (§4.3, after the fix)? |
|---|---|---|
| R1_GTP_IN_GTP | ✅ 120 | ✅ 82 |
| R2_TEID_SPOOF | ✅ 120 | ✅ 88 |
| R3_CP_SMUGGLING | ✅ 240 | ✅ 150 |
| R4_INNER_TO_CORE | ✅ 360 | ✅ 230 |

Raw counts are not directly comparable between these two columns (the corpora
differ in size and composition), but **coverage is identical**: the same
four rules, using the exact same `rules.py` code, fire on both a synthetic
labelled pcap and on packets
that only exist because a real raw socket put them on a real (virtual)
wire. This is the strongest evidence in this project that the offline
metrics in §3.1 are not an artifact of testing against packets the detector
was implicitly designed around. For the identical corpus the agreement is
exact: the live findings stream and an offline pass over the same 500 packets
match finding for finding (§4.3, `REPRODUCE.md` Part C).

## 5. Cross-dissector consistency (R1 rule)

The offline path ran under scapy 2.4.4; the live path ran under scapy 2.7.0
inside the `detector` container (`detector/requirements.txt` pins
`scapy==2.7.0`). Finding R1_GTP_IN_GTP hits under both (120 offline, 82 live).

The blind spot is not a Scapy quirk. A three-packet probe
(`attacker/dissector_probe.py`; reproduced in `REPRODUCE.md` Part D) carries a
bare-nested abuse packet, a benign inner-IP packet, and a control-plane-smuggle
packet inside a realistic outer G-PDU. Read with `tshark` (Wireshark 4.x), all
three frames decode as GTP-U on the outer tunnel, but the nested frame's stack
ends there: its inner is an opaque T-PDU, no second GTP layer or inner IP
appears, while the benign and smuggle frames decode their inner IP. Zeek 8.2.2
records exactly one GTPv1 tunnel, logs the benign and smuggle inner connections
via `tunnel_parents`, but produces no inner connection and no `weird.log` for the
nested packet. Zeek's GTPv1 analyzer finds that the decapsulated payload is
neither IPv4 nor IPv6, records one analyzer violation in `analyzer.log`, `non-IP
packet in GTPv1`, and does not pass the payload on, so no inner connection or
second tunnel appears. The violation does not identify the payload as a tunnel. Scapy, tshark and Zeek,
three independent implementations, all miss the bare-nested form.

Note that the realistic G-PDU outer is what makes this rigorous: under it Scapy
guesses the nested bytes as `PPP`, not `Raw`, so `_reparse_inner()` keys on the
raw bytes rather than on the `Raw` class (see `PAPER.md` §5.1). An earlier
`Raw`-only version of the rule missed this realistic case until the probe
exposed it.

## 6. Defects found and fixed by running the live path

Seven defects were found and fixed purely by attempting to run the live path
end-to-end: five at first bring-up (1 to 5) and two when the labelled live run
was scored packet by packet during revision (6 and 7). None was caught by the
pre-existing offline test suite: defects 1 to 6 live in code the offline path
never runs, and defect 7's code runs offline but no offline input triggered it. Full root-cause analysis, diagnosis
commands, and diffs are in `FINDINGS.md`. Summary:

1. `core` image missing `mongosh` → bring-up hangs forever with no error.
2. Config-rebind regex silently no-ops on real YAML → AMF/UPF stayed bound
   to loopback while logging a false success message.
3. `nr-binder` helper script lost its executable bit in a multi-stage
   Docker build.
4. **The live attack sender (`--send`) emitted structurally malformed
   Ethernet frames on every invocation, for the entire history of this
   project, because it called `sendp()` on packets with no `Ether()`
   layer**, the single highest-severity finding, since it means the
   README's own "fire abuse and watch detections" instructions never
   actually worked before this session.
5. `network_mode: service:core` silently orphans `detector` (and any running
`attacker`) on any `core` container recreation, while `ran` needs a separate
restart because its one-shot NG Setup can race the AMF; an operational trap, not a code bug, now
   documented as a required manual step in `REPRODUCE.md`.
6. The UE data path never worked, and the documented check hid it. Nothing in
   the container configured the UPF's TUN device `ogstun` (no address, link
   down), so the UPF decapsulated uplink GTP-U and then logged
   `ogs_tun_write() failed` for every packet; no UE packet reached the data
   network. The documented `nr-binder` ping still got replies because it never
   used the tunnel (§4.2). `core/entrypoint.sh` now gives `ogstun`
   10.45.0.1/16, brings it up and NATs the UE pool out, and the check is now
   `ping -I uesimtun0`.
7. R2 handed a TEID to whichever source sent last and keyed ownership on the
   TEID alone. On the live corpus, where spoofs and legitimate packets
   interleave on one TEID, this caused 16 false positives and 15 false
   negatives (§4.3). The TEID-only key would also have conflated the live
   session's downlink TEID `0x1` with the attack corpus's uplink TEID `0x1`.
   R2 now keys ownership on (receiving address, TEID), as TS 29.281 makes a
   TEID unique only within the receiving endpoint; the first source wins, and
   only an allowlisted gNB can take ownership. The defect
   was invisible offline because the offline corpus gives every spoof its own
   victim TEID, emits all victims first, and has a single receiver. The offline
   results in §3 are unchanged by the fix.
