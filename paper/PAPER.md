# Passive Detection of GTP-U Tunnel Abuse in 5G/4G User-Plane Traffic:
## A Reproducible, Open-Source Testbed, Rule-Based Detector, and a Case Study in Validating Passive Network-Security Tooling

Companion documents: `RESULTS.md` (full raw results), `FINDINGS.md` (detailed
bug case studies), and `REPRODUCE.md` (exact manual commands to reproduce every
number in this paper). This folder is self-contained and does not modify
anything under the main repo tree except where noted.

---

## Abstract

Mobile networks carry each subscriber's internet traffic through tunnels called
GTP-U (GPRS Tunnelling Protocol, user plane). On the link between the radio
network and the core, called N3 in 5G and S1-U or Iu in 4G and 3G, this traffic
usually travels as plain UDP on port 2152, with no authentication or encryption
between network elements. Anyone who gains a foothold on that link can therefore
abuse it. That foothold could be a compromised or rogue base station, a
misconfigured roaming connection, or an insider with network access.

This paper presents `gtpu-abuse-lab`, a small and fully open testbed built with
Docker Compose. It combines a real Open5GS 5G core, a real UERANSIM-simulated
base station and handset, a passive detector written with Scapy, and a generator
that produces labelled abuse traffic. The detector applies four rules: nested
GTP tunnels (GTP-in-GTP), TEID spoofing, control-plane messages hidden inside
user-plane traffic (PFCP and NGAP), and inner packets aimed at core network
functions.

We evaluate the detector on a 1,320-packet labelled corpus. Its 720 benign
packets span twelve traffic types, including deliberately awkward cases such as
non-IP "Unstructured" payloads and legitimate handovers. On this corpus the
detector reaches precision, recall, and F1 of 1.0 with a false-positive rate of
0.0, and the result stays the same across five random seeds. The whole
evaluation runs offline with no special infrastructure. It also does three
things that a single score cannot: it compares against a naive detector that
misses every nested tunnel, it traces each remaining false positive to one cause
(legitimate handovers) and then removes it, and it lists the attacks the
detector cannot catch in an explicit evasion suite.

We then validate the same detector against a genuinely live 5G core and radio
inside Docker. Fired with real packets sent over a raw socket rather than
replayed from a file, it produced 131 correct findings across all four rules.

Finally, the paper reports a lesson about testing. Bringing the live system up
for the first time exposed five real bugs, including one where the traffic
generator had been sending malformed Ethernet frames on every live run since the
project began. None of these bugs were reachable by the existing, fully passing
offline tests. We argue this is structural rather than accidental. For tools
that work on raw network bytes, an in-memory or file-replay test suite is
necessary but not sufficient, because the bugs that matter most only appear when
bytes are actually put on, or read off, a real wire.

---

## 1. Introduction

### 1.1 Motivation

Mobile core networks move user data through GTP-U tunnels. Each tunnel has a
Tunnel Endpoint Identifier (TEID), a number that identifies it locally. The
protocol does not cryptographically tie a TEID to its claimed source or to the
subscriber session it represents. Production networks make up for this with
physical and network isolation: GTP-U is expected to cross only trusted
infrastructure, such as links between the radio network and the core, or roaming
interconnects secured by other means. That isolation is a deployment assumption,
not a guarantee built into the protocol, and it has failed in practice at the
interconnect layer for related protocols in the same family, notably SS7 and
Diameter.

A party with access to the transport segment can attempt several GTP-specific
abuses:

- Nested tunnels (GTP-in-GTP): placing a second GTP header inside what should be
  an ordinary IP payload. Depending on how downstream equipment or a naive
  detector reads the packet, this can smuggle traffic past inspection points
  that only look one layer deep, or pivot into infrastructure that trusts the
  inner tunnel.
- TEID spoofing: sending traffic under a TEID that belongs to another
  subscriber's session, from an unexpected source address. This can hijack,
  inject into, or deny service to that session.
- Control-plane smuggling: hiding control-plane traffic (PFCP on N4, GTP-C, or
  NGAP/S1AP normally carried over SCTP on N2) inside GTP-U user-plane payload, to
  reach or influence control-plane functions through a data path that may be
  watched less closely.
- Inner-traffic misdirection: putting an inner IP packet inside a normal-looking
  tunnel but addressing it to an internal core function (UPF, SMF, or AMF)
  instead of the external internet, using the tunnel to reach systems the
  subscriber should never be able to route to.

Commercial "GTP firewall" products are sold against exactly these abuses, but
they are closed appliances. Their detection logic, false-positive behaviour, and
performance cannot be checked independently, and no small, open, reproducible
testbed lets a researcher try a detection approach against a real (simulated) 5G
core instead of a static packet capture of unknown origin.

### 1.2 Contributions

1. An open, Dockerized, reproducible testbed that combines a real Open5GS 5G
   core and a UERANSIM radio and handset simulator on an isolated
   `10.10.10.0/24` network under the test PLMN `999/70`, together with a passive
   detector and a labelled attack-traffic generator (Section 4).
2. A four-rule passive detector (Section 5), evaluated rigorously rather than
   circularly (Section 6.1). On a 1,320-packet corpus whose 720 benign packets
   span twelve traffic types, including awkward Unstructured-PDU bytes and
   legitimate handovers, it reaches precision, recall, and F1 of 1.0 with a
   false-positive rate of 0.0, stable across five seeds. The evaluation adds
   three things a bare score omits: a naive-baseline comparison that measures the
   contribution, a false-positive analysis that traces every remaining false
   alarm to one cause and then removes it, and an evasion suite that states the
   detector's blind spots plainly. All of it runs with two `pip install` commands
   and no root or Docker.
3. A methodological finding built into the detector (rule R1, Section 5.1).
   Scapy's default parsing of a GTP-U payload quietly treats a nested GTP header
   as opaque `Raw` bytes. A naive `haslayer()` check on captured or live traffic
   therefore misses 100% of nested-tunnel abuse, even though an in-memory unit
   test that builds the layers directly in Python would pass. Section 6.1.3
   measures this: an otherwise identical naive detector scores 0.0 recall on
   nested tunnels where the real detector scores 1.0.
4. Live validation of the same detector against real, transmitted (not replayed)
   5G traffic (Section 6.2), confirming that the same rules fire as in the
   offline test.
5. A documented case study (Section 8, with full detail in `FINDINGS.md`) of
   five real bugs: a missing runtime dependency, a config-patching regex that
   quietly does nothing while logging success, a lost file permission in a
   multi-stage container build, a Docker Compose networking trap, and, most
   importantly, a traffic generator that had been sending malformed Ethernet
   frames on every live run since the project began. All five were found only by
   running the live path, and none were reachable from the existing, fully
   passing offline tests.

---

## 2. Background

### 2.1 GTP-U and its role in the mobile core

GTP-U (defined in 3GPP TS 29.281) carries user traffic inside UDP, normally on
port 2152. In 5G the interface this paper focuses on is N3, the link between the
gNB (the base station) and the UPF (the User Plane Function). N3 carries every
subscriber's actual data, and each session's tunnel is identified by a TEID that
the receiving end chooses when the tunnel is set up. Two neighbouring interfaces
matter for the threat model:

- N2 carries signalling between the gNB and the AMF, using NGAP over SCTP. It
  handles registration, authentication, and session setup, and is supposed to
  stay strictly separate from N3's user traffic.
- N4 carries signalling between the SMF and the UPF, using PFCP (3GPP TS
  29.244). It controls how the UPF forwards a tunnel's traffic, and is also
  supposed to stay separate from N3.

The abuses listed in Section 1.1 are all attempts to blur or bypass this
separation, or to exploit the fact that GTP-U does not cryptographically bind a
TEID to a subscriber.

### 2.2 Threat model

The testbed assumes an attacker who can inject arbitrary UDP packets onto the N3
segment. This is the position a compromised or rogue gNB, a misconfigured roaming
partner, or a network insider would hold. It does not assume an attacker who has
taken over the UPF or SMF itself, which is a stronger and different problem, and
it does not cover radio-layer attacks on the air interface. The detector is a
passive tap: it watches N3 traffic and raises findings, but it does not block or
change traffic. This matches where a production GTP firewall usually sits, in
front of or spanning the UPF's N3 interface rather than in the UPF's own
forwarding path.

---

## 3. Related work

Abuse of mobile interconnects has a long record at the SS7 and Diameter layers,
including location tracking, fraud, and interception attacks disclosed over the
past decade. Industry bodies such as the GSMA publish security guidance for GTP
as part of their wider mobile-security work. Commercial GTP and signalling
firewalls from telecom security vendors target this abuse directly, but they are
closed appliances with no independently reproducible detection logic or benchmark
corpus.

The set of abuse classes used by this project's traffic generator
(`attacker/generate_attacks.py`) was designed with reference to prior published
discussion of GTP tunnel-endpoint abuse, as noted in the tool's own comments. We
have not independently traced that taxonomy to a single citable, permanent
source, and we do not invent a specific citation here; we would rather flag the
gap than fabricate a reference. Whatever the taxonomy's exact provenance, what
this project adds is a runnable, open implementation of the detectors, the
labelled attack traffic, and a real (simulated) 5G core to test both against.
That combination is rarely available together in either the commercial or the
academic literature.

---

## 4. System architecture

### 4.1 Components

| Component | Role |
|---|---|
| `core/` | Open5GS all-in-one 5G core (AMF, SMF, UPF, plus support functions: NRF, SCP, AUSF, UDM, UDR, PCF, BSF, NSSF) |
| `ran/` | UERANSIM-simulated gNB and UE, generating real GTP-U traffic on N3 |
| `detector/` | The main research contribution: a passive Scapy-based detector, the rule engine, metrics, and the naive baseline (`baselines.py`) used to measure the contribution |
| `attacker/` | Lab-only traffic: the abuse generator, the realistic twelve-category benign generator (`benign_traffic.py`), and the crafted evasion suite (`evasions.py`) |
| `eval/` | Reproducible offline benchmark (`benchmark.py`) producing `metrics.json` and `RESULTS.md`: headline metrics, baseline comparison, false-positive analysis, multi-seed stability, and evasion scoring |

### 4.2 Topology

```
 UE (uesimtun0)                     gNB                         Core (10.10.10.10)
 10.45.0.x  ── PDU session ──►  10.10.10.20  ── N3 / GTP-U ──►  UPF ─► data network
                                (UERANSIM)      UDP 2152        (Open5GS)
                                                   │
                                                   ▼
                                          ┌──────────────────┐
                                          │  DETECTOR (tap)  │  shares core netns,
                                          │  sniffs eth0     │  sees every N3 packet
                                          └──────────────────┘
```

All components run on a fixed private Docker network (`10.10.10.0/24`) under the
test PLMN `999/70`. This is never a real operator's identity and is never meant
to be reachable outside the isolated lab (see Section 11, Ethics).

### 4.3 Why the detector shares the core's network namespace

Traffic between two containers on a Docker bridge is switched at Layer 2, so a
third container on the same bridge does not see it by default. The
`docker-compose.yml` file sets `detector: network_mode: "service:core"`, which
places the detector inside the UPF's own network namespace and lets it sniff the
real `eth0`. This is deliberately the same tap point a production GTP firewall
uses, in front of or spanning the UPF's N3 interface, rather than a
port-mirroring approximation. The `attacker` service shares the same namespace
for the live-fire path, for the same reason. This choice has an operational
consequence, documented in Section 8 and in `FINDINGS.md` as Finding 5.

### 4.4 Two operating modes

1. Offline evaluation, with no Docker, core, or root. The attack generator writes
   a labelled packet capture, the detector replays it, and a scoring harness
   produces `metrics.json` and a markdown results table. This is the reproducible
   path behind the headline numbers in Section 6.1, and it runs with
   `pip install scapy pytest` alone.
2. Live lab, the full Docker stack, which produces genuinely transmitted (not
   replayed) 5G traffic and is used for the validation in Section 6.2.

Both modes use the exact same `detector/rules.py` and `detector/metrics.py`
code. There is one detection engine, not two, so results from the two modes are
directly comparable in kind (Section 6.3).

---

## 5. Detection methodology

The detector (`detector/rules.py`) applies four rules. Each rule is a small,
self-contained function of the form `rule(pkt, state) -> list[Finding]`, and a
shared `evaluate()` dispatcher runs all four over every GTP-U packet. The
dispatcher catches and discards any exception from an individual rule, so a
single malformed packet can never crash the detector (verified by
`test_detector_survives_garbage`). The `DetectorState` object holds the small
amount of memory the rules need between packets: a map from each TEID to the
first source that used it (for R2), and a configured set of core-function IP
addresses (for R4).

### 5.1 Rule R1: nested tunnels (GTP-in-GTP), severity critical

R1 catches a second GTP header hidden inside a payload that should contain plain
user IP data. In other words, a tunnel inside a tunnel.

The interesting part, and this project's main technical contribution, is how
easily a passive detector misses this. When Scapy parses the payload of a GTP-U
packet, it looks at the first four bits to decide what the inner data is: a value
of 4 means an IPv4 packet, and 6 means IPv6. A nested GTP header starts with
neither. Its first byte falls in the range 0x30 to 0x3f (GTP version 1, with the
protocol-type bit set), so Scapy gives up and treats the whole inner payload as
opaque `Raw` bytes. A detector that checks
`pkt[GTP_U_Header].payload.haslayer(GTP_U_Header)` on captured or live traffic
therefore gets `False` for every real nested-tunnel packet. The abuse is present;
Scapy's own parsing heuristic has simply thrown away the information needed to
see it.

This gap is invisible to a naive unit test. If a test builds the nested packet
directly in Python, for example `GTP_U_Header(...)/GTP_U_Header(...)/IP(...)`,
the inner `GTP_U_Header` already exists as a real Scapy layer in memory,
`haslayer()` finds it at once, and the test passes. The test never puts the
packet through the serialize-to-bytes and parse-from-bytes round trip that real
captured traffic goes through, so it cannot notice that parsing, as opposed to
the in-memory object, loses this information.

The fix (`_looks_like_gtp()`, `_reparse_inner()`, and `_carries_inner_ip()` in
`rules.py`) actively re-reads any `Raw` payload sitting under a GTP-U layer. If
the first byte's top three bits indicate GTP version 1 with the protocol-type bit
set, and the second byte is a known GTP message type (a G-PDU, an echo request or
response, and so on), the raw bytes are parsed again as a GTP header before the
rule checks for nesting.

Two extra guards stop this from raising false alarms on harmless non-IP payloads.
(5G "Unstructured" PDU sessions carry arbitrary bytes, and some of them happen to
match the GTP byte pattern.) First, the 16-bit GTP length field must match the
bytes actually present, so that `8 + length` equals the datagram size apart from
padding. Second, and decisively, the nested header must actually carry a routable
inner IP packet, recognisable by an IPv4 or IPv6 version nibble. A tunnel used
for abuse forwards a real packet; random noise does not. Section 6.1.4 shows that
these guards remove the Unstructured-PDU false positives completely (zero across
200 crafted payloads), and Section 6.1.3 shows they cost nothing in detection.

As far as we know, this is an underdocumented requirement for any Scapy-based
passive GTP-U tool, and it generalises. Any passive detector tested only against
packet objects built in memory, rather than against bytes parsed back off the
wire, risks silently missing exactly the abuse that depends on a parser's
fallback behaviour. Section 8 develops this point further, using four more
concrete cases from this project's own deployment tooling.

### 5.2 Rule R2: TEID spoofing, severity high

R2 catches a TEID that was first seen from one source IP and later arrives from a
different source IP.

The implementation is deliberately simple. `DetectorState.teid_owner` records the
first source to use each TEID; that source becomes the owner. Any later packet
with the same TEID from a different source raises a finding. This first-source-
wins approach trades the ability to catch sophisticated, session-aware spoofing
for something auditable and easy to unit-test.

There is one honest complication: handovers. A legitimate Xn or N2 handover moves
a handset from one base station to another. The UPF's uplink TEID stays the same,
but user-plane packets now arrive from a different gNB IP. Looking at the user
plane alone, that is indistinguishable from a spoof, so a naive version of R2
raises a false alarm on every handover. Section 6.1.4 quantifies this: without
any mitigation, every remaining false positive is a handover.

The mitigation is an optional allowlist of known gNB IPs, supplied by the
operator (`--gnb-ips`, stored in `DetectorState.known_gnb_ips`). If a TEID's
owner changes but both the old and new sources are known gNBs, R2 treats it as a
handover and stays quiet. If the TEID is re-sourced from any address outside the
pool, R2 still fires. With the allowlist, handover false positives drop to zero
while the rogue-source spoof of Section 6.1.5 is still caught. This is a
deliberate, honest treatment of a real limitation of stateless passive
attribution, rather than a corpus that quietly leaves handovers out. Two blind
spots remain: a rogue that forges a legitimate gNB's source IP, and a rogue that
claims a TEID the detector has never seen. Both are listed as evasion cases in
Section 6.1.5 and in Section 9. Closing either one needs control-plane
correlation, which is outside the scope of a user-plane-only tap.

### 5.3 Rule R3: control-plane smuggling, severity critical

R3 catches control-plane traffic hidden inside a GTP-U user-plane payload: PFCP
(N4, UDP port 8805), GTP-C (UDP port 2123), GTP-U (UDP port 2152, kept here as
defence in depth alongside R1), or SCTP (protocol 132, which carries NGAP and
S1AP). These are control protocols appearing where only user data belongs. The
rule inspects the inner packet's transport protocol and port, re-parsing the
inner bytes first where needed (as in Section 5.1), and compares them against
this known-bad set.

### 5.4 Rule R4: inner traffic aimed at a core function, severity high

R4 catches an inner IP packet, inside an otherwise normal-looking tunnel, whose
destination is a configured core-function address (UPF, SMF, AMF, and so on)
rather than the external data network. The implementation is an
operator-configured allowlist (`DetectorState.core_nf_ips`, set with `--core-ips`
when the detector starts). This is a deliberate trade-off: the rule is only as
complete as its configuration, and a missing or wrong entry quietly disables the
rule for that address rather than raising an error (see Section 9).

---

## 6. Evaluation

The full raw data, JSON artifacts, and verbatim log excerpts for this section are
in `RESULTS.md`, and the exact commands to reproduce every number are in
`REPRODUCE.md`.

### 6.1 Offline evaluation (comprehensive benchmark)

The evaluation is built to answer the questions that a perfect score on a
self-generated corpus would otherwise invite. It runs from one reproducible
command (`python3 eval/run_eval.py`, with no Docker, root, or network) and
produces seven distinct pieces of evidence, all written to `RESULTS.md`.

The corpus has 1,320 packets on the primary seed. 600 are malicious, spread
evenly across the five attack classes. The other 720 are benign and span twelve
traffic types: TLS, HTTP, DNS, QUIC, NTP, RTP/VoIP, ICMP, IPv6, fragmented IP,
and IP-options, plus two types chosen specifically to stress the detector. The
first is Unstructured-PDU-session bytes, non-IP inner payloads, some crafted to
begin with GTP-looking bytes. The second is legitimate Xn/N2 handovers, where the
uplink TEID is unchanged but the source gNB IP is different. The earlier
evaluation used a single benign shape (ICMP to 8.8.8.8); it is replaced entirely,
because a false-positive rate only means something when it is measured against
varied benign traffic.

#### 6.1.1 Headline classification (robust detector)

| Metric | Value |
|---|---:|
| Precision | 1.0 |
| Recall | 1.0 |
| F1 | 1.0 |
| False-positive rate | 0.0 |
| Mean per-packet latency | about 686 µs (dissection and rules together) |
| Implied single-core throughput | about 1,450 packets per second |

#### 6.1.2 Stability across seeds

The headline metrics are not the product of one lucky corpus. Across seeds
{1337, 1, 2, 3, 4}, precision, recall, F1, and the false-positive rate each have
a mean of 1.0 and a standard deviation of 0.0.

#### 6.1.3 Naive-baseline comparison (the contribution, measured)

To measure what the R1 re-parse is worth, we implement the detector a competent
engineer would write first: Scapy's default parsing with `haslayer` and no inner
re-parse (`detector/baselines.py`). We score it on the identical corpus, holding
every other design decision fixed, so the difference isolates one variable, the
re-parse.

| Attack class | Robust recall | Naive recall |
|---|---:|---:|
| gtp_in_gtp | 1.0 | 0.0 |
| pfcp_smuggle | 1.0 | 1.0 |
| ngap_smuggle | 1.0 | 1.0 |
| inner_to_core | 1.0 | 1.0 |
| teid_spoof | 1.0 | 1.0 |
| overall | 1.0 | 0.80 (F1 0.889) |

The naive baseline misses 100% of nested tunnels, because a nested GTP header is
parsed as `Raw` by default (Section 5.1). This makes the claim in Sections 1.2
and 5.1 concrete: the contribution is worth moving R1 recall from 0.0 to 1.0, and
overall F1 from 0.889 to 1.0.

#### 6.1.4 Where the false positives come from, and the handover ablation

Against the corpus above, the robust detector's only remaining source of false
positives is the handover category, because a legitimate source-IP change on an
unchanged TEID looks exactly like a spoof on the user plane. We report this as an
explicit before-and-after rather than hiding it:

| R2 configuration | FPR | False positives | Source |
|---|---:|---:|---|
| with known-gNB allowlist (`--gnb-ips`) | 0.0 | 0 | none |
| without allowlist | 0.0083 | 6 | 100% handover |

Supplying the operator's known gNB addresses removes the handover false positives
while still flagging a TEID re-sourced from any address outside the pool. The
other earlier source of false positives, benign Unstructured-PDU bytes that
happened to match the GTP pattern, was removed at the root by checking the nested
header's length field and requiring a routable inner IP (Section 5.1). It now
produces zero false positives across 200 crafted Unstructured payloads
(`test_benign.py`).

#### 6.1.5 Adversarial robustness (evasion suite)

The detector is scored against 11 crafted evasions (`attacker/evasions.py`). Each
one is labelled in advance with whether a correct detector should catch it, or
whether it is an inherent blind spot of a stateless passive rule. Six are
robustness wins, all still caught: an IPv6 inner tunnel, an outer
extension-header offset shift, generic-GTP nesting, standard-port PFCP,
SCTP/NGAP, and targeting a listed core function. Five are documented blind spots:
a rogue that owns a never-seen TEID, a forged gNB source IP, PFCP moved off its
usual port, and a core function outside the configured set. The suite checks that
observed behaviour matches the labelled expectation on every case, so a change in
either direction fails the build.

All of Section 6.1 is reproducible with two `pip install` commands and no Docker,
root, or network, through `python3 eval/run_eval.py`.

### 6.2 Live full-stack validation

A real Open5GS core and a UERANSIM UE and gNB were brought up in Docker. The UE
completed NG Setup, NAS registration, and PDU session establishment, producing a
real `uesimtun0` interface at `10.45.0.2`. A `ping -c3 8.8.8.8` through that
tunnel confirmed genuine N3 GTP-U traffic with 0% packet loss. A 500-packet
attack corpus (400 malicious, 100 benign) was then fired live, as real raw-socket
traffic, at the UPF. The passive detector, running inside the core's own network
namespace, produced 131 findings with no crashes:

| Rule | Live findings |
|---|---:|
| R1_GTP_IN_GTP | 22 |
| R2_TEID_SPOOF | 17 |
| R3_CP_SMUGGLING | 37 |
| R4_INNER_TO_CORE | 55 |

### 6.3 Coverage parity

The same four rules fired in both the offline corpus (Section 6.1) and the live
run (Section 6.2). The counts differ, because the corpus, seed, and live
ARP-driven timing differ, but the coverage is the same. Since both paths share
one detection engine (Section 4.4), this is evidence that the offline numbers
reflect genuine detection ability rather than a corpus quietly shaped to fit the
detector's assumptions.

### 6.4 Consistency across Scapy versions

The offline path ran under Scapy 2.4.4 on the host; the live path ran under Scapy
2.7.0 inside the container. R1 fired correctly under both. Because the central
finding in Section 5.1 is about a Scapy parsing edge case, confirming that the
fix is not itself fragile across Scapy versions is a small but relevant piece of
evidence.

---

## 7. Implementation notes

- The corpus generator (`attacker/generate_attacks.py`) builds all six traffic
  classes (five malicious plus benign) as Scapy packet-construction functions,
  seeded with `random.Random(seed)` for full reproducibility. It supports both
  `--write` (a packet capture with aligned JSON labels, for offline scoring) and
  `--send` (live raw-socket transmission).
- The detector (`detector/gtpu_detector.py`) shares one rule engine and one
  metrics collector (`detector/metrics.py`) between its `live` mode (sniffing an
  interface) and its `pcap` mode (offline replay). It prints either
  human-readable or JSON output per finding, plus a summary block on exit, with
  classification metrics when ground-truth labels are supplied.
- The realistic benign generator (`attacker/benign_traffic.py`) produces the
  twelve-category benign corpus of Section 6.1, including the awkward
  Unstructured-PDU and handover categories.
- The naive baseline (`detector/baselines.py`) re-implements the four rules using
  only Scapy's default parsing, holding every design choice fixed except the
  inner re-parse, so the comparison in Section 6.1.3 is like-for-like.
- The evasion suite (`attacker/evasions.py`) lists 11 crafted evasions, each
  tagged with its expected outcome and checked in CI (Section 6.1.5).
- The evaluation harness (`eval/benchmark.py`, `eval/run_eval.py`,
  `eval/report.py`) chains corpus generation, robust and naive scoring, the
  false-positive analysis, the multi-seed run, and the evasion suite into one
  reproducible command, then writes the markdown report. Every number in
  Section 6.1 comes from a single `python3 eval/run_eval.py`.

---

## 8. Case study: the gap between "passes every test" and "works on the wire"

Before this investigation the offline test suite was fully green: 7 of 7 unit
tests passing, and perfect precision, recall, F1, and false-positive rate on the
labelled corpus. Bringing the live Docker lab up for the first time, which the
project's own README treats as an equally important way to run it, exposed five
real bugs. Each is documented with full root-cause analysis and diffs in
`FINDINGS.md`.

1. The `core` image never installed `mongosh`, which both the entrypoint's health
   check and the upstream subscriber-provisioning tool depend on. Bring-up hung
   forever with no error at all, and every container still showed healthy in
   `docker compose ps`.
2. The entrypoint's config-rebind logic used a regex that did not account for
   YAML's `- address:` list syntax, so it never matched. Because Python's
   `re.sub()` does not raise an error on zero matches, the script printed a
   confident and specific but wrong success message
   (`"[core] bound NGAP+GTP-U to 10.10.10.10 ..."`) while the AMF and UPF stayed
   bound to internal loopback addresses that the RAN could not reach.
3. A helper script (`nr-binder`) lost its executable bit while crossing a
   multi-stage Docker `COPY --from=build`.
4. The most consequential one: the traffic generator's `--send` path called
   Scapy's `sendp()`, a Layer-2 send, on packets that were never given an
   `Ether()` layer. This does not raise an error. It quietly writes the raw IP
   bytes onto the wire, where any listener reads the first 14 bytes as a bogus
   Ethernet header. Every live-fired attack packet, for the whole history of the
   project up to this work, was malformed at the link layer. The fix, using
   Scapy's `send()` (Layer 3, which lets the kernel build a real frame and
   resolve ARP), is two lines, but until then the project's own "fire abuse and
   watch detections" demo had never actually worked.
5. The `network_mode: "service:core"` setting in `docker-compose.yml`, the very
   thing that makes the detector's tap point realistic (Section 4.3), binds to a
   specific container instance's namespace at attach time, not to a service name.
   Recreating `core`, which is needed to apply fixes 1 and 2, silently detached
   the detector and required an explicit `--force-recreate` to reattach. This is
   an easy trap to hit repeatedly while iterating, and it is not yet automated
   anywhere in the repo.

None of these five were reachable from `make test` or `make eval`. Findings 1, 2,
3, and 5 live entirely in Docker and container bring-up code that the offline
path never runs. Finding 4 is the sharpest example of why this matters even for
code the offline path does exercise indirectly. The packet-construction logic in
`generate_attacks.py` is shared between the `--write` path, used by every offline
test and the headline numbers in Section 6.1, and the `--send` path, used only
live. The offline path never calls `sendp()` or `send()`, so a bug that lived
only in how packets are transmitted, not in how they are built, was completely
invisible to a result of 100% precision, 100% recall, and 0% false-positive rate.

The general lesson is this. For any tool whose whole value is that it correctly
reads or produces real network traffic, whether a passive detector, a protocol
fuzzer, a traffic generator, or an IDS/IPS rule engine, a test suite based on
packet captures or in-memory objects is necessary but not sufficient. The bug
class that matters most for these tools, such as missing link-layer framing, a
config writer that quietly does nothing, or a parser that discards the very bytes
you are trying to detect, is by construction invisible to any test that never
actually puts bytes on, or reads them off, a real wire. The project's own R1
finding (Section 5.1) and the five deployment findings here are the same failure
mode found at two different layers of one codebase: code that looks correct, and
in R1's case is even provably correct against an in-memory unit test, but quietly
does the wrong thing, or nothing, once real bytes are involved. We take this as
an argument that, for security tooling which touches real wire traffic, running
the live path end to end is not an optional demo but a necessary validation step
that a passing offline suite cannot replace.

---

## 9. Limitations and threats to validity

- The corpus is synthetic, and the class balance is not realistic. The benign
  corpus now spans twelve categories, two of them chosen to be awkward for the
  detector, and it is no longer a single flow shape. It is still synthetic,
  though, and its roughly 55% benign share does not reflect how overwhelmingly
  benign real N3 traffic is. A measured false-positive rate of 0.0 on this corpus
  is far more informative than the earlier single-flow measurement, but it does
  not put a bound on the false-positive rate under production class imbalance, or
  against unusual-but-legitimate handset behaviour outside the twelve categories.
  Testing against captured operator traffic remains future work, and is limited
  by the legal and privacy issues in Section 11.
- R1's check is still a heuristic, now hardened but not cryptographic.
  `_looks_like_gtp()` together with the length-field and routable-inner-IP guards
  (Section 5.1) defeats the benign collisions and the evasions in Section 6.1.5.
  An attacker who fully understands the guard could still, in principle, craft a
  nested tunnel that passes all three checks yet is shaped to confuse some
  downstream parser differently from ours. That residual surface is untested and
  is inherent to any byte-pattern heuristic.
- R2's blind spots are documented, not closed. The known-gNB allowlist
  (Section 5.2) removes the handover false positives measured in Section 6.1.4,
  but a rogue that forges a legitimate gNB's source IP, or that claims a TEID
  never seen before, still evades R2 (Section 6.1.5). Both need control-plane
  correlation, which is out of scope for a user-plane-only tap. First-source-wins
  ownership also has no TEID ageing or expiry, so TEID recycling after a session
  ends, in a long-running deployment, is an unmeasured source of false positives.
- R3 works on ports and protocols, and is evaded by moving a control protocol off
  its usual port (Section 6.1.5). Closing this would need deep payload
  classification.
- R4 depends entirely on correct manual configuration of `--core-ips`. A core
  function outside the configured set is invisible (Section 6.1.5), and a wrong
  entry quietly disables the rule instead of raising an error.
- IPv6 coverage is partial. R1's nesting check now handles an IPv6 inner tunnel
  (Section 6.1.5), but R3 and R4 still inspect only IPv4 inner addresses, so
  control-plane smuggling or core targeting inside an IPv6 inner packet is not
  yet detected.
- The setup is one subscriber, one PDU session, and the test PLMN only. The
  handover scenario is modelled synthetically with two gNB IPs, not run against a
  live multi-gNB core, and no roaming or network-slicing scenarios were
  exercised.
- Performance was measured on a single core, on one lab VM, with no other load.
  The figure of about 1,450 packets per second (Section 6.1) reflects the real
  cost of dissecting and checking every packet, but it is not validated against
  production N3 packet rates, and no multi-core or sustained-load testing was
  done.
- The live-run finding counts (Section 6.2) come from a single run, not a
  repeated set of trials, and are not directly comparable in size to the offline
  corpus (Section 6.3 explains what is and is not comparable).

---

## 10. Future work

- Stateful TEID lifecycle tracking with explicit expiry, to address the R2
  limitation above.
- IPv6 inner-traffic coverage for R3 and R4.
- Growing the evasion suite (Section 6.1.5) from 11 hand-written cases into an
  automated fuzzer that mutates traffic around each rule's decision boundary, and
  closing the blind spots that have a user-plane-only signal (for example,
  classifying R3 payloads independently of port).
- A multi-gNB or roaming topology, to exercise TEID reuse across handovers for
  real rather than synthetically.
- The machine-learning extension sketched in `docs/ARCHITECTURE.md`: treating
  each rule's `Finding` output from `evaluate()` as a feature vector for a
  downstream classifier, instead of a final yes/no severity signal.
- Automating the recreate-and-reattach step from Finding 5 (`FINDINGS.md`),
  either as a `make redeploy` target or as a Compose health-check dependency, so
  it stops being a manual step.

---

## 11. Ethics and responsible use

Everything in this project targets a self-contained lab on a private
`10.10.10.0/24` Docker network, under the test PLMN `999/70`, which is reserved
for testing and is not a real operator's identity. The generator in `attacker/`
exists only to exercise the detector inside this isolated lab. It must not be
pointed at any network the operator does not own and is not explicitly authorised
to test. Generating GTP-U abuse traffic against a live mobile operator's
infrastructure is illegal in most jurisdictions, and it was never done,
attempted, or intended in this work. Every result in this paper was produced
entirely inside the isolated Docker lab described in Section 4.

---

## 12. Conclusion

`gtpu-abuse-lab` shows that meaningful, reproducible research on GTP-U tunnel
abuse does not need a closed commercial appliance or access to real operator
infrastructure. A small, fully open stack (a real 5G core and radio simulator, a
rule-based passive detector, and a labelled corpus generator, all in Docker) is
enough to produce rigorous, reproducible detection numbers (Section 6.1) and to
validate them against genuinely live, transmitted traffic (Section 6.2). The
detector's central technical contribution (Section 5.1) is a specific and
generalisable robustness requirement for passive GTP-U inspection: default
parsing libraries can quietly discard the exact structure you are trying to
detect, in a way that in-memory unit tests do not reveal. The project's own
deployment history (Section 8) turned out to be a second, independent example of
the same lesson at a different layer, and a concrete argument that, for security
tooling which touches real wire traffic, running the live path end to end is not
an optional demo but a necessary validation step that a passing offline test
suite cannot substitute for.
