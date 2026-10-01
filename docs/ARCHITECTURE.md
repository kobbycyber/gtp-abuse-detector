# Architecture

## Data path

```
 UE (uesimtun0)                  gNB (UERANSIM)
 10.45.0.x ── PDU session ──►    10.10.10.20
                                      │
   ┌──────────────────────────────────┘  N3 / GTP-U, UDP 2152
   ▼
 ┌─ core network namespace (10.10.10.10) ─────────────────────────────┐
 │ eth0 ──► UPF (Open5GS) ──► ogstun 10.45.0.1/16 ──► NAT ────────────┼──► data network
 │  │ ▲                                                               │
 │  │ └── ATTACKER (lab only): crafted GTP-U to the UPF               │
 │  │     over a raw socket; not a UE, no PDU session                 │
 │  ▼                                                                 │
 │ DETECTOR (tap): sniffs eth0 passively, udp port 2152               │
 └────────────────────────────────────────────────────────────────────┘
```

- **N2 / NGAP** (SCTP 38412): gNB ⇄ AMF signalling.
- **N3 / GTP-U** (UDP 2152): user-plane tunnel gNB ⇄ UPF. This is what we inspect.
- The **UE data path**: the UE requests an IPv4 PDU session; its packets leave
  the gNB as uplink GTP-U, the UPF decapsulates them onto `ogstun` (given
  10.45.0.1/16 by `core/entrypoint.sh`), an iptables MASQUERADE rule from the
  same script NATs them out, and replies return as downlink GTP-U. `docker compose exec ran ping -I uesimtun0 -c3 8.8.8.8`
  exercises this path.
- The **attacker** is not a UE and holds no PDU session. It shares the core's
  network namespace (`network_mode: service:core`) and writes crafted GTP-U with
  a raw socket onto the core's `eth0` (the N3 interface), addressed to the UPF.
  UERANSIM does not encapsulate these packets. It stands in for the on-path
  position of the threat model, so the detector sees benign and abusive GTP-U on
  the same interface. Whether the UPF acts on the crafted frames was not
  measured; the detector observes them on `eth0` like a tap.

## Why the detector shares the core's network namespace

Container-to-container traffic on a bridge is switched, so a third container does
not see it. Putting the detector in `network_mode: service:core` places it on the
UPF's interface — the realistic tap point — with no port mirroring hacks.
The attacker uses the same mode, so its frames go out on the interface the
detector sniffs.

## The re-parsing subtlety (R1)

Scapy binds a GTP-U G-PDU payload to IPv4/IPv6 by inspecting the first nibble.
A **nested** GTP header (`0x30`–`0x3f`) matches neither, so after `rdpcap()` /
live capture the inner tunnel deserialises as a non-IP layer and
`pkt.haslayer(GTP_U_Header)` on the inner returns false. Which non-IP class
Scapy picks depends on the outer message type: a bare outer leaves the nested
bytes as `Raw`, but a realistic outer **G-PDU** (the form a UPF decapsulates)
makes Scapy guess `PPP`. So the re-parse keys on the raw *bytes*, not on the
`Raw` class:

```
_looks_like_gtp(buf):   version==1 AND PT set AND msg_type known
                        AND length field consistent (8 + len == datagram size)
_reparse_inner():       if inner is not IP/IPv6/GTP: re-check bytes(inner);
                        if looks_like_gtp -> GTP_U_Header(bytes(inner))
_carries_inner_ip(g):   nested header must forward a routable inner IPv4/IPv6
```

A `Raw`-only version of `_reparse_inner()` silently missed the realistic
G-PDU-outer case (Scapy returned `PPP`) until a probe capture with a valid outer
message type exposed it; the byte-level re-parse catches both. `tshark` and Zeek
exhibit the same first-byte blind spot on that probe (`paper/REPRODUCE.md`
Part D).

The last two conditions are hardening added after a realistic benign corpus
(`attacker/benign_traffic.py`) exposed a false positive: 5G *Unstructured* PDU
sessions carry arbitrary non-IP bytes, some of which collide with the GTP byte
pattern. Requiring the nested header's length field to be self-consistent and
to actually carry a routable inner IP removes that false-positive class
entirely (0 FP across 200 adversarial payloads) at no cost to recall — the
naive-baseline comparison (`detector/baselines.py`) confirms the robust
detector still catches 100% of real GTP-in-GTP where the naive one catches 0%.

Without any re-parse, R1 silently misses 100% of GTP-in-GTP on captured
traffic while still passing naive in-memory unit tests — a cautionary result
for the methodology chapter (in-memory tests can hide dissection gaps that only
appear on the wire). The `eval/benchmark.py` harness measures this delta
directly rather than asserting it.

## TEID ownership (R2)

R2 keeps an owner per (receiving address, TEID), where the receiving address is
the outer IP destination. TS 29.281 makes a TEID unique only within the
endpoint that receives it, so the same number on the UPF's uplink and on a
gNB's downlink names two different tunnels. In the lab the real session used
uplink TEID 0xb2aa and downlink TEID 0x1, and the attack corpus sends to the
UPF on TEID 0x1; a key on the TEID alone would conflate them.

```
key = (outer dst, TEID)        outer = the IPv4/IPv6 header carrying the tunnel
no owner yet                          -> record src as owner, no finding
src == owner                          -> no finding
src != owner, src is allowlisted gNB  -> owner = src, no finding
src != owner, otherwise               -> R2 finding, owner unchanged
```

The first source wins. A packet from any other source raises R2 and does not
transfer ownership, so a rogue cannot take a TEID over. The exception applies
only when the gNB allowlist (`--gnb-ips`) is configured: an allowlisted gNB
always takes ownership, which covers a handover and the real gNB reclaiming a
tunnel a rogue was seen on first, for example after a detector restart. Without it
every change is flagged and ownership never moves, so a handed-over session
keeps alerting for as long as it sends from the new gNB. The naive baseline in
`detector/baselines.py` uses the same logic.

An earlier version moved ownership to whichever source sent last and keyed on
the TEID alone. The offline corpus could not expose this, because it gives
every spoof its own victim TEID, emits all victims first and has a single
receiver. The live corpus interleaves spoofs and legitimate packets on one
TEID. There the old rule flagged the legitimate packet that followed a spoof;
16 of those packets were benign (16 false positives). It also missed a spoof
that followed another spoof (15 false negatives).

## Metrics

`metrics.py` records per-packet latency (mean/p50/p95/p99/max, µs) and, when a
labels file is supplied, TP/FP/FN/TN → precision, recall, F1, and FPR. Latency
inverse gives a single-core throughput estimate for the results chapter.

## Extending

- Add a rule: write a pure `rule_x(pkt, state) -> list[Finding]` in `rules.py`
  and append it to `ALL_RULES`. Add a matching builder in `attacker/` and a test.
- Swap heuristics for ML: keep `evaluate()` as the feature extractor and feed
  `Finding` counts / tunnel features to a classifier — a clean thesis extension.
