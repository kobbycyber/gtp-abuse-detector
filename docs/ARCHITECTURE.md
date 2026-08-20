# Architecture

## Data path

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

- **N2 / NGAP** (SCTP 38412): gNB ⇄ AMF signalling.
- **N3 / GTP-U** (UDP 2152): user-plane tunnel gNB ⇄ UPF. This is what we inspect.
- The **attacker** models a compromised gNB/UE: it injects crafted GTP-U onto the
  same segment so the detector sees benign + abusive traffic together.

## Why the detector shares the core's network namespace

Container-to-container traffic on a bridge is switched, so a third container does
not see it. Putting the detector in `network_mode: service:core` places it on the
UPF's interface — the realistic tap point — with no port mirroring hacks.

## The re-parsing subtlety (R1)

Scapy binds a GTP-U G-PDU payload to IPv4/IPv6 by inspecting the first nibble.
A **nested** GTP header (`0x30`–`0x3f`) matches neither, so after `rdpcap()` /
live capture the inner tunnel deserialises as `Raw`, and `pkt.haslayer(GTP_U_Header)`
on the inner layer returns false. A passive detector reading real bytes must
therefore actively re-interpret the payload:

```
_looks_like_gtp(buf):   version==1 AND PT set AND msg_type known
                        AND length field consistent (8 + len == datagram size)
_reparse_inner():       if Raw and looks_like_gtp -> GTP_U_Header(buf)
_carries_inner_ip(g):   nested header must forward a routable inner IPv4/IPv6
```

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

## Metrics

`metrics.py` records per-packet latency (mean/p50/p95/p99/max, µs) and, when a
labels file is supplied, TP/FP/FN/TN → precision, recall, F1, and FPR. Latency
inverse gives a single-core throughput estimate for the results chapter.

## Extending

- Add a rule: write a pure `rule_x(pkt, state) -> list[Finding]` in `rules.py`
  and append it to `ALL_RULES`. Add a matching builder in `attacker/` and a test.
- Swap heuristics for ML: keep `evaluate()` as the feature extractor and feed
  `Finding` counts / tunnel features to a classifier — a clean thesis extension.
