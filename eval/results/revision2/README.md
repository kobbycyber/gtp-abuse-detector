# Revision 2 results

Result files behind every number in the revised manuscript
(`paper/manuscript_rev2.docx`). Development used seeds 1337, 1, 2, 3, 4 and one
live sequence at seed 1337; everything below is held out from that.
Intervals are Wilson 95% over the packets scored (`eval/external_eval.py: wilson`).

## Held-out seeds 101-110 (`eval/heldout.py`)

| File | Run | Recall | FPR |
|---|---|---|---|
| `heldout_plain.json` | plain outer header | 1.0 (0.9994-1.0) | 0.0 (0-0.0005) |
| `heldout_ext.json` | `--realistic-outer` (PDU Session Container on every outer header) | 1.0 (0.9994-1.0) | 0.0 (0-0.0005) |
| `heldout_ext_oldengine.json` | same, engine before the extension-header fix | 0.8 (0.790-0.810) | 0.0 |

6,000 malicious and 7,203 benign packets per run; the naive baseline scores recall 0.8 in all three.

## 5G-CGAD, University of Oulu (`scripts/revision2/run_external.sh`)

| File | GTP-U packets | Engine flagged | Rules |
|---|---|---|---|
| `oulu_benign.json` | 6,218,456 | 0 (upper 6.2e-7) | - |
| `oulu_encapsulation.json` | 290,225 | 290,225 | R1, R3 |
| `oulu_malformed.json` | 353,136 | 176,903 | R2 |
| `oulu_bruteforce_gpdu.json` | 878,333 | 56,002 | R2 |
| `oulu_bruteforce_multi.json` | 10,054,554 | 123,931 | R2 |
| `oulu_intraupf.json` | 426,949 | 1 | R3 |
| `oulu_ddos.json` | 11,561,011 | 109 | R3 |

Labels in 5G-CGAD are per scenario and per flow, so a flagged fraction in an attack
capture is not a recall. The nested scenario is the IP-wrapped form only; TEID
brute force is not detected (blind spot `r2_unseen_teid`).

## Live runs, three UEs (`scripts/revision2/run_live.sh`)

| Run | Seed / TEID | Malicious / benign | Findings (live = offline) | P / R / FPR | Real UE packets, findings |
|---|---|---|---|---|---|
| `live_L1/` | 2026 / 0x2 | 400 / 100 | 565 = 565 | 1.0 / 1.0 / 0.0 | 12,136, 0 |
| `live_L2/` | 4242 / 0x7 | 600 / 200 | 853 = 853 | 1.0 / 0.9967 / 0.0 | 19,390, 0 |

The two L2 misses are the first two packets of the sequence: TEID re-sourcing seen
before any packet from the legitimate gNB on that TEID (R2 first-source binding).

## Comparators (`eval/comparator_pcaps.py`, `comparators/`)

Zeek 8.2.2 (default scripts), Suricata 8.0.7 with ET Open (53,289 rules), tshark 4.6.6.
Zeek reports only `non-IP packet in GTPv1` for the bare-nested class and `GTP-in-GTP`
for the IP-wrapped class; Suricata raises no alert on any class.
`dissector_sources.md` records the source lines read in Scapy, Wireshark and Zeek.

## Cross-version (`xversion/`)

Finding streams for the seed-1337 corpus and held-out seed 101 (realistic outer)
under Scapy 2.4.4 and 2.7.0: byte-identical, 840 findings each.

## Timing (`latency_local.json`, `eval/latency.py`)

Five passes of the seed-1337 corpus: mean 716 µs, P50 602, P95 1,295, P99 1,944 µs,
about 1,400 pkt/s on one core.
