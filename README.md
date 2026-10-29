# GTP-U Abuse Lab

A passive detector for GTP-U tunnel abuse in the 5G user plane, with a
reproducible Docker testbed (Open5GS + UERANSIM), a seeded traffic generator
with per-packet labels, and the evaluation behind the paper

> **Detecting bare-nested GTP-U tunnels that packet dissectors do not decode**
> J. K. Fiagbor and O. Kornyo, KNUST. Manuscript: [`paper/manuscript_rev2.pdf`](paper/manuscript_rev2.pdf)

**Step-by-step guide for everything (install, offline, held-out, external data,
comparators, live lab, figures): [`SETUP.md`](SETUP.md).**

> **Scope and ethics.** Everything here targets a self-contained lab on a
> private `10.10.10.0/24` network using the test PLMN `999/70`. The traffic
> generator in `attacker/` exists only to exercise the detector inside this
> lab. Do not point it at any network you are not authorised to test;
> generating GTP-U abuse against a live operator is illegal in most
> jurisdictions.

## The finding in one paragraph

Scapy, Wireshark and Zeek decide what a GTP-U G-PDU carries from the version
nibble of its first payload byte (4 = IPv4, 6 = IPv6). A second GTP-U header
placed directly after the outer one starts with `0x3X`, so none of them decodes
it as GTP-U, and a detector that asks "is the payload itself GTP-U?" never sees
it and reports no error. This **bare-nested** form needs an on-path position on
N3 or a non-IP (Unstructured/Ethernet) session; the **IP-wrapped** form an
ordinary subscriber can send is decoded natively. The engine here walks the
outer extension-header chain, re-dissects the payload behind a byte-level
plausibility gate and a routable-inner guard, and raises R1.

## Results at a glance

| Evaluation | Data | Result |
|---|---|---|
| Held-out seeds 101–110, realistic N3 framing | 13,203 packets (6,000 malicious) | recall 1.0 (95% CI 0.9994–1.0), FPR 0.0 (0–0.0005) |
| Same, without extension-header handling | same | recall 0.8: every bare-nested packet missed |
| Naive baseline (no re-parse) | same | bare-nested recall 0.0 |
| Oulu 5G-CGAD benign (independent) | 6,218,456 GTP-U packets, 30 UEs | 0 findings |
| Oulu 5G-CGAD GTP encapsulation | 290,225 packets (IP-wrapped) | all flagged |
| Oulu 5G-CGAD TEID brute force | 10.9 M packets | not detected (documented blind spot) |
| Live, 3 UEs, fresh seeds 2026 and 4242 | 1,000 malicious / 300 benign | 998 detected, 0 false positives, live = offline |
| Zeek 8.2.2 / Suricata 8.0.7 + ET Open | per-class captures | Zeek flags only the IP-wrapped form; Suricata flags nothing |
| Cost | one core | ~716 µs/packet, ~1,400 pkt/s |

Every number has a result file in [`eval/results/revision2/`](eval/results/revision2/README.md).

## Quick start (offline, 2 minutes, no Docker)

```bash
git clone https://github.com/kobbycyber/gtp-abuse-detector.git
cd gtp-abuse-detector
python3 -m venv .venv && source .venv/bin/activate
pip install scapy pytest
make test        # 25 passed
make eval        # development benchmark -> eval/RESULTS.md
make heldout     # held-out seeds 101-110 -> eval/results/
```

`make help` lists every target. The full walkthrough, including the live 5G
lab, is in [`SETUP.md`](SETUP.md).

## Detection rules

| ID | Rule | Severity | What it catches |
|---|---|---|---|
| R1 | `GTP_IN_GTP` | critical | a GTP header nested inside the GTP-U payload |
| R2 | `TEID_SPOOF` | high | a TEID, scoped to its receiving address, sent from a source other than its first owner |
| R3 | `CP_SMUGGLING` | critical | SCTP, or UDP to PFCP/GTP-C/GTP-U ports, inside user data |
| R4 | `INNER_TO_CORE` | high | an inner packet aimed at a configured core NF address |

The R1 gate (all on the bytes after the outer header and its extension
headers): GTP version 1 with the protocol-type bit set; message type one of
0x01, 0x02, 0x1A, 0x1B, 0xFE, 0xFF; `8 + length` at most the bytes present and
at least that minus 4; G-PDU/end-marker length ≥ 20; and the recovered header
must forward IPv4 or IPv6. Known blind spots (documented, tested): an unseen
TEID becomes owned by its first sender, a forged gNB address, PFCP on a
non-standard port, a core NF missing from the configured set, and SCTP/R4 on
IPv6 inner packets.

## Repository layout

```
gtp-abuse-detector/
├── SETUP.md               # step-by-step guide for everything
├── Makefile               # make help
├── docker-compose.yml     # the lab on 10.10.10.0/24
├── .env                   # PLMN, subscriber keys, addresses, UE_COUNT
├── core/                  # Open5GS image + entrypoint
├── ran/                   # UERANSIM image + gnb.yaml + ue.yaml
├── detector/              # rules.py, baselines.py, metrics.py, gtpu_detector.py, tests/
├── attacker/              # generate_attacks.py, benign_traffic.py, evasions.py, dissector_probe.py
├── eval/                  # benchmark, heldout, external_eval, comparator_pcaps, latency
│   └── results/revision2/ # result files behind every number in the manuscript
├── scripts/               # lab_up.sh, lab_down.sh, revision2/ (fetch data, external, comparators, live)
├── viz/                   # live browser dashboard
├── paper/                 # manuscript (docx/pdf), response to reviewers, figures; archive/ = earlier drafts
└── docs/                  # ARCHITECTURE.md, LAB_GUIDE.md
```

## Citing the data used

The independent evaluation uses the 5G Core GTP-U Attack Dataset (5G-CGAD),
S. P. Wengappuli Arachchige, Y. Siriwardhana and T. Hewa, University of Oulu,
2025, CC BY 4.0, doi:10.23729/fd-b9459ea4-88a7-35c2-992e-f178a294c12d. It is
not redistributed here; `make fetch-data` downloads it.

## Licence

MIT. See [`LICENSE`](LICENSE).
