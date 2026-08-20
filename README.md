# GTP-U Abuse Lab

An open-source, Dockerised testbed and **passive detection framework for GTP-U
tunnel abuse**. It detects GTP-in-GTP nesting, TEID spoofing, and encapsulated
control-plane smuggling (PFCP / NGAP) in the 5G/4G user plane, the abuse class
that commercial GTP firewalls handle but no reproducible open tool does.

> **Scope / ethics.** Everything here targets a self-contained lab on a private
> `10.10.10.0/24` bridge using the test PLMN `999/70`. The traffic generator in
> `attacker/` exists solely to exercise the detector inside this lab. Do not
> point it at any network you are not authorised to test; generating GTP-U abuse
> against a live operator is illegal in most jurisdictions.

## What's inside

| Component | Role |
|---|---|
| `core/` | Open5GS all-in-one 5G core (AMF/SMF/UPF + support NFs) |
| `ran/` | UERANSIM simulated gNB + UE (generates real GTP-U on N3) |
| `detector/` | **The contribution**, passive Scapy detector + rules + metrics, plus a naive baseline (`baselines.py`) that quantifies the contribution |
| `attacker/` | Lab-only traffic: abuse generator, realistic benign generator (`benign_traffic.py`), crafted evasion suite (`evasions.py`) |
| `eval/` | Reproducible benchmark (`benchmark.py`) → `metrics.json` + `RESULTS.md`: metrics, baseline comparison, FP ablation, multi-seed stability, evasions |

## Two ways to run

### 1. Offline evaluation, no 5G core, fully reproducible (start here)

This is the path that produces your thesis numbers. It needs only Python + Scapy.

```bash
pip install scapy pytest
make test      # 19 tests: abuse detected, realistic benign clean, evasions, baseline & repro locked
make eval      # comprehensive benchmark -> eval/RESULTS.md
make evasions  # list the crafted evasion suite (what the detector must / can't catch)
```

Reference result (primary seed 1337, 1,320-packet corpus whose 720 benign
packets span **twelve** traffic categories, including adversarial
Unstructured-PDU bytes and legitimate handovers, plus 120 victim flows):
precision 1.0, recall 1.0, F1 1.0, false-positive rate 0.0, stable across five
seeds (σ = 0), ≈1,450 pkt/s single core measured over the full
serialize, dissect, and evaluate cycle (dissection is ~76% of that cost on this
host; timing the rules alone gives ≈6,000 pkt/s and is not a tap rate). The evaluation also reports a **naive-baseline comparison**
(the baseline misses 100% of GTP-in-GTP, this is the contribution,
quantified), a **false-positive ablation** tracing every residual FP to a
single mitigated cause, and an **evasion suite** documenting the detector's
blind spots explicitly. See `eval/RESULTS.md`.

### 2. Live lab, full stack in Docker

Needs a host with a real kernel, `/dev/net/tun`, and the `docker compose` plugin.

```bash
make build
make lab-up          # mongo + core + RAN + live detector
make logs            # watch the detector; UE gets a 10.45.x.x address
make attack          # fire the abuse corpus at the lab UPF
make lab-down
```

The detector runs in the **core's network namespace**, so it taps the exact
interface terminating N3, the same place you'd put a passive tap in production.

## Detection rules

| ID | Rule | Severity | What it catches |
|---|---|---|---|
| R1 | `GTP_IN_GTP` | critical | a GTP header nested inside GTP-U payload |
| R2 | `TEID_SPOOF` | high | a TEID re-sourced from a new IP |
| R3 | `CP_SMUGGLING` | critical | PFCP/NGAP/GTP-C encapsulated in user data |
| R4 | `INNER_TO_CORE` | high | inner IP aimed at a core NF, not the data network |

R1 actively **re-parses the inner bytes**: after capture, Scapy's default GTP-U
binding renders a nested GTP header as `Raw` (its payload heuristic only expects
IPv4/IPv6), so a naive `haslayer()` check misses tunnel-in-tunnel abuse. See
`docs/ARCHITECTURE.md`, this is a genuine passive-detection robustness finding.

## Repo layout

```
gtpu-abuse-lab/
├── docker-compose.yml     # wires the whole lab on 10.10.10.0/24
├── .env                   # PLMN, subscriber keys, addresses
├── Makefile               # make help
├── core/                  # Open5GS image + entrypoint + config overrides
├── ran/                   # UERANSIM image + gnb.yaml + ue.yaml
├── detector/              # rules.py, baselines.py, metrics.py, gtpu_detector.py, tests/
├── attacker/              # generate_attacks.py, benign_traffic.py, evasions.py
├── eval/                  # benchmark.py, run_eval.py, report.py -> RESULTS.md
├── viz/                   # live browser dashboard (server.py + index.html)
├── scripts/               # lab_up.sh / lab_down.sh -- one-command bring-up
├── paper/                 # research paper, results, findings, repro guide
└── docs/                  # ARCHITECTURE.md, LAB_GUIDE.md
```

## Live dashboard

```bash
python3 viz/server.py            # while the lab is up
```

Open **http://localhost:8090** for a live view: network topology, live
packet/GTP-U counters, a per-rule findings tally, and a scrolling live
findings feed, watch the N3 link flash when `make attack` fires. See
`viz/README.md` for details.

## Notes on reproducibility

Image tags drift. `.env` pins `UERANSIM_REF`; the core installs Open5GS from the
maintained PPA. If a NF config schema changes upstream, the entrypoint rebinds
only NGAP + GTP-U addresses and leaves the rest as packaged, pin full YAMLs in
`core/configs/` for an exact thesis appendix. The **offline eval path does not
depend on the live core at all**, so your metrics stay reproducible regardless.
