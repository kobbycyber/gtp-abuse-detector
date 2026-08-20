# `paper/` — Research Documentation

This folder documents the results, novel contributions, and reproducibility
of the `gtpu-abuse-lab` project. It is self-contained: nothing here modifies
the main project (`core/`, `ran/`, `detector/`, `attacker/`, `eval/`), it
only documents and analyzes it. Where this folder references code changes
made to the main project during validation, those changes are already
applied in the working tree — `FINDINGS.md` documents them with full diffs
for the record.

**Read in this order:**

1. **[`PAPER.md`](PAPER.md)** — the research paper. Motivation, background,
   architecture, detection methodology (including the R1 nested-GTP
   re-parsing finding, the project's main technical contribution),
   evaluation results, the deployment-bugs case study, limitations, and
   future work.
2. **[`RESULTS.md`](RESULTS.md)** — every raw number referenced by the
   paper: environment/version table, unit test output, offline corpus
   metrics (precision/recall/F1/FPR, latency percentiles), live-run
   findings tally, and offline↔live coverage-parity comparison.
3. **[`FINDINGS.md`](FINDINGS.md)** — detailed root-cause analysis, exact
   diagnosis commands, and diffs for the five deployment bugs found while
   bringing up the live lab for the first time (§8 of the paper). This is
   the evidence log behind the paper's methodological argument.
4. **[`REPRODUCE.md`](REPRODUCE.md)** — exact, manual, copy-pasteable
   commands to reproduce every result in this folder from a clean checkout,
   for both the offline (no Docker/root) and live (full Docker lab) paths,
   including every operational gotcha hit along the way (Docker group
   permissions, the `network_mode: service:core` recreation trap, etc.).
   Deliberately does not hide behind `make` targets, so you can see and
   adapt exactly what each step does.

## One-paragraph summary

`gtpu-abuse-lab`'s passive GTP-U tunnel-abuse detector achieves precision
1.0 / recall 1.0 / F1 1.0 / FPR 0.0 on a reproducible 1,320-packet labelled
corpus (no Docker required), and was further validated against a genuinely
live Open5GS 5G core + UERANSIM RAN in Docker, where it caught 131 real
findings across all four detection rules from traffic that was actually
transmitted, not replayed. Bringing that live path up for the first time
surfaced five real bugs — most notably that the project's own live
attack-traffic sender had been emitting malformed Ethernet frames since
inception, invisible to the fully-passing offline test suite — which we
document as a case study in why passive/wire-facing security tooling needs
live, on-the-wire validation, not just pcap-replay or in-memory testing.
