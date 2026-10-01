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
   diagnosis commands, and diffs for the seven defects: five found while
   bringing up the live lab for the first time (§8 of the paper), and two
   found later by a labelled live run (the UE data path, and R2 TEID
   ownership). This is the evidence log behind the paper's methodological
   argument.
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
live Open5GS 5G core + UERANSIM RAN in Docker. There the 500-packet attack
corpus raised 550 findings across all four detection rules (608 before the R2
ownership fix) from traffic that was actually transmitted, not replayed, and
per-packet scoring of the same corpus against its labels gives precision,
recall and F1 of 1.0 with FPR 0.0. Bringing that live path up for the first
time surfaced five real bugs — most notably that the project's own live
attack-traffic sender had been emitting malformed Ethernet frames since
inception, invisible to the fully-passing offline test suite. A later labelled
live run surfaced two more: the UE data path had never carried traffic, hidden
by a ping check that bypassed the tunnel, and R2 handed a TEID's ownership to
whichever source sent last, including a spoofer. We document all seven as a
case study in why passive/wire-facing security tooling needs live,
on-the-wire validation, not just pcap-replay or in-memory testing.
