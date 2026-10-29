---
title: "Response to reviewers"
subtitle: "Detecting bare-nested GTP-U tunnels that packet dissectors do not decode (revision 2)"
author: "Joseph Kwabena Fiagbor and Oliver Kornyo"
---

We thank the reviewers for careful and constructive reports. The revision changes the evaluation more than the text: every result now reported as evidence comes from data that played no part in changing the code. In short:

- **Independent data.** The engine was scored on the University of Oulu 5G-CGAD captures [25]: no finding on 6,218,456 benign GTP-U packets from 30 subscribers (95% upper bound 6.2 × 10⁻⁷), all 290,225 nested packets flagged, and TEID brute force not detected (Section 7.1, Table 12).
- **Held-out seeds.** Seeds 101 to 110 (13,203 packets) were scored with Wilson 95% intervals, including a run in which every outer header carries the PDU Session Container that real N3 traffic uses (Section 6.1, Table 7).
- **A defect found by the held-out run.** With realistic outer headers, the submitted engine missed every bare-nested packet, because the dissector stops at the extension header. The engine now walks the extension-header chain (Section 5.3), and a regression test covers it. We report the miss rather than hide it.
- **Real comparators.** Zeek 8.2.2 and Suricata 8.0.7 with 53,289 ET Open rules were run on identical per-class captures (Section 6.4, Table 10), and the dissector claim now rests on the source code of Scapy, Wireshark 4.6.6 and Zeek (Section 7.3).
- **Fresh live runs.** Two new sequences (seeds 2026 and 4242) were run with three subscribers. The live finding streams are identical to offline replay, 998 of 1,000 malicious packets are detected, and there is no false positive (Section 7.2, Table 13).
- **Scope.** The title, abstract and threat model are narrowed to the bare-nested form, and Section 8 (the defects narrative) is removed.

All result files and the scripts that produce them are in the repository under `eval/results/revision2/`.

# Priority items in the summary report

| # | Request | Response |
|---|---|---|
| 1 | Independent traffic with confidence bounds | Done. We scored 5G-CGAD (Section 7.1, Table 12) and the held-out seeds (Table 7). Every rate now carries a Wilson 95% interval over the packets scored [32]. |
| 2 | Fix the scope of the headline claim | Done. The new title is "Detecting bare-nested GTP-U tunnels that packet dissectors do not decode". The abstract states that the bare form needs an on-path position or a non-IP session and that the IP-wrapped form is decoded natively. "Tunnel abuse" is no longer in the title. |
| 3 | Correct the related work | Done. 5G-CGAD is cited and described (Section 3.2). Gap 2 is rewritten, Juniper, Fortinet, Palo Alto, Zeek, Suricata and Snort are discussed (Section 3.3), and Table 1 has new rows and neutral columns. |
| 4 | Do not score fixes on the runs that motivated them | Done. Section 5.5 separates development data (seeds 1337 and 1–4, live seed 1337) from held-out data (seeds 101–110, 5G-CGAD, live seeds 2026 and 4242). The live runs use three subscribers and two sequences. |
| 5 | Remove project history, give the missing parameters, make the repository match | Done. Section 8 is removed and the history passages are cut. The gate parameters are in a new Table 5, and the live class split is in Table 13. The repository now has the MIT licence, 25 tests, `make live-score` and the revision-2 results. |

# Reviewer 1

**1.1 The corpus is partly true by construction.** We agree, and Section 6.1 says so for R3 and R4. The independent evidence is now 5G-CGAD (Section 7.1), which other researchers generated. Section 8 states plainly that 5G-CGAD contains only the IP-wrapped form, so the engine's detection of the bare form has been measured only on packets we generated.

**1.2 Five seeds with σ = 0 are not five tests.** Agreed. We dropped σ. Rates are reported with Wilson 95% intervals over the packets scored (Section 5.5, Table 7). The traffic itself now varies in three ways: realistic outer headers in the held-out run, the independent captures, and live runs with real subscriber traffic.

**1.3 Corrections scored on the runs that prompted them.** Corrected. The R2 correction and the extension-header handling are both in the frozen engine, and neither the held-out seeds nor the new live sequences existed before the freeze. Section 7.2 states that the development live sequence is not counted as held-out evidence. Section 5.5 states that the extension-header change was made after inspecting the 5G-CGAD header layout, and that it does not raise their scores (the earlier engine also flags the IP-wrapped packets in full).

**1.4 Live validation too small; the attacker is not a subscriber.** We added two fresh live sequences with three UEs: L1 (400 malicious / 100 benign) and L2 (600 / 200). Table 13 gives the class split. Both live streams are identical to an offline pass. L2 has two misses, explained in Section 7.2 as the R2 cold-start case. Section 5.1 still states that the attacker is a raw-socket process on N3, standing in for the on-path position, and Section 7.2 states what the live runs show and what they do not.

**1.5 The baseline gives 0.0 by definition; F1 depends on the 20% share.** Agreed on both points, and both are now stated. Section 6.2 says the zero is deterministic. Fig. 5(c) plots baseline F1 = 2(1 − s)/(2 − s) against the bare-nested share s. Real comparators are in Section 6.4 and Table 10. Vendor GTP-in-GTP checks are closed, and we had no access to a device. Section 3.3 cites their documentation, Section 8 states the limit, and the per-class captures are released so that the check can be repeated.

**1.6 Scapy 2.4.4 vs 2.7.0 on the same input.** Done. The seed-1337 corpus and held-out seed 101 (realistic outer headers) were scored under both releases. The finding streams are byte-identical, 840 findings each (Section 7.3, `eval/results/revision2/xversion/`).

**1.7 Only seven of eleven cases are evasions.** Agreed. Table 9 now labels each case: seven evasions (three caught, four blind spots), three positive controls and one negative control. On new evasions, extension-header flags were tested at scale in the held-out realistic-outer run, which exposed and led to the fix of the extension-header defect. We have not added further evasion constructions in this revision. Padding is covered by the length check in Table 5. IPv6 extension headers and inner fragmentation are left as named future work, consistent with the partial IPv6 scope stated in Section 4.

**1.8 FPR should be stated against the 23 at-risk packets.** Done. Section 6.5 and Table 7 give the at-risk counts and their bounds: 0 of 23 (upper bound 0.143) at seed 1337, and 0 of 334 (upper bound 0.0114) over the held-out seeds. The 6.2 million benign 5G-CGAD packets are cited as the stronger evidence.

**1.9 Capture point under IPsec.** Added a paragraph in Section 2.2. The tap needs N3 in clear, either on a segment without IPsec or behind the termination point (the UPF host or the inner side of a security gateway); the testbed corresponds to the latter. Section 4 now refers to it.

**1.10 Wireshark version and preference.** Section 7.3 names Wireshark 4.6.6, the `gtp.dissect_tpdu_as` preference with its default heuristic setting, and the heuristics registered on `gtp.tpdu` (IP and Ethernet; no GTP heuristic).

# Reviewer 2

**2.1 Scope in the title and abstract.** Done. See priority item 2.

**2.2 The Oulu dataset.** Cited as [25], described in Section 3.2, added to Table 1, and Gap 2 is revised. We evaluated on all of its scenarios (Section 7.1, Table 12). Its nested scenario is the IP-wrapped form, which we report as such.

**2.3 Commercial and IDS comparators; Table 1 columns.** Section 3.3 discusses Juniper's GTP-in-GTP check, Fortinet's statement that it cannot open nested tunnels, Palo Alto's GTP-U checks, Zeek, Suricata and Snort 3. Zeek and Suricata are run in Section 6.4. Table 1 columns now record what each item is, how it handles the bare form, whether it can be checked by a third party, its labels, and whether it was assessed on others' data.

**2.4 The flow-indistinguishability claim.** Softened. Section 3.3 now presents it as an argument, says that no flow-based or learned detector was run, and leaves the question open. Gap 3 now acknowledges that our development corpus has the same weakness, which is why the held-out and independent evaluations were added.

**2.5 The Section 8 lesson is overgeneralised.** Section 8 is removed, together with its general lesson. The defect write-up remains in the repository (`paper/FINDINGS.md`) and is not cited as a result.

**2.6 First-byte dispatch as a hypothesis.** We read the source of each tool (Section 7.3; the source lines are recorded in `eval/results/revision2/dissector_sources.md`). Section 6.2 now says that the dispatch was first inferred from the layer stacks and then confirmed in the source. The claim is limited to the three open implementations read.

**2.7 "Robust" and "validated".** The Fig. 5 legend now reads "engine" and "naive baseline". "Validated" is removed from the abstract and conclusion. The one remaining use says what was *not* validated (Section 8).

**2.8 Main claim versus supporting contributions.** The contribution list in Section 1 now marks the dissector finding and the re-parse as the main claim and the rest as supporting.

# Reviewer 3

**3.1 Project history in the body.** Removed: the withdrawn draft figure, the README rate, the timing-harness history and the "added during revision" narrative. Two pieces of history remain because other reviewers asked for them: the development-run account of R2 in Section 7.2 (point 3.3) and the note in Section 5.5 on when the extension-header handling was added (point 1.3).

**3.2 Message types and gate parameters.** The new Table 5 lists all six message types (0x01, 0x02, 0x1A, 0x1B, 0xFE, 0xFF), the version, protocol-type and length checks with their thresholds, the 20-byte G-PDU minimum and the routable-inner guard.

**3.3 R2: 146 findings versus 31 errors; class split.** Section 7.2 explains the difference. The 146 counts R2 firings, most of them correct, on malicious packets. The 31 counts packets with the wrong verdict: 16 benign packets that raised R2 and 15 spoofs that raised nothing. Table 13 gives the class split of every live run.

**3.4 Table 5 too dense.** Split. Rules are now in Table 6 (ID, name, condition), gate parameters in Table 5, and the preconditions moved into the text of Section 5.4.

**3.5 IPv6 in the scope statement.** Done. The abstract says that IPv6 inner coverage is partial, and Section 4 has a scope paragraph naming the SCTP check and R4 as IPv4-only.

**3.6 Repository does not match the paper.** Fixed. The repository now has an MIT `LICENSE` file. The README shows 25 tests, matching the paper, and documents `make live-score`. Every result file and run script of the revision is under `eval/results/revision2/` and `scripts/revision2/`. The root-cause file for the development defects is `paper/FINDINGS.md`.

**3.7 Single-subscriber synthetic benign mix; TEID ageing.** Both are stated in Section 8. The benign evidence now also includes 6.2 million packets from 30 subscribers on another testbed, and the live runs use three subscribers.

**3.8 Long title, first-person asides, loose wording.** The title is shortened, the asides are removed, and "core competency" is reworded.
