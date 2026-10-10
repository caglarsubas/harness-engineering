# Alpha 2A — W02 notes errata (W02-CLEANUP, MET-ENFORCE-023)

> Current-status page for W02-CLEANUP. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet status;
> the errata are [`architecture/w02-notes-errata/`](../../architecture/w02-notes-errata/README.md).

Three merged packets carried review notes forward: W02a-F2 (native-profile-v3 round 6: R6-1, R6-2, R6-3), W02g-F2 (I06
backend profile v2: R2-4, R3-1, R3-2) and PERF-032-F (MET-PERF-032 round 3: F12-F15). By owner decisions Q-S = A and
Q-F = A (2026-10-10, via the lane monitor) they are answered in one packet as errata records, with no contract version,
rule, vector or model change:

- **Native profile v3**: counted replacements in the README (the K1 guarantee in decision 2's terms, the kernel image
  or UKI and systemd-stub sidecars as W03/T04 state, the environment sentence, the credentials and SMBIOS
  kernel-cmdline-extra sentences) and a comment-only replacement in the model, checked by token and syntax-tree
  equality; 39 R6-3 vectors (bound pairs, word-order and grammar-word maintenance entries, optional patterns) replayed
  through the unchanged v3 model, each weaker binding round 6 named caught by at least one.
- **I06 v2**: distinct round-2 headings and pointers (R3-1), the Files table and "Still open" (R3-2), and R2-4 by its
  documented alternative (SHA-256 distinctness relies on the observed backend captures). The distinct-verityDigest rule
  and R3-3 go to W02-PROD.
- **PERF-032-F**: the F12 route-setup check, the F14 exact model-symbol pin and the F15 jsonschema-oracle tripwire as
  `scripts/perf032_followup.py`, with the F13 wording in the PERF-032 docstrings, test and catalogue lines. F15 is a
  tripwire for named changes, not a proof; the PERF-032 layer's byte pin stays the guard.

Review: six independent rounds, the sixth PASS_FOR_SOURCE_PUBLICATION with two notes, carried; by owner decision round 6
is final. The new layer `scripts/validate_w02_notes_errata.py` binds every reviewed file and checked input by digest and
checks each round's exact subject list, binding rounds 1 to 5 to their kept copies. Four shared files (the PERF-032
validator and test, the master plan and this catalogue) were reviewed in round 6 on base 5fab673 and here also carry the
mechanical edits of MET-ENFORCE-021, MET-ENFORCE-022 and this packet, so for them the layer requires each F13 edit to be
present and each replaced wording to be gone; the authority pins their exact bytes. It then runs both modules from this
era's reviewed bytes. DATA_CHECK_ONLY.
