# Alpha 2A — W02e-F SELinux matrix v4 (MET-ENFORCE-016)

> Current-status page for W02e-F. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and phase
> status; the adopted v3 matrix is described in its [README](../../architecture/selinux-matrix/README.md).

W02e-F: **ADOPTED_DATA_CONTRACT.** The successor matrix `planeon.internal.selinux-matrix/v4` passed its independent
source-only review (round 1 CHANGES_REQUIRED on wording only, round 2 PASS_FOR_SOURCE_PUBLICATION). It answers the W02e
round-3 findings K2, K3, K4 and K6; K1 and K5 stay carried as the v3 status records them. The v3 matrix is
byte-identical. DATA_CHECK_ONLY: no policy module is written, compiled or loaded, and all E01-E12 remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/selinux-matrix-v2/README.md): what v4 changes and the dispositions.
- [Matrix](../../architecture/selinux-matrix-v2/matrix.json): 109 deny assertions (v3's 100, plus one
  `/proc` assertion per planeon target and A66, no policy load before the seal).
- [Vectors](../../architecture/selinux-matrix-v2/vectors.json): 1873 access checks and 55 mutation checks; every v3
  vector keeps its identifier.
- Reference evaluator `scripts/selinux_matrix_v2.py` (the v3 evaluator with only the matrix version changed).

## Independent review

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | CHANGES_REQUIRED (text only: F1, F2 MINOR; F3-F5 NOTE) | `review-round1.json` | `round1/` (changed files) and current files |
| 2 | PASS_FOR_SOURCE_PUBLICATION (1 finding, a NOTE) | `review-round2.json` | current files |

The reviewer was a separate agent that did not author the contract. It worked read-only, replayed every vector, re-ran
the round-3 probes and checked the kernel statements against Linux v6.12. The
[status record](../../architecture/selinux-matrix-v2/status.json) derives the adoption state from the verdict, and
`scripts/validate_selinux_matrix_v2.py` replays the contract and checks that derivation.

## Carried findings (none blocking)

- **G1** (NOTE) → Next matrix revision (NOTE): README 'Booleans and states' and the round-3 disposition table should name K1's carry to W01's record as the introduction does

## Still open

All E01-E12 and T01-T08. The policy module, its compilation and its behaviour on the enrolled kernel (W03, T04); K1 (W02a-F,
T04, W01's record) and K5 (W03, T04). W03-W07 remain gated. Alpha2 remains open; model-effort transition NOT_DUE.
