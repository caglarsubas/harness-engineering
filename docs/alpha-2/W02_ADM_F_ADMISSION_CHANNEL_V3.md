# Alpha 2A — W02-ADM-F admission-channel successor contracts (MET-ENFORCE-015)

> Current-status page for W02-ADM-F. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and phase
> status. W02-ADM-F folds the follow-ups W02b-F2, W02f-F and W02c-F2 into one packet (owner decision, 2026-10-08).

W02-ADM-F: **ADOPTED_DATA_CONTRACT** for all three successors, after one combined independent source-only review (round 1
PASS with six findings answered, round 2 PASS_FOR_SOURCE_PUBLICATION). The adopted v2 contracts are byte-identical, and so
is the sealed A2 manifest file. DATA_CHECK_ONLY: nothing is opened, forwarded, installed or signed, and all E01-E12 remain
OPEN_UNPROVEN.

## Contracts

- [I05 v3](../../architecture/i05-gate-channel-v3/README.md), `planeon.internal.effect-gate-frame/v3` (215 cases): the
  upstream exchange is bounded (900 s from consumption, then aborted IO_AMBIGUOUS and HELD), a finer storage-failure
  injection pins the drain and deny failure paths, the double-fault residual's exact precondition is stated, the v1
  clauses v2 dropped are restored, and an incomplete priorBindings record is refused.
- [POLICY-ADMISSION-SEMANTICS/v3](../../architecture/admission-semantics-v3/README.md) (114 cases): manifest constraints
  MC39 (no pod-level resources), MC40 (no affinity or topology spread) and MC41 (closed volume sources); the env and volume
  defaults are allowed fixed deltas modelled in `final_object`; A1 and A2 claims need the new evidence (C12, C27), and v2
  claims are refused (C03).
- [I07 v3](../../architecture/i07-policy-write-v3/README.md), `planeon.internal.policy-write-frame/v3` (227 cases): on the
  I05 v3 gate, four more conditional response constraints, the 10-second write bound as an abort, the restart-reason
  wording, and no cluster scope.

## Independent review

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | PASS_FOR_SOURCE_PUBLICATION (2 MINOR, 4 NOTE; all answered in round 2) | `review-round1.json` | `round1/` (changed files) and current files |
| 2 | PASS_FOR_SOURCE_PUBLICATION (3 findings, none blocking or major) | `review-round2.json` | current files |

The reviewer was a separate agent that did not author the contracts. It worked read-only against the exact bytes,
replayed every vector of all three contracts, re-ran the original reviews' probes and ran bounded randomized campaigns,
one process at a time. The [review brief](../../architecture/w02-adm-f/REVIEW_BRIEF.md) and source index sit with the
records; each contract's status record derives its adoption state from the final verdict, and
`scripts/validate_admission_channel_v3.py` replays all three contracts and checks that derivation.

## Carried findings (none blocking)

- **AF2-I05-1** (NOTE) → W03 (NOTE): pin with a vector that a second STORAGE_FAIL_AFTER replaces the first (stated in the README and model, not pinned)
- **AF2-ADM-1** (MINOR) → W03 (T03, MINOR): container lifecycle hook httpGet defaults (path '/', scheme HTTP) have no named disposition; name them ALLOWED_FIXED (not modelled), model them, or rule hooks out with a manifest constraint
- **AF2-ADM-2** (NOTE) → W03 (NOTE): README constraint table MC39 cell should also name the pod-level limit defaulting

## Still open

All E01-E12 and T01-T08; the native comparison of the modelled defaults against a real apiserver (W03, T03); the gate,
writer, signer, substrate and storage formats (W03). W03-W07 remain gated. Alpha2 remains open; model-effort transition
NOT_DUE.
