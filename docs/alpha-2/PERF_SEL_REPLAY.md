# Alpha 2 — PERF-SEL: one SELinux matrix replay per layer test file (MET-PERF-036)

> Current-status page for PERF-SEL. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and phase
> status.

MET-PERF-036 cuts the cost of the two SELinux matrix layer test files (`tests/test_selinux_matrix.py` for matrix v3,
`tests/test_selinux_matrix_v2.py` for matrix v4) without changing what any validator refuses. Owner decision
(2026-10-09, via the lane monitor): a separate small PERF packet after MET-PERF-035.

## What changes

- Each layer's vector replay (`validate_vectors`, `validate_v4_vectors`) is split into per-row helpers
  (`check_access_row`, `check_mutation_row`, the key and inventory checks) whose conjunction, in the old order and with the
  old messages, is the old replay (`replay_vectors`, `replay_v4_vectors`).
- The weakening tests call only the conjunct that checks the changed row; two combined tests per layer apply all the
  weakening cases at once and expect the full replay to refuse with the first weakened row's message.
- The full replay runs inside `validate()`; the test that used to replay a second time now pins that route and the cheap
  parts, and one test per layer drives a vector refusal through the contract route.
- Nothing is cached: the first draft's in-process memo was dropped after independent review round 1.

The new layer `scripts/validate_selinux_replay.py` pins every changed helper, test and test table by its exact whole lines
and requires each step from `validate()` to the vector replay to be an unconditional top-level call.

## Independent review (prototype, rounds 1-3)

Round 1 CHANGES_REQUIRED (the memo could return a stale success: BLOCKING); round 2 CHANGES_REQUIRED (no refusal test
through the contract routes); round 3 PASS_FOR_SOURCE_PUBLICATION, with R3-F1 (pin the route as unconditional calls,
done by the new layer) and R3-F2 (wording) carried into the packet. The packet itself is reviewed again before its PR.

## Expected effect

About 33 s → about 13 s on the Mac for the two files (about 35 s off the serial suite). With MET-PERF-035's parallel
suite the wall-clock gain is smaller, since the files run on workers.
