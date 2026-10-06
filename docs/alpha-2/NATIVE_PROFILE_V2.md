# Alpha 2A — W02a native qualification record v2 (MET-ENFORCE-005)

> Current-status page for the first W02 part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md)
> gives packet and phase status; W01 is recorded on the [W01 resolution page](HOST_INTERFACE_RESOLUTION.md).

W02a: **ADOPTED_DATA_CONTRACT.** The closed `planeon.internal.native-qualification/v2`
contract for profile `SELINUX_FSVERITY_CGROUP_BPF_V2` passed its third independent
source-only review with verdict PASS_FOR_SOURCE_PUBLICATION. W01 review finding F3
(exact v2 cgroup paths and v1/v2 rejection) is closed. The contract is DATA_CHECK_ONLY:
no kernel was observed, nothing is installed, and all E01-E12 remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/native-profile-v2/README.md): rules, bounds, decisions
  1-11, and the disposition of every round-1 and round-2 finding.
- [Schema](../../architecture/native-profile-v2/qualification.schema.json): record, role
  capture, lifecycle capture (containment absence, planeon-slice census, host-wide planeon
  process counts) and backend capture.
- [Vectors](../../architecture/native-profile-v2/vectors.json): 4 positives, 131
  negatives each pinned to its exact refused rule, 4 accepted variants, 13 cross-version
  and 10 migration cases.
- Reference model `scripts/native_qualification_v2.py`. Only `check_qualification`
  is acceptance-shaped, and only as data, under the caller obligations stated in the
  model.

## Independent review

Three rounds, each by a separate agent that did not author the contract, read-only,
with the reviewed bytes kept unchanged:

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | CHANGES_REQUIRED (7 MAJOR, 9 MINOR, 3 NOTE) | `review-round1.json` | `round1/` |
| 2 | CHANGES_REQUIRED (2 MAJOR, 5 MINOR, 9 NOTE; 14 of 19 round-1 findings closed) | `review-round2.json` | `round2/` |
| 3 | PASS_FOR_SOURCE_PUBLICATION (3 MINOR, 4 NOTE) | `review-round3.json` | current files |

The round-3 reviewer replayed all 162 vector checks and ran 36 extra probes. The
[status record](../../architecture/native-profile-v2/status.json) derives the
adoption state from the final verdict, and `scripts/validate_native_profile_v2.py`
checks that derivation.

## Owner decision D5 (2026-10-06)

The reviewed W01 spec required the probe worker's capability bounding set to be
empty. The broker, as original parent, cannot drop bounding-set entries without
CAP_SETPCAP. The owner chose to redefine the worker rule instead of widening the
broker: the bounding set may be any subset of the broker's enrolled set, while
permitted, effective, ambient and inheritable are empty, `no_new_privs` is 1 and the
uid is non-root. This amends HOST-INTERFACE-DRAFT-002 §5.3 (WORKER row). The W01
snapshot stays byte-identical. The amendment is recorded in the status record and
carried to a W01 amendment, to W02d (worker filter) and to T04 (native test).

## Carried findings (none blocking)

- P1, P3-P6 → **W02a-F** follow-up revision: role closures must not list another role's
  executable or an interpreter for a native-only role, and captures should record the
  running executable; compare the slice census with the role captures; check (pid,
  start ticks) uniqueness across all members and backend processes; observe
  `planeon.slice`'s own members; make `pids.max` versus thread counts kernel-plausible.
- P2 → recorded here and in the status record (D5).
- P7 → W02g and W03: mark the `unit-distribution` test profile test-only when the
  selected distribution's profile is added.

## Still open

All E01-E12 and T01-T08. Exact seccomp filters (W02d). The SELinux permission matrix,
label values and the confined backend types (`qualk8s_*_t`), including W01 finding F2
(W02e). The identity closure, including W01 finding F1 (W02g). The I05 and I07 wire
schemas (W02b, W02c). Admission field allowlists (W02f). W03-W07 remain gated.
Alpha2 remains open; model-effort transition NOT_DUE.
