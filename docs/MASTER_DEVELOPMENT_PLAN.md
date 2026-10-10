# Harness-Onion — unified development roadmap

## Current checkpoint — MET-ENFORCE-021 source preparation, October 10, 2026

Alpha2 OPEN. MET-ENFORCE-020 (W02d-V3) passed required verify (64/64, 408 s) and merged as main 5fab673. Owner rule
(via the lane monitor): slot 223 is LIC-HOST. MET-ENFORCE-021 publishes license-policy amendment LIC-HOST-A1 (owner
decisions Q-L, Q-L2, Q-L3) as a reviewed overlay on the byte-identical base policy (independent review round 4,
PASS_FOR_SOURCE_PUBLICATION). DATA_CHECK_ONLY. MET-ENFORCE-021 is the sole 223rd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-021 / LIC-HOST | SOURCE_PREPARED | License-policy amendment as the 223rd packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-020 / W02d-V3 | VERIFY_PASSED_MERGED | Verify 408 s |
| Alpha2A | VERIFIER-EXT | IN_REVIEW | One repository-aware verifier for R10 and R12 (owner root bundle) |
| Alpha2A | W02a-F2, W02g-F2 | PLANNED | Production backend profile and the I06 successor |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane), after the owner's verifier extension |
| Alpha2A | W04 | IN_PROGRESS | Independent enforcement tests and observation-window map (parallel lane) |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02d-V3 source checkpoint — MET-ENFORCE-020 source preparation, October 10, 2026

Alpha2 OPEN. MET-ENFORCE-019 (W03-0) passed required verify (64/64, 503 s under Docker load) and merged as main 0e74704.
Owner decision (via the lane monitor): slot 222 is W02d-V3. MET-ENFORCE-020 publishes the W02d successor seccomp
allowlists v3: owner decision W02d-V3 adds three narrow NATIVE_STATIC rules for the Rust+musl native roles (independent
review round 2, PASS_FOR_SOURCE_PUBLICATION). DATA_CHECK_ONLY. MET-ENFORCE-020 is the sole 222nd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-020 / W02d-V3 | SOURCE_PREPARED | Seccomp allowlists v3 as the 222nd packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-019 / W03-0 | VERIFY_PASSED_MERGED | Verify 503 s |
| Alpha2A | LIC-HOST, W02a-F2, W02g-F2 | IN_PROGRESS_OR_PLANNED | License-policy amendment (slot 223); production backend profile |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane), after the owner's verifier extension |
| Alpha2A | W04 | IN_PROGRESS | Independent enforcement tests and observation-window map (parallel lane); W04-0 review-PASS, slot 224 |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W03-0 source checkpoint — MET-ENFORCE-019 source preparation, October 10, 2026

Alpha2 OPEN. MET-ENFORCE-018 (W01-AMEND) passed required verify (64/64, 490 s) and merged as main 195c4c9. Owner rule
(via the lane monitor): slot 221 goes to the first review-PASS contract packet. MET-ENFORCE-019 is W03-0: the W03 backend
distribution selection (an upstream v1.37.1 component set from sealed files) and the W03 plan (independent review round 5,
PASS_FOR_SOURCE_PUBLICATION). DATA_CHECK_ONLY. MET-ENFORCE-019 is the sole 221st specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-019 / W03-0 | SOURCE_PREPARED | Backend distribution selection and W03 plan as the 221st packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-018 / W01-AMEND | VERIFY_PASSED_MERGED | Verify 490 s |
| Alpha2A | LIC-HOST, W02d v3, W02a-F2, W02g-F2 | IN_PROGRESS_OR_PLANNED | License-policy amendment; steady-state seccomp rules; production backend profile |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane), after the owner's verifier extension |
| Alpha2A | W04 | IN_PROGRESS | Independent enforcement tests and observation-window map (parallel lane), from the W03-0 selection |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W01-AMEND source checkpoint — MET-ENFORCE-018 source preparation, October 10, 2026

Alpha2 OPEN. MET-ENFORCE-017 (W02d) passed required verify (64/64, 376 s, the first under the Interactive verifier
ProcessType) and merged as main b8ce77b. Owner decision (via the lane monitor): the parallel lane takes W01-AMEND, the
primary lane W03. MET-ENFORCE-018 publishes W01 amendment W02D (W02d's carried items; owner decisions W01-AMEND-QW1 to
QW4) and the W02d successor seccomp-allowlists-v2 (independent review round 4, PASS_FOR_SOURCE_PUBLICATION).
DATA_CHECK_ONLY. MET-ENFORCE-018 is the sole 220th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-018 / W01-AMEND | SOURCE_PREPARED | W01 amendment W02D and seccomp allowlists v2 as the 220th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-017 / W02d | VERIFY_PASSED_MERGED | Verify 376 s |
| Alpha2A | W03 | IN_PROGRESS | Host modules in the operator repository (primary lane) |
| Alpha2A | W04 | WAITING_W03_DISTRIBUTION | Independent enforcement tests and observation-window map (parallel lane, after W03 picks the distribution) |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02d source checkpoint — MET-ENFORCE-017 source preparation, October 10, 2026

Alpha2 OPEN. MET-SECTOR-002 (CATALOG-BANK) passed required verify (64/64, 415 s) and merged as main 984c953. Owner
decision (via the lane monitor): W02d takes slot 219. MET-ENFORCE-017 publishes the W02d per-role, per-architecture
seccomp allowlists for the seven roles at Linux v6.12 (independent review round 3, PASS_FOR_SOURCE_PUBLICATION), with the
reference compiler's filter digests. DATA_CHECK_ONLY. MET-ENFORCE-017 is the sole 219th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-017 / W02d | SOURCE_PREPARED | Seccomp allowlists as the 219th packet; verify from the owner's App |
| Alpha2 | MET-SECTOR-002 / CATALOG-BANK | VERIFY_PASSED_MERGED | Verify 415 s |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2A | W02a-F2, W02g-F2, W01 amendments from W02d | WAITING_EXACT_PACKETS | follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical CATALOG-BANK source checkpoint — MET-SECTOR-002 source preparation, October 9, 2026

Alpha2 OPEN. MET-PERF-036 (PERF-SEL) passed required verify (64/64, 399 s) and merged as main da81730. Owner rule
(via the lane monitor): slot 218 goes to the first contract packet that passes review. MET-SECTOR-002 is CATALOG-BANK:
the SECTOR-D1 catalog follow-ups as a reviewed overlay (independent review round 4, PASS_FOR_SOURCE_PUBLICATION). The
catalogs stay byte-identical, and banking-era consumers read them through `scripts/sector_catalog.py`. MET-SECTOR-002
is the sole 218th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-SECTOR-002 / CATALOG-BANK | SOURCE_PREPARED | Sector catalog overlay as the 218th packet; verify from the owner's App |
| Alpha2 | MET-PERF-036 / PERF-SEL | VERIFY_PASSED_MERGED | Verify 399 s |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2A | W02d, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical PERF-SEL source checkpoint — MET-PERF-036 source preparation, October 9, 2026

Alpha2 OPEN. MET-PERF-035 (PERF-035) passed required verify (64/64, 590 s) and merged as main
1d107e4. MET-PERF-036 is PERF-SEL (owner decision via the lane monitor): the two SELinux matrix
layer test files replay the matrix inside validate() (the v3 file once more for one weakening
case) instead of three to five times, and their weakening tests call the exact per-row conjunct
of the unchanged replay. No validator
refusal changes and nothing is cached. MET-PERF-036 is the sole 217th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-PERF-036 / PERF-SEL | SOURCE_PREPARED | SELinux replays inside validate() instead of three to five times per layer test file, as the 217th packet; verify from the owner's App |
| Alpha2 | MET-PERF-035 / PERF-035 | VERIFY_PASSED_MERGED | Verify 590 s |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical PERF-035 source checkpoint — MET-PERF-035 source preparation, October 9, 2026

Alpha2 OPEN. MET-ENFORCE-016 (W02e-F) passed required verify on a quiet re-run (64/64, 784 s; the first run
timed out at 902 s) and merged as main 58e6c25, past the 750 s PERF floor. Owner decisions (via the lane monitor):
MET-PERF-035 is the 216th packet. It runs the outer suite on 4 fail-closed worker processes inside the unchanged
acceptance argv and includes the reviewed suite-reuse cuts. Validators, authorities and freshness are unchanged.
MET-PERF-035 is the sole 216th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-PERF-035 / PERF-035 | SOURCE_PREPARED | Parallel suite and suite reuse as the 216th packet; owner transport approval (ci/) and verify from the owner's App |
| Alpha2A | MET-ENFORCE-016 / W02e-F | VERIFY_PASSED_MERGED | Verify 784 s (quiet re-run) |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02e-F source checkpoint — MET-ENFORCE-016 source preparation, October 9, 2026

Alpha2 OPEN. MET-ENFORCE-015 (W02-ADM-F) passed required verify (64/64, 731 s) and merged as main
4196dae. The owner put W02e-F ahead of the PERF packet, which is mandatory next because this
packet's verify is expected to cross the 750 s floor. MET-ENFORCE-016 is W02e-F. The adopted v3
SELinux matrix is frozen, so it publishes the successor `planeon.internal.selinux-matrix/v4`:
- one `/proc` assertion per planeon target with exactly that target's peers (K2);
- A66: no domain loads policy before the seal (K3);
- the cgroup2 labelling text corrected and S11 checked against the slice type (K4); the review
  brief's count (K6).

Review round 2 passed (PASS_FOR_SOURCE_PUBLICATION; one NOTE carried). Nothing is written or
loaded; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-016 is the sole 215th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-016 / W02e-F | SOURCE_PREPARED | SELinux matrix v4 as the 215th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-015 / W02-ADM-F | VERIFY_PASSED_MERGED | Verify 731 s |
| Alpha2 | PERF-035 | NEXT_MANDATORY | The 216th packet; verify headroom below the 150 s floor |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02-ADM-F source checkpoint — MET-ENFORCE-015 source preparation, October 9, 2026

Alpha2 OPEN. MET-ENFORCE-014 (W02c-F) passed required verify (64/64, 692 s) and merged as
main f88e7f7. PERF-035 was not shipped; the owner lifted the PERF gate with a floor (a PERF
packet becomes mandatory once a verify leaves under 150 s of headroom). MET-ENFORCE-015 is
W02-ADM-F, which folds W02b-F2, W02f-F and W02c-F2 into one packet with three successor
contracts under one combined independent review:
- I05 v3 (`planeon.internal.effect-gate-frame/v3`): the upstream exchange is bounded, a finer
  failure injection pins the drain and deny failure paths, and the residual is stated exactly;
- POLICY-ADMISSION-SEMANTICS/v3: MC39-MC41, modelled env and volume defaults, new A1 and A2
  claim evidence; the sealed A2 manifest file is unchanged;
- I07 v3 (`planeon.internal.policy-write-frame/v3`): on the I05 v3 gate, four more response
  constraints, the write timeout as an abort, no cluster scope.

Review rounds 1 and 2 passed (PASS_FOR_SOURCE_PUBLICATION; findings carried, none blocking).
Nothing is opened or installed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-015 is the sole
214th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-015 / W02-ADM-F | SOURCE_PREPARED | Three successor contracts as the 214th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-014 / W02c-F | VERIFY_PASSED_MERGED | Verify 692 s |
| Alpha2 | PERF-035 | PROFILING | Mandatory once a verify leaves under 150 s of headroom |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02e-F, W02a-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02c-F source checkpoint — MET-ENFORCE-014 source preparation, October 8, 2026

Alpha2 OPEN. MET-ENFORCE-013 (W02f) passed required verify (64/64, 789 s) and merged as main
c1a6784. MET-PERF-033 was dropped after its review. MET-ENFORCE-014 is the W02c-F part. The
adopted I07 v1 writer channel is frozen, so it publishes the successor
`planeon.internal.policy-write-frame/v2`:
- the I07 model extends the I05 v2 gate: maintenance follows its fence after every event, and a
  generation rebuilt after a restart never opens a maintenance;
- ValidatingAdmissionPolicy and its binding are sealed per W02f (ADMISSION_OBJECT_SEALED);
- a write's upstream outcome is its own event, an abort is recorded before the session or
  maintenance ends, a late outcome is never relayed, and lockstep is enforced;
- conditional response constraints, defined request digests and observed fields, and the
  317-character key bound.

It passed its independent review in round 1 (PASS_FOR_SOURCE_PUBLICATION; findings carried,
none blocking). Nothing is opened or installed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-014
is the sole 213th specification. PERF-035 follows before further contract packets.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-014 / W02c-F | SOURCE_PREPARED | I07 policy writer channel v2 as the 213th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-013 / W02f | VERIFY_PASSED_MERGED | Verify 789 s |
| Alpha2 | PERF-035 | NEXT | Structural verify-time cut before further contract packets |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02e-F, W02a-F2, W02b-F2, W02g-F2, W02f-F, W02c-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02f source checkpoint — MET-ENFORCE-013 source preparation, October 8, 2026

Alpha2 OPEN. MET-ENFORCE-012 (W02g-F) passed required verify (64/64, 662 s) and merged as main
4f75ded. MET-ENFORCE-013 is the W02f part. It carries the W01 G05 amendment into its owning
contract as POLICY-ADMISSION-SEMANTICS/v2 and fixes the A2 allowlists:
- the v1 pre-commit sentence is pinned and met by no boundary; A1-A3 are named checks at named
  positions and A4 is explicitly weaker;
- owner decision: the A2 ValidatingAdmissionPolicy objects live in a sealed static admission
  manifest directory, run-independent, not written through I07;
- per-kind allowlists for Pod, immutable ConfigMap and ClusterIP Service from Kubernetes v1.37.1,
  manifest constraints, a Pod shape echo, the root-CA publisher's ConfigMap admitted exactly, and
  a guard that denies API writes of admission policies, bindings and webhook configurations.

It passed its independent review in round 2 (PASS_FOR_SOURCE_PUBLICATION; findings carried, none
blocking). Nothing is installed or compiled; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-013 is
the sole 212th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-013 / W02f | SOURCE_PREPARED | POLICY-ADMISSION-SEMANTICS/v2 and A2 allowlists as the 212th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-012 / W02g-F | VERIFY_PASSED_MERGED | Verify 662 s |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02c-F, W02e-F, W02a-F2, W02b-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02g-F source checkpoint — MET-ENFORCE-012 source preparation, October 8, 2026

Alpha2 OPEN. MET-ENFORCE-011 (W02b-F) passed required verify (64/64, 686 s) and merged as main
487eca6. MET-ENFORCE-012 is the W02g-F part. The adopted W02g I06 profile is frozen by later
layers, so it publishes the successor I06 backend profile v2, closing the findings carried to
W02g-F:
- a distribution evidence record names one W02a v3 record by its qualification digest, and W02a
  v3's check_record must accept that record; a test-only backend qualifies only in an explicit
  fixture call, so no production evidence exists until W03 adds a reviewed production profile;
- no resource rule of any kind on the loopback user system:apiserver;
- shared or nested backend cgroups refused through W02a's rules, and I06's own code distinctness
  rule kept because W02a allows shared backend code.

It passed its independent review in round 3 (PASS_FOR_SOURCE_PUBLICATION; notes carried, none
blocking). Nothing is observed or selected; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-012 is
the sole 211th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-012 / W02g-F | SOURCE_PREPARED | I06 backend profile v2 as the 211th packet; verify from the owner's App on a quiet host |
| Alpha2A | MET-ENFORCE-011 / W02b-F | VERIFY_PASSED_MERGED | Verify 686 s |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02f, W02c-F, W02e-F, W02a-F2, W02b-F2, W02g-F2 | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02b-F source checkpoint — MET-ENFORCE-011 source preparation, October 8, 2026

Alpha2 OPEN. MET-ENFORCE-010 (W02a-F) passed required verify (64/64, 903 s under host load; a
quiet-host dry run of the same tree took 602 s) and merged as main a29c93c. MET-ENFORCE-011 is
the W02b-F part. The adopted v1 I05 channel is frozen, so it publishes the successor
`planeon.internal.effect-gate-frame/v2`, closing every finding carried to W02b-F:
- the I07 drain answered from the A3 fence in every state, including after an urgent close,
  a refused seal or a fatal channel failure;
- DELETE only with a UID from this execution's own CREATE 201; a manifest digest or identity
  belongs to one run across runs and generations;
- every denied action reported, also when a storage failure denied it;
- a failure marker on a separate failure domain and torn-record detection, so a restart after
  an unrecorded write failure is HELD (double-fault residual stated);
- the 408 agreement rows, pinned Kubernetes v1.37.1 sources and decode codes.

It passed its independent review in round 1 (PASS_FOR_SOURCE_PUBLICATION; notes carried, none
blocking). Nothing is opened or installed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-011 is
the sole 210th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-011 / W02b-F | SOURCE_PREPARED | I05 broker-gate channel v2 as the 210th packet; verify from the owner's App on a quiet host |
| Alpha2A | MET-ENFORCE-010 / W02a-F | VERIFY_PASSED_MERGED | Verify 903 s under load; 602 s quiet-host dry run |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02f, W02c-F, W02e-F, W02g-F, W02a-F2 | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical W02a-F source checkpoint — MET-ENFORCE-010 source preparation, October 8, 2026

Alpha2 OPEN. MET-PERF-032 passed required verify (64/64, 564 s, down from 692 s) and merged as
main 51440c8. MET-ENFORCE-010 is the W02a-F part. The adopted v2 record is frozen, so it
publishes the successor `planeon.internal.native-qualification/v3`, closing every finding
carried to W02a-F:
- code identity: closures without another role's executable or the interpreter tree for
  native-only roles; observed running images; one file per inode;
- the slice census against the role captures and `nr_descendants`; the slice's own members;
  thread counts against `pids.current` and `pids.max`;
- the test-only fixture profile, unnested backend cgroups and backend identities bound to
  the W02g closure;
- W02e's label constants, the E1 effective-program census over the 22 other cgroup attach
  types of Linux v6.12, and the K1 boot-entry discriminator;
- migration against the complete v1 and v2 histories.

It passed its independent review in round 6 (PASS_FOR_SOURCE_PUBLICATION; findings carried, none
blocking). Nothing is observed or installed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-010
is the sole 209th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-010 / W02a-F | SOURCE_PREPARED | Native qualification record v3 as the 209th packet; verify from the owner's App |
| Alpha2 | MET-PERF-032 / PERF-032 | VERIFY_PASSED_MERGED | Verify 564 s |
| Alpha2 | CATALOG-BANK, IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking catalog follow-ups, pack, inputs and journey |
| Alpha2A | W02d, W02f, W02b-F, W02c-F, W02e-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical PERF-032 source checkpoint — MET-PERF-032 source preparation, October 7, 2026

Alpha2 OPEN. MET-SECTOR-001 passed required verify (64/64, 692 s) and merged as main
8f77c3f; SECTOR-D1 is recorded. Verify has grown 545, 554, 639 and 692 s over packets 204-207,
against the 900 s cap. MET-PERF-032 comes before the remaining W02 and banking packets. A
per-test profile of the 206-packet suite (Mac pytest 495 s) found the cost spread over the
history chain, with four repeats that the checks do not need:
- each layer's route test computed every route's input for every route (36 s, quadratic in
  the number of layers); each route now computes only its own;
- each native-profile status mutation replayed all contract vectors (14 s); it now stubs only
  that pure replay after a passing control, and the replay keeps its own full test;
- the credential-lifecycle inventory builder re-projected the same inputs per case (15 s); it
  now projects each exact input set once per module;
- the readiness validator compared every pair of 3,868 objects for uniqueItems (4.2 s, three
  runs per verify); `scripts/schema_unique.py` compares only items with an equal key and
  gives jsonschema's answer wherever jsonschema returns one, apart from inputs within one
  stack frame of the recursion limit.

No validator caches a projection or verdict, and every refusal is unchanged, with that same
uniqueItems caveat. MET-PERF-032 is the sole 208th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-PERF-032 / PERF-032 | SOURCE_PREPARED | Verify headroom as the 208th packet; verify from the owner's App |
| Alpha2 | MET-SECTOR-001 / SECTOR-D1 | VERIFY_PASSED_MERGED | Banking sector direction recorded |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2A | W02d, W02f, W02a-F, W02b-F, W02c-F, W02e-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical SECTOR-001 source checkpoint — MET-SECTOR-001 source preparation, October 7, 2026

Alpha2 OPEN. MET-ENFORCE-009 passed required verify (64/64, 639 s) and merged as main
2c14e51; W02e is ADOPTED_DATA_CONTRACT. MET-SECTOR-001 records owner decision SECTOR-D1:
banking replaces white goods as the first and only release sector from Alpha 2 through the
first enterprise release. It publishes:
- the decision record `planeon.internal.sector-direction/v1`, with a disposition for each of the
  28 published packets that name white goods, recomputed by its validator;
- nine unpublished proposals: successors IND-BANK-001 to IND-BANK-005 and CONF-BANK-001, and the
  banking inputs KN-BANK-001, CTRL-BANK-001 and DIST-BANK-001;
- CONF-A2-001 and CONF-WG-001 retargeted to banking with their IDs kept (each needs a revision
  amendment before dispatch), retained accepted edges, and exhaustive catalog follow-ups.

No published packet, catalog, pack, fixture or backlog snapshot changes, and nothing is built or
qualified. MET-SECTOR-001 is the sole 207th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 | MET-SECTOR-001 / SECTOR-D1 | SOURCE_PREPARED | Banking sector direction as the 207th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-009 / W02e | VERIFY_PASSED_MERGED | SELinux matrix, ADOPTED_DATA_CONTRACT |
| Alpha2 | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, inputs and journey |
| Alpha2A | W02d, W02f, W02a-F, W02b-F, W02c-F, W02e-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-009 source checkpoint — MET-ENFORCE-009 source preparation, October 7, 2026

Alpha2 OPEN. MET-ENFORCE-008 passed required verify (64/64, 554 s) and merged as main
f4edb9a; W02c is ADOPTED_DATA_CONTRACT. MET-ENFORCE-009 is the W02e part. It publishes the
closed SELinux matrix `planeon.internal.selinux-matrix/v3`:
- 19 domains (roles, lifecycle, maintenance, confined `qualk8s_*` backend and Pod types,
  the admin login, systemd), 56 types, three booleans and three boot states;
- 100 deny assertions from W01, with per-source closures and cgroup2, bpffs and selinuxfs
  genfscon labelling;
- the corrected closure of W01 finding F2 and the W02a label-slot values;
- 1,716 access and 50 mutation checks on an executable evaluator.

Owner decision E1: the confined runtime may load BPF device programs, a trusted backend use
controlled by W03, T04 and a W02a-F census. It passed its third independent review
(PASS_FOR_SOURCE_PUBLICATION, 2 MINOR and 4 NOTE findings carried to W02e-F, W02a-F, W03 and
T04). No policy is written or loaded; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-009 is the
sole 206th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-009 / W02e | SOURCE_PREPARED | SELinux matrix as the 206th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-008 / W02c | VERIFY_PASSED_MERGED | I07 policy-writer channel contract, ADOPTED_DATA_CONTRACT |
| Alpha2A | W02d, W02f, W02a-F, W02b-F, W02c-F, W02e-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-008 source checkpoint — MET-ENFORCE-008 source preparation, October 7, 2026

Alpha2 OPEN. MET-PERF-031 passed required verify (64/64, 545 s, down from 786 s) and merged as
main f94229a. MET-ENFORCE-008 is the W02c part. It publishes the closed I07 policy-writer
channel contract `planeon.internal.policy-write-frame/v1`:
- MAINTENANCE_STATUS, WRITE_BEGIN, WRITE_OBJECT and WRITE_END on the I05 envelope rules;
- a closed policy-kind table derived from the W02g `planeon:policy-writer` grants, refusing
  effect kinds, policy kinds outside the closure and every other kind;
- a gate model that extends the unchanged W02b model: maintenance opens only when the A3 drain
  fence holds, never on a drain reply (W02b finding P1, write side);
- 180 executable vector checks, counterexamples 18 and 23 and the P1 probes included.

It passed its first independent review (PASS_FOR_SOURCE_PUBLICATION, 4 MINOR and 4 NOTE
findings carried to W02c-F, W02b-F, W02f and W03). Nothing is installed or forwarded; all
E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-008 is the sole 205th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-008 / W02c | SOURCE_PREPARED | I07 policy-writer channel contract as the 205th packet; verify from the owner's App |
| Alpha2A | MET-PERF-031 / PERF-031 | VERIFY_PASSED_MERGED | Test-local exact projection sharing; verify 545 s |
| Alpha2A | W02d-W02f, W02a-F, W02b-F, W02c-F, W02g-F | WAITING_EXACT_PACKETS | seccomp, SELinux matrix, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical PERF-031 source checkpoint — MET-PERF-031 source preparation, October 7, 2026

Alpha2 OPEN. MET-ENFORCE-007 passed required verify (64/64, 786 s) and merged as main
b46446d; W02b is ADOPTED_DATA_CONTRACT. That left 114 s under the trusted 900 s cap, so
MET-PERF-031 comes before W02c. A per-test profile of the 203-packet suite found three
inherited mutation loops that re-project identical unchanged inputs through the whole
history chain on every validator call (162 s of 569 s of Mac pytest). Within those three
tests only, each projection is computed once per exact input and reused:
- every mutated input is still projected fresh and refused on its own;
- each test ends with a fully fresh validation;
- no validator under scripts/ shares projections.

In the full Mac dry run the two files drop
from 137 s to 46 s and from 62 s to 16 s. No validator, launcher, transport or acceptance semantics change.
MET-PERF-031 is the sole 204th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-PERF-031 / PERF-031 | SOURCE_PREPARED | Test-local exact projection sharing as the 204th packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-007 / W02b | VERIFY_PASSED_MERGED | I05 broker-gate channel contract, ADOPTED_DATA_CONTRACT |
| Alpha2A | W02c-W02f, W02a-F, W02b-F, W02g-F | WAITING_EXACT_PACKETS | I07 schema, seccomp, SELinux matrix, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-007 source checkpoint — MET-ENFORCE-007 source preparation, October 6, 2026

Alpha2 OPEN. MET-ENFORCE-006 passed required verify (64/64, 626 s) and merged as main
fe50b57; W02g is ADOPTED_DATA_CONTRACT. MET-ENFORCE-007 is the W02b part. It publishes the
closed I05 broker-gate channel contract `planeon.internal.effect-gate-frame/v1`:
- the lockstep, hash-chained frame envelope and ten closed frame variants;
- an executable gate model of connection stamping C1-C7, exact request rendering at A1, the
  durable journal, the A3 drain fence and A4 urgent invalidation;
- the ACTION_OUTCOME to I02 RESOURCE_RESULT mapping, with I02 unchanged;
- 161 executable vector checks, counterexamples 17, 18, 21 and 22 included.

It passed its third independent review (rounds 1 and 2 CHANGES_REQUIRED, round 3
PASS_FOR_SOURCE_PUBLICATION); minor findings are carried to W02b-F and W02c. Nothing is
installed or forwarded; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-007 is the sole 203rd
specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-007 / W02b | SOURCE_PREPARED | I05 broker-gate channel contract as the 203rd packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-006 / W02g | VERIFY_PASSED_MERGED | I06 backend profile, ADOPTED_DATA_CONTRACT |
| Alpha2A | W02c-W02f, W02a-F, W02b-F, W02g-F | WAITING_EXACT_PACKETS | I07 schema, seccomp, SELinux matrix, admission; follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep the inherited 64 argv unchanged (the installed activation cap and the verifier's inheritance rule; the new
layer validator adds no argv and runs inside the outer pytest), 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-006 source checkpoint — MET-ENFORCE-006 source preparation, October 6, 2026

Alpha2 OPEN. MET-ENFORCE-005 passed required verify (63/63, 605 s) and merged as main
46bcc3e; W02a is ADOPTED_DATA_CONTRACT. MET-ENFORCE-006 is the W02g part. It publishes
the I06 backend profile for SEALED_SINGLE_NODE_CONTROL_PLANE_V1 on Kubernetes v1.37.1:
- distribution selection criteria, with the evidence bound to its W02a backend profile;
- an inventory of every upstream controller and in-process apiserver writer;
- an identity closure derived from the upstream golden RBAC fixtures;
- 141 executable vector checks and a DATA_CHECK_ONLY reference model.

It passed its second independent review (round 1 CHANGES_REQUIRED, round 2
PASS_FOR_SOURCE_PUBLICATION) and closes W01 finding F1. The I06 part of W02a finding P7
is closed and the rest is carried to W02a-F and W03. No distribution is selected and
nothing is installed or observed; all E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-006 is
the sole 202nd specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-006 / W02g | SOURCE_PREPARED | I06 backend profile as the 202nd packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-005 / W02a | VERIFY_PASSED_MERGED | v2 native qualification contract, ADOPTED_DATA_CONTRACT |
| Alpha2A | W02b-W02f, W02a-F, W02g-F | WAITING_EXACT_PACKETS | I05/I07 schemas, seccomp, SELinux matrix, admission; W02a and W02g follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep 64 argv, 420/750/900 s/15 min and 32 MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-005 source checkpoint — MET-ENFORCE-005 source preparation, October 6, 2026

Alpha2 OPEN. MET-ENFORCE-004 passed required verify (62/62, 553 s) and merged as main
0ecc5f3; W01 is DESIGN_RESOLVED_REVIEWED. MET-ENFORCE-005 is the first W02 part (W02a). It
publishes the closed v2 native qualification contract: record, role, lifecycle and
backend captures, 162 executable vector checks and a DATA_CHECK_ONLY reference model.
It passed its third independent review (rounds 1 and 2 CHANGES_REQUIRED, round 3
PASS_FOR_SOURCE_PUBLICATION) and closes W01 finding F3. Owner decision D5 redefines
the worker capability rule. Nothing is installed or observed; all E01-E12 remain
OPEN_UNPROVEN. MET-ENFORCE-005 is the sole 201st specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-005 / W02a | SOURCE_PREPARED | v2 native qualification contract as201st packet; verify from the owner's App |
| Alpha2A | MET-ENFORCE-004 / W01 | VERIFY_PASSED_MERGED | W01 gate resolutions, DESIGN_RESOLVED_REVIEWED |
| Alpha2A | W02b-W02g, W02a-F | WAITING_EXACT_PACKETS | I05/I07 schemas, seccomp, SELinux matrix, admission, identity closure; W02a follow-ups |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep63argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical ENFORCE-004 source checkpoint — MET-ENFORCE-004 source preparation, October 5, 2026

Alpha2 OPEN. MET-VERIFY-004 passed required verify from the dedicated verifier
account (61/61, 592 s); PR #153 merged as main d938151. MET-ENFORCE-004 starts
Alpha 2A item W01. Using the owner's four design decisions, it resolves G04, G05,
G06, G07 and G09 at design level: a sealed single-node qualification control
plane, a versioned admission-versus-commit amendment, a v2 native record with an
EFFECT_GATE role, reboot-only host maintenance, and connection stamping on
unchanged I04. A separate agent reviewed it independently and returned
PASS_FOR_SOURCE_PUBLICATION with every gate RESOLVED_DESIGN, so W01 is
DESIGN_RESOLVED_REVIEWED. This is not native enforcement, an adopted wire ABI or an
installed gate. All E01-E12 remain OPEN_UNPROVEN. MET-ENFORCE-004 is the sole
200th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2A | MET-ENFORCE-004 / W01 | SOURCE_PREPARED | W01 gate resolutions and independent review as200th packet; verify from the owner's App |
| Alpha2 verify | MET-VERIFY-004 | VERIFY_PASSED_MERGED | Dedicated verifier account contract |
| Alpha2A | W02 | WAITING_EXACT_PACKET | Wire schemas, v2 record, syscall allowlists, cgroup paths, carried review findings F1-F3 |
| Alpha2 qualification | CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep62argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical VERIFY-004 source checkpoint — MET-VERIFY-004 source preparation, October 5, 2026

Alpha2 OPEN. MET-VERIFY-003 passed required verify through the owner's App after
the owner's exact-commit approval (60/60, 500.8 s); PR #152 merged as main 2f0ae59.
The verifier then moved to a dedicated macOS account with root-owned code, its own
keys and a root policy binding its activation key to that account; the GitHub CLI
login used by agents lost repository administration. MET-VERIFY-004 records this
in the verifier contract and is the first pull request verified by the new
account. MET-VERIFY-004 is the sole199th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 verify | MET-VERIFY-004 | SOURCE_PREPARED | Dedicated verifier account contract as199th packet; verify from the owner's App |
| Alpha2 verify | MET-VERIFY-003 | VERIFY_PASSED_MERGED | Isolated network canary; MET-VERIFY-002 review notes |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep61argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical003 source checkpoint — MET-VERIFY-003 source preparation, October 4, 2026

Alpha2 OPEN. MET-VERIFY-002 was the first transport change verified through the
owner's exact-commit approval: independent source review, root-owned approval,
then required verify through the owner's App (59/59, 476.2 s); PR #151 merged as
main c269c7d. Its review notes are applied here: the runner now also starts its
network canary with -I (observed by running the runner), the wrapper test accepts
only the three isolated calls as its interpreter calls, and the verifier contract no longer overstates what the
approval protects against. MET-VERIFY-003 is the sole198th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 verify | MET-VERIFY-003 | SOURCE_PREPARED | Isolated network canary as198th packet; owner exact-commit approval, then verify from the owner's App |
| Alpha2 verify | MET-VERIFY-002 | VERIFY_PASSED_MERGED | Isolated runner call; first owner-approved transport change |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep60argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical002 source checkpoint — MET-VERIFY-002 source preparation, October 4, 2026

Alpha2 OPEN. MET-LINUX-006 passed required verify through the owner's App (58/58,
434.6 s) and PR #150 merged as main 0cacd20. The offline wrapper now starts its
runner with python3 -I, so modules planted in the checkout's ci/ directory, PYTHON*
variables or user site-packages cannot shadow what the evidence-printing runner
imports. Pull requests that change the offline transport are verified only after
the owner approves their exact head commit through a root-owned approval record.
MET-VERIFY-002 is the sole197th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 verify | MET-VERIFY-002 | SOURCE_PREPARED | Isolated runner call as197th packet; owner exact-commit approval, then verify from the owner's App |
| Alpha2 Linux | MET-LINUX-006 | VERIFY_PASSED_MERGED | Complete suite passes on Linux as a non-root user; native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep59argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical006 source checkpoint — MET-LINUX-006 source preparation, October 4, 2026

Alpha2 OPEN. MET-PERF-030 passed required verify through the owner's App (57/57,
417.6 s) and PR #149 merged as main a5badfd. Of the six Linux-only failures from
the GCP run, reproduction in an Ubuntu 24.04 container showed one real defect
(the warm-snapshot fixture under macOS-only /private/tmp, also reused by
test_reuse.py); three kit tests failed only because that run used root, which the
kit correctly refuses; the predecessor test failed only because of the first.
MET-LINUX-006 is the sole196th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 Linux | MET-LINUX-006 | SOURCE_PREPARED | Portable fixture parent as196th packet; verify from the owner's App |
| Alpha2 performance | MET-PERF-030 | VERIFY_PASSED_MERGED | In-session predecessor proof; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory |

Keep58argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical030 source checkpoint — MET-PERF-030 source preparation, October 4, 2026

Alpha2 OPEN. MET-PERF-029 passed required verify through the owner's App (56/56,
692.4 s, nested 314 s) and PR #148 merged as main f031cea. Half of each outer run
(326 s of 642 s) was the predecessor test re-running the suite the same session
already runs. An owner-approved GCP Linux speed test (deleted after) ran the suite
about 1.35x slower than the Mac, past the 900 s ceiling. The owner chose: prove, do
not re-run; keep the Mac verifier awake on AC power; use Linux verification only
when it is mandatory. MET-PERF-030 is the sole195th specification.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 performance | MET-PERF-030 | SOURCE_PREPARED | In-session predecessor proof as195th packet; verify from the owner's App |
| Alpha2 performance | MET-PERF-029 | VERIFY_PASSED_MERGED | Linear authority rechecks; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Linux verification only when mandatory; six Linux-only test failures recorded |

Keep57argv, 420/750/900s/15min and32MiB. No cloud, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical029 source checkpoint — MET-PERF-029 source preparation, October 4, 2026

Alpha2 OPEN. MET-VERIFY-001 passed its required verify through the owner's App
(55/55, 750.4 s in the trusted launcher, activation391) and PR #147 merged as
main 8172538 with no administrator exception. Its run showed suite time growing
about50s per packet because composed layers re-read every newer authority
quadratically. MET-PERF-029 is the sole194th specification: each route still
freshly reads every newer authority, now exactly once.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 performance | MET-PERF-029 | SOURCE_PREPARED | Linear authority rechecks as194th packet; verify from the owner's App |
| Alpha2 CI | MET-VERIFY-001 | VERIFY_PASSED_MERGED | Owner-operated required check; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed Linux host, fresh native AMD64 and integrated read-only acceptance |

Keep56argv, both full suites, 420/750/900s/15min and32MiB. No cloud, runner
registration, live/native/tenant or model-effort changes. Phase-end effort
transition NOT_DUE. Prior checkpoints below are history only.

## Historical VERIFY-001 source checkpoint — MET-VERIFY-001 source preparation, October 3, 2026

Alpha2 OPEN. MET-LINUX-005 reached LOCAL_PASS_ONLY (54/54, 671.395 s,
activation390; independent terminal review confirmed) and PR #146 was merged as
main e4e0beb under a second consumed one-time administrator exception. The owner
then replaced the unavailable runner path: required verify is now reported only
by the owner's GitHub App from the installed trusted launcher on an
owner-operated host (docs/alpha-2/OWNER_OPERATED_VERIFIER.md). MET-VERIFY-001 is
the sole193rd specification and the first PR checked through that path.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 CI | MET-VERIFY-001 | SOURCE_PREPARED | Owner-operated required-check contract as193rd packet; verify from the owner's App |
| Alpha2 runner | MET-LINUX-005 | LOCAL_PASS_MERGED_BY_EXCEPTION | LOCAL pass confirmed; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed Linux host, fresh native AMD64 and integrated read-only acceptance |

Keep55argv, both full suites, 420/750/900s/15min and32MiB. No cloud, runner
registration, live/native/tenant or model-effort changes. A GCP Linux verifier is
a later, separately approved successor. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical005 source checkpoint — MET-LINUX-005 source preparation, October 3, 2026

Alpha2 OPEN. MET-PERF-028 reached LOCAL_PASS_ONLY (53/53, 600.586 s,
activation389; independent terminal review confirmed) and PR #145 was merged as
main f7af83e under a consumed one-time administrator exception; its required
verify did not run because no self-hosted runner exists. MET-LINUX-005 is the
sole192nd specification: it carries the reviewed MET-LINUX-004 nested-checkout
and system-alias runner-contract repair onto that main.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 runner | MET-LINUX-005 | SOURCE_PREPARED_AWAITING_REVIEW | Runner-contract repair as192nd packet; independent review and separately authorized full acceptance remain |
| Alpha2 readiness | MET-PERF-028 | LOCAL_PASS_MERGED_BY_EXCEPTION | LOCAL pass confirmed; CI and exact-main NOT_RUN |
| Alpha2 runner | MET-LINUX-004 / PR144 | SUPERSEDED_SOURCE | LOCAL1/2/3 consumed and retained; not a predecessor |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

This packet grants LOCAL0/CI0/exact-main0. Keep54argv, both full suites,
420/750/900s/15min and32MiB. No cloud, root, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical028 source checkpoint — MET-PERF-028 source preparation, October 2, 2026

Alpha2 OPEN. Accepted main0314a684 retains190 immutable packets;028 is the
sole191st specification. Same-host measurement of frozen027 outside the trusted
launcher (no allowance consumed) showed the full predecessor suite at485.15s,
over the420s nested limit. Profiling attributed most of the heaviest tests to
per-call full SHA-256 of three large history authorities and about4s per
validate_reuse call to quadratic uniqueItems over3868 path-index objects.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-028 | SOURCE_PREPARED_AWAITING_REVIEW | Exact-bytes authority recheck reuse, linear uniqueItems and additive regressions; independent review and separately authorized full acceptance remain |
| Alpha2 readiness | MET-PERF-027 | FAILED_LOCAL_FROZEN | 750.277658s timeout;52/53 commands; nested420.012s timeout; independently confirmed cleanup |
| Alpha2 readiness | MET-PERF-019–026 | FAILED_LOCAL_FROZEN | Every previous allowance and failure preserved; no replay |
| Alpha2 runner | MET-LINUX-004 / PR144 | WAITING | Separate three consumed attempts; CI/capacity/exact-main unresolved |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

Every authority call still freshly reads complete bytes through unchanged
custody checks; only a byte-identical read under the identical pin skips a
repeated digest. uniqueItems keeps the pinned verdict and message wherever the
pinned check completes; sortable arrays still use it unchanged. Ten lineage
allowances plus separatePR1443 remain consumed. This packet grants
LOCAL0/CI0/exact-main0. Keep53argv, both full suites,420/750/900s/15min and32MiB.
No cloud, root, runner registration, live/native/tenant or model-effort changes.
Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical027 source checkpoint — MET-PERF-027 source preparation, October 2, 2026

Alpha2 OPEN. Accepted main0314a684 retains190 immutable packets;027 is the
sole191st specification. Two historical recipe readers reuse immutable decoded
recipe data only. Every call retains fresh full reads/hash checks, explicit
overridden-reader semantics, original failure ordering and fresh mutable views.
No function-level speedup or sufficient headroom has been measured.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-027 | SOURCE_PREPARED_AWAITING_REVIEW | Two recipe projections and additive regressions; final frozen-source review and separately authorized full acceptance remain |
| Alpha2 readiness | MET-PERF-026 | FAILED_LOCAL_FROZEN | 750.261581s timeout;52/53 commands; independently confirmed cleanup |
| Alpha2 readiness | MET-PERF-019–025 | FAILED_LOCAL_FROZEN | Every previous allowance and failure preserved; no replay |
| Alpha2 runner | MET-LINUX-004 / PR144 | WAITING | Separate three consumed attempts; CI/capacity/exact-main unresolved |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

026 nested5128passed/10skipped and7/7 commands completed; outer4981passed with
zero observed failures had no final report. Its51snapshot/42semantic regression
passes are partial observations, not acceptance. Final scan did not run. Nine
lineage allowances plus separatePR1443 remain consumed. This packet grants
LOCAL0/CI0/exact-main0. Keep53argv, both full suites,420/750/900s/15min and32MiB.
No cloud, root, runner registration, live/native/tenant or model-effort changes.
Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

Data-only inspection reconciles111 exact owned paths,90 accepted-file inverses,
18 new-file pins and3 closure objects. All190 accepted packets and192 protected
files remain unchanged. The13 repository guides,191-entry index and412 ordered
predecessor edges agree;48 accepted test identity inventories are preserved.
New regression source declares18 functions/50 literal decorator cases;17 use a
two-module fixture. These are syntax observations, not collection or test results.
Independent preliminary core/test review found no concrete blocker. Final exact
commit/tree/history review is separate and remains required before any run.

## Historical026 source checkpoint — MET-PERF-026 source preparation, October 2, 2026

Alpha2 remains OPEN. Accepted main0314a684 has190 immutable YAML; this branch
adds026 only. The sole new optimization is lazy immutable decoding of one
pinned290177-byte historical snapshot. Each call still rereads and hashes the
file, checks the current record and returns a fresh map; other data preserves
the original parser and refusal order. No measured speedup or timing PASS.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-026 | SOURCE_PREPARED_AWAITING_REVIEW | One snapshot decode projection and additive regressions; final exact-source review and every execution gate remain |
| Alpha2 readiness | MET-PERF-025 | FAILED_LOCAL_FROZEN | Outer750.224819s and nested420.016669s timeout,52/53 commands; cleanup independently confirmed |
| Alpha2 readiness | MET-PERF-019–024 | FAILED_LOCAL_FROZEN | All previous allowances/evidence preserved; no replay or transfer |
| Alpha2 runner | MET-LINUX-004 / PR144 | WAITING | Separate three attempts consumed; capacity/CI/exact-main unresolved |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

025 outer3134passed calls/one failed enclosing call and nestedINCOMPLETE27873
records/zero observed failed phases are partial observations. The final scan
did not run. Prior019-025 and separatePR144 remain immutable; cumulative8
lineage allowances are consumed. This packet grants LOCAL0/CI0/exact-main0.
Keep53argv, both full suites and420/750/900s/15min limits. No cloud, root,
runner registration, live/native or tenant effects. Exact-source/helper review
and finite authority are required before a future full run. Phase-end effort
transition NOT_DUE; prior checkpoints below are history, not execution grants.

Data-only source inspection reconciles108 exact owned paths,89 accepted-file
inverses,16 new-file pins and3 closure objects. All190 accepted YAML and192
protected files are unchanged. The13 repository guides,191 current/indexed
packets and412 predecessor edges agree;48 accepted test identity inventories
are preserved. New snapshot regression source declares12 functions/51 literal
cases, not collected or executed tests. Preliminary independent core/test
review found no concrete blocker; final frozen-source/history review remains.

## Historical025 source checkpoint — MET-PERF-025 source preparation, October 2, 2026

Alpha2 remains open. Fresh remote main0314a684 retains190 immutable packet YAML;
this candidate adds only025 for191. Reuse the existing exact-byte-keyed immutable
canonical serializer at one CI-performance call site under an explicit narrow
amendment. Preserve interleaved fresh authority/projection/digest checks, every
inherited test, fixed parser semantics and existing256-entry bound. No changed
shared helper/parser, two-pass rewrite, cached verdict or new acceptance grant.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-025 | SOURCE_PREPARED_AWAITING_REVIEW | One canonical-byte delegation and additive regressions; independent review and finite full acceptance remain |
| Alpha2 readiness | MET-PERF-024 | FAILED_LOCAL_FROZEN | 750.259927s deadline,52/53, no final scan; diagnostic repairs narrowly exercised, cleanup confirmed |
| Alpha2 readiness | MET-PERF-019–023 | FAILED_LOCAL_FROZEN | Every prior allowance and evidence retained; no replay/reset/transfer |
| Alpha2 runner preparation | MET-LINUX-004 / PR144 | WAITING | Separate three LOCAL attempts consumed; CI/capacity/exact-main distinct |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed enforcement, fresh native AMD64 and integrated read-only evidence |

024 nested suite returned0 in385.898376s with COMPLETE30271records,0failed/drop
and10recorded skips; all seven nested commands passed. Outer4676 passed calls
and0observed failed phases are incomplete observations, not acceptance. Exact
failure/cleanup pins are in architecture/packet-schema-performance-inputs/prior-024-terminal.json.

Whole-run timing remains unresolved. Repeated YAML-to-canonical conversion is
a source-confirmed opportunity, not measured speedup. Fixed pinned parser
semantics are required; warm cache entries do not detect arbitrary runtime
parser replacement. Preserve53argv, both full suites,420/750/900s,15min and32MiB.
Cumulative7 and PR144 separate3 remain consumed. NewLOCAL0/CI0/exact-main0;
no helper/signing/activation, cloud, root-policy, runner or native/tenant effect.
Model/effort unchanged; phase-end transition NOT_DUE. Earlier checkpoints below
are retained history, not current implementation or execution authority.

Author data-only inspection reconciles106 owned paths,89 exact inverses and14
new-file pins plus the three closure objects; all190 accepted packets and192
protected files remain unchanged. The13 repository guides,191-entry index and
412 ordered predecessor edges agree. All48 changed accepted test modules retain
ordered identities. The additive semantic module declares15 test functions and
42 literal parameter cases, not collected or executed tests. Pre-freeze review
caught three AST fingerprints generated with system Python3.9; corrected hashes
are bound to pinned3.12.14. Import fixtures restore introduced aliases and observe
the actual loaded authority chain. Independent final review remains required.

## Historical024 source checkpoint — MET-PERF-024 source preparation, October 2, 2026

Alpha 2 remains open. Accepted main `0314a684` retains 190 immutable packet YAML;
this unaccepted source adds only `MET-PERF-024`, for 191. Preserve the schema,
freshness, separate semantic-test ownership and historical reconstruction work.
Correct short explicit IDs for invalid-node fixtures without changing inputs,
and explicitly raise the existing nonzero failure payload without pytest
assertion rewriting. No recorder-limit or strict regression relaxation.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 readiness | MET-PERF-024 | SOURCE_PREPARED_AWAITING_REVIEW | Diagnostic corrections and static regression source prepared; independent review and separately authorized complete acceptance remain |
| Alpha 2 readiness | MET-PERF-023 | FAILED_LOCAL_FROZEN | LOCAL1/1 consumed; 750-second timeout, invalid diagnostic completion, no final scan |
| Alpha 2 readiness | MET-PERF-019 / MET-PERF-020 / MET-PERF-021 / MET-PERF-022 | FAILED_LOCAL_FROZEN | All old allowances remain consumed; no replay, reset or transfer |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Three consumed LOCAL attempts; CI/capacity and exact-main remain separate |
| Alpha 2 qualification | W01 / native Linux / CONF-A2-001 | WAITING_PREREQUISITES | Host enforcement, target qualification and integrated read-only evidence |

Latest023 reached 52/53 commands. Its nested stdout reports 5,019 passed and10
declared skips, but return1 reflects INVALID_NODE and4,680 dropped diagnostic
records. Four outer failed call phases are retained, not a final complete
report. The negative fixture created a65,633-character real node ID; three exact
payload regressions conflict with pinned pytest assertion rewriting. The first
cause is source/log confirmed; the second is a reviewed source-grounded inference
without a retained final traceback. Actual cleanup and unchanged source/history
are independently confirmed. Preserve evidence in
`architecture/packet-schema-performance-inputs/prior-023-terminal.json`.

Whole-run timing is still unresolved. Keep all53 argv, both full suites, nested
420 / local750 / trusted900 seconds, workflow15minutes and32MiB output. This
source grants ZERO attempts; the old shared2/2 plus four separate1/1 allowances
remain consumed at cumulative6. No source/helper execution, CI, merge, cloud,
runner registration, privilege or native/tenant acceptance follows. Model-effort
transition remains NOT_DUE. Prior checkpoints below are historical records.

Author data-only inspection found 104 exact changed paths, 190 unchanged accepted
packets, 191 current entries, 192 protected files, 13 owner guides and 412 ordered
predecessor edges. All 48 changed accepted test modules retain ordered function
identities. The new diagnostic-repair module declares seven functions and 16
literal cases; these are source observations, not executed or collected tests.

## Historical023 source checkpoint — MET-PERF-023 source preparation, October 2, 2026

Alpha 2 remains open. Accepted main `0314a684` has 190 immutable packet YAML;
this unaccepted candidate adds only `MET-PERF-023`, for 191. Move the four new
semantic test functions (14 static cases) into a separate owned module while
restoring the protected file's ten historical identities and bodies. Keep the
canonical owner/root fixes and all unaccepted schema/freshness/diagnostic work.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 preparation | MET-PERF-023 | SOURCE_PREPARED_AWAITING_REVIEW | Exact historical identities restored and semantic coverage separated; independent review and separately authorized full acceptance remain |
| Alpha 2 preparation | MET-PERF-019 / MET-PERF-020 / MET-PERF-021 / MET-PERF-022 | FAILED_LOCAL_FROZEN | Shared 2/2 and three separate 1/1 exceptions consumed; no replay, reset or transfer |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Three consumed LOCAL attempts; base reconciliation, required CI/capacity and exact-main remain separate |
| Alpha 2 qualification | W01 / native Linux / CONF-A2-001 | WAITING_PREREQUISITES | Host enforcement, fresh target qualification and integrated read-only evidence |

The latest 022 LOCAL failed readiness command 2/53 after 16.4475 seconds without
timeout. Projected-byte checks did not replace separate raw AST identity checks:
adding four functions changed a protected ten-test inventory to fourteen. The
prior source review missed this exact-equality requirement. Preserve that review
as history, not acceptance; do not weaken the historical checks. Pytest and new
diagnostics never ran. Independent terminal review confirmed cleanup and unchanged
source/history. Retained pins are in
`architecture/packet-schema-performance-inputs/prior-022-terminal.json`.

Author data-only inspection confirms 102 owned changed paths, 190 unchanged
accepted packets, 191 current entries, 13 repository guides, 412 predecessor
edges and matching root unions. All 48 changed accepted test modules retain
their exact ordered identities. The protected module matches accepted bytes
apart from the catalog scalar; all four moved semantic functions preserve their
AST bodies and fourteen static cases. Seven new-module guard/selection cases
and one retained022-history case are additional source coverage, not executed
tests. Reversible bytes, locked inputs and old failure records remain intact.

This packet grants ZERO new executions. Source preparation is not qualification,
and earlier 020 pytest failure identities remain unresolved. Review exact raw
test inventories as well as reversible source bytes, current canonical owner/ID
sets, README ordering and all allowed-root unions. Keep all 53 argv, both full
suites, nested 420 / local 750 / trusted 900 seconds, workflow 15 minutes and
the 32 MiB output ceiling. No cloud, runner registration, privilege, CI, merge,
native or tenant-acceptance promotion. Model-effort transition remains NOT_DUE.

The older source-era checkpoints below retain history, not current grants.

## Historical022 source checkpoint — MET-PERF-022 source preparation, October 2, 2026

Alpha 2 remains open. Accepted main `0314a684` has 190 immutable packet YAML; this
unaccepted source candidate adds only `MET-PERF-022`, for 191. The correction makes the
canonical owner declaration and root tree agree with the packet catalog and
adds semantic consistency regression source. Earlier schema/freshness/diagnostic
work is carried as unaccepted source, not a completed performance improvement.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 preparation | MET-PERF-022 | SOURCE_PREPARED_AWAITING_REVIEW | Owner/index/tree corrections and regression source prepared; data-only relationships checked, independent review and acceptance still required |
| Alpha 2 preparation | MET-PERF-019 / MET-PERF-020 / MET-PERF-021 | FAILED_LOCAL_FROZEN | Shared 2/2 plus 020 exception 1/1 and 021 LOCAL 1/1 consumed; no replay or transfer |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Three consumed LOCAL attempts; base reconciliation, required CI/capacity and exact-main remain separate |
| Alpha 2 qualification | W01 / native Linux / CONF-A2-001 | WAITING_PREREQUISITES | Host enforcement, fresh target qualification and integrated read-only profile evidence remain unresolved |

The latest 021 LOCAL failed at readiness command 2: 2/53 commands, four errors,
29.908 seconds, no timeout. The guide named 020 in its canonical PR-packets section and
omitted `conftest.py` from its exact root tree. The earlier hash/inverse review
missed these semantic inconsistencies. Pytest, diagnostic hooks and the final
scan never ran. The frozen source and independent cleanup/result pins are kept
in `architecture/packet-schema-performance-inputs/prior-021-terminal.json`.

Author data-only inspection now reconciles all 13 guides, 191 physical packet
owners, 191 indexed entries, 412 predecessor edges and every declared root union.
It preserves all 190 accepted packet bytes and reproduces the two defects in
frozen 021 while finding neither in this candidate. This is not test execution,
an independent security verdict or a full readiness result.

Decision: repair the documents and test the parser-scoped relationships;
do not weaken validation, drop tests, increase deadlines or edit failed source.
This packet grants ZERO new executions. Independent exact-source/helper review
and explicit finite successor authority are prerequisites to any later full run.
All 53 command arrays, nested 420 / local 750 / trusted 900 seconds and the
15-minute workflow ceilings remain unchanged.
No signing, activation, CI, root-policy/cloud/runner or tenant-acceptance change.
Alpha 2 is open; model-effort transition NOT_DUE.

The older source-era checkpoints below retain history, not current grants.

## Historical021 source checkpoint — MET-PERF-021 source preparation, October 1, 2026

Alpha 2 remains open. Accepted main `0314a684` contains 190 immutable packets.
This unaccepted candidate adds only `MET-PERF-021` for 191. It carries forward
reviewed-but-unaccepted schema-lifecycle/fresh-authority work and adds bounded,
redacted per-test phase diagnostics. This is source preparation, not acceptance
or a measured performance improvement.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 preparation | MET-PERF-021 | ONGOING_SOURCE_PREPARATION | Test identity/phase/outcome diagnostics; independent review and static closure pending |
| Alpha 2 preparation | MET-PERF-019 / MET-PERF-020 | BLOCKED_FROZEN | Original 2/2 plus additional custody exception 1/1 consumed; no replay |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Existing three LOCAL allowances consumed; CI/capacity and accepted-base reconciliation remain separate |
| Alpha 2 qualification | Native Linux prerequisites / CONF-A2-001 | WAITING | Required source, installed-host and exact-target evidence remain unresolved |

The last020 exception reached execution but timed out: nested predecessor pytest
420.016s, outer750.444s,52/53 commands, no final summaries or final scan.
Two additional outer failure markers have no established test identity.
Independent terminal review confirmed cleanup and unchanged source/history.
Sanitized immutable pins are in
`architecture/packet-schema-performance-inputs/prior-020-terminal.json`;
the earlier019 record remains byte-for-byte historical data.

Root pytest diagnostics identify setup/call/teardown and outcomes as observed.
Nested `subprocess.run(capture_output=True)` remains unchanged: its events are
buffered until return or the420s inner timeout, not live streaming. No raw
parameter values, traceback locals, exception text or environment are added.
Byte/count limits and sink failures must be explicit; unmatched START means
unfinished/unknown. Mock-only tests alone cannot prove real capture integration.

This packet grants ZERO executions. No source rename, reviewed code, pipeline
availability or installed activation resets old budgets. A future full run needs
a separately reviewed exact source/helper and explicit finite successor allowance.
Keep all53 argv, tests/skips,420/750/900s limits,15-minute workflow and32MiB
outer output limit. No warm-source access, root-policy change, cloud spending,
runner registration, dispatch, merge or native/tenant promotion is included.

No phase-end effort change is due. Previous source-era checkpoints below are
retained history, not current grants or completion claims.

## Historical020 source checkpoint — MET-PERF-020 source preparation, October 1, 2026

Alpha 2 remains open. Accepted main `0314a684` has 190 unchanged packets. This
candidate adds only MET-PERF-020, not failed MET-PERF-019 or unaccepted PR144. It owns
bounded nested-test diagnostics, fresh authority checks without redundant
runner-bridge JSON parsing, carried-forward schema-lifecycle parity tests and
an exact 191-to-190 source inverse. Performance remains unmeasured.

MET-PERF-019 commit `106ae3ec` is frozen, local and unaccepted. LOCAL1 consumed
the first attempt in the shared schema-performance repair lineage and timed
out at 750 seconds during outer pytest: 52/53 commands, last visible 33%, one F
without a final traceback, no completed nested/outer summary. Independent
cleanup/custody checks closed; no acceptance PASS. The sanitized immutable
failure record is [retained here](../architecture/packet-schema-performance-inputs/prior-local-failure.json).

Source preparation grants zero runs. The cumulative 019+020 LOCAL ceiling is two:
019 consumed one and 020 may receive at most one separately reviewed, exact-source,
finite allowance (packet ordinal 1, lineage ordinal 2), never a reset or automatic
retry. No CI/exact-main allowance is automatic. Keep nested 420 / local 750 /
trusted 900 seconds and workflow 15 minutes, full tests and all isolation/freshness
checks unchanged.
The diagnostics identify START and report an inner timeout immediately when
observed; an outer kill can still leave START only. They are not qualification.

PR144/MET-LINUX-004 remains draft with three consumed LOCAL attempts and no
allowance transfer. Required CI capacity/admission, green merge, exact-main,
native Linux and product/tenant qualification remain separate open gates.
No model/effort change is due.

| Phase / ID | Status | Remaining gate |
|---|---|---|
| Alpha 2 / MET-PERF-019 | FAILED_LOCAL_FROZEN | Retain source and consumed attempt; no replay |
| Alpha 2 / MET-PERF-020 | ONGOING_SOURCE_PREPARATION | Freeze and review exact source; no execution grant |
| Alpha 2 / MET-LINUX-004, PR144 | BLOCKED_ALLOWANCE_EXHAUSTED | Preserve three failed attempts and separate runner work |
| Alpha 2 / required CI and exact-main | WAITING | Independently admitted capacity, complete checks and merge |
| Alpha 2 / native Linux and CONF-A2-001 | WAITING_PREREQUISITES | Fresh native and integrated profile evidence |

The following 019 source-era checkpoint is
retained verbatim as history, not a current execution instruction or PASS.


## Historical 019 source checkpoint — October 1, 2026

Accepted source main is `0314a684ba637fb205856d5fb5e50206071e647a`, the PR #143
source merge under its one-time exception. This is **not** required CI PASS,
installed Linux evidence or a transferable exception. Alpha 2 remains open.
`MET-PERF-019` is a separate **ONGOING_SOURCE_PREPARATION** packet on this base:
one invocation-local task-schema validator, exact error/freshness regressions,
and a reversible 191-to-190 source-history bridge. All 190 accepted packet YAML
and historical authority bytes remain unchanged. Speedup is unmeasured.

Draft [PR #144](https://github.com/caglarsubas/harness-onion/pull/144),
`MET-LINUX-004` at `614a08cfaf34ab0c37788231e03a44972f16727e`, is an unaccepted
diagnostic subject, not this packet's predecessor. Its three LOCAL attempts are
consumed. LOCAL3 completed the nested suite (4,902 passes, ten inherited skips)
but timed out during outer pytest at the installed 900-second boundary; only
52/53 commands ran. Cleanup is retained; acceptance did not pass. No LOCAL4,
allowance transfer, test omission or timeout increase is permitted. On October 1,
its required verify remained queued with zero registered repository runners.

This source preparation grants zero new execution attempts. The proposed finite
maximum LOCAL2 / CI2 / LOCAL_EXACT_MAIN1 remains inactive until independent
exact-source review and a finite owner-delegated execution allowance are bound
before reservation. Installed signed packet activation follows the durable
reservation and precedes launch; the owner allowance JSON is not a signature.
Inherited local/main750s, nested420s, trusted900s and workflow15min ceilings stay
unchanged. The old private930s supervisor is not an inherited allowance.
An independently merged repair would require explicit reconciliation of PR144's
old base/inverse before further work there; it does not certify the excluded
Linux runner-kit changes. Required CI capacity/admission and native Linux
qualification remain separate unpassed gates.

The next paragraph is the retained pre-PR-143 source checkpoint, not current
dispatch, runner availability or completion status.

Current source baseline: `945de93f89c94f42f1d63bff7997e3d0fa704fc4` on accepted main, the merge of MET-UNIFY-005 PR #140. Alpha 2 remains **open**. `MET-RUNNER-001` is a source-only development-CI capacity exception candidate, not an installed runner or permission to provision one. As observed on September 29, 2026, [PR #141](https://github.com/caglarsubas/harness-onion/pull/141) and [draft PR #142](https://github.com/caglarsubas/harness-onion/pull/142) have queued self-hosted `verify` jobs and the repository has zero registered runners. Their source/CI/merge, Linux native and tenant-acceptance evidence remain separate. The [bounded exception](alpha-2/CI_CAPACITY_EXCEPTION.md) requires an independently authorized cost ceiling, a separately reviewed and installed exact-job pre-checkout admission boundary, queue serialization, a qualified Linux guest and verified teardown; this publication supplies none of those operational facts. The next source packet is MET-RUNNER-001, while native AMD64 qualification and the W01/Alpha-2 product gates remain waiting.

The next paragraph is the retained pre-PR-140 source checkpoint, not current dispatch or completion status.

Accepted source baseline: 7a353b253bb257aa0abe2148e7fa62d7570f0b5a (PR #138). The roadmap-publication successor is MET-UNIFY-005; its presence in this branch is source work, not merged acceptance. The unpublished MET-UNIFY-001 local candidate at `2cb0b949ee82` exhausted LOCAL-1 and LOCAL-2. The separate unpublished MET-UNIFY-002 candidate exhausted LOCAL-1/2/3; its last isolated suite exposed a stale inherited 204-file assertion after the current YAML corpus became 205. Unpublished MET-UNIFY-003 [PR #139](https://github.com/caglarsubas/harness-onion/pull/139) passed LOCAL-1, then consumed CI-1 on a GitHub API failure before runner registration and CI-2 on a 15-minute cancellation; its runner was retired with zero registrations remaining. The CI log has a failure marker about 420 seconds after the nested predecessor test began, but cancellation prevented a final traceback; pytest was still active when the job stopped. Unpublished MET-UNIFY-004 local commit `8dbfdac` failed LOCAL-1 on a status-document packet-ID check and LOCAL-2/3 at the unchanged 750-second ceiling during outer pytest; no 004 CI or PR was started. These four candidates and their receipts remain historical evidence, none is a merged predecessor or the live 189th packet, and no allowance transfers to MET-UNIFY-005. Current development phase: **Alpha 2, open**. This page is the single current roadmap and progress entry point. The [indexed source crosswalk](alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md), [accepted source index](../architecture/unified-roadmap-source-index.json), and [exact preceding master](history/master-development-plan-7a353b2.md) retain the implementation detail and history.

## Product goal and first enterprise release

Build an Apache-2.0, modular harness platform that guides an enterprise from business understanding and reliable data to governed agents, evidence and acceptance. The platform must operate on tenant-owned Linux Kubernetes, K3s on existing VMs and OpenShift, including a physically disconnected environment. The same contracts can support operator-hosted SaaS or tenant public cloud on **pre-authorized existing capacity**. macOS is for development; Linux AMD64 and ARM64 need separate native qualification.

The architecture has **four planes, sixteen harnesses and thirteen repositories**. The model is a swappable core dependency, not a fifth harness plane; the administrative control plane is not H17. Every harness has one accountable repository owner. Harnesses in one repository may still have separate processes, images, configuration, permissions, stores, lifecycle and failure scope. The 28 canonical service records are a service inventory, not a count of all images, providers or privileged host components.

Require **at least one qualified baseline for every released harness capability** at the first enterprise release. All sixteen harnesses remain targeted in the Alpha-4 capability floor. A release deferment must identify the source requirement, affected capability, owner, phase and accepted disposition; it cannot silently shrink scope. Qualification binds exact provider/adapter version, capability, integration mode, deployment environment and independent evidence. Multiple alternatives can qualify. Progress toward three or four meaningful options per harness over subsequent waves; these are role-specific compatibility relationships, not 64 mandatory first-release technologies.

No cloud-account creation, billable provisioning, hosted-runner dependency, paid API, API-key requirement, runtime package/model download, external telemetry default, online license check or mutable artifact reference may enter the platform. Existing capacity and locally pinned open-source dependencies are required. The separately governed MET-RUNNER-001 exception concerns one externally operated development-CI guest only; it does not change this product rule or grant a VM, runner or CI PASS. An authorized, already-licensed on-premises external target may be attached only with demonstrated zero incremental charge; the platform cannot redistribute its proprietary code or manage its lifecycle.

The five original warm-start repositories remain untouched and reference-only under the existing source-reuse policy. No product implementation task may open, mount, execute or copy from them. Public endpoint attachment is not source-copy authority. A later import would need separately approved path-level legal and packet authority.

## Guided establishment and deployment

The common industry journey has eight ordered gates:

1. Deployment sovereignty and tenant isolation.
2. Business outcome, owner, workflow and measurable KPI.
3. Risk, regulation, classification and autonomy.
4. Domain vocabulary and canonical entities.
5. Data ownership, quality, completeness, freshness, provenance and access.
6. Integrations, protocols, credentials, tools and side effects.
7. Retrieval, memory, model, ML and orchestration requirements.
8. SLO, recovery, observability, evaluation and tenant acceptance.

The first sector pack is banking: owner decision SECTOR-D1 ([sector direction](alpha-2/SECTOR_DIRECTION.md), October 7, 2026) replaces white goods from Alpha 2 through the first enterprise release, and the white-goods pack and its published packets remain historical source. Sector overlays append to the common journey; tenant-specific answers determine applicable controls, technology and readiness. A mandatory predecessor finding that is OPEN, FAIL or STALE blocks dependent approval. Production control waivers document exceptions but never replace fresh required PASS evidence.

The UI and file workflow share the same schema and deterministic compiler:

**Questionnaire or YAML → TenantDemand → locked profile → reviewed change plan → signed minimal bundle → HarnessInstallation → observed status and evidence.**

The compiler produces exactly six outputs: profile.json, bom.json, install-plan.json, evidence-plan.json, explanation.md and profile.sha256. An active exclusive provider group requires one explicit accepted selector; a recommendation never chooses silently. Bundle composition includes only selected modules and their dependency closure. The current 87-record provider/module catalog is PLANNED: 59 packet-owned implementation dispositions, 23 tenant-supplied external records and five non-installable CONTRACT_ONLY entries. Missing release digests prevent installation or qualification.

| Integration mode | Platform responsibility |
|---|---|
| Built-in, platform managed | Install and manage a qualified provider only inside authorized existing infrastructure. |
| Built-in, externally operated | Manage the approved adapter and binding; preserve tenant ownership of the existing service. |
| Tenant custom adapter | Supply contracts, SDK, isolated artifact admission and independent conformance; tenant engineering owns the integration. |

Custom adapters are separate signed workers/services. They cannot shadow a core provider, run inside the administrative control plane, grant permissions, waive controls or certify tenant acceptance.

## Ownership and dependency policy

| R | Repository | Harnesses or cross-harness responsibility |
|---|---|---|
| R00 | harness-onion / Harness-Engineering | Architecture, planning, taxonomy, packets and release coordination |
| R01 | mas-harness-contracts | Public APIs, events, guidance rules, compiler, compatibility vectors |
| R02 | mas-harness-sdks | Python/TypeScript clients and adapter developer interfaces |
| R03 | mas-harness-industry-packs | Sector journeys, quality/regulatory guidance and fixtures |
| R04 | mas-harness-control-plane | Next.js setup, authenticated tenant overview, plane/harness detail pages |
| R05 | mas-harness-runtime-plane | H3 AI Gateway; H4 Experience & Interaction |
| R06 | mas-harness-model-plane | H2 Model & Inference within the runtime plane |
| R07 | mas-harness-knowledge-plane | H5 Domain; H6 Data Integration; H7 Retrieval; H8 Memory |
| R08 | mas-harness-execution-plane | H9 Protocol; H10 Orchestration; H11 Tools/Sandbox; H12 ML/Decision |
| R09 | mas-harness-trust-plane | H13 Security; H14 Governance; H15 Observability; H16 Assurance |
| R10 | mas-harness-operator | H1 Infrastructure & Runtime, including separately governed host modules |
| R11 | mas-harness-distribution | Minimal OCI assembly, locks, SBOM/license closure and air-gap transfer |
| R12 | mas-harness-conformance-labs | Independent compatibility, native, security, lifecycle and acceptance-candidate evidence |

The [repository graph](../architecture/repositories.yaml), [taxonomy](../architecture/taxonomy.yaml), [service catalog](../architecture/services.yaml), [provider catalog](../architecture/providers.yaml) and [runtime dependency graph](../architecture/dependency-graph.yaml) remain their machine authorities. Arrows mean consumer → provider. Keep contract-source, build-artifact, release-set and runtime-integration edges separate; unconditional graphs stay acyclic. The sole assurance callback exception never permits a source/build cycle.

Release contracts and compatibility vectors first, then SDKs/packs, affected services/operator, exact distribution set and independent conformance. Each cross-repository feature has one parent outcome and separate exact owner packets. A packet is one branch/PR with allowed paths, accepted predecessor versions/digests, direct-argv isolated acceptance, finite attempts and rollback. Repository merge is not harness qualification. R01 owns public contracts; R09 owns authoritative provider registry/promotion; R04 presents their management projection; R10 reconciles the verified installation; R11 packages; R12 qualifies.

The browser reads authenticated control-plane projections and never fans out to all planes. The control plane is outside the synchronous agent request path. The runtime gateway calls the selected model route or task orchestration; it does not retrieve data, assemble context or execute tools. Every service owns its durable state and migrations; no service writes another service’s database schema.

## Provider and research direction

The [provider adoption source](alpha-2/PROVIDER_ADOPTION_ROADMAP.md) retains the `MET-ADOPT-001` policy and its detailed alternatives. It is a historical/detail authority for those decisions, not a second current progress roadmap.

The [sixteen-row research map](alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md) and [adoption ledger](../architecture/research-adoption.json) identify papers, OSS upstreams, owner repositories, proposed packets and qualification gates. They are planning research, not evidence that a provider is installed. At least one qualified provider for each released capability is required; an internal module alone does not satisfy an OSS adoption claim. Preserve later alternatives in the [traceability crosswalk](alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md).

Initial directions include Ollama, llama.cpp and vLLM for H2; LiteLLM’s reviewed open-source compatibility surface for H3; AG-UI/CopilotKit for H4; RDFLib/pySHACL, Trino/Great Expectations/OpenLineage, LlamaIndex/pgvector and a governed memory candidate for H5–H8; MCP/A2A, a separately decided Temporal transition, Wasmtime/gVisor/Kata and local ML/optimization libraries for H9–H12; OPA/Presidio, MLflow integration, OpenTelemetry/Prometheus and Inspect for H13–H16. Milvus external attachment is a later retrieval option before any managed-installation proposal. Ollama attachment to the existing endpoint and managed installation require separate qualification. Framework fake-surface tests do not qualify pinned upstream packages.

Before building another general-purpose router, serving, workflow, retrieval or evaluation engine, publish a measured build-versus-integrate ADR. Failed upstream qualification leaves that option unqualified; it is not permission for unreviewed bespoke replacement. The existing PostgreSQL durable-execution source stays historical while R08 decides the Temporal successor, migration, history replay and single side-effect authority. H12’s competing prose API paths are **INTERFACE_NOT_PUBLISHED** until R01 releases a versioned decision contract and compatibility vectors. Closed-schema consumers require old/new vectors even for additive fields and retain the one-minor migration window.

Jev-style typed semantic judgment is an **optional proposal** across selected existing harnesses, not a fifth plane or H17. The official hosted proprietary Jev model is outside the shipped air-gapped, zero-bill baseline. Laya and SemIF require their own open-weight, license, backend, tokenizer, calibration, domain/language, abstention and independent qualification review; neither is currently selectable. Semantic scores may advise classification, route choice, retrieval relevance, memory proposals, decision features or evaluation. Deterministic policy, budgets, side effects and promotion retain authority. The proposed SEM packet IDs remain unpublished.

After the first enterprise release, consider E1 governed evidence-to-improvement, E2 optional behavior/taste distillation and E3 separately approved reinforcement-learning research. Operational evidence, user memory and eligible training data remain distinct; no trace becomes training input or promoted runtime behavior automatically.

## Phase roadmap and current position

The following is a **source-status checkpoint**, not proof of installed runtime or tenant acceptance. PR #138 placed MET-ENFORCE-003 on accepted source main. Its old “ongoing publication” headers are historical. Alpha 2 is still open.

The [item-level backlog](../architecture/unified-roadmap-backlog.json) records phase, owner, status, predecessors, blocker and planned evidence reference for every published packet and proposal; the [requirement dispositions](../architecture/unified-requirement-dispositions.json) join indexed source sections to ownership and unresolved delivery mappings. All accepted source sections now have reviewed delivery and acceptance-plan dispositions; 38 explicit unresolved markers retain actual future design, packet, native-qualification or provider obligations. They do not count as implementation or acceptance, and the affected work cannot advance until its exact owner packet closes them.

| Phase | ID or workstream | Current status | Deliverable / blocking fact |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundation packets | DONE_RECORDED | Historical source/offline foundation; installed-foundation and production-overview evidence are separate carryovers |
| Alpha 2 preparation | MET-ENFORCE-003 | MERGED_SOURCE_RECORDED | PR #138 on accepted main; reviewed W01 candidate remains a design, not a native enforcement proof |
| Alpha 2 preparation | MET-UNIFY-001 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Unpublished failed local candidate; two LOCAL attempts consumed, no PR/CI/merge or budget transfer |
| Alpha 2 preparation | MET-UNIFY-002 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Unpublished candidate; three LOCAL attempts consumed, stale 204-file assertion retained |
| Alpha 2 preparation | MET-UNIFY-003 | BLOCKED_CI_ALLOWANCE_EXHAUSTED | PR #139 unmerged; LOCAL PASS, CI-1 transport failure and CI-2 15-minute cancellation; no runner remains |
| Alpha 2 preparation | MET-UNIFY-004 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Local commit only; LOCAL-1 status-check failure and LOCAL-2/3 750-second timeouts; no PR, CI or merge |
| Alpha 2 preparation | MET-UNIFY-005 | MERGED_SOURCE_RECORDED | PR #140 on exact accepted main `945de93`; source history only, not Linux or tenant qualification |
| Alpha 2 CI capacity | MET-RUNNER-001 / PR #143 | MERGED_SOURCE_EXCEPTION | Source on `0314a684`; one-time merge exception consumed, not required CI PASS, installed runner or native qualification |
| Alpha 2 validation | MET-PERF-019 | FAILED_LOCAL_FROZEN | Unaccepted source and consumed LOCAL1 retained; no replay or transferred allowance |
| Alpha 2 validation | MET-PERF-020 | FAILED_LOCAL_FROZEN | Shared allowance and additional custody exception consumed; failure records retained without replay |
| Alpha 2 validation | MET-PERF-021 | FAILED_LOCAL_FROZEN | LOCAL1/1 failed readiness before pytest; source, evidence and cleanup retained |
| Alpha 2 validation | MET-PERF-022 | FAILED_LOCAL_FROZEN | LOCAL 1/1 failed historical test identity checks before pytest; source and evidence retained |
| Alpha 2 validation | MET-PERF-023 | FAILED_LOCAL_FROZEN | LOCAL1/1 timed out with invalid diagnostics; exact failure and cleanup records retained |
| Alpha 2 validation | MET-PERF-024 | FAILED_LOCAL_FROZEN | Diagnostic fixes narrowly exercised; whole run timed out at52/53, cleanup confirmed |
| Alpha 2 validation | MET-PERF-025 | FAILED_LOCAL_FROZEN | Nested and outer deadlines exhausted;52/53 commands and independently confirmed cleanup |
| Alpha 2 validation | MET-PERF-026 | SOURCE_PREPARED_AWAITING_REVIEW | Snapshot decode source prepared; final independent review and full execution gates remain |
| Alpha 2 runner repair | MET-LINUX-004 / PR #144 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | All three LOCAL attempts consumed; preserve frozen source/results, separately queued CI and unpassed Linux gates |
| Alpha 2 CI capacity | MET-UNIFY-008 / PR #141 | BLOCKED_SELF_HOSTED_CI | Source PR open; `verify` queued with no registered runner |
| Alpha 2 CI capacity | MET-LINUX-003 / PR #142 | BLOCKED_SELF_HOSTED_CI | Draft source PR open; `verify` queued on the same labels; queue must be serialized before one-job admission |
| Alpha 2A | W01 / MET-ENFORCE-004 | DESIGN_RESOLVED_REVIEWED | G04–G07/G09 resolved at design level and independently reviewed; E01–E12 remain OPEN_UNPROVEN |
| Alpha 2A | W02 (W02a MET-ENFORCE-005, W02g MET-ENFORCE-006, W02b MET-ENFORCE-007, W02c MET-ENFORCE-008, W02e MET-ENFORCE-009, W02a-F MET-ENFORCE-010, W02b-F MET-ENFORCE-011, W02g-F MET-ENFORCE-012, W02f MET-ENFORCE-013, W02c-F MET-ENFORCE-014, W02-ADM-F MET-ENFORCE-015, W02e-F MET-ENFORCE-016) / W03–W07 | W02a, W02g, W02b, W02c, W02e, W02a-F, W02b-F, W02g-F, W02f, W02c-F, W02-ADM-F and W02e-F VERIFY_PASSED_MERGED; others WAITING_EXACT_PACKETS | W02a v2 record contract, W02g I06 backend profile, W02b I05 channel, W02c I07 writer and W02e SELinux matrix contracts reviewed; remaining W02 parts and W03–W07 are labels, not executable YAML |
| Alpha 2A | CONF-FIX-010 | BLOCKED_SAFE_DESIGN | Zero product attempts; requires separately reviewed safe design and bounded packet authority |
| Alpha 2A | CONF-LIVE-004/005/006 | WAITING_PREREQUISITES | Native probes, package handoff and trusted campaign integration |
| Alpha 2A | CONF-LINUX-001 native AMD64 | NOT_RUN_ENV_UNAVAILABLE | Fresh real-Linux PASS gates runtime coding of CTRL-INTEGRATE-001, MODEL-001, EXEC-001 and RUN-001; ARM64 separate |
| Alpha 2B | Seven EXT proposal IDs | WAITING_PACKET_PUBLICATION | Contract-first provider/adapter/binding qualification, registry, UI, packaging and mode-aware reconciliation |
| Alpha 2B onward | Sixteen OSS adoption proposal IDs | WAITING_PACKET_PUBLICATION | Owner-specific actual pinned upstream integrations and qualification |
| Alpha 2B onward | JEV/Laya/SemIF SEM proposals | WAITING_PACKET_PUBLICATION | Optional local semantic contracts, adapters and independent evidence |
| Alpha 2 sector | MET-SECTOR-001 / SECTOR-D1 | VERIFY_PASSED_MERGED | Banking replaces white goods through the first enterprise release; dispositions for 28 published packets; no catalog, pack or packet change |
| Alpha 2 sector | IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001, CONF-BANK-001 | WAITING_PACKET_PUBLICATION | Banking pack, banking inputs for retained packets and journey certification |
| Alpha 2 acceptance | CONF-A2-001 | WAITING | Integrated cited read-only banking profile (ID kept; revision amendment before dispatch), installed foundations and real overview |
| Alpha 3 | Governed action / CONF-A3-001 | WAITING | Approval, memory, sandbox, tools, decision service and full interaction |
| Alpha 4 | Enterprise campaigns / CONF-WG-001 | WAITING | Qualified baseline per released capability, disconnected install, lifecycle/security and independent banking tenant acceptance |
| Post-release | E1–E3 and provider expansion | DEFERRED | Governed improvement research and additional meaningful provider options |

Historical no-go and exhausted work stays closed: PLAN-CANON-001 is a recorded no-go; CONF-PERF-005 is unauthorized; CONF-FIX-007/008 retain prior outcomes; CONF-FIX-009 consumed its local allowance. No old attempt allowance transfers to a successor.

### Counted near-term checklist

These checkboxes count only the named deliverable at the stated evidence level. They are not a platform-completion percentage or permission to dispatch.

- [x] Phase 0 / Alpha 1 · MET-P0-002 · Record the five-source, license and provenance foundation in historical source evidence.
- [x] Alpha 2 · MET-ENFORCE-003 · Merge the reviewed host-interface source candidate as PR #138 on accepted main.
- [x] Alpha 2 · MET-UNIFY-005 · Publish this unified roadmap with exact historical inverse, independent review, declared offline acceptance, required CI and exact-main evidence at `945de93`.
- [ ] Alpha 2 · MET-RUNNER-001 · Publish the source-only bounded development-CI admission contract with exact 189-packet history, isolated acceptance, required CI and exact-main evidence.
- [ ] Alpha 2 · MET-PERF-028 · Complete exact-bytes authority recheck reuse and linear uniqueItems, independent review and separately authorized full LOCAL/CI/exact-main; preserve failed019–027/PR144 and unresolved timing/native Linux gates.
- [ ] Alpha 2 · MET-LINUX-005 · Complete the runner-contract repair on accepted 028 main, independent review and separately authorized full LOCAL/CI/exact-main; preserve PR144 attempts and unresolved native Linux gates.
- [x] Alpha 2 · MET-VERIFY-001 · Publish the owner-operated required verify contract and pass its own required verify through the owner's App; exact-main and native Linux remain separate.
- [x] Alpha 2 · MET-PERF-029 · Make history-chain authority rechecks linear with unchanged freshness and refusal semantics; pass required verify through the owner's App.
- [x] Alpha 2 · MET-PERF-030 · Prove the predecessor suite from the same packet session instead of re-running it; pass required verify through the owner's App.
- [x] Alpha 2 · MET-LINUX-006 · Make the complete suite pass on Linux as a non-root user; pass required verify through the owner's App.
- [x] Alpha 2 · MET-VERIFY-002 · Start the offline runner in isolated mode and admit transport changes only with the owner's exact-commit approval; pass required verify through the owner's App.
- [x] Alpha 2 · MET-VERIFY-003 · Start the network canary in isolated mode and apply the MET-VERIFY-002 review notes; pass required verify through the owner's App.
- [x] Alpha 2 · MET-VERIFY-004 · Record the dedicated verifier account in the verifier contract; pass required verify through the owner's App from that account.
- [x] Alpha 2A · W01 / MET-ENFORCE-004 · Resolve G04–G07/G09 and adopt a versioned host interface only after the required independent review; pass required verify through the owner's App.
- [x] Alpha 2A · W02a / MET-ENFORCE-005 · Publish the independently reviewed v2 native qualification contract; pass required verify through the owner's App.
- [x] Alpha 2A · W02g / MET-ENFORCE-006 · Publish the independently reviewed I06 backend profile (selection criteria, writer inventory, identity closure incl. W01 F1); pass required verify through the owner's App.
- [x] Alpha 2A · W02b / MET-ENFORCE-007 · Publish the independently reviewed I05 broker-gate channel wire contract; pass required verify through the owner's App.
- [x] Alpha 2A · PERF-031 / MET-PERF-031 · Cut required-verify time with test-local exact projection sharing in three mutation loops; pass required verify through the owner's App.
- [x] Alpha 2A · W02c / MET-ENFORCE-008 · Publish the independently reviewed I07 policy-writer channel contract and closed policy-kind table; pass required verify through the owner's App.
- [x] Alpha 2A · W02e / MET-ENFORCE-009 · Publish the independently reviewed SELinux domain, type, boolean and permission matrix with the F2 closure; pass required verify through the owner's App.
- [x] Alpha 2 · MET-SECTOR-001 · Record owner decision SECTOR-D1 (banking replaces white goods through the first enterprise release) with packet dispositions and successor proposals; pass required verify through the owner's App.
- [x] Alpha 2 · PERF-032 / MET-PERF-032 · Cut required-verify time by removing four repeated computations with unchanged refusals; pass required verify through the owner's App.
- [x] Alpha 2A · W02a-F / MET-ENFORCE-010 · Publish the independently reviewed native qualification record v3 closing the findings carried to W02a-F; pass required verify through the owner's App.
- [x] Alpha 2A · W02b-F / MET-ENFORCE-011 · Publish the independently reviewed I05 broker-gate channel v2 closing the findings carried to W02b-F; pass required verify through the owner's App.
- [x] Alpha 2A · W02g-F / MET-ENFORCE-012 · Publish the independently reviewed I06 backend profile v2 closing the findings carried to W02g-F; pass required verify through the owner's App.
- [x] Alpha 2A · W02f / MET-ENFORCE-013 · Publish the independently reviewed POLICY-ADMISSION-SEMANTICS/v2 and A2 admission allowlists; pass required verify through the owner's App.
- [x] Alpha 2A · W02c-F / MET-ENFORCE-014 · Publish the independently reviewed I07 policy writer channel v2 closing the findings carried to W02c-F; pass required verify through the owner's App.
- [x] Alpha 2A · W02-ADM-F / MET-ENFORCE-015 · Publish the independently reviewed I05 v3, POLICY-ADMISSION-SEMANTICS/v3 and I07 v3 successor contracts closing W02b-F2, W02f-F and W02c-F2; pass required verify through the owner's App.
- [x] Alpha 2A · W02e-F / MET-ENFORCE-016 · Publish the independently reviewed SELinux matrix v4 closing K2, K3, K4 and K6; pass required verify through the owner's App.
- [x] Alpha 2 · PERF-035 / MET-PERF-035 · Run the outer suite on fail-closed workers inside the unchanged argv, with suite reuse (validators and freshness unchanged); pass required verify through the owner's App.
- [x] Alpha 2 · PERF-SEL / MET-PERF-036 · Replay the SELinux matrices inside validate() instead of three to five times per layer test file, with per-row weakening conjuncts (no validator refusal changes, nothing cached); pass required verify through the owner's App.
- [x] Alpha 2 · CATALOG-BANK / MET-SECTOR-002 · Publish the SECTOR-D1 catalog follow-ups as a reviewed overlay with the catalogs byte-identical; pass required verify through the owner's App.
- [x] Alpha 2A · W02d / MET-ENFORCE-017 · Publish the per-role, per-architecture seccomp allowlists and filter digests as reviewed data; pass required verify through the owner's App.
- [x] Alpha 2A · W01-AMEND / MET-ENFORCE-018 · Publish W01 amendment W02D and the W02d successor seccomp-allowlists-v2 as reviewed data; pass required verify through the owner's App.
- [x] Alpha 2A · W03-0 / MET-ENFORCE-019 · Publish the W03 backend distribution selection and the W03 plan as reviewed data; pass required verify through the owner's App.
- [x] Alpha 2A · W02d-V3 / MET-ENFORCE-020 · Publish the W02d successor seccomp-allowlists-v3 (Rust+musl NATIVE_STATIC rules) as reviewed data; pass required verify through the owner's App.
- [ ] Alpha 2A · LIC-HOST / MET-ENFORCE-021 · Publish license-policy amendment LIC-HOST-A1 as a reviewed overlay on the byte-identical base policy; pass required verify through the owner's App.
- [ ] Alpha 2A · CONF-FIX-010 · Complete safe design and exact authority before any product attempt.
- [ ] Alpha 2A · CONF-LIVE-004 · Produce the exact native-probe source implementation and separately qualify it.
- [ ] Alpha 2A · CONF-LIVE-005 · Produce a reproducible selected package and operator handoff.
- [ ] Alpha 2A · CONF-LIVE-006 · Integrate the external trusted campaign path.
- [ ] Alpha 2A · CONF-LINUX-001 · Obtain fresh native Linux AMD64 PASS for the blocked runtime-coding gate.
- [ ] Alpha 2 · CTRL-INTEGRATE-001 · Complete production tenant overview and durable status projection after its Linux gate.
- [ ] Alpha 2 · CONF-A2-001 · Qualify the exact integrated read-only profile and inherited foundation evidence.
- [ ] Alpha 3 · CONF-A3-001 · Qualify governed action and interaction.
- [ ] Alpha 4 · CONF-WG-001 · Produce an unsigned banking tenant-acceptance candidate (ID kept from the white-goods plan) after required enterprise campaigns.

## Retained MET-PERF-019-era launch order (historical; not current dispatch)

1. Prepare MET-PERF-019 as one source-only packet against accepted main `0314a684`: exact 92 paths, 190 immutable predecessor YAML, reversible current-to-190 projection, inherited 52 commands plus its one declared validator, and source/error-parity review. No executed diagnostic, selected test or new attempt follows from source publication.
2. Bind independently reviewed exact-source finite execution authority before any reservation. Complete the unchanged full isolated acceptance, required self-hosted CI, protected green merge and separate exact-main evidence. A separately authorized operator must prove Linux host image, root-owned signed admission, throughput, egress/cost bounds and automatic plus independent teardown before runner registration. Refresh and serialize the actual queue before exact-job admission. Preserve PR144's failed history and require its own later base/scope reconciliation. Dashboard source registration remains a separately owned orchestrator packet.
3. Continue W01 design and the existing conformance correction chain under their exact approved packet boundaries. W02–W07 and unpublished EXT/OSS/SEM proposals are not dispatch targets.
4. Run native Linux campaigns only with the external trusted signed launcher, pre-existing authorized capacity and the exact server-side zero-cost admission. Missing target/backend is NOT_RUN_ENV_UNAVAILABLE, never PASS or permission to provision.
5. Start an eligible product packet only after its published predecessor contracts, immutable locks, required native gate and repository policy are satisfied. Release qualification and tenant acceptance require their own exact evidence.

All local packet acceptance runs use the preinstalled deny-all-outbound OS-isolated launcher, direct argv and the same process tree for prefetch and acceptance. Warm snapshots remain denied. Live campaign evidence may cover only declared deployment, runtime, security, assurance and unsigned tenant-candidate axes. Source, unit, PR, merge, SBOM/artifact, signature/release, deployment, runtime, assurance and tenant acceptance are independently recorded. A waiver never replaces a fresh required production PASS.

Required cross-harness acceptance includes unknown-outcome retry safety, streaming cancellation acknowledgement, memory deletion surviving restore, staged-versus-committed data, budget reservations, stateful-provider migration and rollback, real tenant RLS, stale overview projections, local assets, WCAG 2.2 AA, offline installation, security/upgrade campaigns and independent tenant acceptance. Thresholds and profile scope must be frozen in the owning packet before tests.

Alpha 2 has not ended, so the requested phase-end model-effort reminder is **NOT_DUE**. Keep the selected model/effort unchanged; at phase closeout report the next phase’s recommended effort without switching it automatically.

## Retained source-navigation keys (historical)

The links and exact tokens below preserve predecessor source-navigation checks. Their recorded labels—including `WAITING_PREDECESSOR_CORRECTION`, `NOT_AUTHORIZED` and `BLOCKED_LOCAL_BUDGET_EXHAUSTED`—describe earlier checkpoints, **not** today's dispatch authority or the current phase status above.

| Detailed source | Retained publication keys |
|---|---|
| [Paper/repository map](alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md) | `MET-ADOPT-002`; `WAITING_PREDECESSOR_CORRECTION` |
| [Proxy diagnostics](alpha-2/PROXY_PERFORMANCE_DIAGNOSTICS.md) | `MET-PERF-006` |
| [Canonical repair](alpha-2/CANONICAL_REPAIR_PLAN.md) | `MET-PERF-007`; `NOT_AUTHORIZED` |
| [Backend timing](alpha-2/BACKEND_TIMING_DIAGNOSTICS.md) | `MET-PERF-008`; `CONF-DIAG-002`; `NOT_AUTHORIZED` |
| [Completion profiling](alpha-2/COMPLETION_PROFILING.md) | `MET-PERF-009`; `CONF-DIAG-003`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Validation performance](alpha-2/VALIDATION_PERFORMANCE_REPAIR.md) | `MET-PERF-010`; `WAITING_PREDECESSOR_CORRECTION` |
| [Document repair plan](alpha-2/DOCUMENT_REPAIR_PLAN.md) | `MET-PERF-011`; `CONF-DIAG-003`; `INCOMPLETE_DIAGNOSTIC_RETAINED`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Document repair authority](alpha-2/DOCUMENT_REPAIR_AUTHORITY.md) | `MET-PERF-012`; `CONF-PERF-006`; `CONF-BENCH-002`; `WAITING_META`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Benchmark transport](alpha-2/BENCHMARK_TRANSPORT.md) | `MET-PERF-013`; `CONF-BENCH-003`; `NON_DISPATCHABLE`; `CANDIDATE_FROZEN` |
| [Factory diagnostics](alpha-2/FACTORY_DIAGNOSTICS.md) | `MET-PERF-014`; `CONF-DIAG-004`; `BLOCKED_LOCAL_FAILURE` |
| [Guard cost repair](alpha-2/GUARD_COST_REPAIR.md) | `MET-PERF-015`; `CONF-FIX-009`; `CLOSED_PARTIAL_DIAGNOSTIC` |
| [Accounting scope](alpha-2/ACCOUNTING_SCOPE_AMENDMENT.md) | `MET-PERF-016`; `CONF-FIX-009` |
| [Guard traversal](alpha-2/GUARD_TRAVERSAL_REPAIR.md) | `MET-PERF-017`; `CONF-FIX-010` |
| [Catalog traversal](alpha-2/CATALOG_TRAVERSAL_REPAIR.md) | `MET-PERF-018`; `BLOCKED_SAFE_DESIGN` |
| [Local acceptance](alpha-2/LOCAL_ACCEPTANCE_REVALIDATION.md) | `MET-ACCEPT-001`; `CONF-LIVE-003` |
| [Conformance publication](alpha-2/CONFORMANCE_PUBLICATION.md) | `MET-PUBLISH-001`; `CONF-LIVE-003` |
| [Conformance completion](alpha-2/CONFORMANCE_COMPLETION.md) | `MET-REPAIR-017`; `WAITING_PREDECESSOR_CORRECTION` |
| [Completion integration](alpha-2/COMPLETION_INTEGRATION.md) | `MET-REPAIR-018`; `CONF-FIX-008`; `DONE_SOURCE_GATES` |
| [Observation/enforcement](alpha-2/OBSERVATION_ENFORCEMENT_PUBLICATION.md) | `MET-REPAIR-019`; `BLOCKED_SAFE_DESIGN` |
| [Enforcement integration](alpha-2/ENFORCEMENT_INTEGRATION.md) | `MET-ENFORCE-001`; `BLOCKED_SAFE_DESIGN` |
| [Host-interface publication](alpha-2/HOST_INTERFACE_PUBLICATION.md) | `MET-ENFORCE-003`; `BLOCKED_SAFE_DESIGN` |
