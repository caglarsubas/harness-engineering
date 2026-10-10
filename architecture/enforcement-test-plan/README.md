# W04-0 — independent enforcement test plan and observation-window register schema (DATA_CHECK_ONLY)

Status: **CANDIDATE_ROUND4_AWAITING_INDEPENDENT_REVIEW**. Rounds 1 to 3 (`review-round1..3.json`, subject bytes in
`round1/` to `round3/`) returned CHANGES_REQUIRED; the dispositions sections below answer each finding.
Roadmap item W04 (parallel lane; owner decisions D-R12,
D-TOOL, D-MAP, D-OW and D-ID, 2026-10-10, via the lane monitor).

W04 writes the independent adversarial test source for the later verification matrix (T01-T08 of
`architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81`, with the T08 additions of the resolved specification
section 4.4) and the exhaustive direct and indirect observation-window map. No document maps the test groups to the
obligations E01-E12, and nothing splits W04's work from W06's native campaign; this record does both, before any test is
written.

- `traceability.json` (`planeon.internal.enforcement-test-plan/v1`): the R12 repository record, the independence rules
  and attestation fields, the adopted contract inputs pinned by sha256, the eight test groups, the twelve obligations, the
  acceptance items A01-A09, the packets W04-0..W04-7 and the owner decisions.
- `observation-windows.schema.json` (`planeon.internal.observation-windows/v1`): the schema of the exhaustive register W04-7
  fills after W05. It is bound to the R12 observation reader, which owns the observation calls: one baseline revision of
  the reader, W05's R10 release (and harness-onion main) as the enforcement context the exclusion proofs rely on, and an
  inventory of boundaries generated mechanically by a pinned tool. Each window (OW-nn) names its boundary, observation
  call, nested checks, protected facts, trace position, autonomous-event latency, rows and tests; its removal fields
  (removed or moved call, new position, lost window, exclusion proof, state keeping fresh checks) stay null until W07's
  reader-successor candidate proposes them. `check_register` validates a filled register against the schema and checks
  unique ids, inventory coverage and acyclic indirect parents.
- `../../scripts/enforcement_test_plan.py`: reference model; `check(read)` validates both through an injected byte reader.

## Test groups

| Group | Matrix row | Evidence class | Case phases | Obligations | Packet |
|---|---|---|---|---|---|
| TG-01 | T01 contract | OFFLINE_CONTRACT | AFTER_W05_RELEASE_SET, W04_OFFLINE | E04, E06, E07, E10, E11 | W04-2 |
| TG-02 | T02 lifecycle | SOURCE_OWNER_IMPLEMENTATION | AFTER_W05_RELEASE_SET, W04_OFFLINE, W06_NATIVE_ONLY | E07, E09, E10 | W04-3 |
| TG-03 | T03 persistence | SOURCE_MULTIPROCESS_FAULT | AFTER_W05_RELEASE_SET, W06_NATIVE_ONLY | E10, E11, E12 | W04-3 |
| TG-04 | T04 host | NATIVE_HOST | W06_NATIVE_ONLY | E01, E02, E03, E04, E05, E06, E07, E11, E12 | W04-4 |
| TG-05 | T05 clocks | NATIVE_LIFETIME | W06_NATIVE_ONLY | E07, E08, E11 | W04-4 |
| TG-06 | T06 API/writers | BACKEND_INTEGRATION | W06_NATIVE_ONLY | E10, E11 | W04-5 |
| TG-07 | T07 cleanup | NATIVE_INTEGRATION | W06_NATIVE_ONLY | E10, E12 | W04-5 |
| TG-08 | T08 compatibility | SOURCE_AND_INSTALLED_MIGRATION | AFTER_W05_RELEASE_SET, W04_OFFLINE, W06_NATIVE_ONLY | E07, E10, E11 | W04-6 |

Native evidence classes (host, lifetime, backend and native integration) run only in W06; the model refuses any of their
cases with an earlier phase. Source groups may also carry native cases (TG-02, TG-03, TG-08), which run in W06.

## Cases

### TG-01 contract

- `MATRIX:exact fields` exact fields, checked against the adopted reference models' frame and record vectors (W04_OFFLINE; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:duplicate/unknown keys` duplicate/unknown keys (W04_OFFLINE; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:role/version mismatch` role/version mismatch (W04_OFFLINE; E07, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:transcript replay` transcript replay (W04_OFFLINE; E10, E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:wrong peer` wrong peer (W04_OFFLINE; E07; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `CE23` counterexample 23: an I07 WRITE_OBJECT carrying a Pod or an unknown kind is refused (W04_OFFLINE; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (23))
- `CONTRACT-DATA` host data contracts (I06 v2 criteria, SELinux matrix v4, seccomp v2) replay offline through their reference models as the input the probes are generated from (W04_OFFLINE; E04, E06, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; the adopted contracts)
- `CODEC` the same contract cases against the implementation's frame and record codecs, through a narrow adapter, using W05's released build only (AFTER_W05_RELEASE_SET; E07, E10, E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)

### TG-02 lifecycle

- `MATRIX:unarmed/duplicate/cross-case action` unarmed/duplicate/cross-case action (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:old socket` old socket (AFTER_W05_RELEASE_SET; E07, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:queued action` queued action (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:conflicting gate/server result` conflicting gate/server result (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:same-generation delayed-identical-request across two armed actions` same-generation delayed-identical-request across two armed actions (counterexample 17, G09) (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `S63-SOURCE` the section 6.3 residual (a new connection after ARM(B) sends bytes identical to B; misattribution becomes HELD) as a source case (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 6.3)
- `S63-NATIVE` the same section 6.3 residual as a native case (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 6.3; blocked by D-W02A-F2)
- `CE18` counterexample 18: a policy writer commits an RBAC change while an admitted CREATE is in flight; A3 blocks it, the urgent path records ADMITTED_BEFORE_INVALIDATION (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (18))
- `CE22` counterexample 22: connection K opened while A is armed and used after B is armed carries A's stamp and C4 refuses (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (22))
- `S8-C2C3` C2/C3 flush and stamp behaviour under load and restart (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8 (T02/T03); blocked by D-W02A-F2)
- `LEDGER-E09` the R12 reader's private factory and dynamic guards: reentrancy, wrong owner, partial construction and state corruption fail sticky; an explicit trusted-code boundary; real fixed factories, dynamic peer overrides, partial acquisition and original-resource-only cleanup under resource substitution (W04_OFFLINE; E07, E09; docs/alpha-2/ENFORCEMENT_FEASIBILITY.md:166 (row E09); docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md:327 (A02))

### TG-03 persistence

- `MATRIX:kill at each fsync/send/result boundary` kill at each fsync/send/result boundary (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:ENOSPC` ENOSPC (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:partial records` partial records (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:lost acknowledgements` lost acknowledgements (AFTER_W05_RELEASE_SET; E11, E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:restart/rollback` restart/rollback (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `CE21` counterexample 21: the gate restarts mid-execution with clients connected; deny-first, HELD, no stamps restored (AFTER_W05_RELEASE_SET; E10, E11; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (21))
- `S8-C2C3` C2/C3 flush and stamp behaviour under load and restart (W06_NATIVE_ONLY; E11; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8 (T02/T03); blocked by D-W02A-F2)

### TG-04 host

- `MATRIX:policy/load/boolean/relabel` policy/load/boolean/relabel (W06_NATIVE_ONLY; E04; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:namespaces/mount aliases` namespaces/mount aliases (W06_NATIVE_ONLY; E01, E03; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:effective BPF ancestors` effective BPF ancestors (W06_NATIVE_ONLY; E05; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:mappings/injection` mappings/injection (W06_NATIVE_ONLY; E06; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:parent/FD spoof` parent/FD spoof (W06_NATIVE_ONLY; E02, E07; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `LEDGER-E01` path and writer aliases: transient rename and restore, retained writers, relabel and mode changes (W06_NATIVE_ONLY; E01; docs/alpha-2/ENFORCEMENT_FEASIBILITY.md:158 (row E01); blocked by D-W02A-F2)
- `LEDGER-E02` process-owned descriptors: close, dup, reuse, inheritance and ancillary injection (W06_NATIVE_ONLY; E02; docs/alpha-2/ENFORCEMENT_FEASIBILITY.md:159 (row E02); blocked by D-W02A-F2)
- `S8-KERNEL-FACTS` the section 5.1 kernel facts hold on the enrolled kernel and policy (W06_NATIVE_ONLY; E05, E06; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8; blocked by D-W02A-F2)
- `S8-POLICYLOAD` secure_mode_policyload conditionals in the pinned binary policy (W06_NATIVE_ONLY; E04; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8; blocked by D-W02A-F2)
- `S8-FREEZE` freeze before user space under CLONE_INTO_CGROUP on the enrolled kernel (W06_NATIVE_ONLY; E07, E12; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8 (T04/T05); blocked by D-W02A-F2)
- `S8-CLOSURE` completeness of the section 2 closure on a real host (E03-E05) (W06_NATIVE_ONLY; E03, E04, E05; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8; blocked by D-W02A-F2)
- `O-T04-AMEND` per-role seccomp decisions (ALLOW, KILL_PROCESS, ENOSYS) on both architectures; MFD_NOEXEC_SEAL memfds non-executable and exec-sealed; a pidfd signal from the broker without CAP_KILL fails; the worker shows Seccomp_filters: 2 and lists no supplementary groups (W06_NATIVE_ONLY; E06, E07, E12; architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md section 11; blocked by D-W02A-F2)
- `CE19` counterexample 19: a runtime restart of host containment is refused (W06_NATIVE_ONLY; E04, E05; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (19); blocked by D-W02A-F2)
- `CE25` counterexample 25: a datastore restore at runtime is refused outside reboot maintenance (W06_NATIVE_ONLY; E04, E11; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (25); blocked by D-W02A-F2)
- `CE27` counterexample 27: no reader keeps CAP_SYS_ADMIN for GET_FD_BY_ID; command 13 is removed (W06_NATIVE_ONLY; E05; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (27); blocked by D-W02A-F2)
- `CE28` counterexample 28: an O_PATH fd on a role cgroup cannot detach its enrolled program (W06_NATIVE_ONLY; E05; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (28); blocked by D-W02A-F2)

### TG-05 clocks

- `MATRIX:expiry with stalled Python` expiry with stalled Python (W06_NATIVE_ONLY; E08; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:suspend` suspend (W06_NATIVE_ONLY; E08; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:wall-clock rollback` wall-clock rollback (W06_NATIVE_ONLY; E08; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:peer death/restart` peer death/restart (W06_NATIVE_ONLY; E07; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:original deadlines` original deadlines (W06_NATIVE_ONLY; E08, E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `S8-FREEZE` freeze before user space under CLONE_INTO_CGROUP, as a lifetime case (a frozen child never reaches user space before W3) (W06_NATIVE_ONLY; E07, E08; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8 (T04/T05); blocked by D-W02A-F2)

### TG-06 API/writers

- `MATRIX:reads` reads (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2, D-SC01-PEER)
- `MATRIX:final mutated objects` final mutated objects (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2, D-SC01-PEER)
- `MATRIX:controller/aggregate-role changes` controller/aggregate-role changes (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2, D-SC01-PEER)
- `MATRIX:privileged/alternate paths` privileged/alternate paths (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2, D-SC01-PEER)
- `MATRIX:direct-storage hazards` direct-storage hazards, including etcd over its unix socket (selection owner decision Q4) (W06_NATIVE_ONLY; E10, E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2, D-SC01-PEER)
- `S8-CLOSURE` completeness of the section 2 closure on a real host (E10) (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8; blocked by D-W02A-F2, D-SC01-PEER)
- `S8-A2` A2 field allowlists against real defaulting (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8 (T06); blocked by D-W02A-F2, D-SC01-PEER)
- `CE20` counterexample 20: a root login with a leftover admin kubeconfig is refused by name_connect (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (20); blocked by D-W02A-F2, D-SC01-PEER)
- `CE24` counterexample 24: an aggregated ClusterRole widening is excluded from the closure and refused by the observer (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (24); blocked by D-W02A-F2, D-SC01-PEER)
- `CE26` counterexample 26: CSR approval cannot mint a privileged client certificate (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (26); blocked by D-W02A-F2, D-SC01-PEER)

### TG-07 cleanup

- `MATRIX:ambiguous create` ambiguous create (W06_NATIVE_ONLY; E10, E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:conflicting UID` conflicting UID (W06_NATIVE_ONLY; E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:delete precondition` delete precondition (W06_NATIVE_ONLY; E10, E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:revoked cleanup` revoked cleanup (W06_NATIVE_ONLY; E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)
- `MATRIX:pending remote effects` pending remote effects (W06_NATIVE_ONLY; E10, E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)

### TG-08 compatibility

- `S44` the section 4.4 rejection vectors through native qualification v3's cross-version and negative vectors: each reader refuses a record of another version with no fallback; a record missing EFFECT_GATE, with an extra role, with the gate under the BROKER key or path, with an aliased role path, with a lifecycle subject inside a resident role cgroup, or with unknown backendComponents keys refuses (W04_OFFLINE; E07, E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 4.4)
- `MATRIX:old profile rejection` old profile rejection, as source tests of the released build (AFTER_W05_RELEASE_SET; E07, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:new profile missing gate/backend` new profile missing gate/backend, as source tests of the released build (AFTER_W05_RELEASE_SET; E07, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `MATRIX:export/upgrade/rollback without nonce reuse` export/upgrade/rollback without nonce reuse; migration never reinterprets accepted data or reuses a generation or nonce (section 4.4), as source tests (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- `INSTALLED` the same migrations on the installed host, separately from the source tests (W06_NATIVE_ONLY; E10, E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; blocked by D-W02A-F2)

Blockers (on native cases only): D-W02A-F2: a production W02a backend profile naming the selected components, their canonical paths, confined types and verity digests (selection open item; native qualification v3 has none yet); gates the W06 run of every native case, not the writing of its source; D-SC01-PEER: the I06 successor accepting etcd's single AF_UNIX peer listener (selection open item); gates the W06 run of TG-06's native cases

## Obligations

| Row | Theme | Test groups | Gates (resolved spec section 8) | W06 |
|---|---|---|---|---|
| E01 | Path and writer aliases (SELinux plus fs-verity; ancestor, path and writer policy) | TG-04 | G07 | Runs the native cases of TG-04 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E02 | Process-owned file descriptors | TG-04 | - | Runs the native cases of TG-04 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E03 | Mount and namespace restrictions | TG-04 | G04, G07 | Runs the native cases of TG-04 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E04 | SELinux policy changes and exclusive update lifecycle | TG-01, TG-04 | G04, G07 | Runs the native cases of TG-04 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E05 | Cgroup v2 and exact BPF endpoint programs | TG-04 | G04, G07 | Runs the native cases of TG-04 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E06 | Code, maps and injection (loader versus sealed phase) | TG-01, TG-04 | G07 | Runs the native cases of TG-04 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E07 | Peer and PID replacement | TG-01, TG-02, TG-04, TG-05, TG-08 | G06, G07 | Runs the native cases of TG-04, TG-05 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E08 | Original clocks, deadlines and independent expiry | TG-05 | G07 | Runs the native cases of TG-05 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E09 | The R12 reader's private factory and dynamic guards | TG-02 | - | No native case; W04's source evidence stands for this row until W07. |
| E10 | API-operation and policy-generation gate | TG-01, TG-02, TG-03, TG-06, TG-07, TG-08 | G04, G05, G09 | Runs the native cases of TG-02, TG-06, TG-07, TG-08 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E11 | Protected durable history and deny on restart | TG-01, TG-03, TG-04, TG-05, TG-06, TG-08 | G05 | Runs the native cases of TG-03, TG-04, TG-05, TG-06, TG-08 on the enrolled AMD64 and ARM64 hosts and records the evidence. |
| E12 | Broker process ownership, reaping and exact-UID records | TG-03, TG-04, TG-07 | G05, G07 | Runs the native cases of TG-04, TG-07 on the enrolled AMD64 and ARM64 hosts and records the evidence. |

## Independence

- W04 source lives in R12, separate from W03's R10 operator repository; no source crosses (ENFORCEMENT_INTEGRATION.md:110-114).
- Only the parallel lane authors W04; W03's authors write no W04 source, and W04's authors read no W03 source or work in progress.
- Allowed W03 inputs are reviewed records the owner names (today only the distribution selection record, pinned in w03Inputs) and, later, W05's released artifact digests.
- Expected results come from the adopted contracts' reference models and vectors, never from reading or running the implementation; implementations are run only as the subject under test, from W05's release.
- Every W04 packet carries an independence attestation with the fields below, and its separate-agent reviewer checks it.
- R12 never implements or self-certifies the enforcement premise (ENFORCEMENT_INTEGRATION.md:93).
- The new toolchains stay in W04's enforcement test area; the stdlib-only R12 reader is not extended (ENFORCEMENT_INTEGRATION.md:100-102).
- Agents never send personal data in network requests, headers or queries.

## Repository

R12 `mas-harness-conformance-labs` exists (public, `main`), but harness-onion's `architecture/repositories.yaml` records no
remote, and its verification today is a GitHub Actions workflow on a self-hosted ephemeral runner last used on 2026-09-16.
The owner's verifier is bound to harness-onion only. W04-1 waits for the owner's R12 verification route.

## Not claimed

- No test is written or run; W04-1..W04-7 write them.
- No native evidence; every native case runs only in W06.
- E01-E12 stay OPEN_UNPROVEN.
- The observation-window register is not filled; W04-7 fills it at the R12 reader's baseline.
## Owner decision D-OW-1 (2026-10-10, via the lane monitor)

D-OW stays recorded verbatim. D-OW-1 = A splits the register: W04-7 delivers the exhaustive register of the R12 reader's
current observation calls at a pinned R12 baseline, generated by a pinned inventory tool reviewed in the same packet and
re-run by its reviewer, with W05's R10 release as the enforcement context; W07 adds the lost-window half per removal
candidate. A01 is split between W04 and W07, and W04's exit wording (`ENFORCEMENT_INTEGRATION.md:125`) is amended through
the roadmap.

## Round-3 findings and dispositions

| Finding | Disposition |
|---|---|
| R3-1 MAJOR, D-OW rewritten in place without an owner answer | D-OW is recorded verbatim; the clarification is owner decision D-OW-1 (A, accepted), its own entry with a state; the model refuses a rewritten or pending D-OW and `check_publishable` refuses any pending decision. |
| R3-2 MINOR, A01 entirely in W04 | A01's `outsideW04` names the lost-window half as W07's, per D-OW-1; the model ties A01 to D-OW-1. |
| R3-3 MINOR, lax validator and an unpinned inventory generator | Patterns match with `re.fullmatch` (a trailing newline fails); `const` needs the same type (`exhaustive: 1` fails); W04-7's packet content requires a pinned inventory tool reviewed in the same packet and re-run by its reviewer. |
| R3-4 MINOR, unguarded content | INSTALLED is a required TG-08 W06 case; owner-implementation and fault groups refuse offline cases except the R12 reader's own E09 case; every tagged case keeps a pinned key phrase; per-group contracts, acceptance items and R12 locations are pinned. |
| R3-5 MINOR, group-level blockers | Blockers move onto the native cases they gate; each blocker's text says it gates the W06 run, not writing the source. |
| R3-6 NOTE | No change. |

## Round-2 findings and dispositions

| Finding | Disposition |
|---|---|
| R2-1 MAJOR, register bound to the wrong code | The register is bound to the R12 observation reader at a baseline revision, with W05's R10 release as enforcement context and a pinned mechanical inventory; removals wait for W07's candidate. The owner decided this as D-OW-1 = A (round 3, R3-1). |
| R2-2 MAJOR, the model claimed more than it checked | Every case has a tag. The model derives the matrix phrases from the pinned brief and requires each as a case starting with that phrase, in the phase its evidence class allows; it requires counterexamples 18-28, the section 8 items, the section 6.3 source and native cases, section 4.4, the ledger items, O-T04-AMEND, CODEC and CONTRACT-DATA in their groups and phases, with their source text present; case sources start with a pinned path; the contract file lists, independence rules, packet table, group packets, blockers and window binding are exact. |
| R2-3 MINOR, check_register and the schema check | `check_window_schema` requires equality with the schema the model builds; `check_register` validates against it with a stdlib validator, refuses self-parents and cycles, and requires a DIRECT root. |
| R2-4 MINOR, TG-01's codec half offline | The codec half is its own case (CODEC), after W05, against the released build only. |
| R2-5 MINOR, D-W02A-F2 blocked only TG-06 | Every group with a native case lists D-W02A-F2; TG-06 also D-SC01-PEER. |
| R2-6 MINOR, selection pin | The pin records commit 104b11529b6448a2c208450e5fbbd677e5dd8069 and its review state; a missing input is refused, not a crash; W04-0's earliest is after packet 221. |
| R2-7 MINOR, E09 case | The case names the explicit trusted-code boundary, partial acquisition and original-resource-only cleanup under resource substitution. |
| R2-8 NOTE | The freeze item is also a TG-05 case; the source index pins the earlier rounds' subject copies. |

## Round-1 findings and dispositions

| Finding | Disposition |
|---|---|
| R1-1 MAJOR, TG-02/TG-03 native parts had no W06 phase | Cases carry their own phase; TG-02 has the G09 residual and C2/C3 as W06 cases, TG-03 C2/C3 (resolved spec sections 6.3 and 8). |
| R1-2 MAJOR, TG-08 lacked E07 and I06 v2 | TG-08 covers E07 (G06) and pins I06 v2. |
| R1-3 MAJOR, E09 outside the groups contradicted A02 | E09 is a TG-02 case (the R12 reader's factory and guards, ledger row E09 at line 166), so A02's groups cover it. |
| R1-4 MAJOR, section 8 native items, counterexamples 18-28, uncited seccomp case | Each is a case with its source: section 8 items in TG-02/03/04/06, counterexamples 18, 21, 22, 23 offline or source and 19, 20, 24-28 native; the seccomp case cites O-T04-AMEND. |
| R1-5 MAJOR, missing or unpinned inputs | planeon-a2.json pinned; the W03 selection record pinned in w03Inputs (on main from packet 221); TG-06 blockedBy D-W02A-F2 and D-SC01-PEER; the six source documents pinned. |
| R1-6 MAJOR, schema did not force exhaustiveness | A required non-empty boundary inventory and candidate repository; non-empty windows; anchored ids; the removed or moved call, nested checks, state keeping fresh checks and indirect parent; non-empty strings; check_register enforces unique ids, inventory coverage and parents; the candidate is named. |
| R1-7 MAJOR, the model checked shape only | The model checks content against the pinned sources: matrix rows and evidence classes, the section 8 gate map, the design document's acceptance text, the adopted contract set and states, case phases for native classes, derived W04/W06 texts and the exact non-claims; type checks before use. |
| R1-8 MINOR, section 4.4 case partial | TG-08's offline case lists every section 4.4 vector, through native qualification v3's cross-version and negative vectors. |
| R1-9 MINOR, TG-08 source and installed not separate | TG-08 has offline, source (after W05) and installed (W06) cases, separately. |
| R1-10 MINOR, A02/A05 groups and shortened texts | A02 includes TG-05, A05 TG-02; acceptance texts are the design document's exact cells. |
| R1-11 MINOR, TG-01 subject and host data vectors | TG-01 names its subject and replays the I06 v2, SELinux v4 and seccomp v2 vectors offline. |
| R1-12 MINOR, attestation fields and toolchain rule | Attestation adds lane, input digests and implementation read or run; a rule keeps the new toolchains out of the stdlib-only R12 reader. |
| R1-13 NOTE, wording drift | TG-05 says "stalled Python", as the matrix does. |
