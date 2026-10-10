# W04-0 — independent enforcement test plan and observation-window register schema (DATA_CHECK_ONLY)

Status: **CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. Round 1 (`review-round1.json`, its subject bytes in `round1/`)
returned CHANGES_REQUIRED; "Round-1 findings and dispositions" below answers each finding. Roadmap item W04 (parallel lane; owner decisions D-R12,
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
  fills at the exact candidate revision (window ids OW-nn; every window names its protected facts, old and new trace
  positions, lost window, exclusion proof, direct or indirect kind, autonomous-event latency, obligations and tests).
- `../../scripts/enforcement_test_plan.py`: reference model; `check(read)` validates both through an injected byte reader.

## Test groups

| Group | Matrix row | Evidence class | Case phases | Obligations | Packet |
|---|---|---|---|---|---|
| TG-01 | T01 contract | OFFLINE_CONTRACT | W04_OFFLINE | E04, E06, E07, E10, E11 | W04-2 |
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

- exact fields, checked against the adopted reference models and, through a narrow adapter, any implementation's frame codec (W04_OFFLINE; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- duplicate and unknown keys (W04_OFFLINE; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- role and version mismatch (W04_OFFLINE; E07, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- transcript replay (W04_OFFLINE; E10, E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- wrong peer (W04_OFFLINE; E07; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- counterexample 23: an I07 WRITE_OBJECT carrying a Pod or an unknown kind is refused (W04_OFFLINE; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (23))
- host data contracts replay offline through their reference models before any probe is generated: I06 v2 criteria, SELinux matrix v4 and seccomp v2 vectors (W04_OFFLINE; E04, E06, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; the adopted contracts)

### TG-02 lifecycle

- unarmed, duplicate and cross-case action (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- old socket (AFTER_W05_RELEASE_SET; E07, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- queued action (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- conflicting gate and server result (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- same-generation delayed identical request across two armed actions (counterexample 17, G09): source case (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 6.3)
- the same G09 residual as a native case (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 6.3)
- counterexample 18: a policy writer commits an RBAC change while an admitted CREATE is in flight; A3 blocks it, the urgent path records ADMITTED_BEFORE_INVALIDATION (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (18))
- counterexample 22: connection K opened while A is armed and used after B is armed carries A's stamp and C4 refuses (AFTER_W05_RELEASE_SET; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (22))
- C2/C3 flush and stamp behaviour under load and restart (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8 (T02/T03))
- the R12 reader's private factory and dynamic guards: reentrancy, wrong owner, partial construction and state corruption fail sticky; real fixed factories, dynamic peer overrides and original-resource-only cleanup (W04_OFFLINE; E07, E09; docs/alpha-2/ENFORCEMENT_FEASIBILITY.md:156-169 (row E09); docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md (A02))

### TG-03 persistence

- kill at each fsync, send and result boundary (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- ENOSPC (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- partial records (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- lost acknowledgements (AFTER_W05_RELEASE_SET; E11, E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- restart and rollback (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- counterexample 21: the gate restarts mid-execution with clients connected; deny-first, HELD, no stamps restored (AFTER_W05_RELEASE_SET; E10, E11; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (21))
- C2/C3 flush and stamp behaviour under load and restart (W06_NATIVE_ONLY; E11; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8 (T02/T03))

### TG-04 host

- policy, load, boolean and relabel changes (W06_NATIVE_ONLY; E04; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- namespaces and mount aliases (W06_NATIVE_ONLY; E01, E03; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- effective BPF ancestors (W06_NATIVE_ONLY; E05; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- mappings and injection (W06_NATIVE_ONLY; E06; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- parent and FD spoofing (W06_NATIVE_ONLY; E02, E07; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- path and writer aliases: transient rename and restore, retained writers, relabel and mode changes (W06_NATIVE_ONLY; E01; docs/alpha-2/ENFORCEMENT_FEASIBILITY.md:156-169 (row E01))
- process-owned descriptors: close, dup, reuse, inheritance and ancillary injection (W06_NATIVE_ONLY; E02; docs/alpha-2/ENFORCEMENT_FEASIBILITY.md:156-169 (row E02))
- the section 5.1 kernel facts hold on the enrolled kernel and policy (W06_NATIVE_ONLY; E05, E06; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8)
- secure_mode_policyload conditionals in the pinned binary policy (W06_NATIVE_ONLY; E04; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8)
- freeze before user space under CLONE_INTO_CGROUP on the enrolled kernel (W06_NATIVE_ONLY; E07, E12; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8 (T04/T05))
- completeness of the section 2 closure on a real host (E03-E05) (W06_NATIVE_ONLY; E03, E04, E05; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8)
- per-role seccomp decisions (ALLOW, KILL_PROCESS, ENOSYS) on both architectures; MFD_NOEXEC_SEAL memfds non-executable; a pidfd signal without CAP_KILL fails; the worker shows Seccomp_filters: 2 and no supplementary groups (W06_NATIVE_ONLY; E06, E07, E12; architecture/host-interface-amendment-w02d/amendment.json (obligation O-T04-AMEND))
- counterexample 19: runtime restart of host containment is refused (W06_NATIVE_ONLY; E04, E05; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (19))
- counterexample 25: datastore restore at runtime is refused outside reboot maintenance (W06_NATIVE_ONLY; E04, E11; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (25))
- counterexample 27: no reader keeps CAP_SYS_ADMIN for GET_FD_BY_ID; command 13 removed (W06_NATIVE_ONLY; E05; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (27))
- counterexample 28: an O_PATH fd on a role cgroup cannot detach its enrolled program (W06_NATIVE_ONLY; E05; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (28))

### TG-05 clocks

- expiry with stalled Python (W06_NATIVE_ONLY; E08; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- suspend (W06_NATIVE_ONLY; E08; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- wall-clock rollback (W06_NATIVE_ONLY; E08; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- peer death and restart (W06_NATIVE_ONLY; E07; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- original deadlines (W06_NATIVE_ONLY; E08, E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)

### TG-06 API/writers

- reads (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- final mutated objects (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- controller and aggregate-role changes (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- privileged and alternate paths (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- direct-storage hazards, including etcd over its unix socket (W06_NATIVE_ONLY; E10, E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; architecture/backend-distribution/selection.json (owner decision Q4; open items D-W02A-F2, D-SC01-PEER))
- completeness of the section 2 closure on a real host (E10) (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8)
- A2 field allowlists against real defaulting (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 8 (T06))
- counterexample 20: a root login with a leftover admin kubeconfig is refused by name_connect (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (20))
- counterexample 24: an aggregated ClusterRole widening is excluded from the closure and refused by the observer (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (24))
- counterexample 26: CSR approval cannot mint a privileged client certificate (W06_NATIVE_ONLY; E10; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 9 (26))

Blocked by: D-W02A-F2: a production W02a backend profile naming the selected components (selection open item); D-SC01-PEER: the I06 successor accepting etcd's single AF_UNIX peer listener (selection open item)

### TG-07 cleanup

- ambiguous create (W06_NATIVE_ONLY; E10, E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- conflicting UID (W06_NATIVE_ONLY; E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- delete precondition (W06_NATIVE_ONLY; E10, E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- revoked cleanup (W06_NATIVE_ONLY; E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- pending remote effects (W06_NATIVE_ONLY; E10, E12; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)

### TG-08 compatibility

- the section 4.4 rejection vectors through the native qualification v3 cross-version and negative vectors: each reader refuses a record of another version with no fallback; a record missing EFFECT_GATE, with an extra role, with the gate under the BROKER key or path, with an aliased role path, with a lifecycle subject inside a resident role cgroup, or with unknown backendComponents keys refuses (W04_OFFLINE; E07, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 4.4)
- old profile rejection and new profile missing gate or backend, as source tests of the released build (AFTER_W05_RELEASE_SET; E07, E10; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)
- export, upgrade and rollback without nonce reuse; migration never reinterprets accepted data or reuses a generation or nonce, as source tests (AFTER_W05_RELEASE_SET; E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md section 4.4)
- the same migrations on the installed host, separately (W06_NATIVE_ONLY; E10, E11; architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81)

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
- Expected results come from the adopted contracts' reference models and vectors, never from reading or running the implementation.
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
- The observation-window register is not filled; W04-7 fills it at the exact candidate revision.
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
