# W04-0 — independent enforcement test plan and observation-window register schema (DATA_CHECK_ONLY)

Status: **CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. Roadmap item W04 (parallel lane; owner decisions D-R12,
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

| Group | From | Evidence class | Runs | Obligations | Packet | Cases |
|---|---|---|---|---|---|---|
| TG-01 | T01 Contract | OFFLINE_CONTRACT | W04_OFFLINE | E07, E10, E11 | W04-2 | exact fields; duplicate and unknown keys; role and version mismatch; transcript replay; wrong peer |
| TG-02 | T02 Lifecycle | SOURCE_OWNER_IMPLEMENTATION | AFTER_W05_RELEASE_SET | E07, E10 | W04-3 | unarmed, duplicate and cross-case action; old socket; queued action; conflicting gate and server result; same-generation delayed identical request across two armed actions (counterexample 17, G09) |
| TG-03 | T03 Persistence | SOURCE_MULTIPROCESS_FAULT | AFTER_W05_RELEASE_SET | E11, E12 | W04-3 | kill at each fsync, send and result boundary; ENOSPC; partial records; lost acknowledgements; restart and rollback |
| TG-04 | T04 Host | NATIVE_HOST | W06_NATIVE_ONLY | E01, E02, E03, E04, E05, E06, E07 | W04-4 | SELinux policy, load, boolean and relabel changes; namespaces and mount aliases; effective BPF ancestors; mappings and code injection (mprotect, memfd, fork, exec); parent and FD spoofing; per-role seccomp decisions (ALLOW, KILL_PROCESS, ENOSYS) on both arches |
| TG-05 | T05 Clocks | NATIVE_LIFETIME | W06_NATIVE_ONLY | E07, E08, E11 | W04-4 | expiry with a stalled role; suspend; wall-clock rollback; peer death and restart; original deadlines |
| TG-06 | T06 API and writers | BACKEND_INTEGRATION | W06_NATIVE_ONLY | E10 | W04-5 | reads; final mutated objects; controller and aggregate-role changes; privileged and alternate paths; direct-storage hazards (etcd over its unix socket, owner decision Q4 of the distribution selection) |
| TG-07 | T07 Cleanup | NATIVE_INTEGRATION | W06_NATIVE_ONLY | E10, E12 | W04-5 | ambiguous create; conflicting UID; delete precondition; revoked cleanup; pending remote effects |
| TG-08 | T08 Compatibility | SOURCE_AND_INSTALLED_MIGRATION | AFTER_W05_RELEASE_SET, W06_NATIVE_ONLY | E10, E11 | W04-6 | old profile rejection; new profile missing gate or backend; export, upgrade and rollback without nonce reuse; HOST_INTERFACE_SPEC.md 4.4 rejection vectors (v1/v2 refusal, role keys and paths, unknown backendComponents) |

Native evidence classes (host, lifetime, backend and native integration) run only in W06; the model refuses a native
group with an earlier phase.

## Obligations

| Row | Theme | Test groups | Gates (resolved spec section 8) |
|---|---|---|---|
| E01 | Path and writer aliases (SELinux plus fs-verity; ancestor, path and writer policy) | TG-04 | G07 |
| E02 | Process-owned file descriptors (close, dup, reuse, inheritance, ancillary injection) | TG-04 | - |
| E03 | Mount and namespace restrictions (bind, overmount, propagation, setns) | TG-04 | G04, G07 |
| E04 | SELinux policy changes (policy, boolean, permissive, relabel; deny then quiesce) | TG-04 | G04, G07 |
| E05 | Cgroup v2 and exact BPF endpoint programs | TG-04 | G04, G07 |
| E06 | Code, maps and injection (loader versus sealed phase; COW, mprotect, memfd, fork, exec) | TG-04 | G07 |
| E07 | Peer and PID replacement (pidfds, exact peer credentials, broker parentage) | TG-01, TG-02, TG-04, TG-05 | G06, G07 |
| E08 | Clocks and expiry (original clocks and deadlines; independent expiry enforcement) | TG-05 | G07 |
| E09 | In-process factory and guards (reentrancy, wrong owner, partial construction, sticky failure) | outside: The R12 reader's own private factory and dynamic guards: covered by its retained regression identities and acceptance item A02, and by the W07 reader successor; not a host-enforcement test group (ENFORCEMENT_FEASIBILITY.md:164) | - |
| E10 | API-operation and policy-generation gate (old connections, queued work, writer bypasses, admission order) | TG-01, TG-02, TG-06, TG-07, TG-08 | G04, G05, G09 |
| E11 | Durable history and deny on restart (fsync, partial write, crash, rollback, generation reuse) | TG-01, TG-03, TG-05, TG-08 | G05 |
| E12 | Cleanup and reaping (descendant escape, hung termination, in-flight remote effects) | TG-03, TG-07 | G05, G07 |

## Independence

- W04 source lives in R12, separate from W03's R10 operator repository; no source crosses (ENFORCEMENT_INTEGRATION.md:110-114).
- Only the parallel lane authors W04; W03's authors write no W04 source, and W04's authors read no W03 source or work in progress.
- Allowed W03 inputs are reviewed records the owner names (today only the distribution selection record) and, later, W05's released artifact digests.
- Expected results come from the adopted contracts' reference models and vectors, never from running or reading the implementation.
- Every W04 packet carries an independence attestation, and its separate-agent reviewer checks it.
- R12 never implements or self-certifies the enforcement premise (ENFORCEMENT_INTEGRATION.md:93).
- Agents never send personal data in network requests, headers or queries.

## Repository

R12 `mas-harness-conformance-labs` exists (public, `main`), but harness-onion's `architecture/repositories.yaml` records no
remote, and its verification today is a GitHub Actions workflow on a self-hosted ephemeral runner last used on 2026-09-16.
The owner's verifier is bound to harness-onion only. W04-1 waits for the owner's R12 verification route.

## Not claimed

- No test is written or run; W04-1..W04-7 write them.
- No native evidence; every native group runs only in W06.
- E01-E12 stay OPEN_UNPROVEN.
- The observation-window register is not filled; W04-7 fills it at the exact candidate revision.
