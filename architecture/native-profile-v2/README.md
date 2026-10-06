# Native qualification record v2 — W02a contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-06. Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**.

This is the first W02 (native profile contract) deliverable. It turns the G06 and
G07 resolutions of the independently reviewed W01 candidate
(`../host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md` §2, §4, §5; SHA256
`8a3a09bb5dbc08804dbea06dd0700a14648a9cdbc8efd62112dc64ba0b6ba1b4`) into a closed,
versioned schema with executable data vectors and a reference model. It also closes
W01 review finding F3 (exact v2 cgroup paths plus v1/v2 rejection vectors).

Review history: round 1 CHANGES_REQUIRED (`review-round1.json`: 7 MAJOR, 9 MINOR,
3 NOTE); round 2 CHANGES_REQUIRED (`review-round2.json`: 14 of 19 round-1 findings
closed, new N1-N16 with 2 MAJOR). The reviewed bytes of each round are kept unchanged
in `round1/` and `round2/`. This round-3 candidate answers every open item (tables at
the end).

Nothing here is a native result, installed profile, kernel observation or grant. Every
vector and model result is DATA_CHECK_ONLY. All E01-E12 stay OPEN_UNPROVEN. The v1
schema and vectors are byte-identical.

Two predecessor scripts change only by the mechanical catalog update every packet
applies, and this packet's inverse authority reverses both: two lines each (the packet
catalog set and the success-message count) in `scripts/validate_native_qualification.py`
and `scripts/validate_proxy_contract.py`. Their `validate_record`, `validate_capture`
and `validate_profile` functions are byte-identical. `source-index.json` pins base
bytes on purpose: predecessor inputs are named by their accepted-base digests. v2
never reinterprets v1 data.

Accepted base: main `0ecc5f3a428dd3cdb3a9eba9f8626e5d5fdfd93b` (MET-ENFORCE-004, 200 packets).

## Files

- `qualification.schema.json` — JSON Schema 2020-12, `$id`
  `urn:planeon:internal:native-qualification:v2`, four variants: `record`, `capture`
  (one resident role), `lifecycleCapture` (containment absent, a census of the
  planeon slice, host-wide planeon process counts) and `backendCapture` (one backend
  component). Primitive definitions are copied unchanged from v1. Every variant has
  its own version discriminator.
- `vectors.json` — 4 positives derived from the 4 v1 positives; 131 negatives, each
  an explicit operation list pinned to the exact refused rule (every schema-level
  refusal is a single error); 4 accepted variants; 13 cross-version cases; 10
  migration cases.
- `../../scripts/native_qualification_v2.py` — reference data model. `check_record`,
  `check_capture`, `check_lifecycle_capture`, `check_backend_capture` and
  `check_migration` each raise the first refused rule. **None of them is an acceptance
  decision on its own.** `check_qualification` is the only acceptance-shaped check. It
  adds cross-capture rules: no process reported twice; disjoint cgroup memberships;
  the worker's parent is the broker process; and host-wide planeon domain counts equal
  the role memberships.
- `round1/`, `round2/`, `review-round1.json`, `review-round2.json` — earlier reviewed
  subjects and their verbatim verdicts.

Caller obligations (stated in the model; not checked by it):
1. The profile is valid under the pinned proxy profile contract
   (`scripts/validate_proxy_contract.py`, `validate_profile`). The vector builder and
   the packet's test check all four positive profiles with it.
2. `v1_records` is the host's complete retained v1 enrollment history, owned by the
   host's enrollment ledger (W03). A host whose history is attested empty passes
   `no_v1_history`.
3. An inspector reports a per-process field only when it holds for every thread
   (`threadsUniform`); one filter on the main thread is not enough.

## What v2 adds to v1

| Area | v2 rule | Source |
|---|---|---|
| Roles | Closed resident set SERVER, OBSERVER, BROKER, WORKER, EFFECT_GATE, all five required. Zero-resource gates have no listener | Spec §4.1 |
| Gate identity | Native-only `/opt/planeon/bin/harness-effect-gate`, domain `planeon_gate_t`, own cgroup. Role executables are pairwise distinct in content, and none equals an enrolled interpreter, so a copied broker or Python binary cannot pass as the gate | Spec §2.1, §4.2; decision 5; round-2 N5 |
| Cgroups (F3) | Slice `/sys/fs/cgroup/planeon.slice`: `planeon-proxy-server.service`, `planeon-policy-observer.service`, `planeon-effect-gate.service`, and the delegated `planeon-capacity-broker.service` with exactly the leaves `broker` and `probe-worker`. The v1 `planeon-live/*` paths are refused. Each role cgroup records its SELinux label; inodes are unique | Spec §4.2; W01 F3 |
| Subtrees | Every role capture reports its role cgroup's child cgroups and descendant count, both required empty. The broker capture also reports processes directly in the delegated service cgroup, required empty. The lifecycle capture lists every cgroup under the planeon slice with `populated` from `cgroup.events`; every cgroup not enrolled must be unpopulated | Round-2 N2, N3 |
| Membership | Role captures list every cgroup member (pid, start ticks, parent, uid, label, no_new_privs, seccomp mode). SERVER, OBSERVER, BROKER and EFFECT_GATE hold exactly the inspected process (decision 10). WORKER members are worker-domain processes with the worker's uid, no_new_privs and seccomp, each descended from the inspected worker | Spec §4.4; round-1 F3; round-2 N10 |
| Host-wide counts | The lifecycle capture counts processes per planeon domain. The containment domain must be 0, and each role domain must equal its role's cgroup membership, so no planeon-domain process exists outside its role cgroup | Round-2 N10 |
| Lifecycle subjects | HOST_CONTAINMENT (entry `INIT_T_ONCE_PER_BOOT`; absent after its seal). POLICY_WRITER (entry `OPERATOR_ENTRYPOINT_I07_ONLY`, placement `OUTSIDE_PLANEON_SLICE`, enforced by the slice census and the role memberships). No code is shared between owner classes (resident roles, each lifecycle subject, backend), by path or content | Spec §4.1, §5.2; decisions 6, 8 |
| Backend | Each `implementationId` is bound in the schema to its exact component set; only the test profile `unit-distribution` exists until W03 adds the selected distribution through a reviewed schema revision. Each component runs in its own confined type, `qualk8s_<component>_t`, fixed per component in the schema. Types that container-selinux or refpolicy declare unconfined (`kubelet_t`, `container_runtime_t`, `unconfined_t`, ...) or that are privileged (`rpm_t`, ...) therefore cannot qualify. The qualification backend policy module that defines these types is W02e (matrix) and W03 (implementation) work. Components also have distinct cgroups under cgroupfs outside the planeon slice, and disjoint API identities. DATASTORE and CONTAINER_RUNTIME have none; APISERVER may list in-process identities such as `system:apiserver`; every other API client has at least one | Spec §2.1 P1/P4/P9, §2.3, §4.1, §5.3; decisions 4, 11; round-2 N1, N4 |
| Inspection | Reader BPF commands exactly {7, 15, 16}; pins under `/sys/fs/bpf/planeon/<role>/<hook>` with a recorded label; programs attached with BPF_F_ALLOW_MULTI, helper-free, map-free, never shared, not blinded | Spec §5.1 |
| Capabilities | Enrolled sets: SERVER and OBSERVER {CAP_BPF, CAP_NET_ADMIN}; BROKER adds CAP_SETGID and CAP_SETUID; EFFECT_GATE and WORKER none; CAP_NET_BIND_SERVICE only with a signed port below 1024. Captures report permitted, effective, bounding, ambient and inheritable. For every role except WORKER, permitted = effective = bounding = the enrolled set, and ambient and inheritable are empty (decision 9). WORKER: see owner decision D5 | Spec §5.3; round-1 F2; D5 |
| Process lock state | `no_new_privs` = 1, `RLIMIT_CORE` = 0, seccomp mode 2 with default action KILL_PROCESS and a recorded filter digest (W02d defines the expected filters); uniform across threads | Spec §5.3; round-2 N12 |
| Host lock state | Booleans `secure_mode_policyload`=1, `planeon_containment_enabled`=0, `planeon_maintenance_mode`=0; `lockdown`=integrity; `modules_disabled`=1; `kexec_load_disabled`=1; `ptrace_scope`=3; `unprivileged_bpf_disabled`=1; loaded module set pinned by digest | Spec §5.2 |
| Seal marker | At `/run/planeon/containment/sealed` on tmpfs, uid 0, mode 0444, with a recorded label (value from W02e). The content is canonical JSON `{schemaVersion, bootId, policyDigest, containmentArtifactDigest, programs}`, where `programs` lists every (role, hook, program ID, translated digest). The marker digest can be recomputed from the record; the booleans and the pinned programs remain the stronger evidence that containment ran | Decision 1; round-2 N13 |
| Endpoints | One internal `I06_APISERVER_LOOPBACK` endpoint on loopback, never equal to a signed tuple; no two signed endpoints share a tuple | Spec §2.1 P2; decision 2 |
| Migration | A maintenance reboot (different boot ID); predecessors valid under the pinned v1 schema; no v2 nonce equal to any v1 nonce, and no v1 nonce anywhere in v2 data; or an attested empty v1 history | Spec §4.4, §5.5; round-2 N6 |

`EMPTY` (containment cgroup) means `cgroup.events` reports `populated 0`. `ABSENT`
means the cgroup no longer exists, and then the slice census must not list it.

## Bounds compared with v1

| Bound | v1 reader | v2 |
|---|---|---|
| Planeon code files | ≤128, each ≤64 MiB, total ≤512 MiB | Unchanged (`files`, at least 8) |
| Backend code files | n/a | `backendFiles`: ≤64 files, each ≤1 GiB, total ≤4 GiB (kube-apiserver v1.31.0 is 90,501,272 bytes) |
| One record or capture | ≤256 KiB canonical data | Unchanged |

## Owner decision

**D5 (2026-10-06), round-2 finding N7.** The spec requires the worker's bounding set
to be empty. But the broker, the worker's original parent, cannot drop bounding-set
entries without CAP_SETPCAP, so no real worker could qualify. The owner chose to
redefine the worker rule rather than widen the broker. The worker's bounding set may
be any subset of the broker's enrolled set. Its permitted, effective, ambient and
inheritable sets must be empty, with `no_new_privs` = 1 and a non-root uid. Under
`no_new_privs`, a leftover bounding set cannot grant capabilities. This amends the
reviewed spec's §5.3 WORKER row and is carried to W01's record and to T04.

## Decisions made in this contract (not in the reviewed spec)

1. Seal marker path, filesystem, owner, mode and content as above.
2. The internal loopback apiserver endpoint (`i06-apiserver`) is a record field. It
   is the first outbound tuple outside the signed envelope. It is authorized by the
   sealed apiserver configuration (P2/P5) and the `planeon_kubeapi_port_t` label
   (W02e), not by the envelope. It gives the gate and observer a closed outbound set
   for the independent program-semantics review.
3. Program IDs are unique across all roles and hooks.
4. Backend components may share an executable (multi-call binaries) only as separate
   processes in separate confined types and cgroups, never with a planeon owner.
   Separate processes are checked through the distinct (pid, start ticks) rule in
   `check_qualification`.
5. The gate is native only, and role executables are content-distinct from each other
   and from interpreters.
6. No code sharing across owner classes, by path or content. Consequence:
   containment, the policy writer and backend components cannot list a library shared
   with a resident role (for example libc), so they must be statically linked or
   leave such libraries unlisted. Their code closures beyond the executable are
   declared, not observed (lifecycle subjects have no process to observe; backend
   captures observe the executable).
7. HOST_CONTAINMENT runs once in `planeon.slice/planeon-host-containment.service`.
8. POLICY_WRITER placement is a recorded rule (`OUTSIDE_PLANEON_SLICE`), enforced by
   the slice census and the role memberships. Its steady-state process policy (spec
   §5.3 row: uid 0, no capabilities, I07-only seccomp) is not observed here; W02d
   (filter) and W02e (domain) define it.
9. The inheritable set must be empty for every role. The spec requires only ambient
   to be empty; an empty inheritable set removes a capability path across exec.
10. SERVER, OBSERVER, BROKER and EFFECT_GATE cgroups hold exactly one process; the
    spec's single-process daemons make any other member foreign.
11. Backend confined types are fixed per component in the schema (allow-list), not
    denied by name.

## Round-1 findings (F1-F19)

Round 2 closed F1, F2, F4-F6, F8-F14, F17 and F19. Round 3 completes the five
partial ones:

| Finding | Round-2 status | Round 3 |
|---|---|---|
| F3 lifecycle subject inside a role cgroup | PARTIAL | Child cgroups, descendant counts, delegated-service members, slice census and host-wide domain counts (N2, N3, N10) |
| F7 backend separation | PARTIAL | Confined-type allow-list per component (N1) |
| F15 component set not bound | PARTIAL | Implementation profiles bound in the schema (N4) |
| F16 out-of-subject edits | PARTIAL | Two-line deltas in both scripts stated; base-digest pins explained (N16) |
| F18 sets, messages, constants | PARTIAL | Cross-version expectations reader-independent; unused `roleProcess` removed (N11, N15) |

## Round-2 findings (N1-N16)

| Finding | Severity | Disposition |
|---|---|---|
| N1 unconfined backend domains accepted | MAJOR | Per-component confined-type allow-list in the schema; positives use `qualk8s_*` types; R61-R66 |
| N2 descendants of role cgroups invisible | MAJOR | `childCgroups`, `descendantCount`, `delegatedServiceMembers`, slice census; C20, C22-C25, L11, L12 |
| N3 placement rule unenforced | MINOR | Slice census enforces it; decision 8 restated; L11, L13, L14 |
| N4 component set self-declared | MINOR | `implementationId` bound to its key set in the schema; R58, R59 |
| N5 gate can be a copy of another role or interpreter | MINOR | Content-distinct role executables; R52, R53 |
| N6 caller-chosen predecessors, no empty history | MINOR | Caller obligation stated; attested empty history; M08-M10 |
| N7 worker bounding set unsatisfiable | MINOR | Owner decision D5; C06, C07, A04; positives show the inherited set |
| N8 precondition unchecked | NOTE | Caller obligation in the docstring and in `validate_qualification`'s result text |
| N9 one process reported as several | NOTE | Distinct (pid, start ticks) across captures; disjoint memberships; Q05 |
| N10 worker co-members, host-wide counts, EMPTY | NOTE | Member credentials and descent; domain counts; EMPTY defined; C17, C18, Q07 |
| N11 heuristic cross-version strings | NOTE | Expectations are "refused, with these discriminator errors present", not jsonschema heuristics |
| N12 per-thread state, policy writer row | NOTE | `threadsUniform` and inspector obligation; decision 8; C26 |
| N13 seal marker evidence | NOTE | Owner, mode and label recorded and observed; role/hook assignment bound; L05, L06, R54 |
| N14 library sharing consequence | NOTE | Disclosed in decision 6 |
| N15 undisclosed additions, unused definition | NOTE | Decisions 9 and 10; `roleProcess` removed |
| N16 delta wording | NOTE | Corrected above |

## Not claimed

No real kernel, SELinux policy, bpffs or cgroup was observed. The kernel facts behind
the rules come from the reviewed W01 candidate (Linux v6.12 source reading) and stay
T04 obligations. Exact seccomp filters (W02d), the SELinux permission matrix, label
values and the confined backend types' policy, including W01 finding F2 (W02e), and
the identity closure, including W01 finding F1 (W02g), belong to later W02 parts.
Native qualification, installation and tenant acceptance remain separate states.
