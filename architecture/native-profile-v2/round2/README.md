# Native qualification record v2 — W02a contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-05. Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**.

This is the first W02 (native profile contract) deliverable. It turns the G06 and
G07 resolutions of the independently reviewed W01 candidate
(`../host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md` §2, §4, §5; SHA256
`8a3a09bb5dbc08804dbea06dd0700a14648a9cdbc8efd62112dc64ba0b6ba1b4`) into a closed,
versioned schema with executable data vectors and a reference model. It also closes
W01 review finding F3 (exact v2 cgroup paths plus v1/v2 rejection vectors).

Round 1 received CHANGES_REQUIRED (`review-round1.json`, 7 MAJOR, 9 MINOR, 3 NOTE).
The reviewed round-1 bytes are kept unchanged in `round1/`. This round-2 candidate
answers every finding (table below).

Nothing here is a native result, installed profile, kernel observation or grant. Every
vector and model result is DATA_CHECK_ONLY. All E01-E12 stay OPEN_UNPROVEN. The v1
schema and vectors are byte-identical. The v1 reference model's `validate_record`
and `validate_capture` logic is unchanged. Its file gets only the one-line packet
catalog update every packet applies, which this packet's inverse authority
reverses. v2 never reinterprets v1 data.

Accepted base: main `0ecc5f3a428dd3cdb3a9eba9f8626e5d5fdfd93b` (MET-ENFORCE-004, 200 packets).

## Files

- `qualification.schema.json` — JSON Schema 2020-12, `$id`
  `urn:planeon:internal:native-qualification:v2`, four variants: `record`,
  `capture` (one resident role), `lifecycleCapture` (containment absent after its
  seal) and `backendCapture` (one backend component). Primitive definitions are copied
  unchanged from v1. Every variant has its own version discriminator, so a v1 reader
  refuses each one.
- `vectors.json` — 4 positives derived from the 4 v1 positives; 103 negatives, each
  an explicit operation list pinned to the exact refused rule (every schema-level
  refusal is a single error, so its reported JSON path is unambiguous); 3 accepted
  variants; 13 cross-version cases; 7 migration cases.
- `../../scripts/native_qualification_v2.py` — reference data model. `check_record`,
  `check_capture`, `check_lifecycle_capture`, `check_backend_capture` and
  `check_migration` each raise the first refused rule. **None of them is an acceptance
  decision on its own.** `check_qualification` is the only acceptance-shaped
  check. It requires the record, one capture per resident role, the lifecycle capture,
  one observation per backend component and the migration rules, all for one boot and
  window, and is still DATA_CHECK_ONLY. `explain` names the refused rule.
- `round1/` and `review-round1.json` — the reviewed round-1 subject and its verbatim
  verdict.

Precondition: a profile is valid under the pinned proxy profile contract
(`scripts/validate_proxy_contract.py`, `validate_profile`). The vector builder checked
all four v2 positive profiles with it, and the packet's test checks them again.
`check_record` also refuses resource labels that do not carry the binding's nonces.

## What v2 adds to v1

| Area | v2 rule | Source |
|---|---|---|
| Roles | Closed resident set SERVER, OBSERVER, BROKER, WORKER, EFFECT_GATE, all five required in every record. Zero-resource gates have no listener | Spec §4.1 |
| Gate identity | `/opt/planeon/bin/harness-effect-gate`, native only (no interpreter), domain `planeon_gate_t`, own cgroup. Listener = the signed KUBERNETES_API_PROXY endpoint when resources exist; outbound = the internal apiserver endpoint only | Spec §2.1, §4.2; native-only is decision 5 |
| Cgroups (F3) | Slice `/sys/fs/cgroup/planeon.slice` with `planeon-proxy-server.service`, `planeon-policy-observer.service`, `planeon-effect-gate.service` and the delegated `planeon-capacity-broker.service`, which owns exactly the leaves `broker` and `probe-worker` (observed by the broker capture). The v1 `planeon-live/*` paths are refused. Each role cgroup records its SELinux label. Role cgroup inodes are unique | Spec §4.2; review F3 |
| Cgroup membership | A role capture lists every member of its cgroup. SERVER, OBSERVER, BROKER and EFFECT_GATE allow exactly the inspected process. WORKER allows only worker-domain processes, at most `pidsMax`. Any POLICY_WRITER, containment or foreign process in a role cgroup is refused | Spec §4.4; round-1 F3 |
| Lifecycle subjects | HOST_CONTAINMENT (entry `INIT_T_ONCE_PER_BOOT`; absent after its seal: cgroup ABSENT or EMPTY and no process in its domain). POLICY_WRITER (entry `OPERATOR_ENTRYPOINT_I07_ONLY`, placement `OUTSIDE_PLANEON_SLICE`). Code may not be shared between a resident role and a lifecycle subject, between the two subjects, or with the backend, by path or by content digest | Spec §4.1, §5.2; sharing rule is decision 6 |
| Backend | `backendProfile.componentKeys` fixes the exact component set for an implementation ID; components must match it exactly, and the six core components are always required. Each component has a distinct confined domain (never planeon, never a known unconfined or privileged type), a distinct cgroup under cgroupfs and outside the planeon slice, and disjoint API identities. DATASTORE and CONTAINER_RUNTIME have none; every other API client has at least one. APISERVER may list its in-process identities such as `system:apiserver`; exact values are W02g work | Spec §2.1 P1/P4/P9, §2.3, §4.1; round-1 F6, F7, F15, F19 |
| Inspection | Reader BPF commands exactly {7 BPF_OBJ_GET, 15 BPF_OBJ_GET_INFO_BY_FD, 16 BPF_PROG_QUERY}; pins under `/sys/fs/bpf/planeon/<role>/<hook>` with a recorded pin label; programs attached with BPF_F_ALLOW_MULTI, helper-call-free, map-free, never shared between hooks or roles, not blinded (`bpf_jit_harden` 0 or 1) | Spec §5.1 |
| Capabilities | Enrolled sets: SERVER and OBSERVER {CAP_BPF, CAP_NET_ADMIN}; BROKER adds CAP_SETGID and CAP_SETUID; EFFECT_GATE and WORKER none. CAP_NET_BIND_SERVICE is allowed only for SERVER or EFFECT_GATE with a signed port below 1024. Captures report permitted, effective, bounding, ambient and inheritable separately. Permitted, effective and bounding must each equal the enrolled set (compared as sets); ambient and inheritable must be empty | Spec §5.3; round-1 F2, F18 |
| Process lock state | `no_new_privs` = 1, `RLIMIT_CORE` = 0, seccomp mode 2 with default action KILL_PROCESS, and a recorded filter digest per role (W02d defines the expected filters) | Spec §5.3; round-1 F13 |
| Host lock state | SELinux booleans `secure_mode_policyload`=1, `planeon_containment_enabled`=0, `planeon_maintenance_mode`=0; `lockdown`=integrity; `modules_disabled`=1; `kexec_load_disabled`=1; Yama `ptrace_scope`=3; `unprivileged_bpf_disabled`=1 (only 1 is locked in v6.12); loaded module set pinned by digest; seal marker at `/run/planeon/containment/sealed` on tmpfs | Spec §5.2; round-1 F1, F13, F17 |
| Seal marker | The content is canonical JSON `{schemaVersion: planeon.internal.containment-seal/v1, bootId, policyDigest, containmentArtifactDigest, programIds}`, and the record pins its digest. The marker therefore binds one boot, the active policy, the containment artifact and the enrolled programs | Round-1 F17; decision 1 |
| Internal endpoint | Exactly one `I06_APISERVER_LOOPBACK` endpoint on 127.0.0.1 or ::1, never equal to a signed tuple | Spec §2.1 P2; decision 2 |
| Signed endpoints | No two signed endpoints share an (address, port) tuple | Round-1 F12 |
| Migration | v1 to v2 needs a maintenance reboot (different boot ID). Each predecessor must be a valid v1 record under the pinned v1 schema (canonical digest `8e184d60...`, the v1 model's own pin). No v2 nonce may equal any v1 run or capacity nonce, and no string anywhere in the v2 profile or record may equal one | Spec §4.4, §5.5; round-1 F4, F11 |

## Bounds compared with v1 (round-1 F5, F14e)

| Bound | v1 reader | v2 |
|---|---|---|
| Planeon code files | ≤128, each ≤64 MiB, total ≤512 MiB | Unchanged: `files` ≤128 (at least 8), each ≤64 MiB, total ≤512 MiB |
| Backend code files | n/a | Separate `backendFiles`: ≤64 files, each ≤1 GiB, total ≤4 GiB. Admits mainstream control-plane binaries, e.g. kube-apiserver v1.31.0 at 90,501,272 bytes, which the positives use |
| One record or capture | ≤256 KiB canonical data | Unchanged: ≤256 KiB |

## Decisions made in this contract (not in the reviewed spec)

1. Seal marker path `/run/planeon/containment/sealed` on tmpfs (`runFsType` recorded
   and observed), with the content defined above. If systemd removes a finished
   unit's cgroup, the lifecycle capture reports it as ABSENT.
2. The internal loopback apiserver endpoint is a record field (`i06-apiserver`). It
   is the first outbound tuple outside the signed envelope. Its authorization comes
   from the sealed apiserver configuration (P2/P5) and the `planeon_kubeapi_port_t`
   label (W02e), not from the envelope. Its purpose here is a closed, recorded outbound set
   for the gate and observer, which the independent review of program semantics compares
   with the enrolled map-free programs. The record cannot read program semantics itself.
3. Program IDs are unique across all roles and hooks.
4. Backend components may share an executable (multi-call binaries) only as separate
   processes in separate confined domains and cgroups. They never share with a planeon
   role or lifecycle subject. W03 selects the distribution against W02g; until then the
   component set is fixed per `implementationId` by `componentKeys`.
5. The gate is native only (`interpreterPath` null).
6. Code-sharing rule across owner classes (resident roles, each lifecycle subject,
   backend), by path and by content digest. The spec implies it; this contract states it.
7. HOST_CONTAINMENT runs once in `planeon.slice/planeon-host-containment.service`
   (spec §5.2 S2 names the unit, not its slice).
8. POLICY_WRITER placement is recorded as a rule (`OUTSIDE_PLANEON_SLICE`), not a
   path, because operators start it from their own sessions (spec §2.4). It is
   enforced by every role capture's complete membership list.

## Round-1 findings and their disposition

| Finding | Severity | Disposition in round 2 |
|---|---|---|
| F1 `unprivileged_bpf_disabled`=2 accepted | MAJOR | Record const 1; observed value may be 0-2 and must equal the record; R18, C09 |
| F2 single capability list | MAJOR | Captures report five sets; set equality with the enrolled set; empty ambient and inheritable; C01-C05, A03 |
| F3 lifecycle subject inside a role cgroup inexpressible | MAJOR | Complete `cgroupMembers` per role capture; broker `delegatedChildren`; POLICY_WRITER placement rule; C12-C16, R50, R51 |
| F4 v1 nonce in v2 positive manifests | MAJOR | Positives regenerated with v2 nonces and names and checked with the proxy contract; label rule in `check_record`; full-string nonce scan in migration; R66, M06 |
| F5 64 MiB cap rejects real backends | MAJOR | Separate `backendFiles` bounds; positives use real sizes; all bounds disclosed above |
| F6 APISERVER identity forced null | MAJOR | `apiIdentities` list; null only where no API client exists; R63, R64 |
| F7 backend separation not enforced | MAJOR | Distinct domains, cgroups (under cgroupfs, not the root) and identities; type denylist pending the W02e matrix; `backendCapture` observes each component; R57-R62, K01-K03 |
| F8 coverage gaps, cross-version IDs | MINOR | 103 negatives covering every listed gap (gate under the BROKER key: R67); unique IDs and exact expected results for all cross-version cases; path-only cases for the v1 reader (X11) and the v2 reader (R07 record, C21 capture), and the packet test checks the v1 reference model refusing a v1 capture with a v2 path; round-1 C07 replaced by C12-C14 and C20 |
| F9 copies bypass ownership | MINOR | Ownership by content digest as well as path; R47, R48 |
| F10 no aggregate acceptance | MINOR | `check_qualification`; positives pass only through it; Q01-Q04 |
| F11 migration predecessors unvalidated | MINOR | v1 schema validation and pin; every-nonce comparison; M04, M05, M07 |
| F12 tuple and inode aliasing | MINOR | Duplicate signed tuples and role cgroup inodes refused; R39, R43 |
| F13 unbound spec items | MINOR | Added `rlimitCore`, `seccompDefaultAction`, `seccompFilterDigest`, cgroup and pin labels, `moduleSetDigest`; exact filters (W02d), label values (W02e) and module list (W02/W03) stay with those parts |
| F14 undisclosed decisions | MINOR | Decisions 1-8 above; internal-tuple authorization stated; spec attributions corrected |
| F15 component set not bound | MINOR | `componentKeys`; mode-independent positives (all eight components in every positive); R54 |
| F16 working-tree changes outside the subject | MINOR | Those were this packet's mechanical history-chain edits, outside the contract subject. The v1 model wording is corrected above. The packet's mechanics are checked by the required verify suite, not by this contract review |
| F17 seal marker content | NOTE | Defined content and digest rule; tmpfs recorded; ABSENT state; R21, R22, L05, A02 |
| F18 order-sensitive sets, messages, constants | NOTE | Set comparison; separate "lifecycle subjects share code" rule (R46); unused constants removed; single-error schema vectors |
| F19 identity list | NOTE | `apiIdentities` list |

## Not claimed

No real kernel, SELinux policy, bpffs or cgroup was observed. The kernel facts behind
the rules come from the reviewed W01 candidate (Linux v6.12 source reading) and stay
T04 obligations. Exact seccomp filters (W02d), the SELinux permission matrix and label
values including W01 finding F2 (W02e), and the identity closure including W01
finding F1 (W02g) belong to later W02 parts. Native qualification, installation and
tenant acceptance remain separate states.
