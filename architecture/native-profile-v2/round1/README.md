# Native qualification record v2 — W02a contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-05. Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**.

This is the first W02 (native profile contract) deliverable. It turns the G06 and
G07 resolutions of the independently reviewed W01 candidate
(`../host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md` §4-§5, SHA256
`8a3a09bb5dbc08804dbea06dd0700a14648a9cdbc8efd62112dc64ba0b6ba1b4`) into a closed,
versioned record schema with executable data vectors. It closes review finding F3:
exact v2 cgroup paths plus v1/v2 rejection vectors.

It is not a native result, installed profile, kernel observation or grant. Every
vector and every reference-model result is DATA_CHECK_ONLY. All E01-E12 stay
OPEN_UNPROVEN. The v1 schema, vectors and reference model
(`../native-qualification-inputs/`, `scripts/validate_native_qualification.py`)
are unchanged and keep their meaning. v2 never reinterprets v1 data.

Accepted base: main `0ecc5f3a428dd3cdb3a9eba9f8626e5d5fdfd93b` (MET-ENFORCE-004, 200 packets).

## Files

- `qualification.schema.json` — JSON Schema 2020-12, `$id`
  `urn:planeon:internal:native-qualification:v2`, with three variants: `record`,
  `capture` (one resident role's observation) and `lifecycleCapture` (absence of
  the one-shot containment subject). The primitive definitions are copied unchanged
  from v1.
- `vectors.json` — 4 positives derived from the 4 v1 positives (x86_64 and
  aarch64, zero-resource and resource profiles); 42 negatives written as explicit
  mutation operations on a positive, each pinned to the exact refused rule; 10
  cross-version cases; 3 migration cases.
- `../../scripts/native_qualification_v2.py` — reference data model:
  `check_record`, `check_capture`, `check_lifecycle_capture` and `check_migration`
  each raise the first refused rule; `validate_*` wrap them into the v1-style
  generic DATA_CHECK_ONLY result; `explain` names the refused rule (schema refusals
  name the JSON path). The schema digest is pinned in the module.

## What v2 adds to v1

| Area | v2 rule | Source |
|---|---|---|
| Roles | Closed resident set SERVER, OBSERVER, BROKER, WORKER, EFFECT_GATE; all five required in every record, including zero-resource ones where the gate has no listener and denies everything | Spec §4.1 |
| Gate identity | `/opt/planeon/bin/harness-effect-gate`, domain `planeon_gate_t`, own cgroup, listener = the signed KUBERNETES_API_PROXY endpoint when resources exist, outbound = the internal loopback apiserver endpoint only | Spec §2.1, §4.2 |
| Cgroups (F3) | One systemd slice `/sys/fs/cgroup/planeon.slice`: `planeon-proxy-server.service`, `planeon-policy-observer.service`, `planeon-effect-gate.service`, and the delegated `planeon-capacity-broker.service` with leaves `broker` and `probe-worker`; containment runs once in `planeon-host-containment.service`. The v1 `planeon-live/*` paths are refused | Spec §4.2, review F3 |
| Lifecycle subjects | HOST_CONTAINMENT (entry `INIT_T_ONCE_PER_BOOT`, must be absent after its seal: empty cgroup, no domain process) and POLICY_WRITER (entry `OPERATOR_ENTRYPOINT_I07_ONLY`); their code may not be loaded by a resident role | Spec §4.1, §5.2 |
| Backend components | Closed keys APISERVER, DATASTORE, CONTROLLER_MANAGER, SCHEDULER, KUBELET, CONTAINER_RUNTIME (+ optional SERVICE_PROXY, NETWORK_POLICY_AGENT); never in a planeon domain or under the planeon slice; API identity null exactly for APISERVER, DATASTORE and CONTAINER_RUNTIME | Spec §2.3, §4.1 |
| Inspection | Reader BPF commands exactly {7 BPF_OBJ_GET, 15 BPF_OBJ_GET_INFO_BY_FD, 16 BPF_PROG_QUERY}; pins under `/sys/fs/bpf/planeon/<role>/<hook>`; programs attached with BPF_F_ALLOW_MULTI, helper-call-free, not blinded (`bpf_jit_harden` 0 or 1) | Spec §5.1 |
| Capabilities | SERVER and OBSERVER {CAP_BPF, CAP_NET_ADMIN}; BROKER adds CAP_SETGID, CAP_SETUID; EFFECT_GATE and WORKER none; CAP_NET_BIND_SERVICE only for SERVER/EFFECT_GATE when their signed port is below 1024; `no_new_privs` = 1 everywhere | Spec §5.3 |
| Host lock state | SELinux booleans `secure_mode_policyload`=1, `planeon_containment_enabled`=0, `planeon_maintenance_mode`=0; `lockdown`=integrity; `modules_disabled`=1; `kexec_load_disabled`=1; Yama `ptrace_scope`=3; `unprivileged_bpf_disabled` 1 or 2; seal marker at `/run/planeon/containment/sealed` (tmpfs, so it cannot survive a reboot) pinned by digest | Spec §5.2 |
| Internal endpoint | Exactly one `I06_APISERVER_LOOPBACK` endpoint on 127.0.0.1 or ::1, never one of the signed tuples | Spec §2.1 P2 |
| Captures | Observed booleans and hardening may hold any value so a reader can report what it saw; the model refuses any difference from the record | Design choice here |
| Migration | v1 to v2 requires a maintenance reboot (different boot ID) and fresh run and capacity nonces | Spec §4.4, §5.5 |

## Decisions made in this contract (not in the reviewed spec)

1. Seal marker path `/run/planeon/containment/sealed`, chosen so the marker is
   per-boot by construction.
2. The internal loopback apiserver endpoint is a record field with endpoint ID
   `i06-apiserver`, so the gate and observer have a closed outbound set that can
   be compared with their enrolled BPF tuples.
3. Program IDs must be unique across all roles and hooks (no program shared between
   cgroups), extending the v1 per-hook rule.
4. Backend components may share an executable (multi-call binaries) but never with a
   planeon role or lifecycle subject. Exact components are fixed when W03 selects a
   distribution against W02g.

## Not claimed

No real kernel, SELinux policy, bpffs or cgroup was observed. The kernel facts behind
the rules come from the reviewed W01 candidate (Linux v6.12 source reading) and stay
T04 obligations. The per-architecture syscall allowlists (W02d), the SELinux
permission matrix including F2 (W02e) and the identity closure including F1 (W02g)
are separate W02 parts. Native qualification, installation and tenant acceptance
remain separate states.
