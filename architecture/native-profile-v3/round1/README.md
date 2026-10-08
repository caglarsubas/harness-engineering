# Native qualification record v3 — W02a-F contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-08. Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**.

v3 is the W02a-F successor of the adopted v2 record (`../native-profile-v2/`, ADOPTED_DATA_CONTRACT after three review
rounds). It closes the findings carried to W02a-F:
- W02a review round 3: P1 and P3-P6;
- W02g: P7(a)-(c) and the network-policy agent identity;
- W02e: the label constants, the E1 effective-program census and K1, the boot-entry discriminator.

The v1 and v2 schemas, vectors, models and records are byte-identical; v3 never reinterprets v2 data. Nothing here is a
native result, installed profile, kernel observation or grant. Every vector and model result is DATA_CHECK_ONLY, and all
E01-E12 stay OPEN_UNPROVEN.

Accepted base: main `51440c8de083b09e9d74fbaef3365b86d9fe89da` (MET-PERF-032, 208 packets).

## Files

- `qualification.schema.json`: JSON Schema 2020-12, `$id` `urn:planeon:internal:native-qualification:v3`. It is the
  v2 schema with the changes below and every version discriminator moved to v3. It has the same four variants: `record`,
  `capture`, `lifecycleCapture` and `backendCapture`.
- `vectors.json`: 4 positives derived from the 4 adopted v2 positives; 173 negatives (all 131 v2 negatives replayed
  under v3, plus V01-V42), each pinned to its exact refused rule, with every schema-level refusal a single error; 7
  accepted variants (the 4 from v2 plus A05-A07); 14 cross-version cases; 9 v2-to-v3 migration cases.
- `../../scripts/native_qualification_v3.py`: the reference data model. It is the v2 model with the changes below, so
  the v2-to-v3 diff is the review surface. `check_qualification` remains the only acceptance-shaped check.

Caller obligations (stated in the model, not checked by it):
1. The profile is valid under the pinned proxy profile contract (`scripts/validate_proxy_contract.py`).
2. `v2_records` is the host's complete retained v2 enrollment history, owned by the host's enrollment ledger (W03), or
   `no_v2_history` is set because that history is attested empty.
3. Inspectors report a per-process field only when it holds for every thread (`threadsUniform`).
4. `test_fixture=True` is passed only when qualifying a test fixture.

## What v3 changes

| Item | v3 rule | Vectors |
|---|---|---|
| P1: role closures | Only the role's own executable may appear in its closure. No closure lists another role's executable, by path or by content (sha256 or verity). A native-only role (`interpreterPath` null: OBSERVER, BROKER, EFFECT_GATE) lists no enrolled interpreter, by path or content. | V01-V06; A05 |
| P1: running image | Each role capture records the process image (`/proc/<pid>/exe`: path, device, inode). It must be the role's interpreter if it has one, otherwise its executable, with the device and inode observed for that file. | V07-V09 |
| P3: census and captures | `check_qualification` refuses a census entry below any role cgroup. The direct children of `planeon-capacity-broker.service` must be exactly `broker` and `probe-worker`. The slice, the broker service and every role cgroup must be reported populated: each holds a captured process. Census paths must be canonical, and every listed cgroup's parent must be listed. | V10-V17, V41 |
| P4: one process, one report | (pid, start ticks) is unique over every role cgroup member and every backend process. | V18 |
| P5: the slice's own members | The lifecycle capture lists the processes directly in `planeon.slice` (`cgroup.procs`), required empty. This is observed rather than inferred from cgroup v2's no-internal-process rule. | V19 |
| P6: tasks and `pids.max` | Each cgroup member reports its thread count. The capture reports the role cgroup's `pids.current`, which must equal the members' total and not exceed `pids.max` (the pids controller counts tasks, and a role cgroup has no descendants). The positives' SERVER `pidsMax` is now 16 for its 4 threads. | V20-V22 |
| P7(a): fixture profile | Implementation profiles carry `testOnly`. `unit-distribution` is bound to `testOnly: true`, and `check_qualification` refuses a test-only profile unless the caller passes `test_fixture=True`. No production profile exists until W03 adds one through a reviewed schema revision. | V24, V25 |
| P7(b): type names | The confined backend types are fixed per component: `qualk8s_apiserver_t`, `qualk8s_datastore_t`, `qualk8s_controller_manager_t`, `qualk8s_scheduler_t`, `qualk8s_kubelet_t`, `qualk8s_runtime_t` (CONTAINER_RUNTIME), `qualk8s_proxy_t` (SERVICE_PROXY) and `qualk8s_netpol_t` (NETWORK_POLICY_AGENT). That they are confined is a W02e/W03 policy obligation. | unchanged R61-R66 |
| P7(c): nested backend cgroups | No backend cgroup lies inside another backend cgroup. | V23 |
| Network-policy agent identity | Each backend component's `apiIdentities` must be names the reviewed W02g identity closure gives that component as holder. KUBELET may also use `system:node:<node name>`, and DATASTORE and CONTAINER_RUNTIME have none. The fixture's agent is now the host-component user `planeon:netpol-agent`. | V26-V28; A07 |
| W02e label slots | The schema fixes the W02e values: each role cgroup's label (`planeon_cgroup_server_t`, `_observer_t`, `_broker_t`, `_worker_t`, `_gate_t`), `planeon_bpf_pin_t` for every pin and `planeon_seal_t` for the seal marker. | V29-V32 |
| W02e E1: effective-program census | Each role capture reports the effective program IDs (BPF_PROG_QUERY with BPF_F_QUERY_EFFECTIVE, command 16, already in the reader set) for every other cgroup attach type of Linux v6.12 (22 types, listed below), each required empty. The seven containment hooks are observed per hook as in v2. | V33-V36 |
| W02e K1: boot entries | The record pins the enrolled and the maintenance boot entry (loader entry ID and kernel command line); the two must differ in both. The enrolled command line must carry `lockdown=integrity` (W01 §5.2 S1). Every role and lifecycle capture reports the boot entry it observed (`entryId`, and SHA-256 of the command line text without its trailing newline), which must be the enrolled one. | V37-V40, V42 |

**Counts row, reworded (P5).** The lifecycle capture counts processes per planeon domain. The containment domain must be
0, and each role domain must equal its role cgroup's membership, so no role-domain process exists outside its role
cgroup. The policy-writer count is informational: writer processes run outside the slice by design (decision 8 of v2).

**K1 statement.** The maintenance domain is a trusted installer. With `load_policy` and boolean preservation it can reach
any boolean state, so v2's boolean pins alone cannot tell a maintenance boot from an enrolled one. The boot entry can.
The entry ID and command line are what the boot loader and kernel report (systemd-boot's `LoaderEntrySelected` and
`/proc/cmdline`); they are not measured. Measuring them (TPM event log) is a T04 obligation.

**E1 census, scope.** Every process inside the planeon slice is in a role cgroup: the slice's and the broker service's
own members are observed empty, and unenrolled slice cgroups must be unpopulated. So any cgroup program effective on a
process in the slice is effective at its role cgroup, and the census covers role cgroups. The policy writer runs outside
the slice by design and is not covered. It sees only cgroup attachments, and only when it
runs. The runtime's other BPF use, and attachments made and removed between census points, rest on W03 runtime
selection and T04 (W02e owner decision E1).

### Cgroup attach types (Linux v6.12)

The list comes from `to_cgroup_bpf_attach_type` in `include/linux/bpf-cgroup.h`, plus `BPF_LSM_CGROUP`, whose
effective query spans the ten LSM slots (`kernel/bpf/cgroup.c` `__cgroup_bpf_query`). The source files are tag v6.12,
read as published:

| File | SHA-256 |
|---|---|
| `include/uapi/linux/bpf.h` | `7d67e542c00f833a99b4c4e465aa3bc6bc785bc490d4969e879e931907af4807` |
| `include/linux/bpf-cgroup.h` | `c0b27f271619c1b2ab6b15b6572c0b6db472e676ac08017db6b589452cdc5319` |
| `include/linux/bpf-cgroup-defs.h` | `724cf75eb56d6069abb00b09d36c6109548ea8f11a83c24930d8ee75ca37bf5c` |
| `kernel/bpf/cgroup.c` | `362592cccd78cc900f93a3662c14aae836d12687baff024b1c8650e8f2610afa` |

The seven containment hooks are BPF_CGROUP_INET_SOCK_CREATE, INET4_BIND, INET6_BIND, INET4_CONNECT, INET6_CONNECT,
UDP4_SENDMSG and UDP6_SENDMSG. The census covers the other 22:

| Group | Attach types |
|---|---|
| Socket and SKB | INET_INGRESS, INET_EGRESS, SOCK_OPS, INET_SOCK_RELEASE |
| Bind, connect and send | INET4_POST_BIND, INET6_POST_BIND, UNIX_CONNECT, UNIX_SENDMSG |
| Receive and names | UDP4_RECVMSG, UDP6_RECVMSG, UNIX_RECVMSG, INET4_GETPEERNAME, INET6_GETPEERNAME, UNIX_GETPEERNAME, INET4_GETSOCKNAME, INET6_GETSOCKNAME, UNIX_GETSOCKNAME |
| Other | DEVICE, SYSCTL, GETSOCKOPT, SETSOCKOPT, BPF_LSM_CGROUP |

All names except BPF_LSM_CGROUP take the `BPF_CGROUP_` prefix.

## Replayed v2 cases

All 131 v2 negatives and 4 accepted variants are replayed under v3 against the derived positives. v2 member rows gain
`threadCount` 1, and Q03 uses a v3 capture. Four refusals change, each recorded:

| Case | v2 refusal | v3 refusal | Reason |
|---|---|---|---|
| R70 | backend components share an API identity | schema enum on SCHEDULER `apiIdentities` | The closure binding refuses the borrowed name first. Because the closure gives each name one holder, the model's disjointness rule is now subsumed by the schema. |
| R71 | backend API identity | schema `maxItems` on DATASTORE `apiIdentities` | DATASTORE has no closure name. |
| L13 | planeon slice census incomplete | planeon slice census omits a parent cgroup | Deleting the slice root now meets the parent rule first. V41 keeps a vector for the incomplete-census rule. |
| Q07 | planeon process outside its role cgroup | role-domain process outside its role cgroup | Reworded (P5). |

## Migration from v2

A v3 enrollment needs a maintenance reboot (a boot ID different from every retained v2 record) and fresh nonces. No v2
nonce may appear anywhere in v3 data. Predecessors must be valid under the pinned v2 schema, or the v2 history must be
attested empty (M01-M09). The rules are v2's v1-to-v2 rules, one version later.

## Decisions made in this contract

1. The process image is observed through `/proc/<pid>/exe`. An interpreted role's image is its interpreter.
2. Boot-entry observation is loader-reported, not measured (T04 measures).
3. The effective census covers role cgroups only. Every other planeon cgroup is observed to hold no process.
4. Test-only implementation profiles qualify only in an explicit fixture call.

## Not claimed

No real kernel, SELinux policy, bpffs, cgroup, boot loader or TPM was observed. The kernel facts come from the reviewed
W01 candidate and the v6.12 source files above, and stay T04 obligations. The exact seccomp filters (W02d), the backend
policy module and the distribution (W03), and native, installation and tenant acceptance remain separate.
