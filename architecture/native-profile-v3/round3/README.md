# Native qualification record v3 — W02a-F contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-08. Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**.

v3 is the W02a-F successor of the adopted v2 record (`../native-profile-v2/`, ADOPTED_DATA_CONTRACT after three review
rounds). It closes the findings carried to W02a-F:
- W02a review round 3: P1 and P3-P6;
- W02g: P7(a)-(c) and the network-policy agent identity;
- W02e: the label constants, the E1 effective-program census and K1, the boot-entry discriminator.

Review history: round 1 CHANGES_REQUIRED (`review-round1.json`: 2 MINOR, 7 NOTE; all twelve carried items CLOSED);
round 2 CHANGES_REQUIRED (`review-round2.json`: 1 MINOR, 6 NOTE; W1-W5, W7 and W8 CLOSED, W6 and W9 PARTIAL). The
reviewed bytes of each round are kept unchanged in `round1/` and `round2/`. This round-3 candidate answers R2-1 to R2-7
(tables at the end).

The v1 and v2 schemas, vectors, models and records are byte-identical; v3 never reinterprets earlier data. Nothing here is a
native result, installed profile, kernel observation or grant. Every vector and model result is DATA_CHECK_ONLY, and all
E01-E12 stay OPEN_UNPROVEN.

Accepted base: main `51440c8de083b09e9d74fbaef3365b86d9fe89da` (MET-PERF-032, 208 packets).

## Files

- `qualification.schema.json`: JSON Schema 2020-12, `$id` `urn:planeon:internal:native-qualification:v3`. It is the
  v2 schema with the changes below and every version discriminator moved to v3. It has the same four variants: `record`,
  `capture`, `lifecycleCapture` and `backendCapture`.
- `vectors.json`: 4 positives derived from the 4 adopted v2 positives; 187 negatives (all 131 v2 negatives replayed
  under v3, plus V01-V56), each pinned to its exact refused rule, with every schema-level refusal a single error; 8
  accepted variants (the 4 from v2 plus A05-A08); 14 cross-version cases; 13 migration cases. The positives are
  JSON round-tripped before any case is pinned, so each result is what a replay from the file computes. Disabling any
  one v3 rule in the model changes the result of at least one negative or migration case, except the schema-digest pins
  (checked by the layer validator) and the capture, lifecycle and backend version discriminators (cross-version cases
  X09-X11).
- `../../scripts/native_qualification_v3.py`: the reference data model. It is the v2 model with the changes below, so
  the v2-to-v3 diff is the review surface. `check_qualification` remains the only acceptance-shaped check.

Caller obligations (stated in the model, not checked by it):
1. The profile is valid under the pinned proxy profile contract (`scripts/validate_proxy_contract.py`).
2. `v1_records` and `v2_records` are the host's complete retained v1 and v2 enrollment histories, owned by the host's
   enrollment ledger (W03), or `no_earlier_history` is set because both are attested empty.
3. Inspectors report a per-process field only when it holds for every thread (`threadsUniform`). They read a role
   cgroup's members, thread counts and `pids.current` while the cgroup is frozen and holds no unreaped task: an exited,
   unreaped task still counts in `pids.current` but is no longer in `cgroup.procs`. The broker freezes and thaws the
   probe-worker leaf itself (W01 §5.4), so the inspector freezes through an ancestor it controls (a cgroup is frozen
   while any ancestor is), or reads while the broker holds the leaf frozen. It never writes the broker-owned leaf's
   `cgroup.freeze`. This is carried to the W02e/W03 inspector policy.
4. `test_fixture=True` is passed only when qualifying a test fixture.

## What v3 changes

| Item | v3 rule | Vectors |
|---|---|---|
| P1: role closures | No declared closure lists another role's executable, by path or by content (sha256 or verity); only the role's own executable may appear. A native-only role (`interpreterPath` null: OBSERVER, BROKER, EFFECT_GATE) lists no enrolled interpreter, by path or content, and nothing from the interpreter's installation tree `/opt/planeon/python/` (its runtime library and modules), by path or by content: a copy of a tree file elsewhere is refused too. A Python runtime the record does not carry under the tree (other bytes, installed elsewhere) is not recognised by the data; it would need that role's own enrolled binary to load it. | V01-V06, V46, V55; A05 |
| P1: running image | Each role capture records the process image (`/proc/<pid>/exe`: path, device, inode) of the inspected process and of every cgroup member. Each must be the role's interpreter if it has one, otherwise its executable, with the device and inode observed for that file. Across all role captures, one (device, inode) names one path with one content, and one path one (device, inode). For the interpreted roles (SERVER, WORKER) the script is declared, not observed: the image is the interpreter. | V07-V09, V43-V45 |
| P3: census and captures | `check_qualification` refuses a census entry below any role cgroup. The direct children of `planeon-capacity-broker.service` must be exactly `broker` and `probe-worker`. The slice, the broker service and every role cgroup must be reported populated: each holds a captured process. Census paths must be canonical, and every listed cgroup's parent must be listed. | V10-V17, V41 |
| P4: one process, one report | (pid, start ticks) is unique over every role cgroup member and every backend process. | V18 |
| P5: the slice's own members | The lifecycle capture lists the processes directly in `planeon.slice` (`cgroup.procs`), required empty. This is observed rather than inferred from cgroup v2's no-internal-process rule. | V19 |
| P6: tasks and `pids.max` | Each cgroup member reports its thread count. The capture reports the role cgroup's `pids.current`, which must equal the members' total and not exceed `pids.max` (the pids controller counts tasks, and a role cgroup has no descendants). The positives' SERVER `pidsMax` is now 16 for its 4 threads. | V20-V22 |
| P7(a): fixture profile | Implementation profiles carry `testOnly`. `unit-distribution` is bound to `testOnly: true`, and `check_qualification` refuses a test-only profile unless the caller passes `test_fixture=True`. No production profile exists until W03 adds one through a reviewed schema revision. | V24, V25 |
| P7(b): type names | The confined backend types are fixed per component: `qualk8s_apiserver_t`, `qualk8s_datastore_t`, `qualk8s_controller_manager_t`, `qualk8s_scheduler_t`, `qualk8s_kubelet_t`, `qualk8s_runtime_t` (CONTAINER_RUNTIME), `qualk8s_proxy_t` (SERVICE_PROXY) and `qualk8s_netpol_t` (NETWORK_POLICY_AGENT). That they are confined is a W02e/W03 policy obligation. | unchanged R61-R66 |
| P7(c): nested backend cgroups | No backend cgroup lies inside another backend cgroup. | V23 |
| Network-policy agent identity | Each backend component's `apiIdentities` lists the identities of the reviewed W02g closure that the component holds, by holder: a subset of those names, not every identity it authenticates as (controller service accounts outside the closure are not listed). KUBELET may also use one `system:node:<node name>`, and DATASTORE and CONTAINER_RUNTIME have none. The fixture's agent is now the host-component user `planeon:netpol-agent`. | V26-V28, V51; A07 |
| W02e label slots | The schema fixes the W02e values: each role cgroup's label (`planeon_cgroup_server_t`, `_observer_t`, `_broker_t`, `_worker_t`, `_gate_t`), `planeon_bpf_pin_t` for every pin and `planeon_seal_t` for the seal marker. | V29-V32 |
| W02e E1: effective-program census | Each role capture reports the effective program IDs (BPF_PROG_QUERY with BPF_F_QUERY_EFFECTIVE, command 16, already in the reader set) for every other cgroup attach type of Linux v6.12 (22 types, listed below), each required empty. The seven containment hooks are observed per hook as in v2. | V33-V36 |
| W02e K1: boot entries | The record pins the enrolled and the maintenance boot entry: the loader entry ID and the kernel command line as `/proc/cmdline` reports it for that entry (for a systemd-boot v256 type #1 entry, `initrd=<path>` followed by the entry's options, plus the SMBIOS `io.systemd.boot.kernel-cmdline-extra` string if a VM supplies one). The two must differ in both. A command line may not contain `"`, so splitting on spaces gives the words the kernel and systemd see. The enrolled entry must carry `lockdown=integrity` among its kernel parameters (the words before the first bare `--`; W01 §5.2 S1). systemd reads every word, after `--` too, and the last `systemd.unit=` wins: no word of the enrolled entry may name `planeon-maintenance.target` (`systemd.unit=` or `rd.systemd.unit=`), and the maintenance entry's last `systemd.unit=` must be that target. Every role and lifecycle capture reports the boot entry it observed (`entryId`, and SHA-256 of the command line text without its trailing newline), which must be the enrolled one. | V37-V40, V42, V47-V49, V52-V54; A08 |

**Counts row, reworded (P5).** The lifecycle capture counts processes per planeon domain. The containment domain must be
0, and each role domain must equal its role cgroup's membership, so no role-domain process exists outside its role
cgroup. The policy-writer count is informational: writer processes run outside the slice by design (decision 8 of v2).

**K1 statement.** The maintenance domain is a trusted installer. With `load_policy` and boolean preservation it can reach
any boolean state, so v2's boolean pins alone cannot tell a maintenance boot from an enrolled one. The recorded boot
entries tell an honest maintenance boot apart, within these limits:
- the two entries are declared data, not tied to the installed loader configuration;
- `LoaderEntrySelected` is a volatile EFI variable with runtime access, so a privileged domain could rewrite it; the
  command line in `/proc/cmdline` is fixed for the boot, and the two command lines must differ;
- `kernelCmdline` is the `/proc/cmdline` text, which may include bootconfig keys and init arguments;
- without Secure Boot, systemd also reads `systemd.unit=` from the `SystemdOptions` EFI variable when the command line
  names no unit itself; the enrolled entry names none, so W03 must run Secure Boot or make the enrolled entry name its
  target;
- nothing is measured. Measuring the entry and command line (TPM event log) is a T04 obligation.

The observed `hardening.lockdown` value, pinned to `integrity`, remains the evidence of the lockdown state itself.

**E1 census, scope.** Every process inside the planeon slice is in a role cgroup: the slice's and the broker service's
own members are observed empty, unenrolled slice cgroups must be unpopulated, and the census must list every live
descendant of the slice (its `cgroup.stat` `nr_descendants`). Task-selected programs (DEVICE, SYSCTL, LSM on the current
task) are therefore effective at the role cgroup. Socket-attached programs (INGRESS/EGRESS, SOCK_OPS, the sock_addr and
sockopt types, LSM socket hooks) select by the cgroup the socket was created in, so the census covers sockets a role
creates in its role cgroup. A descriptor created elsewhere and passed in (socket activation, SCM_RIGHTS) or created
before a cgroup move is out of this census; W03 must not hand planeon roles such sockets. The policy writer runs outside
the slice by design and is not covered. This narrowing of owner decision E1's "every planeon cgroup" to role cgroups
(decision 3) will be carried to W03 and T04 in the status record written when this contract is adopted; W02e's adopted
status record is not changed. It sees only cgroup attachments, and only when it
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
`threadCount` 1 and an image of their own (an unenrolled path), Q03 uses a v3 capture, A02 also lowers the slice's
descendant count with the removed containment cgroup, and L11, L12 and L14 raise it with the cgroup they add. R01's refusal changes mechanically, from "not a v2 record" to "not
a v3 record". Four refusals change for a reason, each recorded:

| Case | v2 refusal | v3 refusal | Reason |
|---|---|---|---|
| R70 | backend components share an API identity | schema enum on SCHEDULER `apiIdentities` | The closure binding refuses the borrowed name first. Because the closure gives each name one holder, the model's disjointness rule is now subsumed by the schema. |
| R71 | backend API identity | schema `maxItems` on DATASTORE `apiIdentities` | DATASTORE has no closure name. |
| L13 | planeon slice census incomplete | planeon slice census omits a parent cgroup | Deleting the slice root now meets the parent rule first. V41 keeps a vector for the incomplete-census rule. |
| Q07 | planeon process outside its role cgroup | role-domain process outside its role cgroup | Reworded (P5). |

## Migration from v1 and v2

A v3 enrollment needs a maintenance reboot and fresh nonces against every earlier version: its boot ID differs from every
retained v1 and v2 record, and no v1 or v2 nonce appears anywhere in v3 data. v1 predecessors must be valid under the
pinned v1 schema and v2 predecessors under the pinned v2 schema, or both histories must be attested empty (M01-M13; M10
to M13 cover a v1-only host).

## Decisions made in this contract

1. The process image is observed through `/proc/<pid>/exe`. An interpreted role's image is its interpreter.
2. Boot-entry observation is loader-reported, not measured (T04 measures). The maintenance entry selects
   `planeon-maintenance.target` through its effective `systemd.unit=`; W01 leaves the mechanism open, and W02e K1 names
   the systemd target. Command lines are read as systemd reads them (every word, last `systemd.unit=` wins) and contain
   no `"`.
3. The effective census covers role cgroups only. Every other planeon cgroup is observed to hold no process.
4. Test-only implementation profiles qualify only in an explicit fixture call.

## Not claimed

No real kernel, SELinux policy, bpffs, cgroup, boot loader or TPM was observed. The kernel facts come from the reviewed
W01 candidate and the v6.12 source files above, and stay T04 obligations. The exact seccomp filters (W02d), the backend
policy module and the distribution (W03), and native, installation and tenant acceptance remain separate.

## Round-1 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| W1 one inode, two files | MINOR | One path and one content per (device, inode), and one inode per path, across all role captures. The positives' gate binary now has its own inode (2104), not the interpreter's inherited from v2. V43, V44 |
| W2 v1 history dropped from migration | MINOR | `check_migration` and `check_qualification` take the complete v1 and v2 histories under their pinned schemas; no shared boot ID and no earlier nonce. Caller obligation 2 restated. M10-M13 |
| W3 co-member images, interpreted scripts | NOTE | Every cgroup member reports its image, which must be the role's image. Scripts are stated as declared, not observed. V45 |
| W4 interpreter runtime in native-only roles | NOTE | Nothing under `/opt/planeon/python/` in a native-only closure. The residual (an interpreter elsewhere, loaded by the role's own binary) is stated. V46 |
| W5 unreaped tasks in pids.current | NOTE | Inspector obligation 3: read the cgroup frozen, with no unreaped task |
| W6 K1 precision | NOTE | Statement qualified. Maintenance token pinned. Parameters only before `--`. Systemd-boot-shaped command lines. V47-V49 |
| W7 socket-attached programs, census completeness | NOTE | Scope sentence restated for socket programs. The census must match the slice's `nr_descendants`. Decision 3's narrowing is carried to W03 and T04. V50 |
| W8 several node names, identity meaning | NOTE | At most one `system:node:` name. `apiIdentities` stated as held closure identities. V51 |
| W9 R01 and stale strings | NOTE | R01's mechanical change noted. The docstrings now say "one v3 record" and "earlier-version nonce scan" |

## Round-2 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| R2-1 maintenance token read unlike systemd | MINOR | `"` refused in command lines. `lockdown=integrity` stays a kernel-parameter test (before the first bare `--`). The maintenance target is read over every word, and the last `systemd.unit=` wins. V52-V54; A08; V47 and V48 now carry the new refusals |
| R2-2 initrd= order, SMBIOS extra string | NOTE | The positives put `initrd=` first, as systemd-boot v256 does. The K1 row names the SMBIOS kernel-cmdline-extra string |
| R2-3 content copy of the interpreter tree | NOTE | Native-only closures refuse content equal to any record file under `/opt/planeon/python/`. V55 |
| R2-4 rules without their own vector | NOTE | Distinct messages for the inode rule's two halves (V56) and for the descendant count (V50). V41 keeps the enrolled-cgroup rule with a consistent count. L11, L12 and L14 raise the count. A mutation replay is stated under Files |
| R2-5 stale strings | NOTE | R01's intent and the module docstring are corrected |
| R2-6 status record not yet written | NOTE | The E1 narrowing is stated as carried in the status record written at adoption |
| R2-7 inspector freezing the broker's leaf | NOTE | Caller obligation 3: freeze through an ancestor, or read while the broker holds the leaf frozen; never write the leaf's `cgroup.freeze`. Carried to the W02e/W03 inspector policy |
