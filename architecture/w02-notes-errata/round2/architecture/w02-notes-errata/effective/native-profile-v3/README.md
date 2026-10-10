# Native qualification record v3 — W02a-F contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-08. Status: **CONTRACT_CANDIDATE_ROUND6_AWAITING_INDEPENDENT_REVIEW**.

v3 is the W02a-F successor of the adopted v2 record (`../native-profile-v2/`, ADOPTED_DATA_CONTRACT after three review
rounds). It closes the findings carried to W02a-F:
- W02a review round 3: P1 and P3-P6;
- W02g: P7(a)-(c) and the network-policy agent identity;
- W02e: the label constants, the E1 effective-program census and K1, the boot-entry discriminator.

Review history: round 1 CHANGES_REQUIRED (`review-round1.json`: 2 MINOR, 7 NOTE; all twelve carried items CLOSED);
round 2 CHANGES_REQUIRED (`review-round2.json`: 1 MINOR, 6 NOTE; W1-W5, W7 and W8 CLOSED, W6 and W9 PARTIAL); round 3
CHANGES_REQUIRED (`review-round3.json`: 1 MINOR, 2 NOTE; every earlier finding CLOSED except R2-1 and W6, PARTIAL); round 4
CHANGES_REQUIRED (`review-round4.json`: 1 MINOR, 1 NOTE); round 5 CHANGES_REQUIRED (`review-round5.json`: 1 MINOR, 3 NOTE).
Every finding before round 5 is CLOSED. The reviewed bytes of each round are kept unchanged in `round1/` to `round5/`. Rounds
2-5 concerned only the boot-entry command line. This round-6 candidate answers R5-1 to R5-4 (tables at the end): the
grammar is narrower, the maintenance entry is bound to the enrolled one, and the property is stated as the model enforces it.

The v1 and v2 schemas, vectors, models and records are byte-identical; v3 never reinterprets earlier data. Nothing here is a
native result, installed profile, kernel observation or grant. Every vector and model result is DATA_CHECK_ONLY, and all
E01-E12 stay OPEN_UNPROVEN.

Accepted base: main `51440c8de083b09e9d74fbaef3365b86d9fe89da` (MET-PERF-032, 208 packets).

## Files

- `qualification.schema.json`: JSON Schema 2020-12, `$id` `urn:planeon:internal:native-qualification:v3`. It is the
  v2 schema with the changes below and every version discriminator moved to v3. It has the same four variants: `record`,
  `capture`, `lifecycleCapture` and `backendCapture`.
- `vectors.json`: 4 positives derived from the 4 adopted v2 positives; 207 negatives (all 131 v2 negatives replayed
  under v3, plus V01-V76), each pinned to its exact refused rule, with every schema-level refusal a single error; 9
  accepted variants (the 4 from v2 plus A05-A09); 14 cross-version cases; 14 migration cases. The positives are
  JSON round-tripped before any case is pinned, so each result is what a replay from the file computes. Disabling any
  one v3 rule in the model changes the result of at least one negative or migration case. The exceptions are the
  schema-digest pins (checked by the layer validator), the capture, lifecycle and backend version discriminators
  (cross-version cases X09-X11) and the `migration inputs` type guard, which no JSON case can reach. Some cases carry a
  second defect by construction: L14, V15 and V16 list a path that is no real descendant of the slice, V17 also leaves
  the descendant count unraised (a listed child implies an unlisted parent), and V42's equal command lines also break
  the maintenance-entry rule. Under the round-5 binding, every one-sided command-line negative also breaks the
  binding: V38, V47-V49, V52, V53, V57, V59-V66, V69, V70 and V73-V76 (V54, V58 and V68 are refused by the
  schema first; V67 is single-defect). The errata vectors (`architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json`)
  add bound pairs, which no longer break the binding. Under the binding the enrolled and maintenance grammar rules
  are equivalent, so every bound grammar pair breaks both, and R63-02 and R63-04 also name the unit twice; the
  lockdown pair R63-01 breaks only the lockdown rule. The maintenance-target rule is implied by the twice-named rule
  (exactly one unit word) and also by the binding with distinct command lines. So the maintenance-grammar and
  maintenance-target rules are reached first only by cases that also break the binding; all rules are kept, and the
  overlap is stated here.
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
| P1: role closures | No declared closure lists another role's executable, by path or by content (sha256 or verity); only the role's own executable may appear. A native-only role (`interpreterPath` null: OBSERVER, BROKER, EFFECT_GATE) lists no enrolled interpreter, by path or content, and nothing from the interpreter's installation tree `/opt/planeon/python/`, by path or by content: a copy of a tree file elsewhere is refused too. A native-only role therefore shares no byte string with any file under the tree, including non-Python libraries the tree bundles (OpenSSL, libffi, zlib); W03 links Python against shared copies outside the tree rather than bundling them. A Python runtime the record does not carry under the tree (other bytes, installed elsewhere) is not recognised by the data; it would need that role's own enrolled binary to load it. | V01-V06, V46, V55; A05 |
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
| W02e K1: boot entries | The record pins the enrolled and the maintenance boot entry: the loader entry ID and the kernel command line as `/proc/cmdline` reports it for that entry (for a systemd-boot v256 type #1 entry, `initrd=<path>` followed by the entry's options). The entry IDs must differ. The command line contains no quote character and is split on single spaces. Every word of the enrolled entry must be one of `initrd=<path>`, `root=UUID=`/`PARTUUID=`/`LABEL=<id>` or `root=/dev/<name>`, `ro`, `rw`, `security=selinux`, `selinux=1`, `enforcing=1`, `lockdown=integrity`, `quiet` and `loglevel=<0-7>`, and `lockdown=integrity` must be present (W01 §5.2 S1). The maintenance entry is the enrolled entry with `systemd.unit=planeon-maintenance.target` added exactly once and nothing else changed. What this guarantees, in decision 2's terms: no word of either entry names a unit or carries a unit-bearing value, apart from the maintenance entry's own unit word; `root=`, `ro` and `rw` only drive systemd's fixed root-mount units (in a systemd initrd, `root=` makes the fstab generator write `sysroot.mount` and, for a device path, `systemd-fsck-root.service`, and turns off gpt-auto root discovery; `ro` and `rw` set `sysroot.mount`'s mount flag, and on the host they suppress gpt-auto's remount drop-in); no allowlisted word reaches init's arguments; the two command lines differ only by the maintenance unit word, so both name the same `initrd=` files and the same `root=` device, in the same order; and SELinux and lockdown can only be enabled. The kernel image or UKI that an entry loads is not on its command line, so the binding does not fix it (K1 statement). Refused, among others: `--` and every later word, every `systemd.*`, `rd.*` and `SYSTEMD_*` word, runlevel words, `rootflags=` (`x-systemd.*` options add initrd unit dependencies; `subvol=` and `X-mount.subdir=` pick another tree), `rootfstype=`, `console=` (systemd's getty generator adds a serial login getty; W03 may admit it through review, ordered after containment per W01 §5.2 S2) and any `selinux=`, `enforcing=` or `lockdown=` value other than the enabling one. On a kernel built without the handler of an allowlisted key, that word reaches init's environment, where it is an inert name for systemd: `selinux=`, `enforcing=` and `lockdown=` without the SELinux boot-parameter, SELinux develop or lockdown LSM handlers, `initrd=` without `CONFIG_BLK_DEV_INITRD` and `security=` without `CONFIG_SECURITY`. No allowlisted bare word reaches init's arguments, because the `ro`, `rw` and `quiet` handlers are always built. The grammar is widened only through a reviewed revision of this contract (`KERNEL_PARAMETERS` in the model). On a non-confidential VM, systemd-boot v256 appends the SMBIOS string `io.systemd.boot.kernel-cmdline-extra` to the command line of a type #1 entry with a `linux` key, and systemd-stub appends `io.systemd.stub.kernel-cmdline-extra`, regardless of Secure Boot. Those words appear in `/proc/cmdline`, so they are part of both declared entries and must be inside the grammar; the hypervisor controls that part of the bound text. Every role and lifecycle capture reports the boot entry it observed (`entryId`, and SHA-256 of the command line text without its trailing newline), which must be the enrolled one. | V37-V40, V42, V47-V49, V52-V54, V57-V76; A08, A09 |

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
- the enrolled entry names no unit, so systemd starts the installed default target. Which units start is otherwise
  installed and firmware state, which W03 must fix and T04 check:
  - the root tree's `default.target` link, unit aliases, generators and its init binary;
  - the initramfs contents and its own command-line handling;
  - the kernel image or UKI that each entry loads (the type #1 `linux` or `efi` key), which the command line
    does not name: its built-in initramfs, which the kernel unpacks before the `initrd=` files; a UKI's embedded
    `.initrd`; under Secure Boot, a UKI's embedded `.cmdline`, which replaces the loader options; and its addons;
  - systemd-stub's sysext and confext sidecars (`/.extra/sysext`, `/.extra/confext`), which an initramfs that
    ships `systemd-sysext.service` or `systemd-confext.service` merges;
  - a network root: `root=/dev/nfs` is inside the grammar and hands root selection to the initramfs;
  - without Secure Boot, every word of the `SystemdOptions` EFI variable (`systemd.unit=`, `systemd.wants=`,
    `systemd.mask=`, credentials and root mount options alike);
  - system credentials that define units or drop-ins (`systemd.extra-unit.*`, `systemd.unit-dropin.*`) from SMBIOS
    type 11 strings and qemu fw_cfg, which systemd v256 imports regardless of Secure Boot; and from
    `/.extra/credentials` and `/.extra/global_credentials` (from `\loader\credentials`), which systemd-stub
    packs (systemd-boot v256 packs none) and systemd v256 imports into the encrypted, untrusted credential
    directory, so they take effect only if they decrypt;
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
   `planeon-maintenance.target` with `systemd.unit=`; W01 leaves the mechanism open, and W02e K1 names the systemd target.
   The command line has a closed grammar of kernel parameters that neither name units nor carry unit-bearing values,
   and the maintenance entry is bound to the enrolled one. The guarantee is limited to the command line; which units
   start is installed and firmware state (rounds 2-5).
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
| R2-2 initrd= order, SMBIOS extra string | NOTE | The positives put `initrd=` first, as systemd-boot v256 does. The K1 row names the SMBIOS kernel-cmdline-extra string (restored by errata R6-2) |
| R2-3 content copy of the interpreter tree | NOTE | Native-only closures refuse content equal to any record file under `/opt/planeon/python/`. V55 |
| R2-4 rules without their own vector | NOTE | Distinct messages for the inode rule's two halves (V56) and for the descendant count (V50). V41 keeps the enrolled-cgroup rule with a consistent count. L11, L12 and L14 raise the count. A mutation replay is stated under Files |
| R2-5 stale strings | NOTE | R01's intent and the module docstring are corrected |
| R2-6 status record not yet written | NOTE | The E1 narrowing is stated as carried in the status record written at adoption |
| R2-7 inspector freezing the broker's leaf | NOTE | Caller obligation 3: freeze through an ancestor, or read while the broker holds the leaf frozen; never write the leaf's `cgroup.freeze`. Carried to the W02e/W03 inspector policy |

## Round-3 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| R3-1 single quotes and runlevel words | MINOR | The schema refuses `'` as well as `"`. The maintenance entry's default unit is the last `systemd.unit=` value or runlevel word (systemd v256 `rlmap`). V58-V60 |
| R3-2 unpinned halves, double-defect cases, unlisted exception | NOTE | V57 pins `rd.systemd.unit=` in the enrolled entry, and M14 pins attested-empty history with v1 records. The double-defect cases and the `migration inputs` guard are named under Files |
| R3-3 scope of the tree-content rule | NOTE | The P1 row states that native-only roles share no byte string with any file under the tree, including bundled non-Python libraries, and what W03 does about it |

## Round-4 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| R4-1 systemd selectors beyond the word parse | MINOR | Closed grammar: every word of either entry is a named kernel parameter, and the maintenance entry adds `systemd.unit=planeon-maintenance.target` exactly once. `--` and later words, `systemd.*`, `rd.*`, `SYSTEMD_*`, runlevel words and every other word are refused. The K1 row, statement, decision 2 and the model comment are restated, and the installed-state residuals are W03 obligations. V61-V67; A08 is now an accepted case inside the grammar |
| R4-2 rlmap coverage, V17 wording, maintenance quote | NOTE | The rlmap table is gone: runlevel words are outside the grammar (V59, V60). The V17 wording now names the unraised count. V68 pins the quote refusal on the maintenance entry |

## Round-5 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| R5-1 rootflags= unit dependencies, unbound tree selection | MINOR | `rootflags=` and `rootfstype=` are outside the grammar (W03 sets root mount options in the file system). The maintenance entry must equal the enrolled entry plus the maintenance unit word, so both name the same `initrd=` files and `root=` device (errata R6-1: the kernel image or UKI each entry loads is W03/T04 state). The K1 row, decision 2 and the model comment state the enforced property. V69-V72 |
| R5-2 console= getty, environment claim, grammar location, V67 message | NOTE | `console=` is outside the grammar (V76), and admitting it is a reviewed W03 change ordered under W01 §5.2 S2. The environment claim is stated per kernel configuration. The grammar is widened through a reviewed contract revision (the model's `KERNEL_PARAMETERS`). V67 has its own message |
| R5-3 incomplete installed-state list | NOTE | The K1 statement lists every `SystemdOptions` word, unit-defining system credentials (SMBIOS, fw_cfg, `/.extra`), the root's init binary, generators and the initramfs as W03/T04 state; errata R6-1 adds each entry's kernel image or UKI, systemd-stub's sysext and confext sidecars and a network root |
| R5-4 unpinned value constraints, Debian initrd paths | NOTE | V73-V75 pin `selinux=0`, `enforcing=0` and a prefix-extended word. A08 and A09 accept `rw`, `quiet`, `loglevel=`, `root=PARTUUID=` and a `+` in the initrd path |
