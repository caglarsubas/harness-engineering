# SELinux domain, type, boolean and permission matrix — W02e (MET-ENFORCE-009), round 1

Status: **CONTRACT_CANDIDATE**, awaiting the round-1 independent review. DATA_CHECK_ONLY: no policy module is written or
compiled, nothing is loaded or installed, and all E01-E12 stay OPEN_UNPROVEN.

This part turns the SELinux choices of the reviewed W01 design (HOST-INTERFACE-DRAFT-002 §2.1 P1/P2/P4/P5/P9, §2.3, §4.1-
§4.3, §5.1-§5.5) into one closed matrix. It also fills what the adopted W02a v2 record leaves to W02e:
- the role cgroup, bpffs pin and seal-marker labels;
- the confined backend types `qualk8s_<component>_t` (W02a round-2 N1);
- the closure of W01 review finding F2.

## Files

| File | Content |
|---|---|
| `matrix.json` | `planeon.internal.selinux-matrix/v1`. It holds three booleans and three boot states, 19 domains, 52 types, 6 sockets, 3 ports, 17 transitions, the capability, `bpf`, `security`, `process` and `service` grants, and 54 deny assertions |
| `vectors.json` | 738 access checks (allow, deny or outside, each with its state and intent), 29 mutation checks and the W02a slot values |
| `scripts/selinux_matrix.py` | Reference evaluator: `allowed`, `check_matrix`, `failed_assertions`, `w02a_slots`, `apply_ops` |

## What the matrix closes

The matrix is closed over its own objects and over the security classes. For every declared domain, and for any other
domain (`OTHER_DOMAIN`), `allowed(state, source, target, class, perm)` is True or False when:
- the target is a declared type (file classes `file`, `dir`, `sock_file`, `lnk_file`), a declared socket (`unix_stream_socket`
  `connectto`, `create`, `bind`, `listen`, `accept`), a declared port (`tcp_socket` `name_bind`, `name_connect`) or a declared
  domain (`process` permissions, and `file` `read` as the ptrace read check on `/proc`);
- or the class is `capability`, `capability2`, `cap_userns`, `cap2_userns`, `bpf`, `security` or `service`.

Anything else is outside the matrix (None): ordinary access to libraries, devices or the domain's own `/proc` entries.
The W03 policy module adds that access. It may grant nothing the matrix closes beyond the matrix. File-class permissions are
grouped as READ, WRITE, RELABEL, EXECUTE and ENTRYPOINT (exact SELinux permission names in `FILE_PERMS`). A transition is
effective only with `process transition`, `file execute` on the entrypoint type for the source and `file entrypoint` for the
target, all in the same state.

## Booleans and states

| State | planeon_containment_enabled | planeon_maintenance_mode | secure_mode_policyload | Meaning |
|---|---|---|---|---|
| ENROLLED_CONTAINMENT | 1 | 0 | 0 | Enrolled boot, S2-S4: containment may run |
| ENROLLED_SEALED | 0 | 0 | 1 | Enrolled boot after S4; the state every v2 record requires (W02a host lock state) |
| MAINTENANCE_BOOT | 0 | 1 | 0 | The maintenance boot entry (W01 §5.5); no planeon role starts |

`secure_mode_policyload` = 1 freezes booleans, policy load and enforcing mode until reboot. In the matrix no rule grants
`setbool`, `load_policy` or `setenforce` in that state (A19). The pinned binary policy must contain the matching conditional
rules (W01 §5.2), so this matrix states the requirement and T04 checks the policy.

## Domains

| Kind | Domains |
|---|---|
| Resident roles | `planeon_server_t`, `planeon_observer_t`, `planeon_broker_t`, `planeon_worker_t`, `planeon_gate_t` |
| Lifecycle subjects | `planeon_policy_writer_t` (entered by the admin login through `/opt/planeon/bin/harness-policy-write`), `planeon_contain_t` (entered by init once per boot, only while `planeon_containment_enabled`) |
| Maintenance | `planeon_maint_t` (entered by the admin login, only in the maintenance boot) |
| Backend | `qualk8s_apiserver_t`, `qualk8s_controller_manager_t`, `qualk8s_scheduler_t`, `qualk8s_kubelet_t`, `qualk8s_runtime_t`, `qualk8s_datastore_t`, `qualk8s_netpol_t`, `qualk8s_proxy_t` |
| Qualification Pods | `qualk8s_container_t` |
| Admin | `planeon_admin_t`: the confined domain root logins map to |
| System | `init_t` (systemd), referenced only as a source |

The process contexts equal the W02a v2 schema's fixed `processLabel` values. A domain's name is fixed by its kind:
planeon kinds start `planeon_`, backend and Pod domains start `qualk8s_`, and the system domain is `init_t`. So an upstream
unconfined or privileged type, such as container-selinux's `kubelet_t`, `container_runtime_t` or `spc_t`, or refpolicy's
`unconfined_t`, cannot appear (W02a round-2 N1; mutation M25).

## Types

| Category | Types | Access |
|---|---|---|
| Entrypoints | one `*_exec_t` per role, lifecycle, maintenance and backend domain (16) | READ any domain; EXECUTE the starter only; ENTRYPOINT the entered domain only; WRITE/RELABEL `planeon_maint_t` only in the maintenance boot |
| Interpreter | `planeon_interpreter_exec_t` (Python for SERVER and WORKER) | EXECUTE init, broker, server, worker; never an entrypoint |
| Sealed configuration and units | `planeon_etc_t`, `qualk8s_config_t`, `planeon_unit_file_t`, `qualk8s_unit_file_t` | READ any; WRITE/RELABEL maintenance only |
| Credentials | `planeon_server_cred_t`, `planeon_observer_cred_t`, `planeon_gate_effect_cred_t`, `planeon_gate_writer_cred_t`, `qualk8s_sa_key_t`, `qualk8s_encryption_key_t`, one `qualk8s_<component>_cred_t` per API client | READ the owners only (the gate alone for both upstream credentials; apiserver and controller-manager for the service-account key); WRITE/RELABEL maintenance only (W01 §5.5 M5) |
| Socket files | I05, I07, observer, broker, datastore and runtime socket files | The listener and its one connector |
| Cgroups | `planeon_cgroup_{slice,server,observer,broker,worker,gate,contain}_t` | READ init, containment and the reader roles; WRITE init (the broker also writes its delegated `broker` and `probe-worker` cgroups); RELABEL containment, only before the seal |
| bpffs pins, seal marker | `planeon_bpf_pin_t`, `planeon_seal_t` | READ containment and the reader roles; WRITE/RELABEL containment, only before the seal |
| Journal, data | `planeon_gate_journal_t`, `qualk8s_datastore_data_t` | The owner; the maintenance domain only in the maintenance boot (reconciliation, restore: counterexample 25) |
| Container content | `qualk8s_container_file_t` | The runtime writes; the Pod domain enters it |

Sockets: the gate labels its two listening sockets `planeon_i05_socket_t` and `planeon_i07_socket_t` with `setsockcreate`,
so `connectto` tells I05 from I07 even though one domain listens on both. Only the broker connects to I05 and only the
policy writer to I07. The observer, broker, datastore and runtime sockets keep their listener's domain as their label.
Ports: `planeon_kubeapi_port_t` is bound by the apiserver and connected to by exactly the gate, the observer, the
controller-manager, the scheduler, the kubelet, the network-policy agent and the service proxy (P2).
`planeon_i04_port_t` is bound by the gate and connected to by the server. `qualk8s_kubelet_port_t` is bound by the kubelet
and connected to by the apiserver.

## Assertions

54 deny properties, each evaluated for every listed boot state, every target and every domain, including `OTHER_DOMAIN`.
Each states who alone may have the access.

| IDs | Property | Source |
|---|---|---|
| A01-A08 | Apiserver port (P2), I04 port, datastore socket (P1), runtime socket (P9), I05 and I07: exactly the enumerated connectors and binders | W01 §2.1, §5.3; W02b; W02c |
| A09-A11.9 | Each credential readable by its owners only | W01 §5.3, §2.1 P4 |
| A12-A13 | No sealed type written or relabelled in an enrolled boot; only the maintenance domain in the maintenance boot | W01 §5.5 |
| A14-A17 | `prog_load` only by containment before the seal, plus the runtime under owner decision E1; no BPF maps; `prog_run` on containment programs only for the reader roles | W01 §5.1, §5.3; E1 |
| A18-A21 | `setbool` only by containment before the seal; nothing after the seal; maintenance only in the maintenance boot; never `setenforce` | W01 §5.2 S4, §5.5 |
| A22-A29 | Who enters containment, maintenance, the daemon roles, the worker and the writer, and in which states; no role in the maintenance boot | W01 §5.2, §5.4, §5.5, §2.4 |
| A30-A32 | No `dyntransition`, `setexec` or `ptrace` into any declared domain; no `execmem`, `execstack` or `execheap` | W01 §5.3 |
| A33-A38 | Cgroup access (F2): search and open only by init, containment and the readers; writes only by init and, for the broker's delegated cgroups, the broker; relabel only by containment before the seal; no `dac_read_search` for any domain, in the initial or a user namespace | W01 §5.1; F2 |
| A39 | `sys_admin` only for the confined kubelet and runtime | W01 §5.3; W02a N1 |
| A40-A44 | Pins, seal marker, gate journal and datastore data | W01 §5.1; W02a; W02b; counterexample 25 |
| A45 | Only systemd starts, stops or reloads planeon and backend units in an enrolled boot | W01 §5.3 |
| A46 | `net_bind_service` only for the server and gate (enrolled only with a signed port below 1024), the admin login and the runtime | W01 §5.3; W02a |

The 29 mutation checks show the assertions are not vacuous. Each mutation adds one forbidden grant and names exactly the
assertions it breaks: for example, the admin domain connecting to the apiserver port (A01), the admin domain holding
CAP_DAC_READ_SEARCH (A37), or containment loading programs after the seal (A15). Five structural mutations are refused
by `check_matrix` itself: an upstream unconfined type, an undeclared domain, a credential readable by every domain, a
transition through a non-entrypoint type, and a dead transition rule.

## W01 finding F2: the cgroup gate, stated exactly

F2 found that W01 §5.1 and counterexample 28 argued "no other domain can even get an O_PATH fd". But cgroup2 on kernfs
exports file handles, so `open_by_handle_at` can produce a descriptor without a path walk; with CAP_DAC_READ_SEARCH it also
bypasses DAC search checks. The stated mechanism is therefore replaced by the following, which rests on the controls that
actually decide:

1. **Every non-O_PATH access is the SELinux label check on the planeon cgroup types.** The check applies however the dentry
   was found, path walk or file handle. Opening a role cgroup directory, or opening `cgroup.procs`, `cgroup.kill`,
   `cgroup.freeze` or any limit file for reading or writing, needs `dir`/`file` `open` and `read` or `write` on
   `planeon_cgroup_*_t`. Only init, containment, the reader roles and, for its delegated cgroups, the broker get them (A33-A35;
   F02, F03).
2. **An O_PATH descriptor gets no open check, so it is denied where it is obtained.**
   - A path walk needs `dir search` on the planeon slice and role directories, which the admin domain lacks (A33; F01).
   - Decoding a file handle needs CAP_DAC_READ_SEARCH (Linux v6.12 `fs/fhandle.c` `may_decode_fh`): in the initial user
     namespace or, under the v6.10 relaxation, in the user namespace that owns the mount. cgroup2 is mounted in the initial
     user namespace, and in any case no domain in the matrix holds the capability in either form (A37, A38; F04, F05).
3. **An O_PATH cgroup descriptor would still not detach an enrolled program.** Containment attaches with
   BPF_F_ALLOW_MULTI, so detaching needs that program's descriptor. That descriptor comes only through `bpf prog_run` on
   containment-owned programs (checked in `bpf_prog_new_fd`) and a read of the pin. Only the reader roles get either
   (A17, A40; F06, F07).

The outcome W01 claimed is unchanged: no domain outside the enumerated ones can read, write or detach planeon cgroup
controls. The argument now cites the gates that decide it, and the vectors pin each one. Whether the enrolled kernel and
policy behave this way is native evidence (T04), not shown here.

## W02a slot values

| W02a slot | Value |
|---|---|
| `roles.SERVER.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_server_t:s0` |
| `roles.OBSERVER.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_observer_t:s0` |
| `roles.BROKER.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_broker_t:s0` |
| `roles.WORKER.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_worker_t:s0` |
| `roles.EFFECT_GATE.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_gate_t:s0` |
| `program.pinLabel` (every pin) | `system_u:object_r:planeon_bpf_pin_t:s0` |
| `sealMarker.selinuxLabel` | `system_u:object_r:planeon_seal_t:s0` |

All values match the W02a schema patterns. Fixing them as constants in the record schema is a W02a-F revision; until then
the validator of this part pins them here.

## Confined backend types (W02a round-2 N1)

Each backend component runs in its own `qualk8s_<component>_t`, defined by the qualification backend policy module, which
W03 writes. The module must meet these requirements, and the matrix and its assertions bind them:
- no backend or Pod type is unconfined, permissive or carries a type attribute that grants unrestricted access;
- every type has exactly the closed accesses above on planeon and qualk8s objects;
- the kubelet alone connects to the runtime socket, and the apiserver alone to the datastore;
- no backend type reads a planeon credential, searches a planeon cgroup, reads a pin or enters a planeon domain;
- the network-policy agent and the service proxy must not need BPF: only the runtime has the E1 exception, so an
  iptables or nftables agent is a selection criterion for W03;
- the kubelet and runtime keep `sys_admin` inside confined types, where SELinux type rules still bound it (A39).

container-selinux's `kubelet_t` and `container_runtime_t` are unconfined types and cannot be used.

## Owner decision

**E1 (2026-10-07).** W01 §5.3 makes `planeon_contain_t` the only domain with `bpf { prog_load }`. On a cgroup-v2-only host
every OCI runtime loads a BPF_PROG_TYPE_CGROUP_DEVICE program per container to enforce device access, so a confined runtime
could not work. The owner chose a narrow exception.

What the policy enforces:
- `qualk8s_runtime_t` gets `bpf { prog_load }` and CAP_BPF, and nothing else of the BPF surface;
- no maps (A16);
- no `prog_run` on containment programs (A17);
- no search or open of planeon cgroups and no read of pins (A33, A40), so it cannot attach to a planeon cgroup or obtain a
  planeon program.

SELinux cannot restrict the program type. "Only cgroup-device programs, only on container cgroups" is therefore a W03
runtime-selection requirement and a T04 native check, and the readers' comparison of attached program IDs with the
containment pins (W02a) refuses any foreign program on a planeon cgroup. E1 amends W01 §5.3 and is carried to W01's
record and T04.

## Decisions made in this contract (not in the reviewed spec)

1. The gate labels its I05 and I07 listening sockets with `setsockcreate` (the only domain with that permission). A
   requirement on the gate implementation (W03).
2. Containment creates and labels pins, cgroup labels and the seal marker before the seal. That is the only labelling
   outside the maintenance domain, and only while `planeon_containment_enabled` = 1.
3. In the maintenance boot no planeon role or the writer is entered (A28). Backend components may run there, for
   credential issuance and datastore restore.
4. The admin domain's capabilities are closed: chown, dac_override, fowner, fsetid, kill, setgid, setuid,
   net_bind_service, sys_boot (it must reboot into maintenance), sys_nice, sys_resource and audit_write. It lacks
   dac_read_search, sys_admin, sys_module, sys_ptrace, net_admin, bpf, mac_admin and mac_override.
5. The reader roles read `/proc` of every enrolled role, lifecycle subject, backend component and Pod for their captures.
   That is the ptrace read check. The gate and broker read each other, the gate reads the writer, and the broker reads
   its worker.
6. Required policy capabilities: `cgroup_seclabel` (labels on cgroupfs), `open_perms` (the `open` permission) and
   `network_peer_controls`.
7. Backend capability sets are declared, not observed (W03 confirms against the selected distribution): kubelet and runtime
   as listed, network-policy agent and proxy `net_admin` and `net_raw`, apiserver, controller-manager, scheduler and
   datastore none.

## Not claimed

No policy module, compiled policy or loaded host. No observation that the kernel or the selected distribution behaves as
modelled. No seccomp filter (W02d), no admission allowlist (W02f), no selected distribution (W03). All E01-E12 stay
OPEN_UNPROVEN. The W01, W02a, W02g, W02b and W02c bytes are unchanged.

## Spec mapping

| Design text | Here |
|---|---|
| §2.1 P1 datastore `connectto` from the apiserver alone | Socket row, A05 |
| §2.1 P2 `planeon_kubeapi_port_t`, enumerated connectors, no root login | Port row, A01, A02 |
| §2.1 P4 signing key readable only by apiserver and controller-manager | `qualk8s_sa_key_t`, A10 |
| §2.1 P5 sealed control-plane configuration | `qualk8s_config_t`, `qualk8s_unit_file_t`, A12, A13 |
| §2.1 P9 runtime socket only from the kubelet | Socket row, A06 |
| §5.1 bpffs pins, `prog_run` only to readers, MULTI detach, containment owns programs | A14-A17, A40, A41; E1 |
| §5.1 `dir search` denial on planeon cgroups | A33; restated for F2 |
| §5.2 S2-S5 containment once, booleans, `secure_mode_policyload` | States, A18, A19, A22, A23, A42 |
| §5.3 per-role domains and key denials | Domains, capabilities, A01-A11, A30-A32, A39, A45, A46 |
| §5.5 sealed types, `planeon_maint_t`, `planeon_maintenance_mode` | A12, A13, A20, A24, A25, A28 |

## Still open

All E01-E12 and T01-T08. The binary policy, its conditionals and its behaviour on the enrolled kernel (T04). The backend
policy module and the selected distribution (W03). The seccomp filters (W02d). The W02a schema constants for these labels
(W02a-F). W03-W07 remain gated. Alpha2 remains open; model-effort transition NOT_DUE.
