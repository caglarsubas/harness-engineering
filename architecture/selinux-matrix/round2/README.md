# SELinux domain, type, boolean and permission matrix — W02e (MET-ENFORCE-009), round 2

Status: **CONTRACT_CANDIDATE**, awaiting the round-2 independent review. Round 1 (`review-round1.json`, reviewed bytes in
`round1/`) returned CHANGES_REQUIRED with 8 MAJOR, 9 MINOR and 1 NOTE findings; each is answered below. DATA_CHECK_ONLY:
no policy module is written or compiled, nothing is loaded or installed, and all E01-E12 stay OPEN_UNPROVEN.

This part turns the SELinux choices of the reviewed W01 design (HOST-INTERFACE-DRAFT-002 §2.1 P1/P2/P4/P5/P9, §2.3, §4.1-
§4.3, §5.1-§5.5) into one closed matrix. It also fills what the adopted W02a v2 record leaves to W02e:
- the role cgroup, bpffs pin and seal-marker labels;
- the confined backend types `qualk8s_<component>_t` (W02a round-2 N1);
- the closure of W01 review finding F2.

## Files

| File | Content |
|---|---|
| `matrix.json` | `planeon.internal.selinux-matrix/v2`. It holds three booleans and three boot states, 19 domains, 53 types, 6 sockets, 3 ports, 17 transitions, 16 named type transitions, a genfscon rule, the capability, `bpf`, `security`, `process`, `process2` and `service` grants, `/proc` access, per-source closures and 88 deny assertions |
| `vectors.json` | 1,209 access checks (allow, deny or outside, each with its state and intent), 43 mutation checks and the W02a slot values |
| `scripts/selinux_matrix.py` | Reference evaluator: `allowed`, `check_matrix`, `failed_assertions`, `w02a_slots`, `apply_ops` |

## What the matrix closes

`allowed(state, source, target, class, perm)` answers True or False where the matrix is closed and None outside it.

| Closed | Exactly |
|---|---|
| The matrix's own types | Every file-class permission (`file`, `dir`, `sock_file`, `lnk_file`; all v6.12 classmap permissions in seven groups: READ, WRITE, RELABEL, EXECUTE, EXECUTE_NO_TRANS, EXECMOD, ENTRYPOINT), for every declared domain and any other domain |
| Its sockets and ports | `unix_stream_socket` `connectto`, `create`, `bind`, `listen`, `accept`; `tcp_socket` `name_bind`, `name_connect` |
| Per-source closures | The server, observer, broker, worker, gate, writer and containment get no `name_connect`, `name_bind` or `connectto` on any target the matrix does not list for them, declared or not (W01 §5.3 "only" rows; review R5) |
| Another process's `/proc` | `dir`/`file`/`lnk_file` READ on a declared domain and `process getattr` on it come only from `procAccess` |
| Process permissions on declared domains | `transition` (effective with `file execute` for the source, `file entrypoint` for the target and, after `no_new_privs`, `process2 nnp_transition`), `dyntransition`, `ptrace`, `sigkill`, `sigstop`, `signal`; on the caller itself `setexec`, `setsockcreate`, `execmem`, `execstack`, `execheap` |
| Capabilities of declared domains | Every `capability`, `capability2`, `cap_userns` and `cap2_userns` permission |
| `bpf`, `security`, `service` | Every permission listed, `service` on the matrix's unit types |

Outside the matrix (None): ordinary access to undeclared types (libraries, devices), a domain's own `/proc`, the capabilities
of undeclared host domains, other process and socket permissions (`sigchld`, `fork`, socket `read`/`write`), connections of
backend components to undeclared ports or sockets, and transitions into the admin login and into systemd, which the host's
login and boot policy defines (pam_selinux, `kernel_t` to `init_t`; review R3). The W03 policy module adds that access. It
may grant nothing the matrix closes beyond the matrix.

## Booleans and states

| State | planeon_containment_enabled | planeon_maintenance_mode | secure_mode_policyload | Meaning |
|---|---|---|---|---|
| ENROLLED_CONTAINMENT | 1 | 0 | 0 | Enrolled boot, S2 up to S4 |
| ENROLLED_SEALED | 0 | 0 | 1 | Enrolled boot after S4; the state every v2 record requires (W02a host lock state) |
| MAINTENANCE_BOOT | 0 | 1 | 0 | The maintenance boot entry (W01 §5.5); no planeon role starts |

S4 sets both booleans in one commit (selinuxfs `commit_pending_bools`): containment writes both pending values and commits
once, while `setbool` is still granted. No state between the two exists, so the matrix needs no transient state (review
R10). `secure_mode_policyload` = 1 then freezes booleans, policy load and enforcing mode until reboot. The pinned binary
policy must contain the matching conditionals (W01 §5.2), and T04 checks them.

## Domains

| Kind | Domains |
|---|---|
| Resident roles | `planeon_server_t`, `planeon_observer_t`, `planeon_broker_t`, `planeon_worker_t`, `planeon_gate_t` |
| Lifecycle subjects | `planeon_policy_writer_t` (entered by the admin login through `/opt/planeon/bin/harness-policy-write`), `planeon_contain_t` (entered by init once per boot, only while `planeon_containment_enabled`) |
| Maintenance | `planeon_maint_t` (entered by the admin login, only in the maintenance boot) |
| Backend | `qualk8s_apiserver_t`, `qualk8s_controller_manager_t`, `qualk8s_scheduler_t`, `qualk8s_kubelet_t`, `qualk8s_runtime_t`, `qualk8s_datastore_t`, `qualk8s_netpol_t`, `qualk8s_proxy_t` |
| Qualification Pods | `qualk8s_container_t` |
| Admin | `planeon_admin_t`: the confined domain root logins map to (entry by host login policy) |
| System | `init_t` (systemd; entry by host boot policy) |

The process contexts equal the W02a v2 schema's fixed `processLabel` values. A domain's name is fixed by its kind:
planeon kinds start `planeon_`, backend and Pod domains start `qualk8s_`, and the system domain is `init_t`. So an upstream
unconfined or privileged type, such as container-selinux's `kubelet_t`, `container_runtime_t` or `spc_t`, or refpolicy's
`unconfined_t`, cannot appear (W02a round-2 N1; mutation M37). Confinement itself is a T04 check on the compiled policy.

## Types and rules

| Category | Types | Access |
|---|---|---|
| Entrypoints | one `*_exec_t` per role, lifecycle, maintenance and backend domain (16) | READ any domain; EXECUTE the starter only; ENTRYPOINT the entered domain only; EXECUTE_NO_TRANS nobody; WRITE/RELABEL `planeon_maint_t` only in the maintenance boot, which also enables fs-verity |
| Interpreter | `planeon_interpreter_exec_t` (Python for SERVER and WORKER) | EXECUTE init, broker, server, worker; never an entrypoint; nobody runs it without a transition |
| Sealed configuration and units | `planeon_etc_t`, `qualk8s_config_t`, `planeon_unit_file_t`, `qualk8s_unit_file_t` | READ any; WRITE/RELABEL maintenance only |
| Credentials | `planeon_server_cred_t`, `planeon_observer_cred_t`, `planeon_gate_effect_cred_t`, `planeon_gate_writer_cred_t`, `qualk8s_sa_key_t`, `qualk8s_encryption_key_t`, one `qualk8s_<component>_cred_t` per API client | READ the owners only; WRITE/RELABEL maintenance only (W01 §5.5 M5) |
| Socket files | I05, I07, observer, broker, datastore and runtime socket files | The listener and its one connector |
| Cgroups | `planeon_cgroup_{slice,contain,server,observer,gate,delegate,broker,worker}_t` | READ init, containment and the reader roles; WRITE init, containment before the seal, and the broker on its delegated service cgroup (`delegate`) and its `broker` and `probe-worker` leaves; RELABEL nobody |
| bpffs pins, seal marker | `planeon_bpf_pin_t`, `planeon_seal_t` | READ containment and the reader roles. Pins: WRITE containment before the seal, labelled by genfscon. Seal marker: WRITE containment in the enrolled boot (S5) |
| Journal, data | `planeon_gate_journal_t`, `qualk8s_datastore_data_t` | The owner; the maintenance domain only in the maintenance boot (reconciliation, restore: counterexample 25) |
| Container content | `qualk8s_container_file_t` | The runtime writes; the Pod domain enters it |

- **Sockets.** The gate labels its two listening sockets `planeon_i05_socket_t` and `planeon_i07_socket_t` with
  `setsockcreate`, so `connectto` tells I05 from I07. Only the broker connects to I05 and only the writer to I07. The other
  sockets keep their listener's domain as their label.
- **Ports.** `planeon_kubeapi_port_t` is bound by the apiserver and connected to by exactly the gate, the observer, the
  controller-manager, the scheduler, the kubelet, the network-policy agent and the service proxy (P2). `planeon_i04_port_t`
  is bound by the gate and connected to by the server. `qualk8s_kubelet_port_t` is bound by the kubelet and connected to by
  the apiserver.
- **Port numbers.** `name_bind` is not checked for ports inside `net.ipv4.ip_local_port_range`. Every labelled port must
  therefore lie outside it; that is a W03 requirement and a T04 check (review R16).
- **Cgroup creation and labels.** Containment creates the role service cgroups and the broker's leaves before the seal
  (W01 S3 "creates"), sets limits and attaches the programs; systemd reuses them at S6.
  - Sixteen named type transitions label each cgroup at creation, whether containment, systemd or the broker creates it.
    Files inside inherit their directory's type.
  - Nothing relabels a cgroup (review R6).
  - The delegated `planeon-capacity-broker.service` directory has its own type, `planeon_cgroup_delegate_t`. The broker
    writes its `cgroup.procs`, which clone3 `CLONE_INTO_CGROUP` checks at the common ancestor.
- **Pins.** bpffs cannot be relabelled, so pins take `planeon_bpf_pin_t` from the genfscon path rule `bpf /planeon`
  (review R13). Readers open pins with `BPF_F_RDONLY`, which needs read only (review R18).
- **Transitions.** Seventeen transitions: init into the daemon roles (enrolled boot), containment (before the seal) and each
  backend component; the broker into the worker and the runtime into the Pod domain, both after `no_new_privs` through
  `nnp_transition` (policy capability `nnp_nosuid_transition`; review R12); the admin login into the writer (enrolled boot)
  and into maintenance (maintenance boot).
- **Signals.** systemd signals every planeon, backend and Pod domain. The broker kills its worker (pidfd), and the runtime
  signals Pods. The admin login signals no planeon domain (review R15).
- **`/proc` access.** The reader roles read the `/proc` entries of every enrolled role, lifecycle subject, backend
  component and Pod. The gate and broker read each other, the gate reads the writer, and the broker reads its worker.
  - SELinux checks a `/proc/<pid>` entry as an access to the target domain. Ptrace-gated entries (`exe`, `fd`, `cwd`,
    `environ`, `mem`) also need the kernel's own rules: the reader's capabilities must cover the target's, and the uids must
    match unless CAP_SYS_PTRACE, which no role holds. So the gate cannot read the broker's `exe`, and no role reads the
    other-uid worker's or the kubelet's gated entries.
  - Captures and peer checks therefore use SO_PEERCRED, SO_PEERSEC, pidfds and ungated entries (`status`, `stat`,
    `cgroup`) (review R4).
  - Executable identity follows from the peer's label: the matrix lets each domain be entered only through its sealed
    entrypoint type.
- **systemd.** `init_t` holds every capability except `sys_module` and `sys_rawio` (modules are disabled after S5), plus
  `wake_alarm`, `block_suspend` and `audit_read`. That includes `dac_read_search`, `sys_admin` and `setpcap`, which systemd
  needs to set the roles' bounding sets. systemd is the trusted service manager, and the deny assertions name it where
  they allow it (review R2). It loads no BPF programs: the kubelet and runtime use the cgroupfs driver and no planeon or
  backend unit uses a BPF-backed directive (`DeviceAllow`, `IPAddress*`, `RestrictNetworkInterfaces`, `SocketBind*`, ...).
  That is a W03 requirement and a T04 check (review R7).
- **Unit sources.** Every systemd unit search path and drop-in directory (`/etc/systemd/system`, `<unit>.d`, `/run/systemd/*`,
  generator and transient directories) must carry a sealed unit type; that is a W03 requirement and a T04 check (review R17).

## Assertions

88 deny properties, each evaluated for every listed boot state, target and source. Sources are every domain plus
`OTHER_DOMAIN`, the declared domains, or a listed set; for capabilities only declared domains count, because undeclared
host domains' capabilities are outside the matrix.

| IDs | Property | Source |
|---|---|---|
| A01-A08 | Apiserver port (P2), I04 port, datastore socket (P1), runtime socket (P9), I05 and I07: exactly the enumerated connectors and binders | W01 §2.1, §5.3; W02b; W02c |
| A09-A11.9 | Each credential readable by its owners only | W01 §5.3, §2.1 P4 |
| A12-A13 | No sealed type written or relabelled in an enrolled boot, fs-verity included; only the maintenance domain in the maintenance boot | W01 §5.5; R8 |
| A14-A19 | `prog_load`: containment before the seal and the runtime (E1). No BPF maps. `prog_run` on containment programs: containment as loader before the seal and the reader roles. `prog_run` on the runtime's programs: the runtime alone | W01 §5.1; E1; R1 |
| A20-A23 | `setbool` only by containment before the seal; nothing after the seal; maintenance only in the maintenance boot; never `setenforce` | W01 §5.2 S4, §5.5 |
| A24-A31 | Who enters containment, maintenance, the daemon roles, the worker and the writer, and in which states | W01 §5.2, §5.4, §5.5, §2.4 |
| A32-A37 | No `dyntransition` into a declared domain, no `setexec` (on the caller), no `ptrace`, no `execmem`/`execstack`/`execheap`, no `execmod`, no `execute_no_trans` on entrypoints, the interpreter or container content | W01 §5.3; R3, R11, R14 |
| A38-A44 | Cgroups (F2): search, open and read only by init, containment and the readers; writes by init, containment before the seal and the broker on its delegated cgroups; no relabel of cgroups or pins | W01 §5.1, §5.4; F2; R6, R13 |
| A45-A48 | Capabilities of declared domains: no `dac_read_search` except systemd, none in a user namespace; `sys_admin` only systemd, kubelet and runtime; `net_bind_service` only systemd, server, gate, admin login and runtime | F2; W01 §5.3; W02a N1; R2 |
| A49-A55 | Pins, seal marker, gate journal and datastore data | W01 §5.1, §5.2 S5; W02a; W02b; counterexample 25; R10 |
| A56-A59 | Units only by systemd; signals to the roles, the writer and containment only from systemd, to the worker also from the broker; another role's `/proc` only for the enumerated peers | W01 §5.3, §4.3, §5.4; R4, R15 |
| A60.* | 21 per-source closures: each closed source gets nothing beyond its listed ports and sockets, including an undeclared port and socket | W01 §5.3; R5 |

The 43 mutation checks show the assertions are not vacuous. 34 add a forbidden grant and name exactly the assertions it
breaks. For example, the server connecting to the apiserver port breaks A01 and its per-source closure A60.1.name_connect,
and containment writing an artifact before the seal (fs-verity) breaks A12. One removes a closure and changes the result,
and one removes an `nnp_transition` grant, which makes the worker transition dead. Seven are refused by `check_matrix`:
- an unconfined backend type;
- an undeclared domain;
- a world-readable credential;
- a transition through a non-entrypoint type;
- a dead transition;
- a matrix rule entering the admin login;
- a type transition without write on its parent.

## W01 finding F2: the cgroup gate, stated exactly

F2 found that W01 §5.1 and counterexample 28 argued "no other domain can even get an O_PATH fd". But cgroup2 on kernfs
exports file handles, so `open_by_handle_at` can produce a descriptor without a path walk. The stated mechanism is replaced
by the following, which rests on the controls that actually decide.

1. **Every non-O_PATH access is the SELinux label check on the planeon cgroup types.** The check applies however the dentry
   was found, by path walk or file handle (`do_handle_open` uses `file_open_root`). Opening a role cgroup directory, or
   opening `cgroup.procs`, `cgroup.kill`, `cgroup.freeze` or a limit file, needs `open` and `read` or `write` on
   `planeon_cgroup_*_t`. Only init, containment, the reader roles and the broker get them, each within its rows
   (A38-A43; F02, F03).
2. **An O_PATH descriptor gets no open check (`do_o_path`), so it is limited where it is obtained.**
   - A path walk needs `dir search` on the planeon slice and role directories, which the admin domain lacks (A38; F01).
   - Decoding a file handle (v6.12 `fs/fhandle.c` `may_decode_fh`) needs CAP_DAC_READ_SEARCH in the initial user
     namespace. The v6.10 relaxed path needs `O_DIRECTORY`, CAP_SYS_ADMIN in the superblock's or the mount namespace's
     user namespace, and CAP_DAC_READ_SEARCH in the caller's own user namespace. The admin domain holds neither
     `dac_read_search` (in any form) nor `sys_admin` (A45-A47; F04, F05).
   - A procfs magic link (`/proc/<pid>/fd/<n>`, `cwd`) of a process holding a cgroup descriptor is a third route. It needs
     the ptrace read check on the holder: the admin domain has no `/proc` access to any role (A59; F08), and among roles the
     kernel's capability and uid rules apply.
3. **Item 3 is the control that decides detach.** Containment attaches with `BPF_PROG_ATTACH` and BPF_F_ALLOW_MULTI, never
   with a bpf_link. A bpf_link would be reachable through `BPF_LINK_GET_FD_BY_ID` by any CAP_SYS_ADMIN holder, and that
   call has no LSM check. So detaching needs the program's descriptor. That comes only through `bpf prog_run` on the
   containment-owned program (checked in `bpf_prog_new_fd`) and a read of the pin. After the seal only the reader roles
   get either (A17-A18, A49; F06, F07).

So an O_PATH descriptor alone can neither change cgroup controls nor detach an enrolled program. The outcome W01 claimed is
unchanged: no domain outside the enumerated ones can read, write or detach planeon cgroup controls. Two things remain
open:
- the behaviour of the enrolled kernel and policy (T04);
- the residual of owner decision E1 below.

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
- no backend type reads a planeon credential, searches a planeon cgroup, reads a pin, reads a planeon role's `/proc` or
  enters a planeon domain;
- the network-policy agent and the service proxy must not need BPF: only the runtime has the E1 exception, so an
  iptables or nftables agent is a selection criterion for W03.

container-selinux's `kubelet_t` and `container_runtime_t` are unconfined types and cannot be used.

## Owner decision

**E1 (2026-10-07, re-confirmed after review R7).** W01 §5.3 makes `planeon_contain_t` the only domain with
`bpf { prog_load }`. On a cgroup-v2-only host every OCI runtime loads a BPF_PROG_TYPE_CGROUP_DEVICE program per container,
so a confined runtime could not work. The owner chose an exception, stated here at its real scope.

**What the policy enforces.** `qualk8s_runtime_t` gets:
- `bpf prog_load`, CAP_BPF, and `prog_run` on its own programs only (A19);
- no maps (A16);
- no `prog_run` on containment programs (A17, A18);
- no search or open of planeon cgroups and no read of pins (A38, A49).

**What it cannot enforce.** SELinux does not restrict program type, attach type or attach target. With CAP_SYS_ADMIN,
which the runtime needs for mounts and namespaces, `bpf_ns_capable` satisfies the other BPF capability checks too. The
runtime can also attach a cgroup program at an ancestor of the planeon cgroups, such as the root, through an O_PATH
descriptor; with BPF_F_ALLOW_MULTI it then takes effect on the planeon cgroups.

**Accepted.** The runtime is therefore a trusted backend component for its BPF use. The controls are:
- W03 selects a runtime that loads only cgroup-device programs, only on container cgroups, under the cgroupfs driver (so
  systemd loads none);
- T04 checks that natively;
- a census of the effective program set of every planeon cgroup, for every cgroup attach type, must show only the
  containment programs. That census extends the W02a readers, which today query the seven containment hooks, and is
  carried to W02a-F.

E1 amends W01 §5.3 and is carried to W01's record, W03 and T04.

## Decisions made in this contract (not in the reviewed spec)

1. The gate labels its I05 and I07 listening sockets with `setsockcreate` (the only domain with that permission). A
   requirement on the gate implementation (W03).
2. Containment creates the role cgroups and the broker's leaves before the seal (W01 S3 "creates"), with named type
   transitions, and creates pins under the genfscon-labelled `/sys/fs/bpf/planeon`. It relabels nothing.
3. fs-verity is enabled in the maintenance boot by `planeon_maint_t`, which installs the artifacts. At S3 containment only
   measures (FS_IOC_MEASURE_VERITY) and refuses to seal if an enrolled artifact lacks verity. W01 S3 says "enables
   fs-verity", which would need write access on sealed artifacts in the enrolled boot, against §5.5 (review R8).
4. S4 sets both booleans in one atomic commit; the seal marker is written in S5, after it, by the still-running containment
   process. That process can no longer be re-entered, and W02a requires the containment domain to be empty in captures
   (review R10).
5. In the maintenance boot no planeon role or the writer is entered (A30). Backend components may run there, for credential
   issuance and datastore restore.
6. The admin domain's capabilities are closed: chown, dac_override, fowner, fsetid, kill, setgid, setuid,
   net_bind_service, sys_boot (it must reboot into maintenance), sys_nice, sys_resource and audit_write. It lacks
   dac_read_search, sys_admin, sys_module, sys_ptrace, net_admin, bpf, mac_admin and mac_override. It signals no planeon
   domain and reads no role's `/proc`.
7. Peer qualification and captures use SO_PEERCRED, SO_PEERSEC, pidfds and ungated `/proc` entries; executable identity
   follows from the label and the entrypoint closure (review R4).
8. Required policy capabilities: `cgroup_seclabel`, `open_perms`, `network_peer_controls`, `nnp_nosuid_transition`.
9. Backend capability sets are declared, not observed (W03 confirms them against the selected distribution): kubelet and
   runtime as listed, network-policy agent and proxy `net_admin` and `net_raw`, apiserver, controller-manager, scheduler and
   datastore none.

## Round-1 findings and dispositions

| Finding | Disposition in round 2 |
|---|---|
| R1 MAJOR, loaders lack `prog_run` on their own programs | Containment `prog_run` on its programs before the seal, the runtime on its own; A17-A19; Q39, S03 |
| R2 MAJOR, init_t and undeclared domains closed to every capability | systemd's capability set enumerated; capability assertions over declared domains only; undeclared domains' capabilities outside (O04) |
| R3 MAJOR, no entry into the admin login or systemd; setexec target | Transitions into ADMIN and SYSTEM kinds are host policy, outside (O06, O07, M42); `setexec` checked on the caller (A33) |
| R4 MAJOR, `/proc` modelling and ptrace preconditions | `procAccess` for dir/file/lnk_file READ and `process getattr`; self outside (O03); commoncap and uid rules and ungated captures stated (decision 7); A59 |
| R5 MAJOR, per-source "only" properties open for undeclared targets | `sourceClosures` for seven planeon domains; 21 A60 assertions; P01-P06; M02-M04, M35 |
| R6 MAJOR, S3 cgroups do not exist yet; labels after the seal | Containment creates them before the seal; 16 named type transitions; `planeon_cgroup_delegate_t`; A40-A44 |
| R7 MAJOR, E1 broader than stated; systemd BPF | E1 restated at its real scope and re-confirmed by the owner; census to W02a-F; systemd BPF excluded as a W03 requirement (M10) |
| R8 MAJOR, fs-verity at S3 needs write on sealed artifacts | Moved to the maintenance boot; containment measures (decision 3); A12, M08 |
| R9 MINOR, may_decode_fh description, magic links, bpf_link | F2 item 2 corrected, magic-link route added (F08); attachment by `BPF_PROG_ATTACH` only |
| R10 MINOR, seal marker after S4, sequential booleans | Atomic S4 commit; marker written in S5 (decision 4); A52-A53; S14, S15 |
| R11 MINOR, execute_no_trans with execute | Split groups; nobody holds `execute_no_trans` (A37, M23) |
| R12 MINOR, nnp transitions | `noNewPrivs` transitions need `process2 nnp_transition`; `nnp_nosuid_transition` capability (M18) |
| R13 MINOR, bpffs cannot be relabelled | genfscon rule; no pin relabel (A44) |
| R14 MINOR, incomplete FILE_PERMS; execmod | All v6.12 file permissions; A36, M22 |
| R15 MINOR, unknown permissions raise; signals | Unknown permissions are outside (O05, O08); signals closed (A57, A58, M33) |
| R16 MINOR, name_bind inside the ephemeral range | Ports outside `ip_local_port_range` (W03/T04 requirement) |
| R17 MINOR, systemd drop-ins and unit search paths | Sealed unit types on every search path and drop-in directory (W03/T04 requirement) |
| R18 NOTE | Cgroup file assertion A39 added beside A38; readers use `BPF_F_RDONLY`; a `matrixError` vector pins the exact full message; socket-file grants stay as broad groups and are listed as upper bounds |

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
| §5.1 bpffs pins, `prog_run` only to readers, MULTI detach, containment owns programs | A14-A19, A49-A51; E1 |
| §5.1 `dir search` denial on planeon cgroups | A38; restated for F2 |
| §5.2 S2-S5 containment once, booleans, `secure_mode_policyload` | States, A20, A21, A24, A25, A52; decisions 2-4 |
| §5.3 per-role domains and key denials | Domains, capabilities, A01-A11, A32-A37, A45-A48, A56-A60 |
| §5.4 worker exec after `no_new_privs`, kill through the pidfd | A29, A58; `nnp_transition` |
| §5.5 sealed types, `planeon_maint_t`, `planeon_maintenance_mode` | A12, A13, A22, A26, A27, A30 |

## Still open

All E01-E12 and T01-T08. The binary policy, its conditionals and its behaviour on the enrolled kernel (T04). The backend
policy module, the selected runtime's BPF behaviour and the selected distribution (W03). The effective-program census
(W02a-F). The seccomp filters (W02d). The W02a schema constants for these labels (W02a-F). W03-W07 remain gated. Alpha2
remains open; model-effort transition NOT_DUE.
