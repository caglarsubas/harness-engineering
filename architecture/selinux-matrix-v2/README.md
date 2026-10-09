# SELinux domain, type, boolean and permission matrix v4 — W02e-F (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. Round 1 (`review-round1.json`, reviewed bytes of the
files changed since in `round1/`) returned CHANGES_REQUIRED with 2 MINOR and 3 NOTE findings, all on the text; each is
answered under "Round-1 findings and dispositions". DATA_CHECK_ONLY: no policy module is written or
compiled, nothing is loaded or installed, and all E01-E12 stay OPEN_UNPROVEN.

v4 is the W02e-F successor of the adopted W02e matrix `../selinux-matrix/` (`planeon.internal.selinux-matrix/v3`,
MET-ENFORCE-009, review round 3 PASS_FOR_SOURCE_PUBLICATION with K1-K6 carried). A later layer pins the v3 bytes, so v3
stays byte-identical and v4 is published beside it. v4 keeps the v3 matrix and changes only what round 3 carried to
W02e-F: K2, K3, K4 and K6. The other two round-3 findings stay carried as the v3 `status.json` records them:
- K1 to W02a-F, T04 and W01's record: A62-A65 hold under the pinned policy only. The maintenance domain's `load_policy`
  preserves boolean values by name, so as the trusted installer it can reach any boolean state, and the early
  maintenance-boot window relies on the systemd target. It needs a record-level boot-entry discriminator (a measured
  boot entry or command line) or an explicit statement in W01's record.
- K5 to W03 and T04, three requirements: `DelegateSubgroup=broker` (systemd 254 or later) for the pre-created delegated
  leaves; the maintenance unit writes the planeon booleans while running in `init_t` itself; `planeon_server_port_t` is
  assigned by portcon from the signed port at the maintenance install.

Accepted base: main `4196dae` (MET-ENFORCE-015, 214 packets). The packet that publishes v4 is claimed only after the
primary lane's PERF packet merges (owner decision, 2026-10-09).

## What v4 changes

| Finding | v4 rule | Vectors |
|---|---|---|
| K2 MINOR, A59 checked a union | One assertion per planeon target (the five resident roles, the writer, containment and the maintenance domain; the admin login is not a planeon target and its `/proc` is host policy, round-1 F5), `A59.<target>`, each allowing only that target's `procAccess` peers. A59 stays as the union bound (its statement now says so), so every v3 identifier is kept. | M51-M53 (gate to server, gate to containment, broker to maintenance: each breaks exactly its per-target assertion); M34, M45 now also name the per-target assertion |
| K3 NOTE, no assertion pinned load_policy before the seal | A66: in ENROLLED_CONTAINMENT no domain holds `security load_policy`; with A21, no `load_policy` grant is reachable in the two modelled enrolled states, and A23 pins `setenforce` in every state. That the reviewed policy is the only one loaded throughout an enrolled boot does not follow from these assertions alone: systemd may set `planeon_maintenance_mode` before the seal, which reaches a boolean combination the model does not evaluate. It rests on decision 10 and on the policy digest and booleans W01's record pins, the same dependency as K1 (round-1 F3). | M54, M55 |
| K4 NOTE, cgroup2 wording and S11 | The three cgroup2 statements are corrected under "Cgroup creation and labels". S11 now checks `dir create` against `planeon_cgroup_slice_t`, the type computed from the parent, which is what the kernel checks. | S11 |
| K6 NOTE, stale count in the brief | The v4 review brief states 109 assertions. | — |

Every v3 vector keeps its identifier and expected result, except S11 (target, K4) and M34 and M45 (they also name the
per-target assertion). The new access checks (C1623 onward for the new assertions) and M51-M55 are appended. The
evaluator `scripts/selinux_matrix_v2.py` is the v3 evaluator with only the matrix version changed.

## Files

| File | Content |
|---|---|
| `matrix.json` | `planeon.internal.selinux-matrix/v4`. It holds three booleans and three boot states, 19 domains, 56 types, 6 sockets, 4 ports, 17 transitions, 12 genfscon rules, 4 named type transitions, the capability, `bpf`, `security`, `process`, `process2` and `service` grants, `/proc` access, per-source closures and 109 deny assertions |
| `vectors.json` | 1,873 access checks (336 allow, 1,529 deny, 8 outside, each with its state and intent), 55 mutation checks and the W02a slot values (unchanged) |
| `../../scripts/selinux_matrix_v2.py` | Reference evaluator: `allowed`, `check_matrix`, `failed_assertions`, `w02a_slots`, `apply_ops` |

## What the matrix closes

`allowed(state, source, target, class, perm)` answers True or False where the matrix is closed and None outside it.

| Closed | Exactly |
|---|---|
| The matrix's own types | Every file-class permission (`file`, `dir`, `sock_file`, `lnk_file`; all v6.12 classmap permissions in seven groups: READ, WRITE, RELABEL, EXECUTE, EXECUTE_NO_TRANS, EXECMOD, ENTRYPOINT), for every declared domain and any other domain |
| Its sockets and ports | `unix_stream_socket` `connectto`, `create`, `bind`, `listen`, `accept`; `tcp_socket` `name_bind`, `name_connect` |
| Per-source closures | The server, observer, broker, worker, gate, writer and containment get no `name_connect`, `name_bind`, `connectto` or `file execute_no_trans` on any target the matrix does not list for them, declared or not (W01 §5.3 "only" rows; reviews R5, N5). A grant to every domain never reaches a closed source: it needs an explicit grant |
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

Each boot leaves the initial state (1, 0, 0) by one atomic commit (selinuxfs `commit_pending_bools`), so no transient
state exists (review R10):
- the enrolled boot leaves it at S4, when containment sets `planeon_containment_enabled` = 0 and `secure_mode_policyload` = 1;
- the maintenance boot leaves it early, when a systemd unit enabled only in that boot's target sets
  `planeon_maintenance_mode` = 1 and `planeon_containment_enabled` = 0.

A boolean write needs `security setbool` and `file write` on the boolean's selinuxfs file (`sel_write_bool`). selinuxfs
labels each boolean file by genfscon, so the three planeon booleans have their own types. Only the two writers above may
write them, only in the initial state. After either commit no declared domain can write them: the maintenance domain may
change other booleans but cannot leave maintenance mode or re-enable containment (A62-A65; review N4). These assertions
hold under the pinned policy; K1 (a policy load in the maintenance boot carries boolean values into the new policy) stays
carried to W02a-F and T04.

`secure_mode_policyload` = 1 then freezes booleans, policy load and enforcing mode until reboot. The pinned binary policy
must contain the matching conditionals (W01 §5.2), and T04 checks them.

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
| bpffs pins, seal marker | `planeon_bpf_pin_t`, `planeon_seal_t` | READ containment and the reader roles. Pins: WRITE containment before the seal, labelled by genfscon. Seal marker: WRITE containment in the enrolled boot (S5), labelled by a named type transition |
| Boolean files | `planeon_bool_maintenance_t`, `planeon_bool_containment_t`, `planeon_bool_policyload_t` (selinuxfs genfscon) | READ any; WRITE only as described under Booleans and states |
| Journal, data | `planeon_gate_journal_t`, `qualk8s_datastore_data_t` | The owner; the maintenance domain only in the maintenance boot (reconciliation, restore: counterexample 25) |
| Container content | `qualk8s_container_file_t` | The runtime writes; the Pod domain enters it |

- **Sockets.** The gate labels its two listening sockets `planeon_i05_socket_t` and `planeon_i07_socket_t` with
  `setsockcreate`, so `connectto` tells I05 from I07. Only the broker connects to I05 and only the writer to I07. The other
  sockets keep their listener's domain as their label.
- **Ports.** `planeon_server_port_t` is the server's own signed listener (W01 §5.3, W02a `listenEndpointIds`). Only the
  server binds it, which matches the server's CAP_NET_BIND_SERVICE for a signed port below 1024. Campaign clients may
  connect from any domain except the closed planeon sources (review N2). `planeon_kubeapi_port_t` is bound by the apiserver and connected to by exactly the gate, the observer, the
  controller-manager, the scheduler, the kubelet, the network-policy agent and the service proxy (P2). `planeon_i04_port_t`
  is bound by the gate and connected to by the server. `qualk8s_kubelet_port_t` is bound by the kubelet and connected to by
  the apiserver.
- **Port numbers.** `name_bind` is not checked for ports inside `net.ipv4.ip_local_port_range`. Every labelled port must
  therefore lie outside it; that is a W03 requirement and a T04 check (review R16).
- **Cgroup creation and labels.** Containment creates the role service cgroups and the broker's leaves before the seal
  (W01 S3 "creates"), sets limits and attaches the programs; systemd reuses them at S6.
  - kernfs supports security xattrs (`SE_SBGENFS_XATTR`, `kernfs_xattr_set`), but no planeon cgroup node carries one: the
    cgroup2 root has none and nothing relabels (A44). So a named type transition under a cgroup never fires: in v6.12
    `selinux_kernfs_init_security` returns without labelling when the parent has no xattr (review N1). Eight cgroup2
    genfscon path rules therefore label the slice, the containment service, the four role services and the broker's
    two leaves. They apply when a node is instantiated, whoever creates it, and they also label the cgroup interface files
    under each path. hooks.c sets `SE_SBGENFS` for cgroup2 unconditionally, so the path rules apply without any policy
    capability. `cgroup_seclabel` only makes cgroup2 relabelable through setxattr (`selinux_is_genfs_special_handling`,
    `SBLABEL_MNT`); with it enabled an xattr would override the genfs label, which is why the relabel denials (A44, and
    no `relabelfrom` grant anywhere) carry weight (review K4).
  - The kernel checks `dir create` against the type `selinux_determine_inode_label` returns, not against the genfs type
    the new node receives. With `cgroup_seclabel` the cgroup2 mount is `SBLABEL_MNT`, so a creator's fscreate context,
    when set, is that type; otherwise it is the type computed from the parent (the slice type, or the delegate type under
    the broker's delegated cgroup). S11 checks containment's `dir create` on `planeon_cgroup_slice_t` (review K4).
    `process setfscreate` is outside the matrix, so W03 and T04 require that no creator of a planeon cgroup (systemd,
    containment, the broker) sets an fscreate context when it creates one (round-1 F4).
  - Why the matrix lists `cgroup_seclabel`: the path labels do not need it. It is listed because the base policies W03
    can select declare it, and listing it makes the relabel and fscreate consequences above explicit rather than
    depending on its absence (round-1 F4).
  - genfscon matches by prefix and the longest match wins. So no other cgroup path may begin with a planeon path; systemd's
    fixed, sealed unit names keep it that way, and W03 and T04 check it.
  - Nothing relabels a cgroup (A44). `check_matrix` refuses a named type transition under a genfs-labelled parent (M49).
  - The delegated `planeon-capacity-broker.service` directory has its own type, `planeon_cgroup_delegate_t`. The broker
    writes its `cgroup.procs`, which clone3 `CLONE_INTO_CGROUP` checks at the common ancestor.
  - The broker's WRITE grant on its delegated cgroups is an upper bound. It includes `dir create` and `rmdir`, while W01
    §5.4 needs only `cgroup.procs`, `cgroup.freeze` and `cgroup.kill`. A broker that replaced its `probe-worker` leaf after
    the seal would lose the leaf's programs, and the readers' census refuses that (review N8).
- **Objects on tmpfs and other xattr filesystems.** Four named type transitions label runtime objects at creation (review N6):
  - systemd's `/run/planeon` (`planeon_run_t`);
  - containment's seal marker `sealed` (`planeon_seal_t`);
  - the gate's `effect-admission.sock` and `policy-write.sock` (`planeon_i05_sock_t`, `planeon_i07_sock_t`).

  W03 adds the rules for the observer, broker, datastore and runtime socket files, with the names their configurations fix,
  producing the types above. Persistent objects take their types from file contexts when the maintenance boot installs
  them.
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
  - Executable identity follows from the peer's label: the matrix lets each planeon domain be entered only through its
    sealed entrypoint type, and the per-source closure denies `execute_no_trans` on every type, declared or not, so no
    planeon process runs another program without a transition (review N5). The W02d seccomp filters (no `execve` in the
    daemon roles) are a second, independent layer.
- **systemd.** `init_t` holds every capability except `sys_module` and `sys_rawio` (modules are disabled after S5), plus
  `wake_alarm`, `block_suspend` and `audit_read`. That includes `dac_read_search`, `sys_admin` and `setpcap`, which systemd
  needs to set the roles' bounding sets. systemd is the trusted service manager, and the deny assertions name it where
  they allow it (review R2). It loads no BPF programs: the kubelet and runtime use the cgroupfs driver and no planeon or
  backend unit uses a BPF-backed directive (`DeviceAllow`, `IPAddress*`, `RestrictNetworkInterfaces`, `SocketBind*`, ...).
  That is a W03 requirement and a T04 check (review R7).
- **Unit sources.** Every systemd unit search path and drop-in directory (`/etc/systemd/system`, `<unit>.d`, `/run/systemd/*`,
  generator and transient directories) must carry a sealed unit type; that is a W03 requirement and a T04 check (review R17).
- **Further W03 and T04 requirements implied by the closures (review N7):**
  - no planeon or backend unit sets `NoNewPrivileges=` or an option that implies it, because systemd's transitions into
    them carry no `nnp_transition`;
  - no entrypoint and no container root filesystem sits on a `nosuid` mount, because `nosuid_transition` is closed;
  - the container runtime sets no per-Pod process label (no `setexeccon`, no per-Pod MCS), because `setexec` is closed for
    it; qualification Pods run in the one confined `qualk8s_container_t`;
  - no unit uses a BPF-backed directive, because systemd has no `prog_load` and those directives would otherwise fail
    open.

## Assertions

109 deny properties, each evaluated for every listed boot state, target and source. Sources are every domain plus
`OTHER_DOMAIN`, the declared domains, or a listed set; for capabilities only declared domains count, because undeclared
host domains' capabilities are outside the matrix.

| IDs | Property | Source |
|---|---|---|
| A01-A08 | Apiserver port (P2), I04 port, datastore socket (P1), runtime socket (P9), I05 and I07: exactly the enumerated connectors and binders | W01 §2.1, §5.3; W02b; W02c |
| A09-A11.9 | Each credential readable by its owners only | W01 §5.3, §2.1 P4 |
| A12-A13 | No sealed type written or relabelled in an enrolled boot, fs-verity included; only the maintenance domain in the maintenance boot | W01 §5.5; R8 |
| A14-A19 | `prog_load`: containment before the seal and the runtime (E1). No BPF maps. `prog_run` on containment programs: containment as loader before the seal and the reader roles. `prog_run` on the runtime's programs: the runtime alone | W01 §5.1; E1; R1 |
| A20-A23 | `setbool` only by containment and systemd in the initial state; nothing after the seal; maintenance only in the maintenance boot; never `setenforce` | W01 §5.2 S4, §5.5; N4 |
| A24-A31 | Who enters containment, maintenance, the daemon roles, the worker and the writer, and in which states | W01 §5.2, §5.4, §5.5, §2.4 |
| A32-A37 | No `dyntransition` into a declared domain, no `setexec` (on the caller), no `ptrace`, no `execmem`/`execstack`/`execheap`, no `execmod`, no `execute_no_trans` on entrypoints, the interpreter or container content | W01 §5.3; R3, R11, R14 |
| A38-A44 | Cgroups (F2): search, open and read only by init, containment and the readers; writes by init, containment before the seal and the broker on its delegated cgroups; no relabel of cgroups or pins | W01 §5.1, §5.4; F2; R6, R13 |
| A45-A48 | Capabilities of declared domains: no `dac_read_search` except systemd, none in a user namespace; `sys_admin` only systemd, kubelet and runtime; `net_bind_service` only systemd, server, gate, admin login and runtime | F2; W01 §5.3; W02a N1; R2 |
| A49-A55 | Pins, seal marker, gate journal and datastore data | W01 §5.1, §5.2 S5; W02a; W02b; counterexample 25; R10 |
| A56-A59 | Units only by systemd; signals to the roles, the writer and containment only from systemd, to the worker also from the broker; no domain outside the union of the `/proc` peers reads any planeon domain's `/proc` | W01 §5.3, §4.3, §5.4; R4, R15, N8 |
| A59.* (v4) | Eight per-target assertions: each planeon resident, lifecycle and maintenance domain's `/proc` only for its own `procAccess` peers (not the admin login's) | W01 §4.3, §5.3; K2 |
| A60.* | 28 per-source closures: each closed source gets nothing beyond its listed ports, sockets and (no) `execute_no_trans`, including an undeclared port, socket and program type | W01 §5.3; R5, N5 |
| A61-A65 | The server alone binds its listener; the three planeon boolean files only by their writers in the initial state, by nobody afterwards | W01 §5.3, §5.2, §5.5; N2, N4 |
| A66 (v4) | Before the seal no domain loads policy | W01 §5.2 S1, S4; K3 |

The 55 mutation checks show the assertions are not vacuous.
- 42 add a forbidden grant (M51-M55 new in v4) and name exactly the assertions it breaks. For example, the server connecting to the apiserver
  port breaks A01 and its per-source closure A60.1.name_connect; containment writing an artifact before the seal (fs-verity)
  breaks A12; the maintenance domain clearing maintenance mode breaks A65.
- Two remove a per-source closure and change the result.
- Eleven are refused by `check_matrix`:
  - an unconfined backend type;
  - an undeclared domain;
  - a world-readable credential;
  - a transition through a non-entrypoint type;
  - a dead transition, from a removed `nnp_transition`;
  - another dead transition;
  - a matrix rule entering the admin login;
  - a type transition without write on its parent;
  - a type transition under a cgroup parent;
  - a cgroup type without its genfscon rule;
  - a relabel grant on a genfs-labelled type.

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
     the ptrace read check on the holder: the admin domain has no `/proc` access to any planeon domain (A59; F08), and among
     roles the kernel's capability and uid rules apply.
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
which the runtime needs for mounts and namespaces, `bpf_ns_capable` satisfies the other BPF capability checks too, so the
runtime can load program families far beyond cgroup-device, including ones that attach to no cgroup. It can also attach a
cgroup program at an ancestor of the planeon cgroups, such as the root, through an O_PATH descriptor. An ancestor's
program is effective on a descendant cgroup when it was attached with BPF_F_ALLOW_MULTI, or, attached without it, for any
attach type on which the descendant has no program of its own (`compute_effective_progs`).

**Accepted.** The runtime is therefore a trusted backend component for its BPF use. The controls are:
- W03 selects a runtime that loads only cgroup-device programs, only on container cgroups, under the cgroupfs driver (so
  systemd loads none);
- T04 checks that natively;
- a census of the effective program set of every planeon cgroup, for every cgroup attach type, must show only the
  containment programs. That census extends the W02a readers, which today query the seven containment hooks, and is
  carried to W02a-F.

The census sees only cgroup attachments, and only at the moments it runs. The runtime's other BPF use, and attachments made
and removed between two census points, rest on W03 selection and T04 alone (review N3).

E1 amends W01 §5.3 and is carried to W01's record, W03 and T04.

## Decisions made in this contract (not in the reviewed spec)

1. The gate labels its I05 and I07 listening sockets with `setsockcreate` (the only domain with that permission). A
   requirement on the gate implementation (W03).
2. Containment creates the role cgroups and the broker's leaves before the seal (W01 S3 "creates"); cgroup2 genfscon path
   rules label them. It creates pins under the genfscon-labelled `/sys/fs/bpf/planeon`, and the seal marker under a named
   type transition. It relabels nothing.
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
10. The maintenance boot enters maintenance mode through one systemd unit enabled only in that boot's target. That unit is
    the only writer of `planeon_maintenance_mode`, and only in the initial state (N4).

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

## Round-2 findings and dispositions

| Finding | Disposition in round 3 |
|---|---|
| N1 MAJOR, named type transitions under cgroup2 never fire | Eight cgroup2 genfscon path rules; cgroup type transitions removed; `check_matrix` refuses a type transition under a genfs-labelled parent (M49) and a cgroup type without its genfscon rule (M50); prefix rule disclosed |
| N2 MAJOR, the server's listener contradicted its name_bind closure | `planeon_server_port_t`, bound by the server alone (A61); closed sources need explicit grants even where a port is open to every domain (P09, M46, M47) |
| N3 MINOR, E1 statement incomplete | The effective-set rule stated exactly; the census covers cgroup attachments only, at the moments it runs; other BPF use rests on W03 and T04 |
| N4 MINOR, the maintenance domain could flip planeon booleans | Per-boolean selinuxfs types; writers only in the initial state; nobody afterwards (A62-A65, S16-S18, M44) |
| N5 MINOR, executable identity needs a per-source execute closure | `file execute_no_trans` closed for the planeon sources on every type (A60.15-A60.21, P07, P08, M48); seccomp named as a second layer |
| N6 MINOR, no labelling rule for the marker, socket files and /run | Four named type transitions; the remaining socket-file rules and persistent labels assigned to W03 and file contexts |
| N7 NOTE, implied W03 requirements | Listed: no NoNewPrivileges on units, no nosuid entrypoint mounts, no per-Pod labels, no BPF-backed unit directives |
| N8 NOTE, A59 narrow, M42 message, broker delegate grants | A59 covers every planeon domain (M45); the host-policy refusal has its own message; the broker's delegate WRITE disclosed as an upper bound |

## Round-3 findings and dispositions in v4

| Finding | Disposition |
|---|---|
| K1 MINOR, boolean carry-over on a policy load; early window | Not in W02e-F: carried to W02a-F and T04 (stated under "Booleans and states") |
| K2 MINOR, A59 checked a union | A59.<target> per target (M51-M53) |
| K3 NOTE, load_policy before the seal | A66 (M54, M55) |
| K4 NOTE, cgroup2 statements and S11 | Corrected; S11 on the slice type |
| K5 NOTE, implied W03 requirements | Not in W02e-F: carried to W03 and T04 |
| K6 NOTE, stale count | The v4 brief states 109 |

The round-1 and round-2 dispositions above are carried from v3 unchanged.

## Round-1 findings and dispositions (W02e-F review)

| Finding | Disposition in round 2 |
|---|---|
| F1 MINOR, the evaluator comment still said cgroup2 has no xattr labelling | Comment above `GENFS_CATEGORIES` corrected |
| F2 MINOR, the K1 and K5 carries were attributed to the v3 README | Stated from the v3 `status.json`, including K1's carry to W01's record and K5's three requirements |
| F3 NOTE, the K3 row claimed more than the assertions show | Narrowed; the dependency on decision 10 and W01's record stated |
| F4 NOTE, the fscreate branch and the reason for `cgroup_seclabel` | Both stated; a W03 and T04 requirement on fscreate added |
| F5 NOTE, the admin login is not a per-target `/proc` target | The per-target scope is stated: planeon resident, lifecycle and maintenance domains |

## Not claimed

No policy module, compiled policy or loaded host. No observation that the kernel or the selected distribution behaves as
modelled. No seccomp filter (W02d), no admission allowlist (W02f), no selected distribution (W03). All E01-E12 stay
OPEN_UNPROVEN. The W01, W02a, W02g, W02b and W02c bytes and the adopted v3 matrix are unchanged.

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
| §5.2 S2-S5 containment once, booleans, `secure_mode_policyload` | States, A20, A21, A24, A25, A52, A66; decisions 2-4 |
| §5.3 per-role domains and key denials | Domains, capabilities, A01-A11, A32-A37, A45-A48, A56-A60, A59.* |
| §5.4 worker exec after `no_new_privs`, kill through the pidfd | A29, A58; `nnp_transition` |
| §5.5 sealed types, `planeon_maint_t`, `planeon_maintenance_mode` | A12, A13, A22, A26, A27, A30 |

## Still open

All E01-E12 and T01-T08. The binary policy, its conditionals and its behaviour on the enrolled kernel (T04). The backend
policy module, the selected runtime's BPF behaviour and the selected distribution (W03). The effective-program census
(W02a-F). The seccomp filters (W02d). The W02a schema constants for these labels (W02a-F). W03-W07 remain gated. Alpha2
remains open; model-effort transition NOT_DUE.
