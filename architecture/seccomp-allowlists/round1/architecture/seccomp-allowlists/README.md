# Per-role, per-architecture seccomp allowlists — W02d (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: no filter is installed, no role code
exists, and all E01-E12 stay OPEN_UNPROVEN.

The reviewed W01 design (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md` section 5.3) gives each
role's seccomp policy as a shape: mode 2, default action KILL_PROCESS, and a row of named calls. Section 5.1 limits every
enrolled role's `bpf` to commands {7, 15, 16}, and section 5.4 gives the worker's pre-exec steps. W01 leaves "the exact
per-architecture allowlists (x86_64 and aarch64 numbers, argument filters)" to W02, and says a syscall a role needs that
is not derivable from its row blocks implementation. This directory is that W02 data, for the seven roles on x86_64 and
aarch64 at the pinned kernel v6.12 (commit `adc218676eef25575469234709c2d87185ca223a`).

## Owner decisions (2026-10-09, via the lane monitor)

| ID | Decision |
|---|---|
| W02d-Q1 | No worker allowlist exists in the repository, although the W01 WORKER row says "Existing worker allowlist plus FD3 seqpacket I/O". W02d defines it from the worker's duties, and the row text is amended to "the W02d worker allowlist" (carried to W01's record). |
| W02d-Q2 | The role language is unselected except SERVER and WORKER (CPython 3.12.14). Each role gets its row's duty calls exactly plus one closed, reviewed runtime base: `CPYTHON_3_12` for SERVER and WORKER, `NATIVE_STATIC` for the five native roles. W03's language and libc must fit inside it; a further need reopens W02d. |
| W02d-Q3 | `seccompFilterDigest` (the record's slot) is the SHA-256 of the classic-BPF `sock_filter` array, little-endian, that the reference compiler emits per role and architecture. The boot-time proof that the installed filter equals it is an open T04/W02a-F obligation. |

## Files

| File | Content |
|---|---|
| `syscalls.json` | `planeon.internal.seccomp-syscall-table/v1`: the closed table of the 123 syscalls the policy names, grants or denies, each with its x86_64 and aarch64 number and the exact table line it was parsed from (`arch/x86/entry/syscalls/syscall_64.tbl`, ABIs common and 64; `scripts/syscall.tbl`, the arm64 ABIs), the two tables' SHA-256, the audit-arch values, the x32 bit, the argument constants with their header citations, and the names W01 denies everywhere |
| `allowlists.json` | `planeon.internal.seccomp-allowlists/v1`: the two runtime bases and, per role, its base and duties; each duty cites its W01 row (or owner decision) and lists its rules |
| `vectors.json` | the expected filter digest and program length per role and architecture, 1,972 decision checks and 10 policy mutations |
| `../../scripts/seccomp_allowlists.py` | reference model: `effective_rules`, `decide`, `compile_filter`, `run_filter`, `program_bytes`, `filter_digest`, `check_policy` |

## Rules

A rule names a syscall and, optionally, alternatives of argument conditions: `(arg & mask) == eq` on the argument's low
32 bits, AND inside an alternative, OR across alternatives. Every filtered argument is an `int` or `unsigned int` in the
kernel's signature (or, for `clone`, flags the kernel reads in their low 32 bits), so the high word carries nothing the
kernel uses. A role's effective rule for a syscall merges its base and duties; an unconditional grant absorbs conditional
ones; a name absent on an architecture (`poll`, `epoll_wait` and `open` on aarch64) is dropped there.

`decide` is the reference meaning: KILL_PROCESS for a wrong `arch` (x86_64 filters also refuse i386 and every other
audit arch), for an x32 call on x86_64 (`nr >= 0x40000000`), for an unlisted syscall, and for a listed one whose
alternatives all fail; ALLOW otherwise. `compile_filter` emits a deterministic program: load and check `arch`, refuse
x32, load `nr`, then one `jeq` per allowed syscall in ascending number order, each followed by its own body (a return,
or the alternatives, each ending in ALLOW, then KILL_PROCESS), then KILL_PROCESS. Programs are 99 to 213 instructions
(the limit is 4,096); every jump is forward and within one body. `run_filter` interprets the instruction subset; every
decision vector runs through both and they agree.

## Runtime bases

| Base | Roles | Calls |
|---|---|---|
| `CPYTHON_3_12` | SERVER, WORKER | memory (`mmap`, `munmap`, `mprotect`, `madvise`, `mremap`, `brk`), signals (`rt_sig*`, `sigaltstack`, `tgkill`), threads (`clone` only as a thread, `set_robust_list`, `rseq`, `set_tid_address`, `futex`), clocks and randomness, ids, `uname`, `prlimit64`, `sched_yield`, `sched_getaffinity`, readiness waiting (`epoll_*`, `poll`/`ppoll`, `pselect6`), descriptor control (`fcntl`, `dup`, `dup3`, `ioctl` only TCGETS, FIONBIO, FIONCLEX, FIOCLEX), read-only file access (`openat` without write, create, truncate, append or tmpfile flags; `fstat`, `newfstatat`, `statx`, `getdents64`, `readlinkat`, `getcwd`, `lseek`, `read`, `pread64`, `readv`), `write`/`writev`, `close`, `exit`, `exit_group`, `restart_syscall` |
| `NATIVE_STATIC` | OBSERVER, BROKER, EFFECT_GATE, POLICY_WRITER, HOST_CONTAINMENT | memory, signals, threads (as above), clocks, randomness, `prlimit64`, readiness waiting, `read`, `write`, `close`, `fcntl`, `exit`, `exit_group`, `restart_syscall`; no file access |

Every base's `clone` requires CLONE_THREAD, CLONE_VM and CLONE_SIGHAND and no namespace flag (CLONE_NEWNS, NEWCGROUP,
NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET): W01's "clone only with CLONE_THREAD", made exact.

## Derivation from the rows

| Role | Base | Duties (row → calls) |
|---|---|---|
| SERVER | CPYTHON_3_12 | I/O on held FDs → read, write, readv, writev, recvfrom, sendto, recvmsg, sendmsg, shutdown, close, get/setsockopt, getsockname, getpeername, fcntl; `socket` only (AF_INET or AF_INET6, SOCK_STREAM) or (AF_UNIX, SOCK_SEQPACKET), with SOCK_CLOEXEC/SOCK_NONBLOCK allowed; connect; the signed listener → bind, listen, accept4; TLS memory and clocks; `bpf` only cmd 7, 15 or 16; `membarrier` (the readers' inspection, `docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md:121-126`); `memfd_create` only with flags MFD_CLOEXEC \| MFD_ALLOW_SEALING; pidfd_open; exit |
| OBSERVER | NATIVE_STATIC | as SERVER without the listener; the I06 read connection (connect) |
| BROKER | NATIVE_STATIC | as SERVER (with its listener) plus `clone3` (unconditional: its flags are in a struct seccomp cannot read), setresuid, setresgid, close_range, `execveat` only with flags AT_EMPTY_PATH; the W4 pre-exec steps in the filter the child inherits: capset, `prctl` only PR_SET_NO_NEW_PRIVS, `seccomp` only SECCOMP_SET_MODE_FILTER with flags 0 or TSYNC; W1/W3/W6: `openat` without create, truncate or tmpfile flags (cgroup.freeze, cgroup.kill, cgroup.events, /proc/<pid>), `waitid` only P_PIDFD, `pidfd_send_signal` only SIGKILL |
| EFFECT_GATE | NATIVE_STATIC | network I/O; the I05/I07 AF_UNIX listeners, the I04 TLS listener and the upstream connection → socket (as SERVER), bind, listen, accept4, connect; the durable journal and failure marker → fsync, fdatasync, flock, openat, pread64, pwrite64, fstat, lseek; peer qualification → pidfd_open, getsockopt (SO_PEERCRED); TLS randomness and clocks; no bpf |
| WORKER | CPYTHON_3_12 | FD3 seqpacket I/O → sendmsg, recvmsg, sendto, recvfrom only on fd 3; reads on the read-only root → read-only openat, newfstatat, statx, getdents64, readlinkat, lseek, fstat; exit; no socket creation, no exec, no clone3, no bpf. Capability rule (owner decision D5): bounding set inherited from the broker, other sets empty |
| POLICY_WRITER | NATIVE_STATIC | AF_UNIX connect to I07 → socket only (AF_UNIX, SOCK_SEQPACKET), connect; I/O → read, write, sendmsg, recvmsg, sendto, recvfrom, shutdown, close; exit |
| HOST_CONTAINMENT | NATIVE_STATIC | S3 → mkdirat, openat, newfstatat, statx, getdents64, write, fsync; `bpf` only cmd 5 (load), 6 (pin), 8 (attach, with BPF_F_ALLOW_MULTI in the attribute) and 7, 15, 16 (verify); `ioctl` only FS_IOC_ENABLE_VERITY (0x40806685); S4 booleans → openat, write; S5 → openat, read, write, fsync, exit |

Denied everywhere (W01 section 5.3; `check_policy` refuses a policy that grants any of them to any role): execve, the
mount family (mount, umount2, move_mount, open_tree, fsopen, fsconfig, fsmount, fspick, mount_setattr, pivot_root), setns,
unshare, ptrace, process_vm_readv, process_vm_writev, init_module, finit_module, delete_module, kexec_load,
kexec_file_load. `check_policy` also refuses: `execveat` other than the broker's AT_EMPTY_PATH grant, `clone3` outside the
broker, `clone` without the thread flags or with a namespace flag, `bpf` outside {7, 15, 16} (outside {5, 6, 7, 8, 15, 16}
for containment) or at all for EFFECT_GATE, WORKER and POLICY_WRITER, socket creation by the worker, and `memfd_create`
with other flags. HOST_CONTAINMENT and POLICY_WRITER have allowlists and digests but no slot in the record.

## Filter digests

`vectors.json` `filterDigests` holds the 14 expected digests. A role must install exactly the compiled program (for
example not systemd's `SystemCallFilter=`, which compiles a different program and would not match the digest). The
worker runs under two filters after W4: the broker's, inherited, and its own; the kernel applies the most restrictive
result, so the worker's effective set is the intersection, `/proc/<pid>/status` shows `Seccomp_filters: 2`, and the
record's digest for the worker is the worker program's.

## Findings for W01 and W03 (not changed here)

- W01 W6 says the broker "kills through the pidfd and `cgroup.kill`", and the BROKER row gives the broker no CAP_KILL.
  `pidfd_send_signal` to a child whose uid is the signed worker uid needs CAP_KILL (the kill permission check), so that
  path fails and `cgroup.kill` is the effective one. The grant stays (it is in the row); W01's record should state it.
- W4 changes the uid and gid with setresuid/setresgid; it does not name `setgroups`. The broker must run with no
  supplementary groups (a W03 unit requirement), or the row needs setgroups.
- Every runtime base is a closed W03 requirement: a role whose language, libc or TLS library needs a call outside its base
  and row reopens W02d before implementation (owner decision W02d-Q2).
- How a boot proves the installed filter matches its digest (an observer cannot read a filter back without
  CAP_SYS_ADMIN, and `/proc` shows only the mode and the filter count) is open for T04/W02a-F (owner decision W02d-Q3).

## Not claimed

No filter is installed, no role code exists, nothing is observed on a host. The kernel tables are the pinned v6.12
sources; a stable patch release or a distribution kernel must be re-checked against them (W03, T04).
