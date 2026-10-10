# Per-role, per-architecture seccomp allowlists — W02d (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. Round 1 (`review-round1.json`, reviewed bytes of the
files changed since in `round1/`) returned CHANGES_REQUIRED with 2 BLOCKING, 3 MAJOR, 3 MINOR and 4 NOTE findings; each is
answered under "Round-1 findings and dispositions". DATA_CHECK_ONLY: no filter is installed, no role code exists, and all
E01-E12 stay OPEN_UNPROVEN.

The reviewed W01 design (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md` section 5.3) gives each
role's seccomp policy as a shape: mode 2, default action KILL_PROCESS, and a row of named calls. Section 5.1 limits every
enrolled role's `bpf` to commands {7, 15, 16}, and section 5.4 gives the worker's pre-exec steps. W01 leaves "the exact
per-architecture allowlists (x86_64 and aarch64 numbers, argument filters)" to W02, and says a syscall a role needs that
is not derivable from its row blocks implementation. This directory is that W02 data, for the seven roles on x86_64 and
aarch64 at the pinned kernel v6.12 (commit `adc218676eef25575469234709c2d87185ca223a`).

## Owner decisions (2026-10-09, via the lane monitor)

| ID | Decision |
|---|---|
| W02d-Q1 | No worker allowlist exists in the repository, although the W01 WORKER row says "Existing worker allowlist plus FD3 seqpacket I/O". W02d defines it from the worker's duties; the row text is amended to "the W02d worker allowlist" (carried to W01's record). |
| W02d-Q2 | Each role gets its row's duty calls exactly plus one closed, reviewed runtime base: `CPYTHON_3_12` for SERVER and WORKER (CPython 3.12.14), `NATIVE_STATIC` for the five native roles, whose language and libc are unselected. W03's choice must fit inside it; a further need reopens W02d. |
| W02d-Q3 | `seccompFilterDigest` (the record's slot) is the SHA-256 of the classic-BPF `sock_filter` array, little-endian, that the reference compiler emits per role and architecture. The boot-time proof that the installed filter equals it is an open T04/W02a-F obligation. |
| W02d-QA | The worker filter, installed in W4, allows `execveat` only in W5's form (flags AT_EMPTY_PATH, as the broker's); a second exec stays refused by SELinux. Amends Q1's "no exec". |
| W02d-QB | `clone3` fails with ENOSYS (not KILL_PROCESS) in the six non-broker roles, so glibc 2.34 and later fall back to the thread-only `clone` rule. Every other unlisted call stays KILL_PROCESS; the broker keeps `clone3` for W2. |
| W02d-QC | SERVER, OBSERVER and BROKER get an "inspection reads" duty from `docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md:112-135` and the native-profile capture rules (`architecture/native-profile-v3/README.md:60-71`), with `membarrier` only QUERY (0), PRIVATE_EXPEDITED (8) and REGISTER_PRIVATE_EXPEDITED (16), flags 0 and cpu 0. Carried to W01 as a row amendment. |
| W02d-QD | The broker's filter is inherited by the worker and stays after exec, and the kernel applies the most restrictive of stacked filters, so the broker's allowlist covers the worker's. The model checks it. |

## Files

| File | Content |
|---|---|
| `syscalls.json` | `planeon.internal.seccomp-syscall-table/v1`: the closed table of the 128 syscalls the policy names, grants or denies, each with its x86_64 and aarch64 number and the exact table line it was parsed from (`arch/x86/entry/syscalls/syscall_64.tbl`, ABIs common and 64; `scripts/syscall.tbl`, the arm64 ABIs), the two tables' SHA-256, the audit-arch values, the x32 bit, the argument constants with their header citations, and the names W01 denies everywhere |
| `allowlists.json` | `planeon.internal.seccomp-allowlists/v1`: the owner decisions, the two runtime bases and, per role, its base and duties; each duty cites its W01 row, step or owner decision and lists its rules |
| `vectors.json` | the 14 expected filter digests and program lengths, 2,766 decision checks, 350 worker stack checks and 13 policy mutations |
| `../../scripts/seccomp_allowlists.py` | reference model: `effective_rules`, `decide`, `decide_stack`, `compile_filter`, `run_filter`, `program_bytes`, `filter_digest`, `check_policy`, `require_covers` |

## Rules

A rule names a syscall and either grants it unconditionally, grants it under alternatives of argument conditions
(`(arg & mask) == eq` on the argument's low 32 bits, AND inside an alternative, OR across alternatives), or makes it fail
with an errno (only `clone3`, W02d-QB). Every filtered argument is an `int` or `unsigned int` in the kernel's signature
(or, for `clone`, flags the kernel reads in their low 32 bits), so the high word carries nothing the kernel uses. A role's
effective rule for a syscall merges its base and duties; an unconditional grant absorbs conditional ones; an errno rule
never combines with a grant; a name absent on an architecture (`poll`, `epoll_wait`, `open`, `access` and `arch_prctl` on
aarch64) is dropped there.

`decide` is the reference meaning: KILL_PROCESS for a wrong `arch` (x86_64 filters also refuse i386 and every other audit
arch), an x32 call on x86_64 (`nr >= 0x40000000`), an unlisted syscall, or a listed one whose alternatives all fail;
ERRNO(n) for an errno rule; ALLOW otherwise. `decide_stack` applies several filters as the kernel does: the action with
the lowest signed 32-bit value wins (KILL_PROCESS, then ERRNO, then ALLOW). `compile_filter` emits a deterministic program:
load and check `arch`, refuse x32, load `nr`, then one `jeq` per listed syscall in ascending number order, each followed by
its own body (a return, or the alternatives, each ending in ALLOW, then KILL_PROCESS), then KILL_PROCESS. Programs are 103
to 324 instructions (the limit is 4,096); every jump is forward and within one body. `run_filter` interprets the
instruction subset; every decision check runs through both and they agree.

## Runtime bases

| Base | Roles | Calls |
|---|---|---|
| `CPYTHON_3_12` | SERVER, WORKER | memory (`mmap`, `munmap`, `mprotect`, `madvise`, `mremap`, `brk`), signals (`rt_sig*`, `sigaltstack`, `tgkill`), threads (`clone` only as a thread, `set_robust_list`, `rseq`, `set_tid_address`, `futex`), clocks and randomness, ids, `uname`, `prlimit64`, `sched_yield`, `sched_getaffinity`, readiness waiting (`epoll_*`, `poll`/`ppoll`, `pselect6`), descriptor control (`fcntl`, `dup`, `dup3`, `ioctl` only TCGETS, FIONBIO, FIONCLEX, FIOCLEX), read-only file access (`openat` without write, create, truncate, append or tmpfile flags; `fstat`, `newfstatat`, `statx`, `getdents64`, `readlinkat`, `getcwd`, `lseek`, `read`, `pread64`, `readv`), the dynamic loader's `access`, `faccessat`, `faccessat2` and (x86_64) `arch_prctl` only ARCH_SET_FS, `write`/`writev`, `close`, `exit`, `exit_group`, `restart_syscall` |
| `NATIVE_STATIC` | OBSERVER, BROKER, EFFECT_GATE, POLICY_WRITER, HOST_CONTAINMENT | memory, signals, threads (as above), clocks, randomness, `prlimit64`, readiness waiting, `read`, `write`, `close`, `fcntl`, (x86_64) `arch_prctl` only ARCH_SET_FS, `exit`, `exit_group`, `restart_syscall`; no file access |

Every base's `clone` requires CLONE_THREAD, CLONE_VM and CLONE_SIGHAND and no namespace flag (CLONE_NEWNS, NEWCGROUP,
NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET): W01's "clone only with CLONE_THREAD", made exact. Every role except the broker
fails `clone3` with ENOSYS (W02d-QB).

## Derivation from the rows

`socket` is allowed, where a row allows it, only as (AF_INET or AF_INET6, SOCK_STREAM, protocol 0 or IPPROTO_TCP) or
(AF_UNIX, SOCK_SEQPACKET, protocol 0), with SOCK_CLOEXEC and SOCK_NONBLOCK allowed in the type.

| Role | Base | Duties (row → calls) |
|---|---|---|
| SERVER | CPYTHON_3_12 | I/O on held FDs → read, write, readv, writev, recvfrom, sendto, recvmsg, sendmsg, shutdown, close, get/setsockopt, getsockname, getpeername, fcntl; socket; connect; the signed listener → bind, listen, accept4; TLS memory and clocks; `bpf` only cmd 7, 15 or 16; inspection reads (W02d-QC) → read-only openat, read, pread64, lseek, close, fstat, newfstatat, statx, fstatfs, getdents64, readlinkat, `membarrier` only cmd 0, 8 or 16 with flags 0 and cpu 0; `memfd_create` only with flags MFD_CLOEXEC \| MFD_ALLOW_SEALING; pidfd_open; exit |
| OBSERVER | NATIVE_STATIC | as SERVER without the listener; the I06 read connection (connect) |
| BROKER | NATIVE_STATIC | as SERVER (with its listener) plus `clone3` (unconditional: its flags are in a struct seccomp cannot read), setresuid, setresgid, close_range, `execveat` only with flags AT_EMPTY_PATH; W4 in the filter the child inherits: capset, `prctl` only PR_SET_NO_NEW_PRIVS, `seccomp` only SECCOMP_SET_MODE_FILTER with flags 0 or TSYNC; W1/W3/W6: `openat` without create, truncate or tmpfile flags (cgroup.freeze, cgroup.kill, cgroup.events, /proc/<pid>), `waitid` only P_PIDFD, `pidfd_send_signal` only SIGKILL; W3: `socketpair` only (AF_UNIX, SOCK_SEQPACKET, 0) for FD3, getdents64, readlinkat, newfstatat for /proc/<pid>/fd; W5: `ioctl` only FS_IOC_MEASURE_VERITY (0xC0046686); and every call the worker's filter allows (W02d-QD) |
| EFFECT_GATE | NATIVE_STATIC | network I/O; the I05/I07 AF_UNIX listeners, the I04 TLS listener and the upstream connection → socket, bind, listen, accept4, connect; the durable journal and failure marker → fsync, fdatasync, flock, openat, pread64, pwrite64, fstat, lseek; peer qualification → pidfd_open, getsockopt (SO_PEERCRED); TLS randomness and clocks; no bpf |
| WORKER | CPYTHON_3_12 | FD3 seqpacket I/O → sendmsg, recvmsg, sendto, recvfrom only on fd 3; reads on the read-only root → read-only openat, newfstatat, statx, getdents64, readlinkat, lseek, fstat; W5 → `execveat` only with flags AT_EMPTY_PATH (W02d-QA); exit; no socket creation, no bpf. Capability rule (owner decision D5): bounding set inherited from the broker, other sets empty |
| POLICY_WRITER | NATIVE_STATIC | AF_UNIX connect to I07 → socket only (AF_UNIX, SOCK_SEQPACKET, 0), connect; I/O → read, write, sendmsg, recvmsg, sendto, recvfrom, shutdown, close; exit |
| HOST_CONTAINMENT | NATIVE_STATIC | S3 → mkdirat, openat, newfstatat, statx, getdents64, write, fsync; `bpf` only cmd 5 (load), 6 (pin), 8 (attach, with BPF_F_ALLOW_MULTI in the attribute) and 7, 15, 16 (verify); `ioctl` only FS_IOC_ENABLE_VERITY (0x40806685); S4 booleans → openat, write; S5 → openat, read, write, fsync, exit. S3's labelling needs no xattr call: the planeon cgroups and the bpffs pins are labelled by genfscon path rules (SELinux matrix v4, `architecture/selinux-matrix-v2/README.md`, "Cgroup creation and labels"), and nothing relabels them |

Denied everywhere (W01 section 5.3; `check_policy` refuses a policy that grants any of them to any role): execve, the
mount family (mount, umount2, move_mount, open_tree, fsopen, fsconfig, fsmount, fspick, mount_setattr, pivot_root), setns,
unshare, ptrace, process_vm_readv, process_vm_writev, init_module, finit_module, delete_module, kexec_load,
kexec_file_load. `check_policy` also refuses: `execveat` other than the broker's and the worker's AT_EMPTY_PATH grants,
`clone3` other than the broker's grant and ENOSYS elsewhere, any other errno rule, `clone` without the thread flags or
with a namespace flag, `bpf` outside {7, 15, 16} (outside {5, 6, 7, 8, 15, 16} for containment) or at all for EFFECT_GATE,
WORKER and POLICY_WRITER, `membarrier` other than the three per-process commands with flags and cpu 0, socket creation by
the worker, `memfd_create` with other flags, and a broker filter that does not cover the worker's (`require_covers`).
HOST_CONTAINMENT and POLICY_WRITER have allowlists and digests but no slot in the record.

## Filter digests and stacking

`vectors.json` `filterDigests` holds the 14 expected digests. A role must install exactly the compiled program. The
worker runs under two filters after W4: the broker's, inherited, and its own. `workerStackChecks` shows that for every
worker decision check the two together decide exactly as the worker's alone (W02d-QD), and the record's digest for the
worker is the worker program's. `/proc/<pid>/status` then shows `Seccomp_filters: 2`, which holds only if no systemd
unit option installs a further filter (finding F10 below).

## Findings for W01 and W03 (not changed here)

- W01 W6 says the broker "kills through the pidfd and `cgroup.kill`", and the BROKER row gives the broker no CAP_KILL.
  `pidfd_send_signal` to a child whose uid is the signed worker uid needs CAP_KILL, so that path fails and `cgroup.kill`
  is the effective one. The grant stays (it is in the row); W01's record should state it.
- W4 changes the uid and gid with setresuid/setresgid; it does not name `setgroups`. The broker must run with no
  supplementary groups (a W03 unit requirement), or the row needs setgroups.
- `memfd_create` with MFD_CLOEXEC \| MFD_ALLOW_SEALING and without MFD_NOEXEC_SEAL gives an executable memfd unless
  `vm.memfd_noexec` forbids it (round-1 F9); W01's record should pin one or the other.
- systemd unit options that install their own seccomp filter (`SystemCallFilter=`, `SystemCallArchitectures=`,
  `RestrictNamespaces=`, `MemoryDenyWriteExecute=`, `RestrictAddressFamilies=` and similar) would add filters, change
  the filter count and break the "exact program" rule (round-1 F10); the planeon units must not use them (W03).
- Every runtime base is a closed W03 requirement: a role whose language, libc or TLS library needs a call outside its base
  and row reopens W02d before implementation (W02d-Q2).
- How a boot proves the installed filter matches its digest (an observer cannot read a filter back without
  CAP_SYS_ADMIN, and `/proc` shows only the mode and the filter count) is open for T04/W02a-F (W02d-Q3).

## Round-1 findings and dispositions

| Finding | Disposition in round 2 |
|---|---|
| F1 BLOCKING, the worker filter killed W5 and the loader's calls | W02d-QA: the worker's execveat in W5's form; the CPython base gains access, faccessat, faccessat2 and arch_prctl (ARCH_SET_FS), the native base arch_prctl (ARCH_SET_FS) |
| F2 BLOCKING, the inherited broker filter killed worker calls | W02d-QD: the broker covers the worker; `require_covers` and 350 stack checks; mutation M11 |
| F3 MAJOR, glibc 2.34+ clone3 | W02d-QB: ENOSYS in the six non-broker roles; mutations M04, M13 |
| F4 MAJOR, the broker's W3/W5 calls | socketpair, getdents64, readlinkat, newfstatat, ioctl FS_IOC_MEASURE_VERITY added with their steps |
| F5 MAJOR, membarrier not from a row | W02d-QC: the inspection-reads duty with the three per-process membarrier commands; mutation M12 |
| F6 MINOR, S3 labelling | No xattr call: genfscon path rules label the cgroups and pins (stated in the derivation) |
| F7 MINOR, vector coverage | Every condition broken at its lowest and highest mask bit, high words set, i386 refused |
| F8 MINOR, socket protocol | protocol 0 or IPPROTO_TCP for stream sockets, 0 for AF_UNIX |
| F9 NOTE, executable memfd | Carried to W01 (findings above) |
| F10 NOTE, systemd filter options | Carried to W03 (findings above) |
| F11 NOTE, fd 3 limits are defence in depth | Stated: read and write stay unconditional in the CPython base |
| F12 NOTE, deny lists complete for v6.12 | Confirmed by the reviewer; unchanged |

## Not claimed

No filter is installed, no role code exists, nothing is observed on a host. The kernel tables are the pinned v6.12
sources; a stable patch release or a distribution kernel must be re-checked against them (W03, T04).
