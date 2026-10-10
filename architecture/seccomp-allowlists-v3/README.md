# Per-role, per-architecture seccomp allowlists v3 — W02d successor (DATA_CHECK_ONLY)

Status: **SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW** (round 2). Round 1 (`review-round1.json`, changed bytes in
`round1/`) returned PASS_FOR_SOURCE_PUBLICATION with R1-1 and R1-2 MINOR (answered below) and R1-3 to R1-6 NOTE. The adopted v2 contract (`architecture/seccomp-allowlists-v2/`,
`planeon.internal.seccomp-allowlists/v2`, MET-ENFORCE-018) stays byte-identical. This successor is v2 with exactly the
three narrow NATIVE_STATIC rules of owner decision W02d-V3 (2026-10-10, via the lane monitor) for the Rust+musl steady
state of the native roles (W01-AMEND-QW4: Rust with musl, fully static; analysed reference musl 1.2.5, Rust 1.90.0):

| Rule | Why | Source |
|---|---|---|
| `mremap` only with flags (arg 3) == `MREMAP_MAYMOVE` (1) | musl's mallocng `realloc` moves large mmap-backed chunks with `mremap(..., MREMAP_MAYMOVE)` | musl 1.2.5 `src/malloc/mallocng/realloc.c:28-34`, `src/mman/mremap.c:12-29`; v6.12 `include/uapi/linux/mman.h:9` |
| `prctl` only with option (arg 0) == `PR_SET_NAME` (15) | Rust std names threads through `pthread_setname_np(pthread_self(), ...)`, which musl issues as `prctl(PR_SET_NAME)` for the calling thread | Rust 1.90.0 `library/std/src/sys/pal/unix/thread.rs:141-157`; musl 1.2.5 `src/thread/pthread_setname_np.c:17-18`; v6.12 `include/uapi/linux/prctl.h:56` |
| `tkill`, unconditional | musl's `abort()` and `raise()` signal the calling thread with `tkill` | musl 1.2.5 `src/exit/abort.c:22`, `src/signal/raise.c:10` |

`mremap` and `prctl` keep argument filters: `MREMAP_FIXED` and `MREMAP_DONTUNMAP` are refused, and so is every other
`prctl` option (the broker keeps `PR_SET_NO_NEW_PRIVS` for W4). `mremap`'s flags argument is an `unsigned long`, of
which classic BPF compares only the low 32 bits, so flags with high bits set and `MREMAP_MAYMOVE` in the low word pass
the filter; v6.12 refuses them with EINVAL, because `mremap` rejects any flag outside `MREMAP_FIXED | MREMAP_MAYMOVE |
MREMAP_DONTUNMAP` (`mm/mremap.c:1012-1013`). The v1 model's note that every filtered argument is an `int` holds for
every other filtered argument. The roles that run or cover the CPython base (SERVER,
WORKER, BROKER) keep their unconditional `mremap`. `scripts/seccomp_allowlists_v3.py` is the v2 model plus two policy
checks: `mremap` is conditional on `MREMAP_MAYMOVE` outside those roles, and `prctl` admits only `PR_SET_NAME` (and the
broker's `PR_SET_NO_NEW_PRIVS`).

## What changes in the data

- Schemas `planeon.internal.seccomp-syscall-table/v3` and `planeon.internal.seccomp-allowlists/v3`; the table adds
  `tkill` and the constants `PR_SET_NAME` and `MREMAP_MAYMOVE`.
- Filter digests change for BROKER, EFFECT_GATE, HOST_CONTAINMENT, OBSERVER, POLICY_WRITER (both architectures) and stay equal to v2's for SERVER, WORKER.
- Vectors: 2953 decision checks (v2: 2813), 355 worker stack checks (v2: 353), 18 policy mutations (v2: 15). New decision
  checks kill `mremap` with `MREMAP_FIXED`, `MREMAP_DONTUNMAP` or flags 0 and `prctl` with `PR_SET_SECCOMP`,
  `PR_SET_DUMPABLE` or `PR_CAPBSET_READ` in every native role; mutations M16-M18 widen `mremap` or `prctl` and are refused.

## Carried to W03 (not seccomp rules)

- musl's `setresuid`/`setresgid` wrappers signal the other threads when the process is threaded; the broker's W4 child
  must use the raw syscalls (single-threaded child).
- Rust std's `available_parallelism` reads cgroup and /proc files; a role that calls it needs those reads, or must not
  call it.
- Units start every native role with fds 0-2 open, so Rust std's start-up never reopens `/dev/null`.
- musl's `pthread_getattr_np` on the main thread probes the stack with `mremap(..., 0)` (flags 0), which v3 kills; Rust
  1.90 std avoids that path on musl, but no role or crate may call it on the main thread (`src/thread/pthread_getattr_np.c`).
- W03 pins musl 1.2.5 and Rust 1.90.0, or re-checks these rules against the pinned versions.

## What stays open

Exactly as v2: no filter is installed, no role code exists, no build is traced, every E01-E12 obligation stays
OPEN_UNPROVEN, and the boot-time proof that installed filters equal these digests stays a T04/W02a-F obligation.
