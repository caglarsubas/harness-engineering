# Alpha 2A — seccomp allowlists v3 (W02d-V3, MET-ENFORCE-020)

> Current-status page for W02d-V3. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet status; the
> contract is [`architecture/seccomp-allowlists-v3/`](../../architecture/seccomp-allowlists-v3/README.md).

W01-AMEND (MET-ENFORCE-018) made the native roles Rust with musl, fully static (owner decision W01-AMEND-QW4) and added
`poll` to their NATIVE_STATIC base. Owner decision W02d-V3 (2026-10-10, via the lane monitor) adds the three calls their
steady state needs, each as narrowly as the kernel allows:

- **`mremap`** only with flags `MREMAP_MAYMOVE`: musl's mallocng `realloc` moves large chunks with it. `MREMAP_FIXED`,
  `MREMAP_DONTUNMAP` and flags 0 stay refused in OBSERVER, EFFECT_GATE, POLICY_WRITER and HOST_CONTAINMENT; high bits
  are refused by the kernel (`mm/mremap.c:1012-1013`). BROKER keeps every `mremap` flag, as in v2, because its filter
  stays on the CPython worker and must cover the worker's unconditional `mremap`.
- **`prctl`** only with `PR_SET_NAME`: Rust std names threads through musl, which issues `prctl(PR_SET_NAME)` for the
  calling thread. Every other option stays refused (the broker keeps `PR_SET_NO_NEW_PRIVS` for W4).
- **`tkill`**: musl's `abort()` and `raise()` signal the calling thread with it.

SERVER and WORKER are unchanged; the digests change for the five native roles. 2,953 decision checks, 355 worker stack
checks and 18 policy mutations replay. W03 carries the remaining Rust/musl items: the broker's W4 child uses raw
`setresuid`/`setresgid`, `available_parallelism`'s file reads, units starting roles with fds 0-2 open, no main-thread
`pthread_getattr_np`, and pinning musl 1.2.5 and Rust 1.90.0 or re-checking. Review: two independent rounds, both
PASS_FOR_SOURCE_PUBLICATION (round 1 with two MINOR README findings, fixed).

The new layer `scripts/validate_seccomp_v3.py` checks the review binding first, then executes the v3 model from this
era's reviewed bytes and replays every vector. DATA_CHECK_ONLY: no filter is installed, no role code exists, and every
E01-E12 obligation stays OPEN_UNPROVEN.
