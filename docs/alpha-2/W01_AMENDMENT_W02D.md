# Alpha 2A — W01 amendment W02D and seccomp allowlists v2 (W01-AMEND, MET-ENFORCE-018)

> Current-status page for W01-AMEND. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet status;
> the records are [`architecture/host-interface-amendment-w02d/`](../../architecture/host-interface-amendment-w02d/README.md)
> and [`architecture/seccomp-allowlists-v2/`](../../architecture/seccomp-allowlists-v2/README.md).

W02d (MET-ENFORCE-017) carried six items into the W01 host-interface record. The resolved W01 specification stays
byte-identical, because later history layers freeze it; amendment W02D amends it as a reviewed record of exact, counted
replacements, and publishes the amended text beside it.

- **Owner decisions** (2026-10-10, via the lane monitor): W01-AMEND-QW1, the broker kills the worker through
  `cgroup.kill` only (a pidfd signal needs CAP_KILL, which the broker does not hold); QW2, the broker runs with no
  supplementary groups and W3 checks the child holds none; QW3 (M-a), `memfd_create` flags are exactly
  `MFD_CLOEXEC | MFD_NOEXEC_SEAL`, so every memfd is non-executable without relying on `vm.memfd_noexec`.
- **The amendment** answers each carried item (the WORKER row names the W02d worker allowlist; the readers' inspection
  reads; W5's execveat form and the worker's SELinux limits; the stacked filters; W3's groups check; W6's kill path),
  restates W02d-QB's ENOSYS refusal for clone3, and names four obligations: O-SERVER-MEMFD (the SERVER role's existing
  sealed-credential code must pass the new flags), O-W03-WORKER-EXEC, O-W03-GROUPS and O-T04-AMEND.
- **The W02d successor** `seccomp-allowlists-v2` changes only the memfd flags rule and drops the broker's unused
  `pidfd_send_signal` grant; its model refuses any `pidfd_send_signal` or `setgroups` grant. Digests change for SERVER,
  OBSERVER and BROKER; 2,813 decision checks, 353 worker stack checks and 15 policy mutations replay.
- **W01-AMEND-QW4.** The native roles are Rust with musl, fully static (analysed reference: musl 1.2.5, Rust 1.90.0).
  NATIVE_STATIC grants `poll`, which Rust std calls at start-up and musl issues as SYS_poll on x86_64; musl creates
  threads with `clone`, never `clone3`, so the clone3 ENOSYS reason (glibc) applies to the CPython roles.
- **Review.** Four independent rounds: CHANGES_REQUIRED, CHANGES_REQUIRED, PASS_FOR_SOURCE_PUBLICATION, then, after
  QW4 reopened the subject, PASS_FOR_SOURCE_PUBLICATION; notes R3-1 to R3-3 and R4-1 to R4-2 are carried (R4-1 to
  W03's trace of the Rust/musl roles).

The new layer `scripts/validate_w01_amendment.py` checks the review binding first, then executes both reference models
from this era's reviewed bytes: the amendment model's check and the full v2 replay. DATA_CHECK_ONLY: no filter is
installed, no role code changes, and every E01-E12 obligation stays OPEN_UNPROVEN.
