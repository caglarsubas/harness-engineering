# Alpha 2A — per-role seccomp allowlists (W02d, MET-ENFORCE-017)

> Current-status page for W02d. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet status; the
> contract is [`architecture/seccomp-allowlists/`](../../architecture/seccomp-allowlists/README.md).

The reviewed W01 design gives each enrolled role's seccomp policy as a shape: mode 2, default action KILL_PROCESS, and
a row of named calls. It leaves the exact per-architecture allowlists to W02. W02d publishes them as data, for the
seven roles on x86_64 and aarch64 at the pinned kernel v6.12 (`adc218676eef25575469234709c2d87185ca223a`).

- **Syscall table.** `syscalls.json` holds the 129 syscalls the policy names, grants or denies, each with both numbers
  and the exact v6.12 table line it was parsed from, plus the audit-arch values, the x32 bit and the argument constants
  with their header citations.
- **Allowlists.** `allowlists.json` gives each role its W01 row's duty calls exactly plus one closed runtime base
  (`CPYTHON_3_12` for SERVER and WORKER, `NATIVE_STATIC` for the five native roles). Every duty cites its W01 row, step
  or owner decision.
- **Reference model.** `scripts/seccomp_allowlists.py` decides a call, compiles each role's classic-BPF program (audit
  arch first, the x32 bit refused on x86_64, one ascending jump per syscall, KILL_PROCESS last), interprets it, and
  checks the policy: W01's denied-everywhere names, `bpf` commands {7, 15, 16}, `execveat` only in W5's
  AT_EMPTY_PATH form, `clone` thread-only, `clone3` failing with ENOSYS outside the broker, and the broker covering the
  worker it is stacked under.
- **Vectors.** `vectors.json` pins the 14 filter digests (`seccompFilterDigest`: the SHA-256 of the little-endian
  `sock_filter` array) and program lengths, 2,789 decision checks, 351 worker stack checks and 13 policy mutations.
  Each decision must agree between the reference decision and the compiled program.
- **Owner decisions.** W02d-Q1 to Q3 and QA to QD, recorded in the README and `allowlists.json`.
- **Review.** Three independent rounds: CHANGES_REQUIRED, CHANGES_REQUIRED, then PASS_FOR_SOURCE_PUBLICATION.
  `status.json` records them, carries F9, F10, F18 and F19, the W01 amendments and the W03 requirements, and keeps the
  boot-time digest proof open for T04/W02a-F.

The new layer `scripts/validate_seccomp_allowlists.py` executes the reference model from its own era's reviewed bytes,
replays every vector, binds each review round to its exact subject bytes, and keeps the W01 design and the native
profile record byte-identical. DATA_CHECK_ONLY: no filter is installed, no role code exists, no build has been traced,
and every E01-E12 obligation stays OPEN_UNPROVEN.
