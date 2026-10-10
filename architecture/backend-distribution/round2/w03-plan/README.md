# W03 plan — toolchain decision, R10 scope and obligation register (DATA_CHECK_ONLY)

The owner decided Q1, Q2, Q3 and Q5 on 2026-10-10, via the lane monitor, choosing option (a) each time. This record
states those decisions as data, together with the packet plan and a register of every obligation the W02 contracts and
W01 carry to W03. Q4, the backend distribution, is the selection in `../backend-distribution/`. No module source exists,
no toolchain is installed, and E01-E12 stay OPEN_UNPROVEN.

## Toolchains (Q2, Q3)

| Toolchain | Roles | Pin |
|---|---|---|
| `CPYTHON_3_12` | SERVER, WORKER | CPython 3.12.14. W02d's libc rule (glibc 2.34 or later, no CET or shadow-stack `arch_prctl` at start-up) applies to these roles only |
| `RUST_MUSL_STATIC` | BROKER, EFFECT_GATE, HOST_CONTAINMENT, OBSERVER, POLICY_WRITER | Rust 1.99.0 (`b940084d`), targets `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, fully static, self-contained `rust-lld`; bundled musl 1.2.5 with its two CVE patches |

**Threads and W02d.**
- musl 1.2.5 creates threads with plain `clone`, never `clone3`. `pthread_create.c:243-245` sets the flags
  VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|PARENT_SETTID|CHILD_CLEARTID|DETACHED (`0x7d0f00`). It calls `__clone` at line
  355, which issues SYS_clone 56 on x86_64 and SYS_clone 220 on aarch64.
- W02d's NATIVE_STATIC thread rule admits exactly that: `0x7d0f00 & 0x7e030900 == 0x10900`.
- musl never tries `clone3`, so W02d-QB's `clone3` → ENOSYS rule needs no libc fallback for these roles.
- musl's `posix_spawn` uses CLONE_VM|CLONE_VFORK, which the rule refuses. Only the broker spawns, and it does so through
  its own `clone3` (W2).
- No W02d change is needed.

**Start-up re-check at Rust 1.99.0.** W02d v2 (MET-ENFORCE-018) analysed musl 1.2.5 with Rust 1.90.0, and added
`poll` to NATIVE_STATIC. At 1.99.0 the start-up syscalls are the same:
- std's init order is unchanged: fd sanitising, SIGPIPE, the stack-overflow set-up.
- One `poll` on fds 0-2.
- On musl, `install_main_guard_linux_musl` returns no guard without calling `pthread_getattr_np`, so there is no `mremap`
  probe.
- `rt_sigaction`, `mmap`, `mprotect` and `sigaltstack` set up the alternate stack.
- New in 1.99: spawned threads record their OS id through `gettid`, which NATIVE_STATIC grants. The main thread on musl
  issues none at start.
- musl's own start-up polls fds 0-2 under AT_SECURE, which is the same syscall.
`plan.json` (`startupRecheck`) lists the sources.

**Start-up constraints.** NATIVE_STATIC grants no file access, so the modules must avoid three things:
- `std::thread::available_parallelism`, because it reads cgroup and `/proc` files. Thread counts are configuration
  instead.
- Closed standard fds. Units supply fds 0-2, so Rust std's start-up fd sanitising never opens `/dev/null`.
- `current_exe` and locale lookups.
T04 traces each built module's start-up and steady state on both architectures (SEC-1).

**Crates.** Crates are vendored, and builds run `--locked --offline --frozen`. Licenses are checked against
`legal/third-party-license-policy.yaml`, and each artifact gets a CycloneDX SBOM.

## Scope (Q1, Q5)

The source goes into `caglarsubas/mas-harness-operator` under `host-enforcement/`:
- five modules: `containment`, `broker`, `observer`, `gate` and `writer`;
- `host-image/`: units, boot entry, SELinux modules, sysctls and seal configuration, kernel module list, backend artifacts
  and the CPython build;
- `enrollment/`: the manifest signer and the enrollment ledger tool. The signer runs off-host (W01 P4), and the host
  carries public trust material only.

This amends ADR 0009 and `docs/alpha-2/ENFORCEMENT_INTEGRATION.md`, which name four modules. The verifier does not list
R10 yet, so the owner's root extension (VERIFIER-EXT) comes before the first R10 packet.

## Packets

| ID | Where | Content |
|---|---|---|
| W03-0 | meta | this record and the backend distribution selection |
| LIC-HOST | meta | the license-policy amendment approved in Q-L (D-POLICY-AMEND) |
| W02A-F2, W02G-F2 | meta | production backend profile and the I06 successor bound to it |
| VERIFIER-EXT | owner root | verifier policy entry and toolchain profile, inventories, App access and branch protection |
| HE-001 | R10 | scaffold, pins, vendored closure, license and SBOM gate, cross-builds |
| HE-002, HE-003 | R10 | effect gate: I05 and I07 framing; I04 TLS substrate, stamping, upstream bound |
| HE-004 | R10 | policy observer |
| HE-005 | R10 | capacity broker (W1-W6) |
| HE-006 | R10 | host containment (S2-S5) |
| HE-007 | R10 | policy writer |
| HE-008 | R10 | host image and enrollment |

## Obligation register

`plan.json` lists 53 obligations. Each has its source (file and lines) and the packets that discharge it. They come from
native-profile v3, I05 v3, I06 v1 and v2, I07 v3, admission v3, the SELinux matrix v2, the W02d allowlists and W01 §2-§6,
plus the four W01-AMEND items and the license-policy amendment. W01-AMEND (MET-ENFORCE-018) is pending merge, so its four items are cited by name. One of
them, O-SERVER-MEMFD, belongs to the R12 live backend and is listed as outside W03. Two items are discharged here, in
W03-0: the I05 re-check (I05-1) and the version rule (I06-6).

`../../scripts/w03_plan.py` checks the record:
- the two toolchains partition W02d's seven roles, and each role's toolchain matches its W02d runtime base;
- musl's thread flags pass the W02d thread rule;
- every obligation names planned packets;
- every cited repository file exists.
