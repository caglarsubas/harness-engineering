# W01-AMEND — W02d's carried items in the W01 host-interface record (DATA_CHECK_ONLY)

Status: **AMENDMENT_CANDIDATE_ROUND4_AWAITING_INDEPENDENT_REVIEW**. Rounds 1 and 2 returned CHANGES_REQUIRED and round 3
PASS_FOR_SOURCE_PUBLICATION (`review-round1..3.json`, subject bytes in `round1/` to `round3/`). Owner decision
W01-AMEND-QW4 then reopened the subject (section "Round 4" below); the dispositions sections answer every finding.

The resolved W01 specification (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md`, HOST-INTERFACE-DRAFT-002) stays byte-identical: about ten later history layers
freeze it, and `scripts/host_interface_amendment.py` pins its digest. W02d (seccomp allowlists,
`architecture/seccomp-allowlists/`, merged as packet 219) carried six items into the W01 record (`status.json`
`carriedToW01`). This directory amends W01 without editing it, as `HOST-INTERFACE-DRAFT-002-W02D`:

- `amendment.json` (`planeon.internal.host-interface-amendment/v1`): the pinned base, the carried items with one disposition each, every change as an exact,
  counted substring replacement with its section, base line, owner decisions, source and reason, the obligations the
  changes create, and the pinned effective bytes.
- `HOST_INTERFACE_SPEC.md`: the amended specification, exactly the base with every item applied (section 11 summarises
  them). W03 and W04 read this file.
- `../../scripts/host_interface_amendment.py`: reference model. `check(read)` validates the record, the carried items,
  the base and the published file through an injected byte reader; `effective_spec` applies the items and refuses any
  item a later item rewrites.

The W02d successor in the same packet, `architecture/seccomp-allowlists-v2/`, carries W01-AMEND-QW1 and QW3 into the
allowlists.

## Owner decisions

| ID | Date | Decision |
|---|---|---|
| W02d-Q1 | 2026-10-09 | W02d defines the WORKER allowlist from the worker's duties; the W01 section 5.3 WORKER row text 'Existing worker allowlist' is amended to 'the W02d worker allowlist' |
| W02d-QA | 2026-10-09 | the worker filter, installed in W4, allows execveat only in W5's form (flags AT_EMPTY_PATH); a second exec stays refused by SELinux |
| W02d-QB | 2026-10-09 | clone3 fails with ENOSYS (not KILL_PROCESS) in the six non-broker roles, so glibc 2.34 and later fall back to the thread-only clone rule |
| W02d-QC | 2026-10-09 | SERVER, OBSERVER and BROKER get an inspection-reads duty; membarrier only QUERY (0), PRIVATE_EXPEDITED (8) and REGISTER_PRIVATE_EXPEDITED (16), flags 0, cpu 0; carried to W01 as a row amendment |
| W02d-QD | 2026-10-09 | the broker's filter is inherited by the worker and stays after exec, and the kernel applies the most restrictive of stacked filters, so the broker's allowlist covers the worker's |
| W01-AMEND-QW1 | 2026-10-10 | W6 kills through cgroup.kill only: freeze, cgroup.kill, wait for populated 0 (the broker has no CAP_KILL); the unused pidfd_send_signal grant is dropped in the W02d successor seccomp-allowlists-v2 |
| W01-AMEND-QW2 | 2026-10-10 | the broker runs with no supplementary groups (a W03 unit requirement) and W3 checks that the child's /proc Groups: line lists none; no allowlist change |
| W01-AMEND-QW4 | 2026-10-10 | the native roles are Rust with musl, fully static (analysed reference: musl 1.2.5, Rust 1.90.0; W03 pins these or re-checks them against W02d); the W02d successor's NATIVE_STATIC base adds poll, which Rust std calls on fds 0-2 at start-up and musl issues as SYS_poll on x86_64; musl creates threads with clone, never clone3 |
| W01-AMEND-QW3 | 2026-10-10 | M-a, replacing a vm.memfd_noexec pin (which a CAP_SYS_ADMIN holder in the initial namespaces can lower): memfd_create flags become MFD_CLOEXEC | MFD_NOEXEC_SEAL, so the kernel clears exec and sets F_SEAL_EXEC on every call with no reliance on host state; carried by the W02d successor seccomp-allowlists-v2 |

## Carried items and their dispositions

| W02d carried item | Items | Obligations | Disposition |
|---|---|---|---|
| W02d-Q1 WORKER row text amendment | A1, A8 | - | The WORKER row names the W02d worker allowlist; the note points at the data. |
| W02d-QA worker execveat in W5's form | A1, A2, A7, A11 | O-W03-WORKER-EXEC | The worker filter admits W5's execveat form only, SELinux refuses any second exec, and the worker runs under both filters. |
| W02d-QC readers' inspection-reads row amendment | A3 | - | SERVER, and through 'As SERVER' OBSERVER and BROKER, gain the inspection-reads duty; SELinux limits the paths. |
| W6 pidfd kill needs CAP_KILL the broker lacks; cgroup.kill is the effective path | A12 | O-T04-AMEND | W6 kills through cgroup.kill only; the broker keeps no CAP_KILL, and the W02d successor drops pidfd_send_signal. |
| W4 does not name setgroups | A10 | O-W03-GROUPS, O-T04-AMEND | The broker runs with no supplementary groups, and W3 checks the child's Groups: line. |
| F9 executable memfd | A4 | O-SERVER-MEMFD, O-T04-AMEND | SERVER memfd_create flags become MFD_CLOEXEC | MFD_NOEXEC_SEAL; the W02d successor narrows its rule. |

## Obligations

- **O-SERVER-MEMFD** (the SERVER role's sealed-credential code (today the R12 live backend: mas-harness-conformance-labs src/harness_conformance/live_linux_boundary.py:976, pinned in architecture/credential-ordering-inputs/source-before.json)): Call memfd_create with MFD_CLOEXEC | MFD_NOEXEC_SEAL instead of MFD_CLOEXEC | MFD_ALLOW_SEALING, and change its unit rig (tests/live_backend/test_linux_boundary.py:836-870, pinned in architecture/conformance-consumer-closure-inputs/consumer-sources.json) to expect those flags, before the code runs under the W02d v2 filter, which kills the old flags.
- **O-W03-WORKER-EXEC** (W03): Give planeon_worker_t no transition or nnp_transition into any domain in the host policy, beyond the declared domains SELinux matrix v4 already closes (A24-A32), so a second exec the worker filter admits stays refused (W02d-QA).
- **O-W03-GROUPS** (W03): Start the broker with no supplementary groups (W02d carriedToW03), so the W3 Groups: check holds.
- **O-T04-AMEND** (T04): On the enrolled kernel, confirm that a pidfd signal from the root broker without CAP_KILL to the signed-uid child fails, that MFD_NOEXEC_SEAL memfds are non-executable and exec-sealed, that the worker shows Seccomp_filters: 2, and that its Groups: line lists none.

## Items

### E1 — title (EDITORIAL; base line 1; no decision)

Marks the file as the effective amended text.

Current:

```text
# W01 host interfaces — gate resolutions, candidate v2
```
Amended:

```text
# W01 host interfaces — gate resolutions, candidate v2 with amendment W02D

Effective text of `HOST-INTERFACE-DRAFT-002` with amendment W02D (`HOST-INTERFACE-DRAFT-002-W02D`, section 11) applied.
The reviewed v2 file (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md`) stays byte-identical;
`architecture/host-interface-amendment-w02d/amendment.json` lists every change.
```
Source: amendment W02D

### A1 — 5.3 WORKER row, seccomp (CARRIED; base line 406; W02d-Q1, W02d-QA, W02d-QB, W02d-QD)

W01 cited a worker allowlist that existed nowhere in the repository; W02d defines it (Q1) and admits W5's exec in it (QA).

Current:

```text
Existing worker allowlist plus FD3 seqpacket I/O; no socket creation
```
Amended:

```text
The W02d worker allowlist (`architecture/seccomp-allowlists-v2/`, W02d-Q1): its CPython 3.12 runtime base, FD3 seqpacket I/O on fd 3 only, reads of the read-only root and exit; `execveat` only with flags AT_EMPTY_PATH, for W5 (W02d-QA); `clone3` fails with ENOSYS (W02d-QB); no socket creation, no `bpf`. The inherited broker filter stays installed and covers it (W02d-QD)
```
Source: architecture/seccomp-allowlists-v2/allowlists.json (WORKER)

### A2 — 5.3 WORKER row, SELinux (CARRIED; base line 406; W02d-QA)

QA's 'a second exec stays refused by SELinux' rests on the worker domain's rules; the row now states them.

Current:

```text
| `planeon_worker_t`: no network `name_connect`, no ptrace, read-only root |
```
Amended:

```text
| `planeon_worker_t`: no network `name_connect`, no ptrace, read-only root; no `execute_no_trans` on any type (SELinux matrix v4 A60.18) and no `transition` or `nnp_transition` into any declared domain (A24-A32), and the host policy gives it none into any other domain (obligation O-W03-WORKER-EXEC), so a second exec that the worker filter admits is still refused |
```
Source: architecture/selinux-matrix-v2/matrix.json (A24-A32, A60.18)

### A3 — 5.3 SERVER row, seccomp (OBSERVER and BROKER inherit it) (CARRIED; base line 402; W02d-QC)

The readers' native qualification reads were not derivable from the SERVER row; W01 says such a need means the row is wrong.

Current:

```text
pidfd_open, exit. Denied:
```
Amended:

```text
pidfd_open, inspection reads (read-only `openat`, `read`, `pread64`, `lseek`, `fstat`, `newfstatat`, `statx`, `fstatfs`, `getdents64` and `readlinkat`; `ioctl` only FS_IOC_MEASURE_VERITY; `membarrier` only cmd 0, 8 or 16 with flags 0 and cpu 0; W02d-QC). Seccomp checks only the open flags of these reads; which files they reach is set by the role's SELinux domain (`architecture/selinux-matrix-v2/`), exit. Denied:
```
Source: architecture/seccomp-allowlists-v2/allowlists.json (SERVER inspection reads); docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md:112-135

### A4 — 5.3 SERVER row, seccomp (memfd_create) (CARRIED; base line 402; W01-AMEND-QW3)

With MFD_CLOEXEC | MFD_ALLOW_SEALING the memfd is executable unless vm.memfd_noexec says otherwise (round-1 F9), and a CAP_SYS_ADMIN holder in the initial namespaces can lower that sysctl (linux v6.12 (adc218676eef) kernel/pid_sysctl.h:8-32; include/linux/pid_namespace.h:59-67).

Current:

```text
memfd_create with flags limited to the existing sealed-credential path (MFD_CLOEXEC, MFD_ALLOW_SEALING)
```
Amended:

```text
memfd_create with flags exactly MFD_CLOEXEC and MFD_NOEXEC_SEAL for the sealed-credential path (the kernel clears the exec bits and sets F_SEAL_EXEC on every call, and further seals stay possible; the existing code passes MFD_CLOEXEC and MFD_ALLOW_SEALING and must change first, obligation O-SERVER-MEMFD)
```
Source: architecture/seccomp-allowlists-v2/allowlists.json; linux v6.12 (adc218676eef) mm/memfd.c:313-317,401-410; include/uapi/linux/memfd.h:8,12

### A5 — 5.3 SERVER row, seccomp (clone3) (RESTATED; base line 402; W02d-QB)

States the refusal the allowlists use, which W04's tests must expect.

Current:

```text
clone3 (its flags are in a struct seccomp cannot read)
```
Amended:

```text
clone3 (its flags are in a struct seccomp cannot read; it fails with ENOSYS rather than KILL_PROCESS, W02d-QB)
```
Source: architecture/seccomp-allowlists-v2/allowlists.json (SERVER clone3 errno rule)

### A6 — 5.3 EFFECT_GATE row, seccomp (RESTATED; base line 405; W02d-QB)

As A5, for the gate.

Current:

```text
no exec, no clone3, clone only with CLONE_THREAD
```
Amended:

```text
no exec, no clone3 (it fails with ENOSYS, W02d-QB), clone only with CLONE_THREAD
```
Source: architecture/seccomp-allowlists-v2/allowlists.json (EFFECT_GATE clone3 errno rule)

### A7 — 5.3 BROKER row, seccomp (CARRIED; base line 404; W02d-QD)

The worker's effective policy is the intersection of both filters; the row now says so.

Current:

```text
The child inherits this filter, so it must cover the child's pre-exec steps; the narrower worker filter is installed in W4.
```
Amended:

```text
The child inherits this filter, so it must cover the child's pre-exec steps; the narrower worker filter is installed in W4 and stacks on it. The inherited broker filter stays after exec and the kernel applies the most restrictive action of the two, so the broker allowlist covers the worker's (W02d-QD). The broker runs under exactly one filter, its own (W03 adds none, W02d F10), so the worker shows `Seccomp_filters: 2`.
```
Source: architecture/seccomp-allowlists/README.md (filter digests and stacking); linux v6.12 (adc218676eef) kernel/seccomp.c:932; fs/proc/array.c:339-340

### A8 — 5.3 note (CARRIED; base line 410; W02d-Q1)

Points the note at the data.

Current:

```text
allowlists (x86_64 and aarch64 numbers, argument filters) are W02 data, generated
```
Amended:

```text
allowlists (x86_64 and aarch64 numbers, argument filters) are W02 data (W02d, `architecture/seccomp-allowlists-v2/`), generated
```
Source: architecture/seccomp-allowlists-v2/README.md

### A9 — 5.3 note (RESTATED; base line 413; W02d-QB, W01-AMEND-QW4)

Covers POLICY_WRITER and HOST_CONTAINMENT, whose rows name no clone3 refusal.

Current:

```text
added to the allowlist. For all roles:
```
Amended:

```text
added to the allowlist. In every role except BROKER, `clone3` fails with ENOSYS rather than KILL_PROCESS (W02d-QB): in the CPython roles (SERVER, WORKER) glibc 2.34 and later then fall back to the thread-only `clone` rule, and the native roles' static musl runtime creates threads with `clone` only, never `clone3` (W01-AMEND-QW4). Every other call a role's allowlist does not name is KILL_PROCESS. For all roles:
```
Source: architecture/seccomp-allowlists-v2/allowlists.json (clone3 errno rules: SERVER, OBSERVER, EFFECT_GATE, WORKER, POLICY_WRITER, HOST_CONTAINMENT); musl 1.2.5 src/thread/pthread_create.c:243-245,355, src/thread/x86_64/clone.s, src/thread/aarch64/clone.s (SYS_clone 56 and 220)

### A10 — 5.4 W3 (CARRIED; base line 432-434; W01-AMEND-QW2)

W4 changes uid and gid but never names setgroups; supplementary groups held by the broker would survive into the worker.

Current:

```text
only stdio and the broker-created FD3 socketpair end.
```
Amended:

```text
only stdio and the broker-created FD3 socketpair end. The child holds no supplementary groups: the `Groups:` line
of `/proc/<pid>/status` lists none (the kernel writes `Groups:`, a tab and one space). W4's setresgid and setresuid
leave supplementary groups unchanged, so the broker must run with none (obligation O-W03-GROUPS), and neither filter
allows `setgroups`.
```
Source: linux v6.12 (adc218676eef) kernel/sys.c:676-750,778-839; fs/proc/array.c:199-206; architecture/seccomp-allowlists-v2/allowlists.json

### A11 — 5.4 W4 (CARRIED; base line 437; W02d-QA, W02d-QD)

Names the filter W4 installs and how it composes.

Current:

```text
capabilities, `no_new_privs=1`, install the worker seccomp filter.
```
Amended:

```text
capabilities, `no_new_privs=1`, install the worker seccomp filter (W02d). That filter admits W5's `execveat`
form and no other exec, and it stacks on the inherited broker filter.
```
Source: architecture/seccomp-allowlists-v2/allowlists.json (WORKER, BROKER)

### A12 — 5.4 W6 (CARRIED; base line 443; W01-AMEND-QW1)

pidfd_send_signal to another uid needs CAP_KILL, which the BROKER row withholds; W6 contradicted the row. The W02d successor drops the unused grant.

Current:

```text
the leaf, kills through the pidfd and `cgroup.kill`, waits until `cgroup.events`
```
Amended:

```text
the leaf, kills through `cgroup.kill` (a pidfd signal needs CAP_KILL once the child runs as the signed uid, and
the broker holds none; the pidfd serves `waitid` and identity), waits until `cgroup.events`
```
Source: linux v6.12 (adc218676eef) kernel/signal.c:814-824; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md:404

Item E2 appends section 11 to the end of the specification.

## Not amended

- Items A5, A6, A9 restate W02d-QB's ENOSYS refusal; W02d-QB is not a carried item but the rows implied KILL_PROCESS
- The W02d contract itself: its successor architecture/seccomp-allowlists-v2/ (same packet) carries W01-AMEND-QW1's dropped grant and QW3's flags
- Every other W01 text, gate disposition and E01-E12 obligation

## Round-1 findings and dispositions

| Finding | Disposition |
|---|---|
| R1-1 MAJOR, the existing sealed-credential code passes MFD_ALLOW_SEALING | A4 now says flags "exactly" MFD_CLOEXEC and MFD_NOEXEC_SEAL and that the existing code must change first; obligation O-SERVER-MEMFD names the code (R12 `live_linux_boundary.py:976`, snapshot-pinned) and its unit rig. |
| R1-2 MINOR, POLICY_WRITER and HOST_CONTAINMENT rows imply KILL_PROCESS for clone3 | A9 states W02d-QB's ENOSYS refusal for every role except BROKER in the section 5.3 note; A5, A6 and A9 are kind RESTATED. |
| R1-3 MINOR, A1's stacking sentence lacks W02d-QD | A1 cites W02d-QD; W02d-QD is an owner decision of this record; A7 states the stacking in the BROKER row and A11 in W4. |
| R1-4 MINOR, seccomp cannot scope the inspection paths | A3 says seccomp checks only the open flags and the role's SELinux domain limits the paths. |
| R1-5 MINOR, the v2 model does not enforce QW1 | The v2 model refuses any pidfd_send_signal (QW1) or setgroups (QW2) grant; both names are sampled in the table so vectors show them killed; memfd_create vectors for the v1 flags, MFD_EXEC and MFD_CLOEXEC alone; mutations M14 and M15. |
| R1-6 MINOR, a later item could rewrite an earlier one | `effective_spec` requires every proposed text to occur as often after all items as it was applied. |
| R1-7 NOTE, loose record checks | The model pins the base digest itself, closes every object, raises ValueError on bad shapes, and requires one disposition per W02d carried item (read from W02d's `status.json`); A10's base lines are 432-434. |
| R1-8 NOTE, the Groups: line has a trailing space | A10 says the line lists no group and gives the kernel's exact form (`fs/proc/array.c:199-206`). |
| R1-9 NOTE, consistency | SIGKILL leaves the v2 table; the v2 README marks which v1 README rows v2 supersedes; the README shows item texts verbatim in code blocks; decision IDs are W01-AMEND-QW1..QW3 everywhere; v2's status record follows its review. |
| R1-10 NOTE, kernel wording | QW3's reason says a CAP_SYS_ADMIN holder in the initial namespaces can lower the sysctl, citing `kernel/pid_sysctl.h:8-32` and `include/linux/pid_namespace.h:59-67` (now among the pinned sources). |

## Round-2 findings and dispositions

| Finding | Disposition |
|---|---|
| R2-1 MINOR, A3 presented the inspection paths as the domain's whole read set | A3 now says only that seccomp checks the open flags of these reads and the role's SELinux domain sets which files they reach. |
| R2-2 MINOR, 'no transition out of the domain' is not established by A24-A32 | A2 states what the matrix establishes (A60.18: no `execute_no_trans`; A24-A32: no transition into a declared domain) and carries the rest to W03 as obligation O-W03-WORKER-EXEC. |
| R2-3 MINOR, EDITORIAL and RESTATED items were unconstrained | The model allows EDITORIAL items only on the title line and the last line, each keeping that line; RESTATED items must cite only W02d-QB and state ENOSYS. |
| R2-4 NOTE, TypeError and missing cross-checks | Every list entry is type-checked before use; each disposition's decisions must be cited by its items; every obligation is used by a disposition, and every obligation an item names exists. |
| R2-5 NOTE, Seccomp_filters: 2 assumes one broker filter | A7 says the broker runs under exactly one filter (W03 adds none, W02d F10) and cites `kernel/seccomp.c:932` and `fs/proc/array.c:339-340`. |
| R2-6 NOTE, 'runs with none' and an unpinned kernel/sys.c | A10 says 'must run with none'; `kernel/sys.c` is pinned (lines 676-750, 778-839). |
| R2-7 NOTE, 'any CAP_SYS_ADMIN holder' in v2 | The v2 README and data say a CAP_SYS_ADMIN holder in the initial namespaces. |
| R2-8 NOTE, brief, rig pin and name clash | The brief lists E1, A1-A12 and E2; O-SERVER-MEMFD names `consumer-sources.json` for the unit rig; the amendment is now W02D (`HOST-INTERFACE-DRAFT-002-W02D`). |

## Round 4 (owner decision W01-AMEND-QW4)

W03 planning chose Rust with musl, fully static, for the native roles. Checked against musl 1.2.5 and Rust 1.90.0: musl
creates threads with `clone` (`src/thread/pthread_create.c:243-245,355`; `clone.s` issues SYS_clone, 56 on x86_64 and
220 on aarch64), never `clone3`, with flags the thread-only `clone` rule admits; so W02d-QB's ENOSYS rule serves the
CPython roles' glibc, and item A9 now says so. Rust std calls `poll` on fds 0-2 at start-up
(`library/std/src/sys/pal/unix/mod.rs:62-100`), and musl issues it as SYS_poll on x86_64 (`src/select/poll.c`), which the
reviewed NATIVE_STATIC base did not grant: every native role would have been killed at start-up on x86_64. The W02d
successor now grants `poll` in NATIVE_STATIC (only the x86_64 programs of OBSERVER, EFFECT_GATE, POLICY_WRITER and
HOST_CONTAINMENT change; BROKER already granted it through its worker-coverage duty). Round 3's notes R3-1 to R3-3 stay
carried; R3-3's editorial points are fixed only where round 4 rewrites the same text.

## What stays open

Every E01-E12 obligation stays OPEN_UNPROVEN; no filter, unit or code exists. The boot-time proof that the installed
seccomp filters equal the published digests stays a T04/W02a-F obligation; with the successor those are the v2 digests.
QW3 is carried by the W02d successor's flags, not by host state, so nothing goes to W02a-F2.
