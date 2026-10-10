# W01-AMEND — W02d's carried items in the W01 host-interface record (DATA_CHECK_ONLY)

Status: **AMENDMENT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**.

The resolved W01 specification (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md`, HOST-INTERFACE-DRAFT-002) stays byte-identical: about ten later history layers
freeze it. W02d (seccomp allowlists, `architecture/seccomp-allowlists/`, merged as packet 219) carried six items into the
W01 record (`status.json` `carriedToW01`). This directory amends W01 without editing it:

- `amendment.json` (`planeon.internal.host-interface-amendment/v1`): the pinned base, each item as an exact, counted substring replacement with its section, base
  line, owner decisions, source and reason, and the pinned effective bytes.
- `HOST_INTERFACE_SPEC.md`: the amended specification, exactly the base with every item applied. W03 and W04 read this file.
- `../../scripts/host_interface_amendment.py`: reference model; `effective_spec` applies the items and `check` validates
  the record, the base and the published file through an injected byte reader.

## Owner decisions

| ID | Date | Decision |
|---|---|---|
| W02d-Q1 | 2026-10-09 | W02d defines the WORKER allowlist from the worker's duties; the W01 section 5.3 WORKER row text 'Existing worker allowlist' is amended to 'the W02d worker allowlist' |
| W02d-QA | 2026-10-09 | the worker filter, installed in W4, allows execveat only in W5's form (flags AT_EMPTY_PATH); a second exec stays refused by SELinux |
| W02d-QB | 2026-10-09 | clone3 fails with ENOSYS (not KILL_PROCESS) in the six non-broker roles, so glibc 2.34 and later fall back to the thread-only clone rule |
| W02d-QC | 2026-10-09 | SERVER, OBSERVER and BROKER get an inspection-reads duty; membarrier only QUERY (0), PRIVATE_EXPEDITED (8) and REGISTER_PRIVATE_EXPEDITED (16), flags 0, cpu 0; carried to W01 as a row amendment |
| QW1 | 2026-10-10 | W6 kills through cgroup.kill only: freeze, cgroup.kill, wait for populated 0 (the broker has no CAP_KILL); the unused pidfd_send_signal grant is dropped in the W02d successor seccomp-allowlists-v2 |
| QW2 | 2026-10-10 | the broker runs with no supplementary groups (a W03 unit requirement) and W3 checks that the child's /proc Groups: line is empty; no allowlist change |
| QW3 | 2026-10-10 | M-a (replacing the vm.memfd_noexec pin, which any CAP_SYS_ADMIN holder can lower in the init namespace): the memfd_create flags become MFD_CLOEXEC | MFD_NOEXEC_SEAL, so the kernel clears exec and sets F_SEAL_EXEC on every call with no reliance on host state; carried by the W02d successor seccomp-allowlists-v2 |

## Items

### A1 — 5.3 WORKER row, seccomp (base line 406; W02d-Q1, W02d-QA, W02d-QB)

W01 cited a worker allowlist that existed nowhere in the repository; W02d defines it (Q1) and allows W5's exec in the worker's own filter (QA).

- Current: `Existing worker allowlist plus FD3 seqpacket I/O; no socket creation`
- Amended: `The W02d worker allowlist ('architecture/seccomp-allowlists-v2/'): FD3 seqpacket I/O, reads on the read-only root and exit; 'execveat' only in W5's form (flags AT_EMPTY_PATH), and a second exec is refused by SELinux; clone3 fails with ENOSYS; no socket creation. The broker's filter, inherited and still installed, covers it`
- Source: architecture/seccomp-allowlists/status.json carriedToW01 items 1-2

### A2 — 5.3 SERVER row, seccomp (OBSERVER and BROKER inherit it) (base line 402; W02d-QC)

The readers' native qualification reads were not derivable from the SERVER row; W01 says such a need means the row is wrong.

- Current: `pidfd_open, exit. Denied:`
- Amended: `pidfd_open, inspection reads (read-only opens and reads of selinuxfs status and policy, cgroup and /proc files, the fs-verity measurement ioctl, and 'membarrier' only with cmd 0, 8 or 16, flags 0 and cpu 0), exit. Denied:`
- Source: architecture/seccomp-allowlists/status.json carriedToW01 item 3; docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md:112-135

### A3 — 5.3 SERVER row, seccomp (base line 402; W02d-QB)

States the refusal action the allowlists use, which W04's tests must expect.

- Current: `clone3 (its flags are in a struct seccomp cannot read)`
- Amended: `clone3 (its flags are in a struct seccomp cannot read; it fails with ENOSYS rather than KILL_PROCESS, so glibc 2.34 and later fall back to the thread-only clone rule)`
- Source: architecture/seccomp-allowlists/allowlists.json SERVER clone3 rule

### A4 — 5.3 EFFECT_GATE row, seccomp (base line 405; W02d-QB)

As A3, for the gate.

- Current: `no exec, no clone3, clone only with CLONE_THREAD`
- Amended: `no exec, no clone3 (it fails with ENOSYS), clone only with CLONE_THREAD`
- Source: architecture/seccomp-allowlists/allowlists.json EFFECT_GATE clone3 rule

### A5 — 5.3 SERVER row, seccomp (memfd_create) (base line 402; QW3)

With MFD_CLOEXEC | MFD_ALLOW_SEALING the memfd is executable unless vm.memfd_noexec says otherwise, and any CAP_SYS_ADMIN holder can lower that sysctl in the init namespace.

- Current: `memfd_create with flags limited to the existing sealed-credential path (MFD_CLOEXEC, MFD_ALLOW_SEALING)`
- Amended: `memfd_create with flags limited to the existing sealed-credential path (MFD_CLOEXEC, MFD_NOEXEC_SEAL: the kernel clears the exec bits and sets F_SEAL_EXEC on every call, and further seals stay possible)`
- Source: architecture/seccomp-allowlists/status.json carriedToW01 item 6 (round-1 F9); architecture/seccomp-allowlists-v2/allowlists.json; linux v6.12 mm/memfd.c:313-317,401-410

### A6 — 5.4 W3 (base line 433-434; QW2)

W4 changes uid and gid but never names setgroups; supplementary groups inherited from the broker would survive into the worker.

- Current: `only stdio and the broker-created FD3 socketpair end.`
- Amended: `only stdio and the broker-created FD3 socketpair end. It also checks that the child has no supplementary groups (its '/proc/<pid>/status' Groups: line is empty): the broker runs with none, so W4's setresgid/setresuid leaves none, and neither filter allows setgroups.`
- Source: architecture/seccomp-allowlists/status.json carriedToW01 item 5

### A7 — 5.4 W6 (base line 443; QW1)

pidfd_send_signal to a process of another uid needs CAP_KILL (linux v6.12 kernel/signal.c:814-824), which the BROKER row denies; W6 contradicted the row. The W02d successor drops the unused grant.

- Current: `the leaf, kills through the pidfd and 'cgroup.kill', waits until 'cgroup.events'`
- Amended: `the leaf, kills through 'cgroup.kill' only (the broker has no CAP_KILL, so it cannot signal the worker's uid through the pidfd), waits until 'cgroup.events'`
- Source: architecture/seccomp-allowlists/status.json carriedToW01 item 4; architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md:404

## Not amended

- W02d-QD (the broker's filter covers the worker's): already stated in the BROKER row ('The child inherits this filter')
- The W02d contract itself: its successor architecture/seccomp-allowlists-v2/ (same packet) carries QW1's dropped grant and QW3's flags
- Every other W01 text, gate disposition and E01-E12 obligation

## What stays open

Every E01-E12 obligation stays OPEN_UNPROVEN; no filter, sysctl or unit exists. The boot-time proof that the installed
seccomp filters equal the published digests stays a T04/W02a-F obligation; with the successor those are the v2 digests.
QW3 is carried by the W02d successor's flags, not by host state, so nothing goes to W02a-F2. A6's empty supplementary
groups are a W03 unit requirement.
