# Linux runner candidate / external operator handoff

Phase: Alpha 2 foundation. Packet: MET-LINUX-002, with proposed MET-LINUX-003
source-only contract repair. This kit is source work only;
it does not install root authority or close CONF-LINUX-001. macOS remains the
development host. Linux runtime, OCP/Kubernetes, air gap and tenant acceptance
remain independent gates. No root files, GitHub workflows, product repository,
warm source or existing macOS operator installation may be changed by this PR.

## Contents and entry points

| File | Responsibility |
| --- | --- |
| ci/linux-runner/common.py | Closed manifest/policy inputs, byte digests, no-follow root custody, exhaustive inventories and packet argv |
| ci/linux-runner/ed25519.py | Verification-only RFC 8032 implementation; independent published vectors, no key generation/signing |
| ci/linux-runner/launcher.py | Fixed installed identity, signed custody, Linux profile, descriptor handoff, fresh negatives, exact wrapper and deadline |
| ci/linux-runner/preflight.py | Kernel, namespace, network/socket, source/credential/trust metadata and descendant negative probes |
| ci/linux-runner/build.py | Byte-identical standard-library zipapp and source/artifact inventory |
| ci/linux-runner/prepare.py | Unsigned policy/profile rendering; no root writes |
| tests/linux_runner/ | Source-only adapters, malformed inputs, published signature vectors, deterministic build and full predecessor baseline |

The accepted MET-LINUX-002 packet declared one offline/frozen uv pytest argv.
Proposed MET-LINUX-003 declares its own source and inherited-validation argv.
Each must be entered only through its exact hash-pinned packet and the existing
external signed host launcher; no acceptance command is run separately on the
workstation. Nested predecessor checks stay in that same isolated process tree
and exclude only their own test directory to prevent recursion. The builder
is not an installer.

Reviewed standalone operator packaging argv, to be run only in the operator's
already authorized offline environment:

```text
python -IB ci/linux-runner/build.py --output <new-private-absolute-output-directory>
python -IB ci/linux-runner/prepare.py --request <reviewed-request.json> --output <another-new-private-absolute-directory>
```

Angle-bracket values are user-owned local paths, not working commands or invented
evidence. Both output directories must not exist. Builder writes a deterministic
`harness-offline-launch.candidate` (0555) and `inventory.json`; preparation emits
an unsigned policy and a candidate profile. The artifact excludes tests, keys,
policy, caches, platform binaries and generated native outputs. Build twice;
compare complete bytes and inventories, not only version strings.

## External installation and bootstrap sequence

This sequence describes independent operator responsibilities; no install,
sudo policy, password collection, key creation or provisioning script is supplied.
Use only existing authorized zero-incremental-cost native Linux capacity.

1. Independently review the exact candidate source/crypto/profile and package
   digests. A source-test PASS is not security review or Linux qualification.
2. Prestage Linux-native root-owned Python/tool/cache closures and the clean
   owned-product checkout. Supply complete [BUILD_INPUTS.md](BUILD_INPUTS.md).
   V3 admits signed, complete cross-root aliases only in explicitly declared
   root-owned system trees including `/usr/bin`; source, cache, trust and
   dedicated-tool aliases remain refused.
   Pin Firejail binary, helper libraries and configuration in the immutable host
   image. Independently verify the booted image digest and derive its actual
   ELF interpreter, transitive native-library, loader-search and helper closure;
   the source candidate checks ELF class/machine and signed inventory bytes but
   does not compute that dependency closure or attest the host image itself.
   An incomplete/unobservable closure blocks listener registration. Review
   actual feature support; this kit has no automatic upgrade path.
3. Keep the runner non-root, ephemeral and free of cloud/provider keys,
   kubeconfig, external credential homes, agent/control sockets and billable
   brokers. GitHub runner registration credentials stay in the separately
   hidden runnerHome, never the workspace or tool/cache inventories. All
   snapshots belong under the named root-owned warm container; reject aliases,
   extra roots or alternate bind mounts in the host image review. Before
   signing, precreate the inert zero-byte root-owned mode-0444 regular file
   `/srv/planeon-runner-placeholder`. The profile's `private-srv` copies only
   this direct child into a new `/srv`; it must not copy or expose `planeon`.
4. Use existing independent operator authority to sign the exact data-only
   policy. Preserve previous installed bytes, modes, signatures and activation
   history as a rollback transaction before any installation.
5. Externally install reviewed candidate bytes as
   `/opt/planeon/bin/harness-offline-launch`, UID/GID 0, mode 0555; policy,
   signature and exact profile under `/etc/planeon/linux-runner/`; existing
   Ed25519 public key at `/etc/planeon/harness-runner-manifest.pub`; and the
   exact root-owned read-only packet at `/opt/planeon/packet/active.yaml`.
   Parent directories must be root-owned and not group/world writable. No
   symlinks, hardlinks, writable trust paths or copied macOS launcher are accepted.
6. Root-image custody at `/etc/planeon/linux-runner/custody.json` contains only
   `schemaVersion=planeon.linux-runner-custody/v1`, `publicKeySha256`,
   `launcherSha256`, `policySha256`. It is independently installed, not supplied
   by the checkout. The signed policy and exact installed launcher must match it.
7. Execute only the installed absolute launcher with `--operator-preflight`.
   This explicit bootstrap mode verifies that custody/signature/policy and fresh
   kernel boundary, but **cannot execute the repository wrapper** and does not
   require a previously published preflight PASS. This avoids a circular initial
   manifest/preflight dependency without fabricating an initial success record.
8. Independently retain and review that real host probe output. If any negative
   fails, do not sign a PASS manifest. Bind its exact digest in the unchanged
   trusted-runner manifest schema; sign that manifest using the existing key and
   install its manifest/signature/preflight at the existing fixed contract paths.
   Preflight binds launcher, policy, kernel, architecture and time; launcher
   rejects records older than one hour. A new policy requires new probe evidence.
9. Normal installed invocation (no arguments) now requires the signed manifest
   and bound preflight, rechecks all target/tool/cache inputs, creates a fresh
   Firejail boundary and reruns the negatives before the exact packet wrapper.
   Re-sign only reviewed exact packet/source inputs; do not accept an unknown
   candidate by moving a trust digest. Linux authority is separate from macOS.

Existing runner settings must equal the signed workspace, repository and commit;
HARNESS_WARM_SOURCE_ROOTS equals the exact newline-separated root inventory, or
NONE only for an externally proven empty container. Values never reach packet
commands. No setup script or plaintext administrator password is needed by the kit.

### MET-LINUX-003 layout and custody repair (source candidate only)

The signed V3 policy binds `workspace` to exactly
`/opt/planeon/work/<repository-basename>/<repository-basename>`, where the
basename comes from the validated `inputs.source.repository`. The operator must
verify the pinned GitHub runner binary and its configured work root before
signing. A default or private tracking-file override is not evidence. Root-own
`/opt`, `/opt/planeon` and `/opt/planeon/work`; precreate the two repository
directories, `.git`, the sibling runner directories and the separately hidden
runner home for the dedicated non-root UID without group/world write. The
checkout and runner may write inside precreated children, but cannot unlink or
rename an observed top-level sibling or sentinel under the root-owned work
parent. The launcher rechecks these components with no-follow metadata before
isolation. Inside Firejail's `/opt` whitelist, the synthetic intermediate
repository parent must instead be root-owned/non-writable while the bind-mounted
checkout and `.git` retain the runner UID; their Git
identity, top-level, absolute Git directory and HEAD are verified again inside
isolation. Any alias, changed HEAD,
wrong GitHub context or different checkout path fails closed. Host mount
inventory must have no mountpoint at `/opt`, `/opt/planeon`, or at/beneath
`/opt/planeon/work`; a bind mount cannot substitute an ancestor, checkout or
warm tree there.

Before a native preflight, the operator creates the runner-owned, non-writable-
by-others sibling directories `_temp`, `_actions`, `_tool` and
`_PipelineMapping` under `/opt/planeon/work`, plus a root-owned mode-0444
regular `_planeon-deny-sentinel` there. The root-owned work parent stabilizes
their names while the runner operates. The host verifies their existence and
custody; the isolated preflight must deny read, metadata and write access to
each actual path. An `ENOENT` inside isolation only counts when the path was
observed outside. The exact signed profile blacklists these siblings and
whitelists only the selected checkout. A re-created or changed work root
requires a fresh host observation; no V1/V2 manifest or preflight can be reused.

These changes do not install the candidate, register a runner, close PR #141's
queued CI, or certify stock Debian. A later independent root-owned installation,
signed bundle, pinned tool/cache/image inventory and native negative run are
still required before any one-job listener can take work.
The V3 inventory resolves links only through declared root-owned trees. Include
`/etc/alternatives` when the selected image uses alternatives links; pin its
full inventory along with `/usr/bin`, `/usr/lib` and `/etc/firejail`. A system
alias to an undeclared tree, or a symlinked inventory root such as `/lib`, still
fails. Do not delete or rewrite distribution links merely to manufacture a
candidate PASS. A selected image needing root aliases requires a separately
versioned signed contract before qualification.

## Isolation and evidence semantics

Firejail creates independent network, PID and mount namespaces with no network,
no capabilities and no privilege escalation. Secondary syscall architectures,
new namespaces, socket creation/connect/send, ptrace/process_vm access,
pidfd_getfd and io_uring entry points are blocked. A failed or unsupported
backend never executes unisolated code. Strict socket creation denial means
tools requiring even loopback listeners are not compatible with this offline
profile; live service tests belong behind the separate conformance boundary.

The signed policy carries the exact source-root probe set; no warm-root path
appears in process argv. A private `/srv` view contains only the inert host-observed
placeholder: the real warm container, every warm root and runnerHome must be
absent inside, including under metadata probes. A Firejail blacklist by itself
is insufficient because it leaves the blacklisted path visible. `/opt` is
whitelisted to the selected checkout and pinned tools; the real runner sibling
paths must also be absent inside. Probe paths
are opened only to test access and immediately closed; no source or credential
contents are read, enumerated or written even if a denial unexpectedly fails.
The host observes protected directory roots before isolation, but root mount
points themselves may have visible metadata. No PASS may be inferred from
their metadata; actual sensitive descendants are probed individually.
Tests require EPERM/EACCES for socket denial, never a timeout, route failure,
unsupported address family or DNS failure. IPv4, IPv6, UDP/DNS, loopback, Unix
pathname and abstract socket creation are tested without sending packets.

Only explicitly retained root-owned authority descriptors cross the Firejail
boundary: four for bootstrap probes, seven for normal execution (also manifest,
manifest signature and preflight). The trusted supervisor revalidates identity,
custody, pins and signatures, then closes all of them before repository code.
Ambient FDs are closed; stdin is replaced for packet commands. Supervisor
dumpability is disabled, namespace/proc argv leakage is probed, and a fresh
Python descendant must reproduce the negative controls. A pipe payload or
environment marker alone is never authority.

Exact prefetch and acceptance ordering and per-command packet digest checks
remain in the unchanged digest-pinned ARGV_ARRAY_V1 wrapper/transport. The root
supervisor also rechecks authority after the session and bounds the complete
process lifetime. No separate prefetch or command string is executed. The
unprivileged checkout is not permitted to install or mutate the host launcher.

- **SOURCE_PACKAGE_ONLY**: deterministic bytes, unit/adversarial tests, PR CI.
- **HOST_ISOLATION_ONLY**: fresh actual Linux preflight, independently installed
  and signature-bound. This is not a product image build, live runtime test or
  full native release qualification; nativeLinuxAcceptance remains false.
- **NOT_RUN_ENV_UNAVAILABLE**: non-Linux host or absent signed installation,
  Firejail privilege/backend or required namespace capacity. Do not replace it
  with a synthetic adapter PASS. A malformed signature/configuration or observed
  failed negative is FAIL, not unavailable.
- **CONF-LINUX-001**: separate independent native AMD64 build/runtime/migration/
  RLS/restart/restricted-UID/Kubernetes/deny-all evidence. ARM64 must be qualified
  separately; emulation never qualifies a native target.

On this development Mac the real Linux integration operation is unavailable.
Tests exercise the availability disposition without launching nested Firejail
or probing host authority from repository CI. The actual integration subset is
the external installed `--operator-preflight` followed by normal installed
verification on the named Linux host. Fixtures and source-test totals must never
be reported as those operations having run.

## Roadmap and rollback

| Phase | Packet | Current boundary |
| --- | --- | --- |
| Alpha 2 authority | MET-LINUX-001 | DONE: PR94 / b1d7478; no Linux proof |
| Alpha 1 corrective carryover | CTRL-FIX-003 | DONE: control PR10 / 1de7c40; 698 unit + 6 browser tests and exact-main offline replay |
| Alpha 2 foundation | MET-LINUX-002 | DONE: PR95 / c37f2b7; source candidate only, no installed Linux proof |
| Alpha 2 runner repair | MET-LINUX-003 | DRAFT: signed nested checkout/system-alias source changes; catalog and native qualification gates remain open |
| Alpha 2 qualification | CONF-LINUX-001 | WAITING: independent Linux host/build/runtime evidence |
| Alpha 1 integration | CTRL-INTEGRATE-001 | WAITING: native AMD64 gate |
| Alpha 2 runtime | MODEL-001 / EXEC-001 / RUN-001 | WAITING: native AMD64 gate and own predecessors |

Root installation, native Linux proof and full-phase completion are not outcomes
of this source packet. No model-effort transition is implied. Earlier published
meta tables are immutable historical snapshots; MET-LINUX-003 may change only
its exact declared allowed paths. The separately observed control-repository
branch protection gap remains a governance finding, not permission to edit
settings.

Revert an unconsumed source candidate through a scoped PR. For an independently
installed candidate, the external operator restores the complete previous
signed bundle atomically with recorded permissions/digests and reruns negative
probes. Retain failure logs, signature history and retired bytes; never restore
an expired/revoked authority as if current, mutate admitted tenant data, delete
shared capacity or relax a boundary to complete a run.

## Primary technical references

The [Firejail manual](https://github.com/netblue30/firejail/blob/0.9.76/src/man/firejail.1.in)
and [profile grammar](https://github.com/netblue30/firejail/blob/0.9.76/src/man/firejail-profile.5.in)
document the namespace, seccomp, file-denial and explicit descriptor controls.
Operator-supplied pinned bytes and fresh probes determine actual compatibility.
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) supplies independent
verification test vectors; the candidate does not bundle a signing API.
