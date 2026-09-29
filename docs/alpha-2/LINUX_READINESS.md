# Early Linux readiness — MET-LINUX-001

> Current source/native timing is superseded for `CTRL-INTEGRATE-001`,
> `MODEL-001`, `EXEC-001` and `RUN-001` by
> [MET-UNIFY-008](SOURCE_NATIVE_GATE_STAGING.md). Those packets may code and
> test offline after their other predecessors. This historical Linux campaign
> and its mandatory native AMD64 evidence remain required before Linux release
> deployment, runtime qualification or promotion; `NOT_RUN_ENV_UNAVAILABLE`
> is not PASS. Campaign-scoped test deployment is separately signed and is not
> a release deployment.

Status: roadmap authority, not Linux execution evidence. Published in Alpha 2
after the contracts correction. The platform targets Linux; macOS remains a
supported development workstation, not an enterprise runtime dependency.
Thirteen repositories and sixteen harnesses are unchanged. The queue grows
from 115 to 118 packets, not to additional repositories or harnesses.

## Ordered work and gates

| Phase | ID | Status at publication | Owner and acceptance |
|---|---|---|---|
| Foundation correction | CON-FIX-001 | DONE — source/CI/merge/local exact-main | Contracts PR 8; 758 tests, no skips; no Linux claim |
| Alpha 2 authority | MET-LINUX-001 | ONGOING | This publication, closed policy, packet boundaries and regression tests |
| Alpha 1 correction, carried into Alpha 2 | CTRL-FIX-003 | WAITING — next product packet | Read-time freshness, portfolio and status parity; may use the current macOS offline runner |
| Alpha 2 foundation | MET-LINUX-002 | WAITING | Portable trusted Linux launcher candidate and operator build/preflight kit |
| Alpha 2 early Linux gate | CONF-LINUX-001 | WAITING | Source-tested campaign, then independently authorized native Linux evidence |
| Alpha 1 integration, carried into Alpha 2 | CTRL-INTEGRATE-001 | WAITING — fresh Linux gate | Durable authenticated production overview |
| Alpha 2 contracts | CON-MODEL-001 | WAITING — corrections | Contract-only work may proceed after its existing predecessors; no runtime claims |
| Alpha 2 runtime | MODEL-001, EXEC-001, RUN-001 | WAITING — fresh Linux gate | Model, execution and edge implementations |
| Alpha 4 | CONF-K8S-001, CONF-OCP-001, CONF-K3S-001, CONF-AIR-001, CONF-SEC-001, CONF-UPG-001, CONF-WG-001 | WAITING | Full platform matrix, physical air gap, upgrades, assurance and tenant acceptance |

The exact DAG and displayed ordering are in the packet catalog. Each row is
independent work: one packet, branch and PR. Publishing this plan does not
authorize combining meta and product implementation in one coding run.

## Fail-closed runtime coding gate

Before dispatching CTRL-INTEGRATE-001, MODEL-001, EXEC-001 or RUN-001, require
both merged source prerequisites and independently verified CONF-LINUX-001
native Linux AMD64 PASS. Source-kit completion with
NOT_RUN_ENV_UNAVAILABLE does **not** open this stricter gate. It is safe to
continue the named pure corrections/contract exceptions while Linux capacity
is unavailable; do not silently advance runtime coding.

The early gate tests a pinned, already implemented foundation/control/contracts
baseline, not the not-yet-built model/execution/runtime repositories. Their
subsequent artifacts must each earn their own Linux evidence. This avoids a
circular dependency and does not grandfather untested later images.

Evidence is current only within 168 hours of observation, before all signature
expirations, against the exact tested baseline, image, host/isolation, toolchain,
cache and trust state. Changed inputs, revocation or a failing required case
invalidate the affected qualification immediately. Bind an explicit baseline
release digest when dispatching a successor; the successor's new code is not
covered by that baseline result.

The JSON in architecture/linux-readiness.json is an immutable publication
snapshot. Its WAITING states are deliberate, not a live dashboard. Actual
execution records belong to the independently signed conformance evidence
store; a later reviewed checkpoint may reference them without rewriting history.

## Platform and build matrix

| Target | Required proof | What it does not prove |
|---|---|---|
| macOS workstation | Existing source/offline/CI gates | Linux isolation, ELF/native dependencies, container runtime or enterprise acceptance |
| Native Linux AMD64 | Mandatory early baseline build, isolation and runtime PASS | ARM64, GPU availability, every distro or cluster version |
| Native Linux ARM64 | Separate PASS before ARM64 release/support claims | AMD64, even when a multi-platform manifest exists |
| Emulated Linux target | Label emulator, target and host separately; useful supplemental tests | Native qualification or performance |
| OpenShift and other enterprise targets | Early arbitrary-UID checks plus later real target certification | A local Kubernetes smoke is not OpenShift SCC/Route certification |

Use only existing authorized zero-incremental-cost capacity. A local Linux VM
on Apple silicon is an ARM64 target unless explicitly emulated; it cannot be
relabeled native AMD64. No cloud instance, hosted runner, new broker, paid key,
registry egress charge or automatic package/image pull is authorized. Missing
hardware, preloaded tooling, OS isolation or independent signers remains
NOT_RUN_ENV_UNAVAILABLE. Request a concrete capacity/input decision only if it
is necessary; standing localhost runner permission need not be requested again.

Build each release from an exact owned-product source tree in its Linux target.
Pin OS/architecture/libc, base image digest, compiler/Node/Python versions,
lockfiles, local caches and build recipe. Do not carry macOS node_modules,
.next/standalone, virtualenvs, native wheels or Mach-O binaries into Linux
images. Next.js standalone output is built inside the Linux build environment;
Go executables must match Linux ELF and the declared target architecture.
Keep MLX development-only. GPU backends need their own hardware/driver matrix.
Missing target-specific cached dependencies blocks a build; no download fallback.

## MET-LINUX-002 implementation contract

1. Implement ci/linux-runner/launcher.py, build.py and preflight.py using only
   preinstalled locked standard-library tooling. Produce reproducible candidate
   bytes, SHA-256 inventories and a human-readable operator installation plan.
2. Preserve the current trusted-runner manifest schema and fixed launcher path.
   Verify Ed25519 signature, root custody/modes, exact packet, exhaustive source
   deny roots, cache inventory and direct-argv ordering before repository code.
3. Implement Linux Firejail isolation and negative probes for outbound IPv4/IPv6,
   DNS, loopback, child processes, credential homes/environment, broker/agent/
   container sockets, source read/metadata/write and packet/manifest tampering.
   Missing backend or namespace capability is unavailable, never a soft fallback.
4. Keep preparation and acceptance in one isolated process tree, scrub protected
   paths before children and recheck packet digest after every command. Do not
   mount or inspect warm-source contents to run probes.
5. Unit-test dispatch and malformed inputs independently from real Linux probe
   results. Package build repeatability and source tests do not constitute
   root installation or successful host preflight.

The external operator reviews and installs exact signed bytes with a preserved
rollback. Repository CI never performs privileged installation. Existing macOS
runner authority is not Linux authority. No stored administrator password,
interactive prompt automation or broad passwordless sudo grant is introduced.

## CONF-LINUX-001 implementation contract

Implement a fixed LINUX_READINESS handler, closed evidence schema and additive
integration through the packet's exact campaign/CLI/schema/live-context files.
Preserve every existing handler and all predecessor tests. No campaign-provided
module, executable or arbitrary command/URL is admitted.

The selected pre-existing foundation release must identify exact contracts,
control, database and Kubernetes artifacts. The independently installed
operator build/probe kit supplies fixed operations through the signed
CAMPAIGN_PROXY or KUBERNETES_API_PROXY, never a raw Docker/CRI socket. If that
reviewed proxy/kit is absent, report unavailable; building or provisioning a
new server is outside this packet and needs an owning packet before execution.

Required case IDs are closed in the policy:

- HOST_ISOLATION_NEGATIVES and LINUX_TARGET_BUILD: fresh Linux launcher preflight,
  target-local dependency build, image/SBOM and complete build-log digests.
- FULL_PREDECESSOR_REGRESSION: all suites for the selected baseline on Linux;
  no golden-case removal, xfail or hidden deselection.
- CONTROL_CONTAINER_STARTUP: standalone Next.js server starts from the declared
  image with health/readiness responses and no runtime downloads or telemetry.
- POSTGRES_MIGRATION_AND_RLS and DURABLE_RESTART: isolated disposable fixture
  namespace/database, migration forward/idempotency, two-tenant negative access,
  restart and persisted records. Never use or destroy real tenant data.
- ARBITRARY_NON_ROOT_UID and READ_ONLY_ROOT_FILESYSTEM: non-root random UID,
  no root requirement or hard-coded writable home, dropped capabilities,
  seccomp and only declared writable volumes.
- KUBERNETES_SMOKE and DEFAULT_DENY_NETWORK: pre-existing namespace/quota,
  server-side zero-cost admission, startup/readiness and denied undeclared
  egress. Cleanup affects only run-labelled resources within that authority.

Every record binds packet, release, source/image, OS/kernel/architecture/libc,
toolchain/cache/build recipe, host preflight, probe/command and output digests,
tenant/environment, run nonce, timestamps and independent signatures. Require
all mandatory cases and compare exact expected digests; a caller's
signatureVerified=true or capabilities.linux=true is not verification.
Replay, mismatched endpoint/image, stale/expired records, invalid signer purpose,
revocation, malformed types, missing cases and unverified digests fail closed.
Absent authorized context is NOT_RUN_ENV_UNAVAILABLE; an executed bad case is
FAIL. WARN, NOT_APPLICABLE and missing cases cannot satisfy this mandatory gate.

The only live entry point remains the external root-owned launcher with the
existing independent PLATFORM_RELEASE, TENANT_LIVE_EXECUTION and
CAPACITY_OPERATOR authorities. PR execution tests fake transports only and
must never claim real runtime PASS. Live source/fixtures cannot self-certify.
No campaign signs actual tenant acceptance.

## Verification and rollback

MET-LINUX-001 runs seven declared argv commands through the signed offline
launcher: full readiness/reuse/model/repair/Linux validators, the whole meta
suite and zero-bill scan. Negative vectors protect the gate, exact packet
boundaries, architecture/native distinctions, predecessor evidence and billing.

Keep source, local offline, required CI, merge, exact-main, artifact/SBOM,
release, Linux installation/runtime and tenant acceptance separate. Full
Alpha-4 acceptance remains waiting. Revert an unconsumed publication as one
unit; after consumers start, use a new reviewed superseding authority.
Do not erase failure logs, silently reverse migrations or destroy capacity.
