# Repository Plan: `mas-harness-distribution`

## Sector direction — MET-SECTOR-001

Owner decision SECTOR-D1 (October 7, 2026): banking replaces white goods as the first and only release
sector from Alpha 2 through the first enterprise release; [sector direction](../alpha-2/SECTOR_DIRECTION.md)
gives every disposition. The banking provider-profile recommendations in the modular Helm profiles and the
banking pack digest binding move to the unpublished proposal `DIST-BANK-001`, which follows `IND-BANK-004`.
The white-goods provider-profile recommendations and pack digest binding of `DIST-004` are historical; its
modular Helm profiles are kept. This plan never named white goods; MET-SECTOR-002 adds this notice
(SECTOR-001 review finding m1).

## Current reviewed interface candidate — MET-ENFORCE-003

[W01 reviewed candidate and unresolved gates](../alpha-2/HOST_INTERFACE_PUBLICATION.md): Alpha2 ONGOING.
MET-PERF-018 DONE_SOURCE_GATES at fe771b2 / PR137; all gates retained.
PR136 / MET-ENFORCE-002 remains blocked with two LOCAL attempts consumed.
This explicit successor reconciles reviewed source on repaired main; no reset or old retry.
MET-ENFORCE-003 ONGOING_SOURCE_PUBLICATION: 188 specifications; 187 prior packets immutable.
W01 ONGOING_DESIGN: independent source-only review passed after G09 correlation correction.
No adopted ABI, selected writer backend, installed gate or native qualification.
G04-G07 and G09 remain open; all E01-E12 OPEN_UNPROVEN; W02-W07 not dispatchable.
CONF-FIX-009 BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED; CONF-FIX-010 BLOCKED_SAFE_DESIGN, zero attempts.
CONF-LIVE-004/005/006 and CONF-A2-001 WAITING; Alpha3/4 WAITING; effort NOT_DUE.
Preserve the [all16 harness/paper/OSS map](../alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md).
Earlier headings are historical checkpoints, not current dispatch authority.

## Retained planning and historical checkpoints

## Current validation repair — MET-PERF-018

[Single-traversal catalog repair](../alpha-2/CATALOG_TRAVERSAL_REPAIR.md): Alpha2 ONGOING.
MET-ENFORCE-001 DONE_SOURCE_GATES at cdb71ae / PR135; exact-main evidence retained.
MET-PERF-018 ONGOING_SOURCE_REPAIR:187 specifications;186 accepted predecessor packets immutable.
Draft PR136 / MET-ENFORCE-002 remains BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED; not imported or retried.
Repair duplicated META catalog traversals without caching authority or skipping fresh checks.
W01 ONGOING_DESIGN; W02-W07 not dispatchable; all E01-E12 OPEN_UNPROVEN.
CONF-FIX-009 BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED; CONF-FIX-010 BLOCKED_SAFE_DESIGN, zero attempts.
CONF-LIVE-004/005/006 and CONF-A2-001 WAITING; Alpha3/4 WAITING; effort NOT_DUE.
Preserve the [all16 harness/paper/OSS map](../alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md).
Earlier headings are historical checkpoints, not current dispatch authority.

## Retained planning and historical checkpoints

## Current enforcement ownership amendment — MET-ENFORCE-001

[Host enforcement ownership and interfaces](../alpha-2/ENFORCEMENT_INTEGRATION.md): Alpha2 ONGOING.
MET-REPAIR-019 DONE_SOURCE_GATES at69dceab / PR134; separate exact-main evidence retained.
MET-ENFORCE-001 ONGOING_SOURCE_PUBLICATION:186 specifications;185 prior packets immutable.
R10 owns four planned host modules, separate from the nonroot Kubernetes controller.
Delegated-cgroup profile direction selected for a later versioned ABI; current contracts unchanged.
CONF-FIX-009 BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED; CONF-FIX-010 BLOCKED_SAFE_DESIGN, zero attempts.
All12 enforcement obligations OPEN_UNPROVEN; W01 exact interface specification is next.
CONF-LIVE-004/005/006 and CONF-A2-001 WAITING; Alpha3/4 WAITING; effort NOT_DUE.
Preserve the [all16 harness/paper/OSS map](../alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md).
No product execution, installed enforcer selection, native or tenant acceptance.
Earlier headings are historical checkpoints, not current dispatch authority.

## Retained planning and historical checkpoints

## Current research-led implementation direction — MET-ADOPT-002

[Harness / paper / upstream repository map](../alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md)
is the current reuse-first planning amendment. It covers all16 canonical harnesses
and preserves the four planes and13 repository owners. Catalog:166 packet specifications;
all165 predecessor YAML remain byte-immutable. Proposed provider-adoption work is
non-dispatchable until exact successor packets, contracts and offline locks are published.
Require **at least one qualified baseline for every released harness capability** at the first enterprise release.
META source publication is not OSS provider implementation or qualification.
Alpha2 ONGOING: MET-ADOPT-002 ONGOING; CONF-FIX-007 PAUSED_RESEARCH_AMENDMENT.
CONF-LIVE-004 WAITING_PREDECESSOR_CORRECTION; completion C1-C7 and all independent
source gates remain mandatory. No native/tenant promotion or budget reset; effort NOT_DUE.

Repository R11 retains its existing accountable ownership. Shared responsibility: package selected approved OSS artifacts, offline transitive closure, SBOM and notices.
No new repository, source import or cross-repository implementation is authorized here.

## Retained implementation specifications and historical checkpoints

## Current adoption roadmap — MET-ADOPT-001

[Product/provider and multi-repository policy](../alpha-2/PROVIDER_ADOPTION_ROADMAP.md) is the current planning amendment.
Catalog:156 executable packet specifications (155 retained plus this meta packet);
seven extension backlog specifications remain non-dispatchable pending exact
packet/path/argv and accepted predecessor release-lock publication.
Require **at least one qualified baseline for every released harness capability** at the first enterprise release.
Alpha2 remains ONGOING. CONF-LIVE-003 draft is incomplete; native Linux is
NOT_RUN_ENV_UNAVAILABLE. Source, CI, merge, artifact and tenant acceptance differ.
The linked ownership table and machine ledger are normative for provider work;
existing public schemas, service ownership and prerequisite gates remain intact.

## Retained plan and historical publication checkpoints

## Purpose and boundaries

This repository composes a locked tenant profile into a minimal signed OCI bundle that references only selected module images/charts and requested CPU architectures. It owns Helm composition, local OCI layout, SBOM/license/vulnerability evidence, air-gap export/import, offline verification, and release promotion.

Non-goals:

- No product service implementation, tenant-specific mega-image, cluster apply, cloud registry/account creation, source repository modification, model-license assumption, or online-only release path.
- CI may build and scan candidates but cannot access the offline release private key.
- Bundle closure never depends on runtime downloads.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-distribution/
├── .github/workflows/verify.yml
├── .gitignore
├── AGENTS.md
├── CONTRIBUTING.md
├── LICENSE
├── NOTICE
├── README.md
├── SECURITY.md
├── PORTING.yaml
├── Makefile
├── pyproject.toml
├── uv.lock
├── toolchain.lock
├── ci/
├── cmd/harness-bundlectl/
│   ├── export.py
│   ├── import.py
│   ├── sign.py
│   └── verify.py
├── src/planeon_distribution/
│   ├── airgap.py
│   ├── builder.py
│   ├── helm.py
│   ├── licenses.py
│   ├── model_custody.py
│   ├── oci.py
│   ├── promotion.py
│   ├── relocation.py
│   ├── resolver.py
│   ├── sbom.py
│   ├── signing.py
│   └── vulnerabilities.py
├── charts/
├── profiles/
├── schemas/
│   └── bundle-lock.schema.json
├── policies/
├── trust/
├── fixtures/{airgap,attacks,helm,oci-layout,profiles,signing,supply-chain}/
├── scripts/{rebuild_compare.sh,render_profiles.sh,run_supply_chain_campaign.py}
├── docs/
│   ├── airgap.md
│   ├── key-rotation.md
│   ├── oci-bundle.md
│   ├── profiles.md
│   ├── release-ceremony.md
│   ├── supply-chain.md
│   └── runbooks/
└── tests/{airgap,bootstrap,build,helm,reproducibility,resolve,security,signing,supply-chain}/
```

## Package, toolchain, and interfaces

- Distribution/import/CLI: `planeon-harness-distribution` / `planeon_distribution` / `harness-bundlectl`.
- Python 3.12.14, `uv` 0.12.7, cryptography, jsonschema, PyYAML, and OCI-layout libraries frozen in `uv.lock`.
- External tools pinned by version and SHA-256 in `toolchain.lock`: Helm 4.2.0, Cosign 3.1.3, ORAS, Syft, Grype, and platform tools. Prefetch obtains them once; offline verification uses local binaries/databases only.
- Owned APIs, events, and stores: no service API, production event stream, or database. Inputs/outputs and release-state transitions are immutable files/OCI evidence artifacts.

Media types:

```text
application/vnd.planeon.harness.bundle.v1+json
application/vnd.planeon.harness.profile.v1+json
application/vnd.planeon.harness.module.v1+json
application/vnd.planeon.harness.evidence-plan.v1+json
```

`bundle.lock.json` records every blob's digest, size, media type, platform, source, license, SBOM digest, vulnerability evidence, and signature reference. Bundle ID is the SHA-256 digest of canonical `bundle.lock.json`.

CLI surface:

```text
harness-bundlectl resolve
harness-bundlectl build
harness-bundlectl scan
harness-bundlectl sign
harness-bundlectl verify
harness-bundlectl export-airgap
harness-bundlectl import-airgap
harness-bundlectl relocate
harness-bundlectl promote
```

## Task-command ownership

The bootstrap packet is the sole current owner of `Makefile` and installs the
closed `ci/run_make_target.py` direct-argv dispatcher. Each later Make-using
packet owns only `ci/targets/<lowercase-packet-id>.json`, which registers its
exact targets, closed variable values, and packet-local handlers. The dispatcher
validates descriptors and executes every applicable handler cumulatively in
lexical packet order; missing, ambiguous, duplicate, undeclared-variable, or
shell-based handlers fail closed. Later packets never edit `Makefile`. The only
exception is the generic `campaign`, `evidence-verify`, and
`acceptance-package` dispatch owned and tested by `CONF-001` for conformance
campaign packets.

The same bootstrap packet is the only current owner of `PORTING.yaml` and
seeds a closed `NO_AUTHORIZATION` ledger. Reference/discovery-only packets cannot
edit it; a future copy transaction requires a revised `PORT_CANDIDATE` packet.

## Dependencies

- Contract/source and build-artifact graph: locked contracts/catalog schemas only; distribution never imports operator or plane implementation source.
- Release-set graph: already released operator image/chart/CRD, selected plane manifests/images/charts, signed industry packs, SBOMs, vulnerability evidence, licenses, and model custody records are pinned by version and digest.
- Runtime integration: none while building. After bootstrap, the independently installed operator consumes the verified workload bundle; distribution is not a runtime service.
- Downstream: operator installs/verifies released bundles; conformance verifies closure/airgap; meta repository locks released digest.
- No dependency on GitHub, public OCI registry, public chart repository, or control-plane service at install time.

Bootstrap is phase-ordered: the operator builds/releases independently; this repository then assembles a release set that pins that operator and selected workload artifacts; bootstrap installs the pinned operator; the installed operator verifies/applies the workload portion. The apparent `distribution → operator` release-set edge and `operator → distribution` runtime-integration edge belong to different typed DAGs and create no source/build cycle.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `DIST-001-bootstrap-tools`: CLI, toolchain lock/prefetch, schema validation, local OCI-layout fixture, and no-network test harness.
2. `DIST-FIX-001-cumulative-make`: bounded bootstrap correction making future descriptor-owned targets reachable without changing the closed dispatcher or existing argv.
3. `DIST-OCI-001-resolve-build`: exact module/platform closure, Helm vendoring, digest fetch, canonical lock, staging state, and minimal-profile proof.
4. `DIST-002-supply-chain`: SPDX SBOM, license allow/deny, offline Grype DB/scan, model custody, vulnerability disposition, and evidence references.
5. `DIST-003-sign-promote`: offline Ed25519 Cosign ceremony, component/root signatures, public-key rotation/overlap, revocation, atomic promotion, and candidate/released separation.
6. `DIST-AIR-001-export-import`: OCI layout archive, checksums, signatures/trust/SBOM/licenses/vulnerability DB/model manifest, physical offline verification/import, and relocation digest proof.
7. `DIST-004-helm-profiles`: minimal ARM64/AMD64, regulated OCP, bridge/silo, and air-gap profile charts with exact selected subcharts only. Banking profile recommendations and the banking pack digest move to the unpublished proposal DIST-BANK-001 (SECTOR-D1).
8. `DIST-005-repro-security`: two-clean-build digest match, corrupt/missing/extra blob denial, path traversal/archive bombs, compromised staging, and key-revocation drills.

## Testing, verification, and acceptance

The `DIST-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","fixture-verify"],["make","zero-bill"]]`.
Later packets add unit, contract, closure, offline scan, air-gap round-trip,
security, and reproducibility checks as direct argv arrays. The executor
supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

Acceptance: the minimal profile contains no unselected harness/provider/platform blobs; two clean builds are byte/digest reproducible; signatures verify with public key and no network; corrupt, extra, mutable, unlicensed, vulnerable-without-disposition, or revoked content is rejected; relocation preserves digests; runtime dependency/model fetch attempts are impossible.

## Release and rollback

- Candidate lifecycle: `DRAFT → RESOLVED → BUILT → SCANNED → AWAITING_SIGNATURE → SIGNED → RELEASED`; alternatives `FAILED`, `SUPERSEDED`, `REVOKED`.
- Private signing key stays offline. Release promotion creates an immutable released reference; no overwrite.
- Rollback builds or selects a previous released bundle digest. Revoked bundles cannot be restored. Export archives are append-only and checksum-addressed.

## Zero-bill rules

- Default target is local OCI layout/local registry supplied by the operator. No GHCR/GitHub Packages/cloud registry, cloud KMS, transparency-service requirement, remote scan API, or cloud storage.
- No hosted runners, GitHub caches/artifacts, scheduled builds, remote
  package/model download during either prefetch or offline acceptance, external
  telemetry, or API keys. Prefetch uses only the preprovisioned local cache.
- A connected operator may supply its own registry endpoints, but credentials are passed by reference and never stored in locks or logs.
