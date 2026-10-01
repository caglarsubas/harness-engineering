# Harness-Onion — unified development roadmap

Current source baseline: `945de93f89c94f42f1d63bff7997e3d0fa704fc4` on accepted main, the merge of MET-UNIFY-005 PR #140. Alpha 2 remains **open**. `MET-RUNNER-001` is a source-only development-CI capacity exception candidate, not an installed runner or permission to provision one. As observed on September 29, 2026, [PR #141](https://github.com/caglarsubas/harness-onion/pull/141) and [draft PR #142](https://github.com/caglarsubas/harness-onion/pull/142) have queued self-hosted `verify` jobs and the repository has zero registered runners. Their source/CI/merge, Linux native and tenant-acceptance evidence remain separate. The [bounded exception](alpha-2/CI_CAPACITY_EXCEPTION.md) requires an independently authorized cost ceiling, a separately reviewed and installed exact-job pre-checkout admission boundary, queue serialization, a qualified Linux guest and verified teardown; this publication supplies none of those operational facts. The next source packet is MET-RUNNER-001, while native AMD64 qualification and the W01/Alpha-2 product gates remain waiting.

The next paragraph is the retained pre-PR-140 source checkpoint, not current dispatch or completion status.

Accepted source baseline: 7a353b253bb257aa0abe2148e7fa62d7570f0b5a (PR #138). The roadmap-publication successor is MET-UNIFY-005; its presence in this branch is source work, not merged acceptance. The unpublished MET-UNIFY-001 local candidate at `2cb0b949ee82` exhausted LOCAL-1 and LOCAL-2. The separate unpublished MET-UNIFY-002 candidate exhausted LOCAL-1/2/3; its last isolated suite exposed a stale inherited 204-file assertion after the current YAML corpus became 205. Unpublished MET-UNIFY-003 [PR #139](https://github.com/caglarsubas/harness-onion/pull/139) passed LOCAL-1, then consumed CI-1 on a GitHub API failure before runner registration and CI-2 on a 15-minute cancellation; its runner was retired with zero registrations remaining. The CI log has a failure marker about 420 seconds after the nested predecessor test began, but cancellation prevented a final traceback; pytest was still active when the job stopped. Unpublished MET-UNIFY-004 local commit `8dbfdac` failed LOCAL-1 on a status-document packet-ID check and LOCAL-2/3 at the unchanged 750-second ceiling during outer pytest; no 004 CI or PR was started. These four candidates and their receipts remain historical evidence, none is a merged predecessor or the live 189th packet, and no allowance transfers to MET-UNIFY-005. Current development phase: **Alpha 2, open**. This page is the single current roadmap and progress entry point. The [indexed source crosswalk](alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md), [accepted source index](../architecture/unified-roadmap-source-index.json), and [exact preceding master](history/master-development-plan-7a353b2.md) retain the implementation detail and history.

## Product goal and first enterprise release

Build an Apache-2.0, modular harness platform that guides an enterprise from business understanding and reliable data to governed agents, evidence and acceptance. The platform must operate on tenant-owned Linux Kubernetes, K3s on existing VMs and OpenShift, including a physically disconnected environment. The same contracts can support operator-hosted SaaS or tenant public cloud on **pre-authorized existing capacity**. macOS is for development; Linux AMD64 and ARM64 need separate native qualification.

The architecture has **four planes, sixteen harnesses and thirteen repositories**. The model is a swappable core dependency, not a fifth harness plane; the administrative control plane is not H17. Every harness has one accountable repository owner. Harnesses in one repository may still have separate processes, images, configuration, permissions, stores, lifecycle and failure scope. The 28 canonical service records are a service inventory, not a count of all images, providers or privileged host components.

Require **at least one qualified baseline for every released harness capability** at the first enterprise release. All sixteen harnesses remain targeted in the Alpha-4 capability floor. A release deferment must identify the source requirement, affected capability, owner, phase and accepted disposition; it cannot silently shrink scope. Qualification binds exact provider/adapter version, capability, integration mode, deployment environment and independent evidence. Multiple alternatives can qualify. Progress toward three or four meaningful options per harness over subsequent waves; these are role-specific compatibility relationships, not 64 mandatory first-release technologies.

No cloud-account creation, billable provisioning, hosted-runner dependency, paid API, API-key requirement, runtime package/model download, external telemetry default, online license check or mutable artifact reference may enter the platform. Existing capacity and locally pinned open-source dependencies are required. The separately governed MET-RUNNER-001 exception concerns one externally operated development-CI guest only; it does not change this product rule or grant a VM, runner or CI PASS. An authorized, already-licensed on-premises external target may be attached only with demonstrated zero incremental charge; the platform cannot redistribute its proprietary code or manage its lifecycle.

The five original warm-start repositories remain untouched and reference-only under the existing source-reuse policy. No product implementation task may open, mount, execute or copy from them. Public endpoint attachment is not source-copy authority. A later import would need separately approved path-level legal and packet authority.

## Guided establishment and deployment

The common industry journey has eight ordered gates:

1. Deployment sovereignty and tenant isolation.
2. Business outcome, owner, workflow and measurable KPI.
3. Risk, regulation, classification and autonomy.
4. Domain vocabulary and canonical entities.
5. Data ownership, quality, completeness, freshness, provenance and access.
6. Integrations, protocols, credentials, tools and side effects.
7. Retrieval, memory, model, ML and orchestration requirements.
8. SLO, recovery, observability, evaluation and tenant acceptance.

The first sector pack is white goods. Sector overlays append to the common journey; tenant-specific answers determine applicable controls, technology and readiness. A mandatory predecessor finding that is OPEN, FAIL or STALE blocks dependent approval. Production control waivers document exceptions but never replace fresh required PASS evidence.

The UI and file workflow share the same schema and deterministic compiler:

**Questionnaire or YAML → TenantDemand → locked profile → reviewed change plan → signed minimal bundle → HarnessInstallation → observed status and evidence.**

The compiler produces exactly six outputs: profile.json, bom.json, install-plan.json, evidence-plan.json, explanation.md and profile.sha256. An active exclusive provider group requires one explicit accepted selector; a recommendation never chooses silently. Bundle composition includes only selected modules and their dependency closure. The current 87-record provider/module catalog is PLANNED: 59 packet-owned implementation dispositions, 23 tenant-supplied external records and five non-installable CONTRACT_ONLY entries. Missing release digests prevent installation or qualification.

| Integration mode | Platform responsibility |
|---|---|
| Built-in, platform managed | Install and manage a qualified provider only inside authorized existing infrastructure. |
| Built-in, externally operated | Manage the approved adapter and binding; preserve tenant ownership of the existing service. |
| Tenant custom adapter | Supply contracts, SDK, isolated artifact admission and independent conformance; tenant engineering owns the integration. |

Custom adapters are separate signed workers/services. They cannot shadow a core provider, run inside the administrative control plane, grant permissions, waive controls or certify tenant acceptance.

## Ownership and dependency policy

| R | Repository | Harnesses or cross-harness responsibility |
|---|---|---|
| R00 | harness-onion / Harness-Engineering | Architecture, planning, taxonomy, packets and release coordination |
| R01 | mas-harness-contracts | Public APIs, events, guidance rules, compiler, compatibility vectors |
| R02 | mas-harness-sdks | Python/TypeScript clients and adapter developer interfaces |
| R03 | mas-harness-industry-packs | Sector journeys, quality/regulatory guidance and fixtures |
| R04 | mas-harness-control-plane | Next.js setup, authenticated tenant overview, plane/harness detail pages |
| R05 | mas-harness-runtime-plane | H3 AI Gateway; H4 Experience & Interaction |
| R06 | mas-harness-model-plane | H2 Model & Inference within the runtime plane |
| R07 | mas-harness-knowledge-plane | H5 Domain; H6 Data Integration; H7 Retrieval; H8 Memory |
| R08 | mas-harness-execution-plane | H9 Protocol; H10 Orchestration; H11 Tools/Sandbox; H12 ML/Decision |
| R09 | mas-harness-trust-plane | H13 Security; H14 Governance; H15 Observability; H16 Assurance |
| R10 | mas-harness-operator | H1 Infrastructure & Runtime, including separately governed host modules |
| R11 | mas-harness-distribution | Minimal OCI assembly, locks, SBOM/license closure and air-gap transfer |
| R12 | mas-harness-conformance-labs | Independent compatibility, native, security, lifecycle and acceptance-candidate evidence |

The [repository graph](../architecture/repositories.yaml), [taxonomy](../architecture/taxonomy.yaml), [service catalog](../architecture/services.yaml), [provider catalog](../architecture/providers.yaml) and [runtime dependency graph](../architecture/dependency-graph.yaml) remain their machine authorities. Arrows mean consumer → provider. Keep contract-source, build-artifact, release-set and runtime-integration edges separate; unconditional graphs stay acyclic. The sole assurance callback exception never permits a source/build cycle.

Release contracts and compatibility vectors first, then SDKs/packs, affected services/operator, exact distribution set and independent conformance. Each cross-repository feature has one parent outcome and separate exact owner packets. A packet is one branch/PR with allowed paths, accepted predecessor versions/digests, direct-argv isolated acceptance, finite attempts and rollback. Repository merge is not harness qualification. R01 owns public contracts; R09 owns authoritative provider registry/promotion; R04 presents their management projection; R10 reconciles the verified installation; R11 packages; R12 qualifies.

The browser reads authenticated control-plane projections and never fans out to all planes. The control plane is outside the synchronous agent request path. The runtime gateway calls the selected model route or task orchestration; it does not retrieve data, assemble context or execute tools. Every service owns its durable state and migrations; no service writes another service’s database schema.

## Provider and research direction

The [provider adoption source](alpha-2/PROVIDER_ADOPTION_ROADMAP.md) retains the `MET-ADOPT-001` policy and its detailed alternatives. It is a historical/detail authority for those decisions, not a second current progress roadmap.

The [sixteen-row research map](alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md) and [adoption ledger](../architecture/research-adoption.json) identify papers, OSS upstreams, owner repositories, proposed packets and qualification gates. They are planning research, not evidence that a provider is installed. At least one qualified provider for each released capability is required; an internal module alone does not satisfy an OSS adoption claim. Preserve later alternatives in the [traceability crosswalk](alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md).

Initial directions include Ollama, llama.cpp and vLLM for H2; LiteLLM’s reviewed open-source compatibility surface for H3; AG-UI/CopilotKit for H4; RDFLib/pySHACL, Trino/Great Expectations/OpenLineage, LlamaIndex/pgvector and a governed memory candidate for H5–H8; MCP/A2A, a separately decided Temporal transition, Wasmtime/gVisor/Kata and local ML/optimization libraries for H9–H12; OPA/Presidio, MLflow integration, OpenTelemetry/Prometheus and Inspect for H13–H16. Milvus external attachment is a later retrieval option before any managed-installation proposal. Ollama attachment to the existing endpoint and managed installation require separate qualification. Framework fake-surface tests do not qualify pinned upstream packages.

Before building another general-purpose router, serving, workflow, retrieval or evaluation engine, publish a measured build-versus-integrate ADR. Failed upstream qualification leaves that option unqualified; it is not permission for unreviewed bespoke replacement. The existing PostgreSQL durable-execution source stays historical while R08 decides the Temporal successor, migration, history replay and single side-effect authority. H12’s competing prose API paths are **INTERFACE_NOT_PUBLISHED** until R01 releases a versioned decision contract and compatibility vectors. Closed-schema consumers require old/new vectors even for additive fields and retain the one-minor migration window.

Jev-style typed semantic judgment is an **optional proposal** across selected existing harnesses, not a fifth plane or H17. The official hosted proprietary Jev model is outside the shipped air-gapped, zero-bill baseline. Laya and SemIF require their own open-weight, license, backend, tokenizer, calibration, domain/language, abstention and independent qualification review; neither is currently selectable. Semantic scores may advise classification, route choice, retrieval relevance, memory proposals, decision features or evaluation. Deterministic policy, budgets, side effects and promotion retain authority. The proposed SEM packet IDs remain unpublished.

After the first enterprise release, consider E1 governed evidence-to-improvement, E2 optional behavior/taste distillation and E3 separately approved reinforcement-learning research. Operational evidence, user memory and eligible training data remain distinct; no trace becomes training input or promoted runtime behavior automatically.

## Phase roadmap and current position

The following is a **source-status checkpoint**, not proof of installed runtime or tenant acceptance. PR #138 placed MET-ENFORCE-003 on accepted source main. Its old “ongoing publication” headers are historical. Alpha 2 is still open.

The [item-level backlog](../architecture/unified-roadmap-backlog.json) records phase, owner, status, predecessors, blocker and planned evidence reference for every published packet and proposal; the [requirement dispositions](../architecture/unified-requirement-dispositions.json) join indexed source sections to ownership and unresolved delivery mappings. All accepted source sections now have reviewed delivery and acceptance-plan dispositions; 38 explicit unresolved markers retain actual future design, packet, native-qualification or provider obligations. They do not count as implementation or acceptance, and the affected work cannot advance until its exact owner packet closes them.

| Phase | ID or workstream | Current status | Deliverable / blocking fact |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundation packets | DONE_RECORDED | Historical source/offline foundation; installed-foundation and production-overview evidence are separate carryovers |
| Alpha 2 preparation | MET-ENFORCE-003 | MERGED_SOURCE_RECORDED | PR #138 on accepted main; reviewed W01 candidate remains a design, not a native enforcement proof |
| Alpha 2 preparation | MET-UNIFY-001 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Unpublished failed local candidate; two LOCAL attempts consumed, no PR/CI/merge or budget transfer |
| Alpha 2 preparation | MET-UNIFY-002 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Unpublished candidate; three LOCAL attempts consumed, stale 204-file assertion retained |
| Alpha 2 preparation | MET-UNIFY-003 | BLOCKED_CI_ALLOWANCE_EXHAUSTED | PR #139 unmerged; LOCAL PASS, CI-1 transport failure and CI-2 15-minute cancellation; no runner remains |
| Alpha 2 preparation | MET-UNIFY-004 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Local commit only; LOCAL-1 status-check failure and LOCAL-2/3 750-second timeouts; no PR, CI or merge |
| Alpha 2 preparation | MET-UNIFY-005 | MERGED_SOURCE_RECORDED | PR #140 on exact accepted main `945de93`; source history only, not Linux or tenant qualification |
| Alpha 2 CI capacity | MET-RUNNER-001 | ONGOING_SOURCE_DESIGN | Bounded external CI exception and exact-job admission contract; no VM, runner, CI PASS or native qualification |
| Alpha 2 CI capacity | MET-UNIFY-008 / PR #141 | BLOCKED_SELF_HOSTED_CI | Source PR open; `verify` queued with no registered runner |
| Alpha 2 CI capacity | MET-LINUX-003 / PR #142 | BLOCKED_SELF_HOSTED_CI | Draft source PR open; `verify` queued on the same labels; queue must be serialized before one-job admission |
| Alpha 2A | W01 | ONGOING_DESIGN | Resolve G04–G07/G09; E01–E12 remain OPEN_UNPROVEN |
| Alpha 2A | W02–W07 | WAITING_EXACT_PACKETS | Interface, implementation, packaging and native proof labels, not executable YAML |
| Alpha 2A | CONF-FIX-010 | BLOCKED_SAFE_DESIGN | Zero product attempts; requires separately reviewed safe design and bounded packet authority |
| Alpha 2A | CONF-LIVE-004/005/006 | WAITING_PREREQUISITES | Native probes, package handoff and trusted campaign integration |
| Alpha 2A | CONF-LINUX-001 native AMD64 | NOT_RUN_ENV_UNAVAILABLE | Fresh real-Linux PASS gates runtime coding of CTRL-INTEGRATE-001, MODEL-001, EXEC-001 and RUN-001; ARM64 separate |
| Alpha 2B | Seven EXT proposal IDs | WAITING_PACKET_PUBLICATION | Contract-first provider/adapter/binding qualification, registry, UI, packaging and mode-aware reconciliation |
| Alpha 2B onward | Sixteen OSS adoption proposal IDs | WAITING_PACKET_PUBLICATION | Owner-specific actual pinned upstream integrations and qualification |
| Alpha 2B onward | JEV/Laya/SemIF SEM proposals | WAITING_PACKET_PUBLICATION | Optional local semantic contracts, adapters and independent evidence |
| Alpha 2 acceptance | CONF-A2-001 | WAITING | Integrated cited read-only white-goods profile, installed foundations and real overview |
| Alpha 3 | Governed action / CONF-A3-001 | WAITING | Approval, memory, sandbox, tools, decision service and full interaction |
| Alpha 4 | Enterprise campaigns / CONF-WG-001 | WAITING | Qualified baseline per released capability, disconnected install, lifecycle/security and independent tenant acceptance |
| Post-release | E1–E3 and provider expansion | DEFERRED | Governed improvement research and additional meaningful provider options |

Historical no-go and exhausted work stays closed: PLAN-CANON-001 is a recorded no-go; CONF-PERF-005 is unauthorized; CONF-FIX-007/008 retain prior outcomes; CONF-FIX-009 consumed its local allowance. No old attempt allowance transfers to a successor.

### Counted near-term checklist

These checkboxes count only the named deliverable at the stated evidence level. They are not a platform-completion percentage or permission to dispatch.

- [x] Phase 0 / Alpha 1 · MET-P0-002 · Record the five-source, license and provenance foundation in historical source evidence.
- [x] Alpha 2 · MET-ENFORCE-003 · Merge the reviewed host-interface source candidate as PR #138 on accepted main.
- [x] Alpha 2 · MET-UNIFY-005 · Publish this unified roadmap with exact historical inverse, independent review, declared offline acceptance, required CI and exact-main evidence at `945de93`.
- [ ] Alpha 2 · MET-RUNNER-001 · Publish the source-only bounded development-CI admission contract with exact 189-packet history, isolated acceptance, required CI and exact-main evidence.
- [ ] Alpha 2A · W01 · Resolve G04–G07/G09 and adopt a versioned host interface only after the required independent review.
- [ ] Alpha 2A · CONF-FIX-010 · Complete safe design and exact authority before any product attempt.
- [ ] Alpha 2A · CONF-LIVE-004 · Produce the exact native-probe source implementation and separately qualify it.
- [ ] Alpha 2A · CONF-LIVE-005 · Produce a reproducible selected package and operator handoff.
- [ ] Alpha 2A · CONF-LIVE-006 · Integrate the external trusted campaign path.
- [ ] Alpha 2A · CONF-LINUX-001 · Obtain fresh native Linux AMD64 PASS for the blocked runtime-coding gate.
- [ ] Alpha 2 · CTRL-INTEGRATE-001 · Complete production tenant overview and durable status projection after its Linux gate.
- [ ] Alpha 2 · CONF-A2-001 · Qualify the exact integrated read-only profile and inherited foundation evidence.
- [ ] Alpha 3 · CONF-A3-001 · Qualify governed action and interaction.
- [ ] Alpha 4 · CONF-WG-001 · Produce an unsigned white-goods tenant-acceptance candidate after required enterprise campaigns.

## Launch order and acceptance boundaries

1. Complete MET-RUNNER-001 as one source-only packet against accepted main `945de93`: exact allowed paths, all 189 predecessor YAML hashes, reversible current-to-189 projection, inherited checks and bounded attempts. It supplies a reviewed external CI policy, not a host installation or spend authorization.
2. Complete its declared isolated localhost acceptance and required self-hosted CI. Merge only after required checks pass, then verify exact main separately. A separately authorized operator must first prove the Linux host image, root-owned signed admission, 15-minute throughput, egress/cost bound and automatic plus independent teardown. Serialize the same-label PR #141/#142 queue before registering one exact-job runner. Dashboard source registration is a later, separately owned orchestrator packet; it must show source revision and observation time without duplicating status authority.
3. Continue W01 design and the existing conformance correction chain under their exact approved packet boundaries. W02–W07 and unpublished EXT/OSS/SEM proposals are not dispatch targets.
4. Run native Linux campaigns only with the external trusted signed launcher, pre-existing authorized capacity and the exact server-side zero-cost admission. Missing target/backend is NOT_RUN_ENV_UNAVAILABLE, never PASS or permission to provision.
5. Start an eligible product packet only after its published predecessor contracts, immutable locks, required native gate and repository policy are satisfied. Release qualification and tenant acceptance require their own exact evidence.

All local packet acceptance runs use the preinstalled deny-all-outbound OS-isolated launcher, direct argv and the same process tree for prefetch and acceptance. Warm snapshots remain denied. Live campaign evidence may cover only declared deployment, runtime, security, assurance and unsigned tenant-candidate axes. Source, unit, PR, merge, SBOM/artifact, signature/release, deployment, runtime, assurance and tenant acceptance are independently recorded. A waiver never replaces a fresh required production PASS.

Required cross-harness acceptance includes unknown-outcome retry safety, streaming cancellation acknowledgement, memory deletion surviving restore, staged-versus-committed data, budget reservations, stateful-provider migration and rollback, real tenant RLS, stale overview projections, local assets, WCAG 2.2 AA, offline installation, security/upgrade campaigns and independent tenant acceptance. Thresholds and profile scope must be frozen in the owning packet before tests.

Alpha 2 has not ended, so the requested phase-end model-effort reminder is **NOT_DUE**. Keep the selected model/effort unchanged; at phase closeout report the next phase’s recommended effort without switching it automatically.

## Retained source-navigation keys (historical)

The links and exact tokens below preserve predecessor source-navigation checks. Their recorded labels—including `WAITING_PREDECESSOR_CORRECTION`, `NOT_AUTHORIZED` and `BLOCKED_LOCAL_BUDGET_EXHAUSTED`—describe earlier checkpoints, **not** today's dispatch authority or the current phase status above.

| Detailed source | Retained publication keys |
|---|---|
| [Paper/repository map](alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md) | `MET-ADOPT-002`; `WAITING_PREDECESSOR_CORRECTION` |
| [Proxy diagnostics](alpha-2/PROXY_PERFORMANCE_DIAGNOSTICS.md) | `MET-PERF-006` |
| [Canonical repair](alpha-2/CANONICAL_REPAIR_PLAN.md) | `MET-PERF-007`; `NOT_AUTHORIZED` |
| [Backend timing](alpha-2/BACKEND_TIMING_DIAGNOSTICS.md) | `MET-PERF-008`; `CONF-DIAG-002`; `NOT_AUTHORIZED` |
| [Completion profiling](alpha-2/COMPLETION_PROFILING.md) | `MET-PERF-009`; `CONF-DIAG-003`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Validation performance](alpha-2/VALIDATION_PERFORMANCE_REPAIR.md) | `MET-PERF-010`; `WAITING_PREDECESSOR_CORRECTION` |
| [Document repair plan](alpha-2/DOCUMENT_REPAIR_PLAN.md) | `MET-PERF-011`; `CONF-DIAG-003`; `INCOMPLETE_DIAGNOSTIC_RETAINED`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Document repair authority](alpha-2/DOCUMENT_REPAIR_AUTHORITY.md) | `MET-PERF-012`; `CONF-PERF-006`; `CONF-BENCH-002`; `WAITING_META`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Benchmark transport](alpha-2/BENCHMARK_TRANSPORT.md) | `MET-PERF-013`; `CONF-BENCH-003`; `NON_DISPATCHABLE`; `CANDIDATE_FROZEN` |
| [Factory diagnostics](alpha-2/FACTORY_DIAGNOSTICS.md) | `MET-PERF-014`; `CONF-DIAG-004`; `BLOCKED_LOCAL_FAILURE` |
| [Guard cost repair](alpha-2/GUARD_COST_REPAIR.md) | `MET-PERF-015`; `CONF-FIX-009`; `CLOSED_PARTIAL_DIAGNOSTIC` |
| [Accounting scope](alpha-2/ACCOUNTING_SCOPE_AMENDMENT.md) | `MET-PERF-016`; `CONF-FIX-009` |
| [Guard traversal](alpha-2/GUARD_TRAVERSAL_REPAIR.md) | `MET-PERF-017`; `CONF-FIX-010` |
| [Catalog traversal](alpha-2/CATALOG_TRAVERSAL_REPAIR.md) | `MET-PERF-018`; `BLOCKED_SAFE_DESIGN` |
| [Local acceptance](alpha-2/LOCAL_ACCEPTANCE_REVALIDATION.md) | `MET-ACCEPT-001`; `CONF-LIVE-003` |
| [Conformance publication](alpha-2/CONFORMANCE_PUBLICATION.md) | `MET-PUBLISH-001`; `CONF-LIVE-003` |
| [Conformance completion](alpha-2/CONFORMANCE_COMPLETION.md) | `MET-REPAIR-017`; `WAITING_PREDECESSOR_CORRECTION` |
| [Completion integration](alpha-2/COMPLETION_INTEGRATION.md) | `MET-REPAIR-018`; `CONF-FIX-008`; `DONE_SOURCE_GATES` |
| [Observation/enforcement](alpha-2/OBSERVATION_ENFORCEMENT_PUBLICATION.md) | `MET-REPAIR-019`; `BLOCKED_SAFE_DESIGN` |
| [Enforcement integration](alpha-2/ENFORCEMENT_INTEGRATION.md) | `MET-ENFORCE-001`; `BLOCKED_SAFE_DESIGN` |
| [Host-interface publication](alpha-2/HOST_INTERFACE_PUBLICATION.md) | `MET-ENFORCE-003`; `BLOCKED_SAFE_DESIGN` |
