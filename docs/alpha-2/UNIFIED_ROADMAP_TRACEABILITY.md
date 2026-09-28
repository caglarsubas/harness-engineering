# Unified roadmap traceability and dispositions

This is the source crosswalk for the [current master roadmap](../MASTER_DEVELOPMENT_PLAN.md), not another current-status roadmap. The accepted input is `7a353b253bb257aa0abe2148e7fa62d7570f0b5a` (PR #138). The exact preceding master is retained at [the history archive](../history/master-development-plan-7a353b2.md), SHA-256 `4c611f70842a14cc9ab74054ade2fa931e96deb96372b9b89022654df594f3e7`.

The unpublished `MET-UNIFY-001` local candidate at `2cb0b949ee82fd1045a605f7b5f33d41742bc971` failed both bounded LOCAL attempts. The separate unpublished `MET-UNIFY-002` candidate exhausted LOCAL-1/2/3; LOCAL-3 finished the nested suite under its time limit but failed a stale inherited 204-file assertion after the current YAML corpus became 205. Their source and attempt receipts remain historical, not accepted predecessors or renewed execution allowances. The current 189th packet candidate is `MET-UNIFY-003`, based directly on accepted `MET-ENFORCE-003`. Publication, CI, merge and exact-main evidence for `MET-UNIFY-003` remain separate pending gates.

The [source index](../../architecture/unified-roadmap-source-index.json) records the accepted SHA-256 and heading spans of **seven principal documents, thirteen repository guides and sixteen harness specifications**, plus all **188 published packet YAML files**, their owners, predecessors and **4,302 source-unit pointers**. These pointers identify every packet objective, contract, deliverable, exclusion, expected-evidence item, rollback and execution-boundary field. They are a mechanically complete inventory of those packet fields, not a claim that a machine has interpreted every sentence. The original guides, specifications and packets continue to supply their full detail; only the master’s current narrative is condensed. The index also records the **23 unpublished extension/adoption IDs** and four research attachments.

The [requirement disposition join](../../architecture/unified-requirement-dispositions.json) adds one auditable row for each of **923 accepted document heading spans and 4,302 packet source pointers**. It records source revision, section, owner, harness scope, phase, exact or unresolved delivery join, acceptance-plan references and a reasoned disposition. All **51 formerly generic `OPEN_REVIEW` heading spans** have now been reviewed: navigation and obsolete checkpoints are combined or superseded, H1–H16 point to their actual owner and unpublished adoption ID, and active cross-owner obligations retain explicit blockers. Exact accepted bytes show **203 heading-plus-blank spans** with no requirement body; inherited broad joins on these empty spans have been cleared: **188 rows / 304 acceptance-pointer entries** and **119 rows / 2,364 packet-ID entries**. Another **29 historical title, snapshot or superseded-proposal spans** have no new delivery, while **20 specific historical spans** and **15 historical source-status headings** now cite exact published-packet `expectedEvidence` pointers as plans, not PASS results. Across the full 5,225-row join, **38** rows retain explicit markers for open owner, contract, design, native or qualification work and the retained `PLAN-CANON-001` no-go. No `EXACT_DELIVERY_PACKET_JOIN_NOT_REVIEWED` or `ACCEPTANCE_PLAN_JOIN_NOT_REVIEWED` marker remains. This is source-unit accounting, not a claim that 5,225 sentences were independently semantically certified or that the marked work is complete. The [backlog join](../../architecture/unified-roadmap-backlog.json) distinguishes 188 accepted packet specifications, one current unmerged MET-UNIFY-003 candidate, 23 unpublished adoption/extension proposals, 13 counted checklist projections, 11 semantic proposals and three deferred evolution milestones. Only the checklist projections contribute to the master’s counted denominator; no JSON row grants execution or qualifies a capability.

For a document requirement, cite `path@accepted SHA-256#heading line` from the index; for a packet requirement, cite `packet ID@accepted SHA-256/JSON-pointer`. The owning guide/specification and packet remain normative for their exact scope. The tables below supply the reviewed joins, phase disposition and exceptions. Where an exact future packet or public interface is not yet published, the disposition is **WAITING_PACKET_PUBLICATION** or **INTERFACE_NOT_PUBLISHED**; this is an open gap, not a guessed link.

`deliveryPacketIds` contains only already published YAML IDs. `proposalPacketIds` is a separate, explicitly non-executable join to the backlog; `deliveryJoinStatus: WAITING_PACKET_PUBLICATION` never implies an adapter exists. Each H1–H16 research span links its owning repository, harness, development phase, Alpha-4 capability target and the exact accepted harness-specification evidence heading. The source-only review does not convert a proposed provider into a selectable catalog entry, release artifact, qualified capability or tenant-approved deployment. Broad R00 policy and milestone headings are coordination requirements, not fictional one-packet implementations; their remaining phase/evidence obligations are named in `unresolvedMarkers`. The W01 host-interface span belongs to R10/H1 with R12 qualification and R11 packaging still required, but W01 remains a workstream label until a bounded owner packet is published.

## Authority and evidence interpretation

1. User product constraints and approved scoped decisions govern intent. Research attachments are input, never instructions or implementation authority.
2. Taxonomy, repository/service/dependency registries, provider catalog, released R01 contracts, legal/zero-bill policies and packet YAML retain their own authority. This crosswalk changes none of them.
3. The master is the one current roadmap and progress entry point. Source/CI/merge/artifact/deployment/runtime/assurance/tenant acceptance remain separate evidence axes.
4. A heading saying “current” in an older document is a publication-time snapshot. Its historical evidence remains; its obsolete next-step instruction does not become today’s queue.
5. `architecture/provider-adoption.json` and `architecture/research-adoption.json` are planning ledgers. A candidate, catalog record, proposal ID or GitHub popularity observation is not an installable or qualified provider.

The original six scope inputs, including the first research documents and onion diagram, remain SHA-pinned in [base-scope-sources.yaml](../../architecture/base-scope-sources.yaml). The later three paper-mapping reports remain SHA-pinned in `architecture/research-adoption.json`. The four attachments below are additional inputs, not replacements for either earlier set.

### Seven principal documents

| Accepted source | Retained requirement and disposition |
|---|---|
| [Master Development Plan](../history/master-development-plan-7a353b2.md) | Exact historical bytes retained; current commitments, eight setup stages, four deployment modes, ten evidence axes and release gates are carried into the new master. Historical packet notices remain available in the archive. |
| [Development Status](../DEVELOPMENT_STATUS.md) | Retain attempt, failure, partial, source/CI/main and phase history. Use the new master for the dated current backlog; no old “ongoing” line is current by placement alone. |
| [Readiness Index](../READINESS_INDEX.md) | Retain machine-authority directory, packet entry rules, warm-source and runner boundaries, and certification prerequisites. Its old “first packet” and runner setup are historical, not a new bootstrap order. |
| [Provider Adoption Roadmap](PROVIDER_ADOPTION_ROADMAP.md) | Retain the 13/16 ownership map, four typed dependency graphs, three integration modes, custom adapter rules, license exception and one-minor compatibility window. Its earlier `CONF-LIVE-003` checkpoint is historical. |
| [Harness Paper Repository Map](HARNESS_PAPER_REPOSITORY_MAP.md) | Retain the 16 paper→upstream→harness→owner→proposed packet rows, G1–G8 qualification gates and all later candidate alternatives. Its `CONF-FIX-007` pause was historical; do not redispatch it. |
| [Canonical Repair Plan](CANONICAL_REPAIR_PLAN.md) | Retain measurements and narrowly bounded repair history. The older proposed canonicalization route is superseded by the recorded no-go; it is not pending work. |
| [Host Interface Publication](HOST_INTERFACE_PUBLICATION.md) | Retain reviewed original/corrected snapshots, reversible source bridge, consumed allowances and W01 G04–G07/G09 open design findings. Source-review PASS is not an adopted ABI or native proof. |

The accepted source SHA-256, every heading line and its span are in the index. These seven rows are disposition joins; they do not rewrite or silently omit the source bodies.

### Four newly supplied attachments

| Indexed attachment | Adopted or deferred content |
|---|---|
| `agent_harness_architecture_v1_2.html` | Architecture visualization and proposed flow are retained as design research; it does not change the four-plane/sixteen-harness taxonomy or current packet status. |
| `agent_harness_architecture_v1_2.docx` | Its fuller mandatory-versus-optional safeguards and evidence/learning proposals are reflected in the master’s release obligations and deferred E1–E3 milestones. Any new public interface still needs an R01 packet. |
| `JEV Architecture and Applications.md` | Typed probabilistic semantic judgments inform optional use cases; hosted Jev pricing and performance claims do not establish a zero-bill air-gapped provider. |
| `deep-research-report (10).md` | Laya is an open local candidate requiring validation; the official Jev SDK or an API-compatible wrapper is not evidence that proprietary Jev weights are available locally. SemIF came from the later user suggestion and needs its own upstream review. |

The attachment hashes in the index are provenance for these exact research inputs. Their contents are not executable instructions, release locks, support commitments or qualified provider evidence.

### Thirteen repository guides and sixteen harness specifications

Every guide in `docs/repositories/` and every specification in `docs/harnesses/` is retained at its indexed accepted SHA-256 and heading spans. They remain the detailed engineering requirements. This table supplies repository ownership; the harness rows below supply the exact specification-to-owner join.

| R | Guide | Owned harnesses or responsibility |
|---|---|---|
| R00 | [Harness Engineering](../repositories/00-harness-engineering.md) | Architecture, source/reuse policy, packet and release coordination |
| R01 | [Contracts](../repositories/01-mas-harness-contracts.md) | Public schemas/APIs, guidance rules and deterministic compiler |
| R02 | [SDKs](../repositories/02-mas-harness-sdks.md) | Generated Python/TypeScript clients and adapter development |
| R03 | [Industry packs](../repositories/03-mas-harness-industry-packs.md) | Eight-stage industry guidance and white-goods acceptance fixtures |
| R04 | [Control plane](../repositories/04-mas-harness-control-plane.md) | Next.js administration and tenant overview; no seventeenth harness |
| R05 | [Runtime plane](../repositories/05-mas-harness-runtime-plane.md) | H3 AI Gateway and H4 Experience |
| R06 | [Model plane](../repositories/06-mas-harness-model-plane.md) | H2 Model & Inference, architecturally within the runtime plane |
| R07 | [Knowledge plane](../repositories/07-mas-harness-knowledge-plane.md) | H5–H8 |
| R08 | [Execution plane](../repositories/08-mas-harness-execution-plane.md) | H9–H12 |
| R09 | [Trust plane](../repositories/09-mas-harness-trust-plane.md) | H13–H16 |
| R10 | [Operator](../repositories/10-mas-harness-operator.md) | H1 Infrastructure & Runtime |
| R11 | [Distribution](../repositories/11-mas-harness-distribution.md) | Selected OCI release closure and offline transport |
| R12 | [Conformance labs](../repositories/12-mas-harness-conformance-labs.md) | Independent contract, native, security, upgrade and tenant-candidate evidence |

The 28 canonical service records in `architecture/services.yaml` describe service ownership and state. They are not a count of all images, processes, external providers or privileged host components. Each service retains its own required/optional dependencies, startup/readiness conditions, durable-state owner, migrations, outage behavior and restart semantics. Shared infrastructure does not grant cross-service database writes.

### Sixteen harness research, owner and packet joins

Every row’s specification is retained by reference; “target” means a research/adoption direction, never selected or qualified. The `architecture/provider-adoption.json` release floor applies to all 16 at Alpha 4, whereas the phase below is the planned adapter development phase.

| H | Specification and accountable owner | Initial OSS direction | Development phase / unpublished adoption packet |
|---|---|---|---|
| H1 | [Infrastructure & Runtime](../harnesses/runtime.infrastructure.md) · R10 | Kubernetes/Helm | Alpha 2 · `OP-ADOPT-001` |
| H2 | [Model & Inference](../harnesses/runtime.model-inference.md) · R06 | Ollama; llama.cpp; vLLM | Alpha 2 · `MODEL-ADOPT-001` |
| H3 | [AI Gateway](../harnesses/runtime.ai-gateway.md) · R05 | LiteLLM OSS compatibility | Alpha 2 · `RUN-GATEWAY-ADOPT-001` |
| H4 | [Experience & Interaction](../harnesses/runtime.experience.md) · R05 | AG-UI/CopilotKit | Alpha 2 initial, Alpha 3 full · `RUN-UI-ADOPT-001` |
| H5 | [Domain & Semantic](../harnesses/knowledge.domain-semantic.md) · R07 | RDFLib/pySHACL | Alpha 2 · `KN-DOM-ADOPT-001` |
| H6 | [Data Integration & Provenance](../harnesses/knowledge.data-integration.md) · R07 | Trino/Great Expectations/OpenLineage | Alpha 2 · `KN-DATA-ADOPT-001` |
| H7 | [Retrieval & Context](../harnesses/knowledge.retrieval-context.md) · R07 | LlamaIndex/pgvector | Alpha 2 · `KN-RET-ADOPT-001` |
| H8 | [Memory & State](../harnesses/knowledge.memory-state.md) · R07 | Mem0 candidate | Alpha 3 · `KN-MEM-ADOPT-001` |
| H9 | [Protocol & Interoperability](../harnesses/execution.protocol-interoperability.md) · R08 | MCP/A2A SDKs | Alpha 2 · `EXEC-PROTO-ADOPT-001` |
| H10 | [Orchestration & Durable Execution](../harnesses/execution.orchestration.md) · R08 | Temporal adoption decision | Alpha 2 · `EXEC-TEMPORAL-001` |
| H11 | [Tool, Skill & Sandbox](../harnesses/execution.tool-skill-sandbox.md) · R08 | Wasmtime/gVisor; Kata for selected OpenShift profiles | Alpha 3 · `EXEC-SANDBOX-ADOPT-001` |
| H12 | [ML & Decision](../harnesses/execution.ml-decision.md) · R08 | scikit-learn/ONNX Runtime/OR-Tools | Alpha 3 · `EXEC-ML-ADOPT-001` |
| H13 | [Security & Safety](../harnesses/trust.security-safety.md) · R09 | OPA/Presidio | Alpha 2 · `TRUST-SAFE-ADOPT-001` |
| H14 | [Governance & AgentOps](../harnesses/trust.governance-agentops.md) · R09 | OPA/MLflow integration | Alpha 3 · `TRUST-GOV-ADOPT-001` |
| H15 | [Observability & FinOps](../harnesses/trust.observability-finops.md) · R09 | OpenTelemetry/Prometheus | Alpha 2 · `TRUST-OBS-ADOPT-001` |
| H16 | [Evaluation & Assurance](../harnesses/trust.evaluation-assurance.md) · R09 | Inspect | Alpha 2 · `TRUST-EVAL-ADOPT-001` |

The three research reports already indexed by `architecture/research-adoption.json` supply a curated 18-paper/32-upstream snapshot from September 15, with 19 conceptual and two evaluated-component relationship edges. These are not proof that any listed upstream officially implements the cited paper. Recheck immutable upstream versions, repository transfers, licenses, model/dataset custody, dependency closure and maintainer/security state in the owner packet. LiteLLM enterprise code is outside its reviewed OSS subset.

Other existing candidates remain in the historical adoption map for later disposition: SGLang; Envoy AI Gateway and license-reviewed Portkey; Vercel AI SDK, Chainlit and LibreChat attachment; Apache Jena, LinkML and Cube; Apache NiFi, MCP Toolbox and OpenMetadata; Haystack, RAGFlow, Milvus and Qdrant; Graphiti, Letta and LangMem; FastMCP and ContextForge; LangGraph as agent logic only; Firecracker; AutoGluon; NeMo Guardrails and Cedar; CUGA; Jaeger, Langfuse OSS, OpenLLMetry and Laminar; Ragas, promptfoo and DeepEval. These serve different roles and are not interchangeable full-harness baselines.

### Published packets and proposal-only work

The index pins every one of the 188 old YAML files and every listed source-unit pointer. Their complete requirements, allowed paths, commands, predecessors and rollback text remain in the exact YAML. The human phase/status join is:

| Historical catalog order | Development phase | Disposition |
|---|---|---|
| 1–66 | Phase 0 / Alpha 1 | Recorded foundation packets; installed and production-overview carryovers stay open independently |
| 67–128 | Alpha 2 | Read-only work and current prerequisites; individual source/live statuses govern |
| 129–138 | Alpha 3 | Waiting governed-action work |
| 139–155 | Alpha 4 | Waiting enterprise and platform qualification |
| 156–188 | Alpha 2 repair/adoption successors | Explicit override of the old Alpha 4 heading in `task-packets/README.md`; do not infer their phase from placement |

The index carries exactly 23 additional unpublished IDs: seven `*-EXT-001` extension packets from the provider ledger and sixteen harness-specific adoption packets from the research ledger. They are **WAITING_PACKET_PUBLICATION**, never executable YAML. Their contract-first extension chain is `CON-EXT-001` → `SDK-EXT-001` and `CONF-EXT-001` → `TRUST-EXT-001` → `CTRL-EXT-001` / `DIST-EXT-001` → `OP-EXT-001`, subject to exact future predecessors and release locks. An OSS direction does not self-authorize an adapter packet.

## Reviewed conflicts and exact disposition

| Source tension or omission | Adopted roadmap disposition; remaining owner work |
|---|---|
| Old headers still say `MET-ENFORCE-003 ONGOING_SOURCE_PUBLICATION`. | PR #138 is on the accepted source main `7a353b2`; label its source publication recorded/merged. W01 remains design-open and none of its native obligations are thereby passed. |
| W01 corrected source review passed, but G04–G07/G09 and E01–E12 remain unresolved. | Retain `W01 ONGOING_DESIGN`; W02–W07 are work labels, not dispatchable packets. The next design must resolve real writer mediation, admission/storage semantics, native enrollment, host enforcement and request/action correlation. |
| `EXEC-ORCH-001` describes a PostgreSQL executor while research adoption prefers Temporal. | Preserve historical source and contracts. Hold further bespoke dispatch; R08 must publish the adoption/migration ADR and exact successor packet with version, drain/export/replay and no dual side-effect authority. |
| R08 guide and H12 specification use competing decision API paths. | Neither path is in the inspected bound R01 OpenAPI release; record `INTERFACE_NOT_PUBLISHED`. R01 owns a versioned contract and vectors before R08 implementation. |
| R01 guide says optional schema additions are compatible. | Supersede only that assertion: closed-schema consumers need explicit old/new vectors and the retained one-minor migration window; R01 owns the change. |
| `ControlRequirement` and `IntegrationDeclaration` are named in architecture prose but absent from the bound contract release. | Keep R03’s pack-local records; do not claim public types. R01 must publish any future external kind before consumers use it. |
| Service catalog describes policy decision as stateless, whereas trust work needs durable decision/audit/outbox ownership. | R09/R00 must reconcile process statelessness versus owned durable state in a separate architecture/contract packet; no direct database sharing is inferred. |
| OIDC discovery prose is broader than the current local issuer/JWKS bootstrap. | Preserve current local validation. Remote discovery is a future explicit R01/R04 identity contract, with denial behavior and tests. |
| Provider catalog entries and research names appear next to implementation plans. | Catalog `PLANNED`, source/adapter `IMPLEMENTED`, artifact `RELEASED`, exact environment `QUALIFIED`, and tenant decision are independent. The five `CONTRACT_ONLY` records reject selection with `PROVIDER_UNAVAILABLE`. |
| Historic `CONF-FIX-007` pause and canonicalization proposal could look actionable. | Retain `CONF-FIX-007/008` and `PLAN-CANON-001` as bounded history; `PLAN-CANON-001` is a recorded no-go and `CONF-PERF-005` unauthorized. `CONF-FIX-009` exhausted; `CONF-FIX-010` is safe-design-blocked with zero attempts. |
| Requirement to offer at least one release baseline could be read as permission to drop scope. | Every one of H1–H16 remains in the Alpha-4 capability floor. Any release deferment needs a reviewed per-capability source/disposition record; qualification is version, mode and environment specific. |
| A waiver or accepted staging result could be mistaken for readiness. | Data `STAGED` is not `COMMITTED`; source/index freshness, owner approval and tenant acceptance differ. Production controls require fresh scope-exact PASS; waiver records never satisfy them. |

## Newly considered semantic and evolution research

The four user attachments are SHA-pinned in the source index. Their claims are research input; HTML/Word formatting does not create a new plane or harness. TypeSafe Jev’s hosted proprietary model is outside the shipped open, zero-bill, air-gapped baseline. Laya and SemIF are **candidate** local semantic-decision options, not catalog-selectable or qualified providers. The user’s SemIF suggestion is a product input; the attached Jev reports themselves do not establish its package, license, weights, maturity or operational closure.

Potential semantic use is narrow: H2 serving qualification; H3 route advice; H5/H6 semantic categorization; H7 evidence relevance; H8 memory proposal salience; H10 task-branch recommendation; H11 tool recommendation; H12 decision features; H13 risk signals; and H16 evaluation. Deterministic code retains permissions, budgets, branching, side effects, promotion and acceptance. First tests should be advisory or shadow-only where the harness accepts that mode. Qualification must bind exact model weights, backend, tokenizer, calibration, domain/language, abstention, cost and independent evidence. No generic Ollama compatibility is presumed.

Possible follow-up IDs `CON-SEM-001`, `SDK-SEM-001`, `IND-SEM-001`, `MODEL-SEM-001` (Laya), `MODEL-SEM-002` (SemIF), `CONF-SEM-001`, `RUN-SEM-001`, `KN-SEM-001`, `CTRL-SEM-001`, `DIST-SEM-001`, and Alpha-3 `EXEC-SEM-001` are **unpublished proposals**, outside the 23 existing extension/adoption IDs and outside the 188 YAML catalog. Each requires exact owner, source/licensing, predecessor, accepted contract, artifact/qualification and packet authority before implementation.

The attached architecture’s evidence-and-learning loop belongs after the first enterprise release: E1 governed evidence-to-improvement, E2 optional behavior/taste distillation, E3 separately approved reinforcement-learning research. Operational evidence, user memory and training-eligible data have different retention, consent, lineage and authority; no collected trace becomes training input automatically. Improvement candidates pass through existing knowledge, execution, trust and runtime boundaries, never a fifth plane or H17.

## Acceptance obligations inherited without substitution

- No unknown remote outcome is blindly retried; compensation is a new governed action. Non-idempotent retry needs a receipt proving no prior effect.
- No stream provider switch after the first response byte; cancellation needs downstream acknowledgement. The gateway does not retrieve context or execute tools.
- Memory recall denial is immediate after deletion; tombstones and deletion ledger prevent restore/rollback resurrection.
- Provider migration includes export/reindex/schema and reverse-path evidence; an older image is not a data rollback.
- Budget reservations and commits are atomic, exact retry identities are stable, and rollback cannot reset usage accounting.
- The control overview uses authenticated tenant projections, honest stale indicators, real RLS/isolation tests, WCAG 2.2 AA and local assets. Agent serving avoids a synchronous control-plane dependency.
- Assurance is independent and scope-exact. `CONF-WG-001` may produce only an unsigned tenant-acceptance candidate; a separate tenant authority must accept.
- Every OSS provider needs pinned version, dependency/license/model custody, offline artifacts and real-package conformance. Fake-surface tests do not qualify an upstream. A failed provider qualification does not authorize building another general-purpose engine; that needs a separate measured adoption/build ADR.

These obligations are indexed to their unchanged owner specifications and packet evidence fields. Their implementation and production proof remain work in the owning repositories and conformance campaigns.
