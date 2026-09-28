# Research-led harness implementation roadmap

> Current-status note for MET-UNIFY-003: this is the retained research/adoption mapping, not a claim that any named upstream is installed or qualified. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) is the current phase/backlog entry point; proposed adoption IDs still need exact owner packets, release locks and independent qualification.

Owner: `MET-ADOPT-002` · Alpha2 · META_PLANNING_ONLY · 2026-09-15.

Require **at least one qualified baseline for every released harness capability** at the first enterprise release.

This is the operational crosswalk missing from the earlier master plan. The machine authority is
[`architecture/research-adoption.json`](../../architecture/research-adoption.json).
It extends, rather than rewrites, the hash-pinned [provider ledger](../../architecture/provider-adoption.json).
Current runtime selectors, public contracts, source locks and historical qualification claims do not change.

## Product boundary: integrate mature engines, build the harness

Reuse established OSS implementations for their actual function: serving, routing, durable execution,
retrieval, memory, protocols, sandboxing and evaluation. Our differentiator is declarative establishment,
business/domain/data readiness, tenant isolation, policy enforcement, safe bindings, evidence and operations.
A custom module name, database driver or pytest suite alone does not satisfy adoption of the corresponding engine.
Nor is one vendor framework expected to replace every responsibility of a harness.

Before starting a new general-purpose engine, publish a separate build-versus-integrate ADR with
measured incompatibilities, OSS alternatives, scope, maintenance cost, licensing, migration and acceptance.
A failed qualification keeps the capability unreleased; it never silently authorizes a bespoke replacement.

## All16 harnesses: paper → upstream → owner → delivery

Every row is a **planned baseline target, not installed or qualified**. Plus signs join complementary
components; slash-separated hardware/runtime choices are not all installed. Repository stars are not acceptance.
Paper links are conceptual engineering alignment unless explicitly marked otherwise below.

| H | Harness / owner | Planned OSS implementation | Research | Delivery phase / proposed packet |
|---|---|---|---|---|
| H1 | `runtime.infrastructure` / `operator` | [kubernetes/kubernetes](https://github.com/kubernetes/kubernetes) + [helm/helm](https://github.com/helm/helm) | [2606.06448](https://arxiv.org/abs/2606.06448) | ALPHA_2 / `OP-ADOPT-001` |
| H2 | `runtime.model-inference` / `model-plane` | [ollama/ollama](https://github.com/ollama/ollama) + [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp) + [vllm-project/vllm](https://github.com/vllm-project/vllm) | [2606.06448](https://arxiv.org/abs/2606.06448), [2309.06180](https://arxiv.org/abs/2309.06180) | ALPHA_2 / `MODEL-ADOPT-001` |
| H3 | `runtime.ai-gateway` / `runtime-plane` | [BerriAI/litellm](https://github.com/BerriAI/litellm) | [2508.07675](https://arxiv.org/abs/2508.07675) | ALPHA_2 / `RUN-GATEWAY-ADOPT-001` |
| H4 | `runtime.experience` / `runtime-plane` | [ag-ui-protocol/ag-ui](https://github.com/ag-ui-protocol/ag-ui) + [CopilotKit/CopilotKit](https://github.com/CopilotKit/CopilotKit) | [2606.20630](https://arxiv.org/abs/2606.20630) | ALPHA_2 / `RUN-UI-ADOPT-001` |
| H5 | `knowledge.domain-semantic` / `knowledge-plane` | [RDFLib/rdflib](https://github.com/RDFLib/rdflib) + [RDFLib/pySHACL](https://github.com/RDFLib/pySHACL) | [2606.31041](https://arxiv.org/abs/2606.31041) | ALPHA_2 / `KN-DOM-ADOPT-001` |
| H6 | `knowledge.data-integration` / `knowledge-plane` | [trinodb/trino](https://github.com/trinodb/trino) + [fivetran/great_expectations](https://github.com/fivetran/great_expectations) + [OpenLineage/OpenLineage](https://github.com/OpenLineage/OpenLineage) | [2509.13978](https://arxiv.org/abs/2509.13978) | ALPHA_2 / `KN-DATA-ADOPT-001` |
| H7 | `knowledge.retrieval-context` / `knowledge-plane` | [run-llama/llama_index](https://github.com/run-llama/llama_index) + [pgvector/pgvector](https://github.com/pgvector/pgvector) | [2603.07379](https://arxiv.org/abs/2603.07379) | ALPHA_2 / `KN-RET-ADOPT-001` |
| H8 | `knowledge.memory-state` / `knowledge-plane` | [mem0ai/mem0](https://github.com/mem0ai/mem0) | [2602.16313](https://arxiv.org/abs/2602.16313), [2603.21321](https://arxiv.org/abs/2603.21321) | ALPHA_3 / `KN-MEM-ADOPT-001` |
| H9 | `execution.protocol-interoperability` / `execution-plane` | [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk) + [a2aproject/a2a-python](https://github.com/a2aproject/a2a-python) | [2604.05969](https://arxiv.org/abs/2604.05969) | ALPHA_2 / `EXEC-PROTO-ADOPT-001` |
| H10 | `execution.orchestration` / `execution-plane` | [temporalio/temporal](https://github.com/temporalio/temporal) | [2606.20058](https://arxiv.org/abs/2606.20058) | ALPHA_2 / `EXEC-TEMPORAL-001` |
| H11 | `execution.tool-skill-sandbox` / `execution-plane` | [google/gvisor](https://github.com/google/gvisor) + [bytecodealliance/wasmtime](https://github.com/bytecodealliance/wasmtime) | [2605.06614](https://arxiv.org/abs/2605.06614) | ALPHA_3 / `EXEC-SANDBOX-ADOPT-001` |
| H12 | `execution.ml-decision` / `execution-plane` | [scikit-learn/scikit-learn](https://github.com/scikit-learn/scikit-learn) + [microsoft/onnxruntime](https://github.com/microsoft/onnxruntime) | [2606.26859](https://arxiv.org/abs/2606.26859) | ALPHA_3 / `EXEC-ML-ADOPT-001` |
| H13 | `trust.security-safety` / `trust-plane` | [open-policy-agent/opa](https://github.com/open-policy-agent/opa) + [data-privacy-stack/presidio](https://github.com/data-privacy-stack/presidio) | [2606.26479](https://arxiv.org/abs/2606.26479), [2608.20481](https://arxiv.org/abs/2608.20481) | ALPHA_2 / `TRUST-SAFE-ADOPT-001` |
| H14 | `trust.governance-agentops` / `trust-plane` | [open-policy-agent/opa](https://github.com/open-policy-agent/opa) + [mlflow/mlflow](https://github.com/mlflow/mlflow) | [2605.20874](https://arxiv.org/abs/2605.20874), [2608.20481](https://arxiv.org/abs/2608.20481) | ALPHA_3 / `TRUST-GOV-ADOPT-001` |
| H15 | `trust.observability-finops` / `trust-plane` | [open-telemetry/opentelemetry-collector](https://github.com/open-telemetry/opentelemetry-collector) + [prometheus/prometheus](https://github.com/prometheus/prometheus) | [2606.04990](https://arxiv.org/abs/2606.04990) | ALPHA_2 / `TRUST-OBS-ADOPT-001` |
| H16 | `trust.evaluation-assurance` / `trust-plane` | [UKGovernmentBEIS/inspect_ai](https://github.com/UKGovernmentBEIS/inspect_ai) | [2603.23749](https://arxiv.org/abs/2603.23749), [2602.16313](https://arxiv.org/abs/2602.16313) | ALPHA_2 / `TRUST-EVAL-ADOPT-001` |

## Per-harness implementation and acceptance

### H1 · runtime.infrastructure

Use existing Kubernetes reconciliation and Helm packaging; never build a scheduler or container runtime.

**Build:** Own signed installation admission, minimal module closure and constrained reconciliation. H11 owns sandbox invocation; H1 only binds an approved RuntimeClass.

**Accept:** Install on existing Linux Kubernetes and test restart, quota exhaustion, default-deny egress, nonroot OpenShift SCC compatibility and partial reconciliation without cloud provisioning.

**Later coverage:** K3s; Upstream Kubernetes; OpenShift-compatible profile. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `OP-ADOPT-001` is WAITING_PACKET_PUBLICATION in `operator`; related retained packets: `OP-001`, `CONF-K8S-001`, `CONF-OCP-001`, `CONF-K3S-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H2 · runtime.model-inference

Use Ollama for attachment/local developer serving, llama.cpp for Linux CPU-compatible serving and vLLM for selected Linux GPU serving. These are hardware alternatives, not three mandatory services.

**Build:** Own normalized inference contracts, capability negotiation, cancellation, secret references, model/weight license and digest admission; do not build tokenizers, schedulers or decoding engines.

**Accept:** First qualify the authorized existing inference endpoint without reading its source. Independently test streaming, embeddings where supported, cancellation, no network pulls and fully local weights on each declared hardware profile.

**Later coverage:** Ollama; llama.cpp; vLLM; SGLang later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `MODEL-ADOPT-001` is WAITING_PACKET_PUBLICATION in `model-plane`; related retained packets: `MODEL-OLLAMA-001`, `MODEL-LLAMACPP-001`, `MODEL-VLLM-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H3 · runtime.ai-gateway

Adopt the reviewed MIT-only LiteLLM routing/normalization surface behind our gateway API. No paid provider, enterprise directory or cloud fallback.

**Build:** Keep identity, signed routes, tenant-safe budget reservations, trust decisions and redacted evidence as platform enforcement. Retain existing planeon.gateway as compatibility/adapter shell, not a competing general routing engine.

**Accept:** Test real pinned LiteLLM against local model endpoints, no billing/API-key prerequisite, denied provider discovery, cross-tenant route denial, pre-response-only fallback, cancellation and no prompt/response persistence. Semantic caching stays disabled until a separately reviewed isolation design.

**Later coverage:** LiteLLM OSS subset; Envoy AI Gateway later; Portkey gateway subject to license review. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `RUN-GATEWAY-ADOPT-001` is WAITING_PACKET_PUBLICATION in `runtime-plane`; related retained packets: `RUN-GW-001`, `RUN-GW-002`. G1–G8 apply; old packet paths are not authority to add this framework.

### H4 · runtime.experience

Use AG-UI event types and reviewed CopilotKit OSS UI components for the agent interaction surface.

**Build:** Own tenant session binding, authorization, safe rendering, cancellation and durable approval presentation; keep the Next.js/TypeScript administrative onion overview in control-plane, not H4.

**Accept:** Replay pinned event vectors and real package streaming; test reconnect/cancel, XSS, keyboard access, approval identity and stale state. Browser calls control projections, never all planes directly; no cloud UI service or remote font dependency.

**Later coverage:** AG-UI/CopilotKit; Vercel AI SDK later; Chainlit later; LibreChat attachment later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `RUN-UI-ADOPT-001` is WAITING_PACKET_PUBLICATION in `runtime-plane`; related retained packets: `RUN-EXP-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H5 · knowledge.domain-semantic

Use RDFLib RDF processing and pySHACL validation for domain concepts and constraints; this is meaningful semantic-engine reuse, not a generic database count.

**Build:** Own industry mapping, glossary/ontology version approval, provenance, business-question readiness and domain-to-data binding; do not build RDF or SHACL engines.

**Accept:** Validate approved ontology versions, conflicting terms, missing business definitions and SHACL failures against local fixtures. No NL2SQL execution authority is implied by the paper or semantic layer.

**Later coverage:** RDFLib/pySHACL; Apache Jena; LinkML later; Cube semantic metrics later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `KN-DOM-ADOPT-001` is WAITING_PACKET_PUBLICATION in `knowledge-plane`; related retained packets: `KN-DOM-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H6 · knowledge.data-integration

Reuse Trino for selected federated read-only query capabilities, Great Expectations Core for dataset quality and OpenLineage for lineage events. Each is included only for a selected capability.

**Build:** Own connector declarations, endpoint authorization, tenant identity propagation, quarantine, freshness and completeness gates. Do not create a general federation engine or replace existing ingest semantics without migration.

**Accept:** Attach existing local services first. Test row/column restrictions, unknown charges denial, denied writes, source lineage, stale/schema-drift/quarantined data and disconnected fixtures; target adoption must not widen current raw-source access.

**Later coverage:** Trino/GX/OpenLineage complementary roles; Apache NiFi ingestion later; MCP Toolbox for Databases later; OpenMetadata attachment later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `KN-DATA-ADOPT-001` is WAITING_PACKET_PUBLICATION in `knowledge-plane`; related retained packets: `KN-DATA-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H7 · knowledge.retrieval-context

Use pinned minimal LlamaIndex core/local integrations for retrieval pipelines and PostgreSQL/pgvector as the first index option; exclude hosted LlamaCloud and default online models.

**Build:** Own identity filters, citation/provenance envelope, context budgets, corpus/version selection and readiness. Do not rebuild a general RAG framework.

**Accept:** Test real package retrieval on a local corpus with local embeddings, tenant-filter bypass attempts, stale/deleted evidence, bounded iterative retrieval, stable citations and reindex/export before provider migration.

**Later coverage:** LlamaIndex+pgvector; Haystack later; RAGFlow later; Qdrant/Milvus storage alternatives. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `KN-RET-ADOPT-001` is WAITING_PACKET_PUBLICATION in `knowledge-plane`; related retained packets: `KN-RET-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H8 · knowledge.memory-state

Adopt the OSS Mem0 memory extraction/retrieval component with explicitly configured local model and storage backends; hosted Mem0 is excluded.

**Build:** Own tenant-scoped state, provenance, consent, retention, supersession, deletion and authority boundaries; memory content never grants tool permissions.

**Accept:** Test multi-session dependent tasks, poisoning, stale fact supersession, deletion across derived indexes and restore. Bind extraction/model/index versions; online defaults and unknown dependencies fail closed.

**Later coverage:** Mem0 OSS; Graphiti later; Letta later; LangMem later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `KN-MEM-ADOPT-001` is WAITING_PACKET_PUBLICATION in `knowledge-plane`; related retained packets: `KN-MEM-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H9 · execution.protocol-interoperability

Use official MCP and A2A SDK implementations for selected wire protocols, not a new JSON-RPC/protocol stack.

**Build:** Own authenticated discovery, capability restrictions, immutable server manifests, tenant routing and protocol-to-platform error mapping. SDK negotiation cannot grant authority.

**Accept:** Test pinned-package interoperability, malformed and downgraded negotiation, replay, cancellation and forbidden resource access. Preserve versioned contracts and independent policy enforcement.

**Later coverage:** Official MCP SDK; Official A2A SDK complementary; FastMCP later; ContextForge gateway later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `EXEC-PROTO-ADOPT-001` is WAITING_PACKET_PUBLICATION in `execution-plane`; related retained packets: `EXEC-PROT-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H10 · execution.orchestration

Plan self-hosted Temporal as the preferred durable execution engine. LangGraph is a later agent-logic adapter, not a second retry/side-effect authority for the same task.

**Build:** Own task API, business intent, policy admission, approvals, receipts and tool broker integration. Freeze further general-purpose PostgreSQL executor expansion; retain existing work and read-only reference tests until a separately authorized migration.

**Accept:** Prove signals/approval waits, restart/replay, cancellation, idempotent activities, duplicate-side-effect prevention and retention under local Linux. Worker nondeterminism, workflow version upgrades and PostgreSQL history export/drain require reviewed rollback. Temporal does not guarantee exactly-once external effects.

**Later coverage:** Temporal durable baseline; LangGraph optional agent logic; Other durable engines only after comparative ADR. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `EXEC-TEMPORAL-001` is WAITING_PACKET_PUBLICATION in `execution-plane`; related retained packets: `EXEC-ORCH-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H11 · execution.tool-skill-sandbox

Use gVisor for approved Linux container isolation or Wasmtime for eligible Wasm tools; use upstream protocol tool interfaces. Do not build a sandbox kernel.

**Build:** Own tool admission, least privilege, approval/receipt binding, exact resource cleanup and versioned skill promotion. H1 manages runtime installation, not execution authority.

**Accept:** Test escape attempts, denied egress/mounts, resource exhaustion, cancellation and exact-UID cleanup on qualified Linux. Learned/new skill proposals never self-install or self-promote; curated tool artifacts remain digest-pinned.

**Later coverage:** gVisor; Wasmtime; Kata later; Firecracker later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `EXEC-SANDBOX-ADOPT-001` is WAITING_PACKET_PUBLICATION in `execution-plane`; related retained packets: `EXEC-TOOL-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H12 · execution.ml-decision

Use scikit-learn for declared classical ML workflows and ONNX Runtime for pinned inference; OR-Tools remains an independently scoped optimization option.

**Build:** Own decision contracts, lineage, model promotion, confidence/abstention and industry validation. Autonomous training or production self-modification is not enabled.

**Accept:** Test offline deterministic fixtures, schema mismatch, data leakage, drift, rejected unsigned models and local resource caps; unknown executable deserialization denies. Paper results do not qualify our models.

**Later coverage:** scikit-learn; ONNX Runtime; OR-Tools; AutoGluon later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `EXEC-ML-ADOPT-001` is WAITING_PACKET_PUBLICATION in `execution-plane`; related retained packets: `EXEC-ML-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H13 · trust.security-safety

Use OPA for policy evaluation and Presidio for selected PII detection/redaction with local assets; local NeMo Guardrails can follow for a separately released dialog capability.

**Build:** Own authoritative action-boundary admission, signed policy context, tenant isolation and no-privilege-escalation controls. A probabilistic detector cannot override a deterministic denial.

**Accept:** Test injection-aware untrusted tool outputs, sensitive-data leakage, policy outage fail-closed and rule/model false negatives on local adversarial fixtures. Separate PII/detection coverage from authorization assurance.

**Later coverage:** OPA/Presidio complementary; NeMo Guardrails later; Cedar authorization later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `TRUST-SAFE-ADOPT-001` is WAITING_PACKET_PUBLICATION in `trust-plane`; related retained packets: `TRUST-001`, `TRUST-002`, `TRUST-003`. G1–G8 apply; old packet paths are not authority to add this framework.

### H14 · trust.governance-agentops

Reuse OPA policy-as-code and MLflow OSS model/prompt artifact registry capabilities. MLflow does not replace the platform provider/agent registry or tenant acceptance authority.

**Build:** Own signed provider lifecycle, support ownership, human approval identity, autonomy tiers, revocation and immutable evidence links. Share the selected upstream OPA artifact, not another owner or database writer.

**Accept:** Test promotion/revocation, stale policy, approver separation, replay and bounded runtime independence from the control plane. Never infer vendor governance coverage from a registry integration.

**Later coverage:** OPA+MLflow scoped baseline; Cedar alternative; CUGA policy integration later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `TRUST-GOV-ADOPT-001` is WAITING_PACKET_PUBLICATION in `trust-plane`; related retained packets: `TRUST-GOV-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H15 · trust.observability-finops

Use OpenTelemetry collection/export and Prometheus metrics with tenant-local approved storage. Retain Jaeger as a tracing option; Langfuse OSS is a later separately reviewed experience layer.

**Build:** Own correlation, tenant redaction, evidence references and usage attribution; do not create a general telemetry collector/metrics store.

**Accept:** Test no external telemetry, denied payload attributes, cross-tenant queries, loss/backpressure, stale projections and attribution. An unhealthy collector does not make unmeasured requests appear ready or free.

**Later coverage:** OTel+Prometheus/Jaeger; Langfuse OSS later; OpenLLMetry later; Laminar later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `TRUST-OBS-ADOPT-001` is WAITING_PACKET_PUBLICATION in `trust-plane`; related retained packets: `TRUST-OBS-001`. G1–G8 apply; old packet paths are not authority to add this framework.

### H16 · trust.evaluation-assurance

Use Inspect AI for agent/task evaluation with local models; add Ragas for RAG metrics and promptfoo for local red-team suites only after pinned-package and dependency review.

**Build:** Own evidence schemas, immutable subjects, release gates and independence. Keep pytest for deterministic source/contract checks; it is not the agent-quality engine.

**Accept:** Test real pinned evaluation package, local dataset/model assets, reproducibility, known-failing task scores, denied network/API defaults and signed evidence separation. Research about subsampling never permits filtering mandatory acceptance/CI recipes.

**Later coverage:** Inspect AI; Ragas after maintenance review; promptfoo local later; DeepEval later. These are role-specific possibilities, not four interchangeable providers.

**Coordination:** `TRUST-EVAL-ADOPT-001` is WAITING_PACKET_PUBLICATION in `trust-plane`; related retained packets: `TRUST-EVAL-001`, `CONF-A2-001`. G1–G8 apply; old packet paths are not authority to add this framework.

## Cross-repository execution policy

The existing [ownership and typed dependency policy](PROVIDER_ADOPTION_ROADMAP.md) remains normative.
R00 coordinates; R01 owns public contracts; R02 owns generic SDKs; R03 owns industry guidance; R04 owns
Next.js/TypeScript management projections. R05–R10 own the adapters for their existing harnesses.
R09 owns provider registration/promotion/revocation, R11 owns packaging and R12 owns independent qualification.
A provider does not create a14th repository. One harness has one accountable owner.

Each future cross-repository feature has one roadmap parent and separate exact owner packets.
Sequence: contracts → SDK/industry packs → affected harness adapter → trust registration → control projection
→ released artifacts → distribution assembly → operator mode-aware install → independent conformance.
This is coordination order, not permission to introduce an unconditional runtime cycle or synchronously
depend on control-plane availability. Keep contractSource, buildArtifact, releaseSet and runtimeIntegration
edges separate; consumer → provider directions, capability conditions and subjectUnderEvaluation exception
remain unchanged. Publish typed graph amendments before any new interface/dependency is used.

One source branch and PR per packet, exact allowed paths and predecessor digests, declared full isolated
localhost acceptance, required self-hosted CI, protected green merge and independent exact-main.
No submodule/runtime Git composition, mutable artifact references or copied plane implementation.
Shared upstream artifacts may be packaged once; services never directly write another owner schema.
H13 and H14 may use the same OPA artifact but retain distinct adapter, policy and evidence responsibilities.

## Declarative installation and custom systems

Questionnaire or YAML → TenantDemand → deterministic locked profile → reviewed change plan → signed minimal bundle → HarnessInstallation → observed status and independent evidence.

Questionnaire and YAML use the same contracts/compiler and must produce equivalent locked profiles.
First establish business goals, domain vocabulary and data quality/completeness/freshness; then admit
only capability-compatible providers. Show prerequisite suggestions and require explicit acceptance.
One active selection per exclusive group; multiple qualified alternatives are allowed.

Built-in managed installation acts only on existing authorized capacity. External attachment manages
only the adapter/binding and never provisions, upgrades, migrates or deletes the external service.
Custom adapters are signed, versioned, isolated artifacts with explicit support owners; no runtime Git
URLs, control-plane code injection, core provider shadowing or self-certification. Tenant adapters may
live outside our13 repositories. Minimal bundles contain selected modules plus required closure,
not a monolithic image or every alternative. This packet does not change schemas or enable selectors.

## Adoption and qualification gates

- **G1:** Publish exact owner packet and public-contract compatibility; preserve all existing predecessors and source locks.
- **G2:** Pin provider version, image/package and transitive offline assets; component licenses, model/dataset rights, SBOM, notices, signatures and vulnerabilities pass review.
- **G3:** Build a thin adapter using released interfaces; compare real pinned-package behavior to contract vectors. Fake surfaces do not qualify an upstream.
- **G4:** Verify built-in managed, external attachment and custom modes separately. Existing external systems are never provisioned, migrated, upgraded or deleted by attachment.
- **G5:** Prove denied egress, no hosted API/key/download/telemetry/license check and no incremental billing on existing authorized capacity.
- **G6:** Independently test tenant isolation, policy failure, permission escalation, cancellation, stale state and domain/data readiness.
- **G7:** Qualify exact Linux profile and selected bundle offline install, restart, outage, upgrade, export/reindex, data migration and recovery. macOS source tests are not Linux evidence.
- **G8:** Keep source, CI, merge, artifact, deployment, runtime, assurance and tenant acceptance separate; only exact capability/version/mode/environment evidence satisfies a release floor.

`RESEARCH_CANDIDATE → PLANNED_BASELINE_TARGET → PACKET_PUBLISHED → ADAPTER_IMPLEMENTED → ARTIFACT_RELEASED → ENVIRONMENT_QUALIFIED → TENANT_ACCEPTED` is a set of separately evidenced stages, not automatic promotion.
A catalog entry or merged adapter cannot be displayed as READY. Retain per-service owned state,
required/optional capability dependencies, failure/degradation mode, startup/readiness, restart and
recovery. Provider-outage and stale-observation tests must avoid false readiness in the tenant overview.

## Preserve current work; change future implementation direction

- **gateway:** Current planeon.gateway remains the implemented/legacy surface; LiteLLM compatibility-only selectors remain rejected until a new owned adapter, catalog amendment, release locks and conformance evidence are published. The roadmap no longer directs expansion of a competing generic routing engine.
- **orchestration:** Temporal is a planned target, not an authorized runtime change. EXEC-ORCH-001 must not be dispatched for further bespoke executor growth. Publish a compatibility/migration ADR and exact successor packet before implementation; drain/export existing jobs, never rewrite histories or dual-dispatch side effects.
- **evaluation:** Existing pytest/source/conformance evidence stays valid only for its original claim. Inspect/Ragas adoption adds agent-quality evidence without replacing or filtering mandatory acceptance.
- **knowledge:** Existing PostgreSQL, connector and retrieval contracts remain valid. Framework adoption requires profile-specific schema/index/data migration and reverse-path proof; no bulk core rewrite.

The existing `CONF-FIX-007` draft remains paused and untouched during this amendment.
`CONF-LIVE-004` remains WAITING_PREDECESSOR_CORRECTION under
[MET-REPAIR-017](CONFORMANCE_COMPLETION.md). Complete C1–C7 and all source gates before004;
no original command, timeout, signature, source boundary or consumed allowance changes here.
The completion packet remains narrow safety/conformance work, not a place to implement OSS adapters.

## Phase backlog

| Phase | ID | Status | Deliverable |
|---|---|---|---|
| Phase0 / Alpha1 | Historical foundation packets | DONE_RECORDED | Retained source/offline foundations, not universal qualification |
| Alpha2 planning | MET-ADOPT-002 | ONGOING | Publish and verify this crosswalk, ownership, delivery and drift gates |
| Alpha2 correction | CONF-FIX-007 | PAUSED_RESEARCH_AMENDMENT | Resume bounded C1–C7 completion after this amendment source gates |
| Alpha2 native readiness | CONF-LIVE-004/005/006 | WAITING | Existing Linux probes, packaging and trusted integration after correction |
| Alpha2 extensions | CON-EXT-001 → SDK-EXT-001 / CONF-EXT-001 → TRUST-EXT-001 → CTRL-EXT-001 / DIST-EXT-001 → OP-EXT-001 | WAITING_PACKET_PUBLICATION | Contract-first governed built-in, external and custom bindings |
| Alpha2 harness integrations | H1–H7, H9–H10, H13, H15–H16 owner rows | WAITING_PACKET_PUBLICATION | Real pinned OSS integrations for selected read-only profile |
| Alpha2 integrated acceptance | CONF-A2-001 | WAITING | Qualified end-to-end read-only profile; existing source gates remain mandatory |
| Alpha3 | H8/H11/H12/H14 owner rows; CONF-A3-001 | WAITING | Governed actions, memory, sandbox, ML and oversight |
| Alpha4 | Existing enterprise qualification packets | WAITING | At least one qualified baseline for every released capability, offline upgrade and tenant acceptance |
| Post-release | Provider-specific successor packets | WAITING | 3–4 meaningful alternatives progressively; Milvus external before managed |

Alpha2 remains open. Model-effort phase transition: **NOT_DUE**. The16 proposed harness packets
and7 retained extension specifications are roadmap work, not23 additional dispatchable YAML packets.
Before publishing any of them, identify exact current owner-repository tree, predecessor release
versions/digests, affected consumers, allowed paths, complete argv, CI, migration and rollback.

## Research provenance and confidence

All three user reports were read as research inputs; their SHA-256 identities are recorded in the ledger.
The curated crosswalk uses18 primary paper records and32 GitHub metadata snapshots checked2026-09-15.
It does not claim exhaustive verification of every paper/repository in those reports.
Older first-publication years are explicit. The paper-to-component relationship is mostly
**CONCEPTUAL_ALIGNMENT**: our engineering inference, not an official implementation claim.
AEGIS explicitly names OPA/ContextForge integration in its abstract and is marked **EVALUATED_COMPONENT**.
The20th-century/2023/2025 foundations are not relabeled2026 releases.

GitHub metadata redirected Great Expectations to `fivetran/great_expectations`, Presidio to
`data-privacy-stack/presidio`, and Ragas to `vibrantlabsai/ragas`; original aliases remain in the ledger.
This is a discovery observation, not permission to trust a transferred artifact. Revalidate immutable
version provenance, component licenses and maintainer/security continuity at packet publication.
Ragas showed a last-push snapshot of2026-02-24 and therefore needs an explicit maintenance check.

LiteLLM root LICENSE excludes `enterprise/` from the MIT grant. Review the exact OSS-only dependency
closure; do not ship enterprise code or use enterprise-only functions to satisfy a required capability.
A repository root license never licenses arbitrary vendored assets, model weights, datasets or images.
Unknown/NOASSERTION stays unreleased. No public repository license overrides the existing
[legal policy](../../legal/third-party-license-policy.yaml) or [warm-source ADR](../adr/0003-source-reuse-and-provenance.md).
The five original warm inputs remain reference-only; no checkout/source access or copy occurred.

No live services, package installs, cloud resources, model downloads or billable APIs are authorized
by this mapping. Production qualification stays Linux Kubernetes/OpenShift; macOS supports development.
