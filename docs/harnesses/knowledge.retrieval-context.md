# Harness Specification: `knowledge.retrieval-context`

## Sector direction — MET-SECTOR-001

Owner decision SECTOR-D1 (October 7, 2026): banking replaces white goods as the first and only release
sector from Alpha 2 through the first enterprise release; [sector direction](../alpha-2/SECTOR_DIRECTION.md)
gives every disposition. The golden query set moves to banking questions about products, terms and policies,
keeping the ambiguous, stale, absent and conflicting cases. White-goods material below records what was
specified or built; it is historical, not current direction.

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

Planning target: `run-llama/llama_index` + `pgvector/pgvector`.
Use pinned minimal LlamaIndex core/local integrations for retrieval pipelines and PostgreSQL/pgvector as the first index option; exclude hosted LlamaCloud and default online models.
Platform scope: Own identity filters, citation/provenance envelope, context budgets, corpus/version selection and readiness. Do not rebuild a general RAG framework.
Delivery: `KN-RET-ADOPT-001` (ALPHA_2, WAITING_PACKET_PUBLICATION).
Acceptance: Test real package retrieval on a local corpus with local embeddings, tenant-filter bypass attempts, stale/deleted evidence, bounded iterative retrieval, stable citations and reindex/export before provider migration.
This takes precedence over older build-from-scratch directions for future work,
not over current public contracts or active provider selectors. Retained provider
paragraphs below describe the prior/current implementation boundary, not permission
to expand a competing general-purpose engine.

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

## Contract

| Field | Value |
|---|---|
| Plane | Knowledge |
| Owning repository | `mas-harness-knowledge-plane` |
| Warm source | `data-source-harness@858281f4b845ffacfe05cdb2c40a402c237d4c54` |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness creates versioned retrieval indexes from accepted data batches, performs tenant- and policy-filtered lexical/vector/hybrid retrieval, reranks locally, assembles bounded context, and returns source citations with provenance and freshness metadata.

It does not own source ingestion, edit source data, store long-term user memory, persist orchestration checkpoints, or permit uncited model-generated statements to masquerade as retrieved evidence.

## Owner and deployables

- `retrieval-service`: query validation, policy filters, hybrid search, reranking, context assembly, and citation response.
- `index-worker`: builds immutable index generations from accepted batch/domain digests.
- Optional reranker image: local cross-encoder, selected separately.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `knowledge.domain-semantic`, `knowledge.data-integration`, `trust.security-safety`, `trust.observability-finops`.
- Optional: `runtime.model-inference` for embeddings/reranking, `trust.evaluation-assurance`, `runtime.ai-gateway`.
- Conflicts:
  - Index generation references unaccepted or quarantined data.
  - Embedding model lacks custody/license approval or is not available offline.
  - Filter schema cannot enforce tenant/classification restrictions.
  - A profile requests memory write through retrieval APIs.

Index build follows accepted domain and data digests; activation precedes consumer route promotion.

## Provider implementations

- `planeon.postgres-hybrid`: baseline PostgreSQL full-text search plus pgvector; lexical-only mode does not require model inference.
- `planeon.local-cross-encoder`: optional local reranking provider using an approved model artifact.
- `planeon.qdrant`: contract-only, non-installable vector-store guidance; an active selector is rejected as `PROVIDER_UNAVAILABLE`.

PostgreSQL hybrid is the only selectable store in this release. If its certified
capacity/latency envelope is insufficient, compilation reports an unsupported
requirement instead of selecting Qdrant.

## Configuration and runtime boundaries

```yaml
index:
  id: string
  domainDigest: sha256:...
  sourceBatchSelectors: []
  strategy: lexical | vector | hybrid
  chunking:
    method: semantic-boundary | fixed
    maxTokens: integer
    overlapTokens: integer
  embeddingRouteId: string-or-null
  dimensions: integer-or-null
  metadataAllowlist: [field]
query:
  topK: integer
  candidateK: integer
  maxContextTokens: integer
  rerankerRouteId: string-or-null
  minimumScore: decimal-string
citations:
  required: true
  includeProvenance: true
```

- Secrets: no baseline secrets; optional store credentials are references.
- RBAC: no Kubernetes API access. Roles are `retrieval:index-admin` and `retrieval:query`.
- Network: index worker reaches accepted batch storage, domain service, selected embedding route, index store, policy, and OTel. Query service reaches index, policy, optional reranker, and OTel only.
- Storage: each tenant/index generation uses a separate schema/collection. Chunks contain source object IDs and provenance digests, not undisclosed credential/source metadata. Runtime memory/checkpoints are excluded.

## APIs, events, and state

```text
POST /knowledge/v1/indexes
POST /knowledge/v1/indexes/{id}:build
POST /knowledge/v1/indexes/{id}/generations/{generation}:activate
GET  /knowledge/v1/indexes/{id}
POST /knowledge/v1/retrieve
POST /knowledge/v1/context:assemble
```

Index generation states: `DECLARED → BUILDING → VALIDATING → READY → ACTIVE`; alternatives `FAILED`, `STALE`, `SUPERSEDED`, `REVOKED`.

Emitted:

- `retrieval.index.build.requested.v1`
- `retrieval.index.ready.v1`
- `retrieval.index.activated.v1`
- `retrieval.index.stale.v1`
- `retrieval.query.completed.v1`

Consumed: `data.batch.committed.v1`, `data.source.degraded.v1`, `domain.version.superseded.v1`, `model.route.rejected.v1`.

Query events contain counts, filters, scores, latency, and digests—not query text or retrieved content unless an evidence plan explicitly permits classified payload storage.

## Failures, retry, and rollback

- Index builds write a new immutable generation and activate atomically only after validation.
- Build retries from a content-addressed checkpoint; corrupt or changed batch digests fail closed.
- Query failure never broadens filters or falls back across tenant/classification boundaries.
- Vector-provider outage may use lexical fallback only when the profile declares it and the response marks `retrievalMode` accordingly.
- Reranker failure may return pre-reranked results only if its policy marks reranking optional.
- Rollback reactivates a previously validated generation; deletion follows retention and active-reference checks.
- Source/domain supersession marks affected generations `STALE` but does not mutate their contents.

## Evidence and readiness gates

- Accepted source batch and active domain digests.
- Chunk coverage, duplicate rate, orphan citation rate, and sensitive-field handling.
- Tenant/classification filter enforcement.
- Citation resolution from chunk to source and provenance.
- Retrieval quality set with recall, precision/nDCG, citation correctness, and freshness.
- Embedding/reranker custody, license, and local availability when selected.
- Index rebuild determinism or documented acceptable nondeterminism bounds.

Production readiness requires zero cross-tenant/filter violations and current quality/freshness evidence.

## Profile behavior

- `minimal-local`: PostgreSQL full-text or hybrid, one active generation, no reranker by default.
- `enterprise`: hybrid retrieval, replicated query service, local reranking, generation retention and quality gates.
- `airgap-enclave`: all embedding/reranker weights imported; no remote embedding API; offline citations remain resolvable.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: query plans, context assembly, citations, source routing, and semantic mapping fixtures; no warm checkout access.
- Unit: chunking, filters, scoring merge, token budget, citation construction, staleness propagation.
- Contract: APIs/events and model/data/domain dependencies.
- Security: tenant/filter bypass, SQL/filter injection, malicious metadata, payload logging.
- Quality: white-goods golden query set including ambiguous, stale, absent, and conflicting evidence.
- Failure: interrupted build, corrupt batch, model outage, store outage, atomic activation/rollback.
- Air gap: index build and query with egress denied.

## Sol-high implementation packets

1. `KN-001-foundation`: shared knowledge kernel, RLS/inbox/outbox, privacy-safe references, images/charts, and dependency mocks.
2. `KN-RET-001`: index generations, PostgreSQL FTS/pgvector, optional local embeddings/reranking, hybrid ranking, tenant/classification filters, bounded context, citations/provenance, source/domain invalidation, quality gates, and rollback.
3. `KN-002-security-resilience`: tenant/index isolation, malicious content/metadata, stale-index behavior, model/store outages, atomic recovery, and offline operation.

Each packet keeps retrieval storage and APIs independent from memory and orchestration state.
