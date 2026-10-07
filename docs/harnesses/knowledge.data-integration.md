# Harness Specification: `knowledge.data-integration`

## Sector direction — MET-SECTOR-001

Owner decision SECTOR-D1 (October 7, 2026): banking replaces white goods as the first and only release
sector from Alpha 2 through the first enterprise release; [sector direction](../alpha-2/SECTOR_DIRECTION.md)
gives every disposition. Source inventory, quality thresholds and fixtures move to banking customer, account
and transaction sources with synthetic, non-personal data (`IND-BANK-002`). White-goods material below
records what was specified or built; it is historical, not current direction.

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

Planning target: `trinodb/trino` + `fivetran/great_expectations` + `OpenLineage/OpenLineage`.
Reuse Trino for selected federated read-only query capabilities, Great Expectations Core for dataset quality and OpenLineage for lineage events. Each is included only for a selected capability.
Platform scope: Own connector declarations, endpoint authorization, tenant identity propagation, quarantine, freshness and completeness gates. Do not create a general federation engine or replace existing ingest semantics without migration.
Delivery: `KN-DATA-ADOPT-001` (ALPHA_2, WAITING_PACKET_PUBLICATION).
Acceptance: Attach existing local services first. Test row/column restrictions, unknown charges denial, denied writes, source lineage, stale/schema-drift/quarantined data and disconnected fixtures; target adoption must not widen current raw-source access.
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

This harness declares tenant data sources, validates connectivity and schemas, performs bounded read ingestion, normalizes records against the active domain model, records lineage/provenance, measures quality/completeness/freshness, and publishes immutable batches for downstream indexing and assurance.

It does not perform arbitrary source mutations, execute tools, own retrieval indexes, write long-term memory, infer that incomplete data are acceptable, or store credentials in source definitions. Write-capable integration is delegated through `execution.tool-skill-sandbox` with governance and receipts.

## Owner and deployables

- `connector-controller`: source declarations, connector lifecycle, schedules, checkpoints, and readiness aggregation.
- `ingest-worker`: ephemeral/bounded worker for extract, decode, map, validate, persist, and provenance.
- Connector images: independently packaged HTTP/OpenAPI, JDBC/PostgreSQL, filesystem/object, and event-stream providers.

Only selected connector images appear in a tenant bundle.
SFTP is contract-only, non-installable comparative guidance in this release and
cannot be selected into a bundle.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `knowledge.domain-semantic`, `trust.security-safety`, `trust.observability-finops`.
- Required for production acceptance: `trust.governance-agentops`.
- Optional: `knowledge.retrieval-context`, `execution.ml-decision`, `trust.evaluation-assurance`.
- Conflicts:
  - Source mapping targets a non-active or mismatched domain digest.
  - Connector requests mutation/write capability.
  - Offline profile contains a remote endpoint that is not reachable inside the enclave.
  - Source retention or residency conflicts with the tenant evidence plan.
  - Connector image/license is not redistributable for the selected distribution.

Ordering: domain publication, identity/policy, connector validation, sampling/readiness, owner approval, then production ingestion.

## Provider implementations

- `planeon.connector.http`: bounded HTTP/OpenAPI reads with allowlisted hosts and pagination.
- `planeon.connector.jdbc`: read-only JDBC/PostgreSQL queries using prepared statements and source-side limits.
- `planeon.connector.file`: mounted filesystem and imported object batches.
- `planeon.connector.sftp`: contract-only, non-installable guidance for allowlisted reads and host-key pinning; an active selector is rejected as `PROVIDER_UNAVAILABLE`.
- `planeon.connector.events`: tenant-local Kafka/NATS-compatible subscriptions.

The connector contracts, worker pipeline, provenance, freshness, white-goods
fixtures, and certification tests are independent clean-room targets derived
only from released contracts and pre-recorded, digest-pinned observations;
implementation cannot access, copy, adapt, translate, or derive code from a
warm checkout. HMAC production signing, fused state models, and the old
canonical namespace are not retained.

### KN-DATA-001 implementation boundary

The first data-integration packet implements only declaration/validation,
fenced leases, bounded read-plan execution through injected ports, strict local
decoding, and immutable staged-batch metadata. Public source definitions contain
digest references for endpoints, credentials, network policy, active domain,
mapping, schema, and owners; raw locators, paths, URLs, SQL, topics, connection
strings, Secret names/keys/values, and payloads are forbidden. Endpoint and
secret grants are already verified trust inputs and are never discovered,
signed, or verified by the knowledge plane.

FILE, HTTP, PostgreSQL, and EVENT are contract adapters, not bundled drivers.
The core opens no path/socket/database/broker and performs no DNS or credential
operation. Tests inject bounded provider observations. FILE rejects traversal,
symlinks, devices, and archives; HTTP rejects redirects, userinfo, metadata
targets, cross-authority pagination, and unsafe request features; PostgreSQL
accepts only a grant-pinned statement id/digest and read-only prepared execution;
EVENT accepts only a grant-pinned topic/partition and never auto-commits.

KN-DATA-001 source history stops at `VALID` or `SAMPLED`, and its batch history
stops at `STAGED`. `KN-DATA-002` exclusively owns readiness thresholds and
PASS/WARN/FAIL, owner approval, activation, committed batches, checkpoint
advancement, retry/dead-letter, provenance, and quality evidence. A staged batch
therefore cannot be treated as accepted input, deployment/runtime evidence, or
tenant acceptance.

Its cumulative self-hosted verification uses the existing pinned,
credential-free checkout with full public Git history so exact KN-001 and
KN-DOM ancestor objects remain available to unchanged predecessor checks. This
does not authorize hosted runners, credential persistence, artifacts/caches,
external actions, runtime downloads, or any billable service.
The inherited common workflow assertion and zero-bill scanner synchronize only
their required checkout-depth literal to this full-history contract; every
other zero-bill and two-step-workflow denial remains unchanged.

### KN-DATA-002 implementation boundary

The second packet starts only from exact merged KN-DATA-001 and adds no package,
driver, runtime download, source connection, or deployment behavior. It first
closes one activation-critical predecessor gap: every new staged batch and
checkpoint candidate carries the exact lease partition in its canonical digest.
Legacy unbound batches remain readable but cannot be assessed or committed.

Readiness input is injected, digest-bound metadata. A versioned tenant-approved
policy supplies decimal PASS/WARN thresholds; a measurement observation supplies
only bounded counts, source-observation time, validity, and predecessor digests.
The public request cannot supply tenant identity, policy, measurements,
prerequisite evidence, approval, or a result. The industry-pack policy is used
only for deterministic parity and is explicitly ineligible for activation.

Assessment is an append-only worker workflow with fenced claims, at most three
attempts, and deterministic 1- then 4-second retry metadata. No in-process sleep
or cloud scheduler is used. Non-retryable or exhausted work creates a durable
dead letter; review can acknowledge it but cannot delete, silently requeue, or
turn it into a pass. Successful processing atomically appends decimal findings,
an exact ten-gate `DataReadinessAssessment`, a bounded acyclic provenance graph,
a `SOURCE`-axis `EvidenceRecord`, a source-readiness revision, and an outbox
event. Missing or stale evidence never yields READY, and source freshness is not
misrepresented as retrieval-index freshness.

Operational readiness is separate from the KN-DATA-001 source revision history:
absence derives `UNASSESSED`; PASS becomes `READY_FOR_APPROVAL`; WARN/FAIL becomes
`DEGRADED`; an expired input is effectively `DEGRADED`; and explicit `REVOKED`
dominates. Commit additionally requires an exact current PASS, an unexpired
policy allow, and an independently verified owner approval bound to the source,
batch, assessment, evidence, policy, and provenance. One transaction then
appends the committed-batch record, advances only the digest checkpoint for that
partition, activates the source, and records provenance/evidence/events. Owner
approval is neither a policy allow nor tenant acceptance.

## Configuration and runtime boundaries

```yaml
source:
  id: string
  connectorProvider: string
  endpointRefDigest: sha256:...
  credentialRefDigest: sha256:... | null
  networkPolicyDigest: sha256:...
  classification: public | internal | confidential | restricted
  residency: [string]
  ownerDigest: sha256:...
  accessMode: read-only
schema:
  expectedSchemaDigest: sha256:...
  activeDomainVersionDigest: sha256:...
  domainMappingDigest: sha256:...
ingestion:
  mode: snapshot | incremental | stream
  schedule: cron-or-disabled
  checkpointPolicy: source-specific
  maxRecordsPerBatch: integer
  maxBytesPerBatch: integer
readiness:
  policyVersion: semver
  completeness: {passMinimum: decimal-string, warnMinimum: decimal-string}
  freshnessMinutes: {passMaximum: decimal-string, warnMaximum: decimal-string}
  duplicateRate: {passMaximum: decimal-string, warnMaximum: decimal-string}
  classificationCoverage: {passMinimum: decimal-string, warnMinimum: decimal-string}
  provenanceCoverage: {passMinimum: decimal-string, warnMinimum: decimal-string}
```

- Secrets: referenced Kubernetes Secret paths; mounted only into the selected worker and never returned by APIs.
- RBAC: controller reads owned source CRs/config; workers have no Kubernetes API access and use connector-specific service accounts.
- Network: each worker receives an egress policy containing only source host/port, DNS, policy, storage, and OTel. Connector input is never converted into an unrestricted URL.
- Storage: source metadata/checkpoints/provenance live in data-integration-owned knowledge tables. Raw/normalized batches use tenant PVC or declared tenant-owned S3-compatible storage. Batches are content addressed and immutable.

## APIs, events, and state

```text
POST /knowledge/v1/sources
GET  /knowledge/v1/sources/{id}
POST /knowledge/v1/sources/{id}:validate
POST /knowledge/v1/sources/{id}:sample
GET  /knowledge/v1/sources/{id}/readiness
POST /knowledge/v1/sources/{id}:revoke
GET  /knowledge/v1/staged-batches/{id}
POST /knowledge/v1/staged-batches/{id}:assess
POST /knowledge/v1/staged-batches/{id}:commit
GET  /knowledge/v1/readiness-assessments/{id}
GET  /knowledge/v1/dead-letters/{id}
POST /knowledge/v1/dead-letters/{id}:review
```

Connector source revisions remain `DECLARED → VALIDATING → VALID → SAMPLING →
SAMPLED`, with `INVALID` and `DISABLED` alternatives. Repeated sampling may start
from `VALID` or `SAMPLED`.

Separate operational readiness states are derived `UNASSESSED`, then
`READY_FOR_APPROVAL`, `ACTIVE`, `DEGRADED`, or terminal `REVOKED`. Batch metadata
remains immutable `STAGED`; an accepted batch gains a separate immutable
`COMMITTED` record. Work states are `PENDING`, `CLAIMED`, `RETRY_SCHEDULED`,
`SUCCEEDED`, or `DEAD_LETTERED`.

Emitted:

- `data.source.validated.v1`
- `data.readiness.assessed.v1`
- `data.batch.committed.v1`
- `data.batch.quarantined.v1`
- `data.source.degraded.v1`

Consumed: `domain.version.published.v1`, `approval.decided.v1`, `policy.bundle.activated.v1`.

## Failures, retry, and rollback

- Connectivity and sampling failures do not activate a source.
- Snapshot/incremental batches commit atomically after validation. Partial output remains staging and is never advertised.
- Checkpoints advance only after batch commit. Duplicate source records are handled through declared stable record IDs and batch digests.
- Readiness work has at most three fenced attempts and deterministic 1- then 4-second retry metadata for an allowlisted transient failure. The core never sleeps or schedules external work. Authentication, schema, policy, mapping, and contract failures dead-letter without automatic retry.
- Stream consumers use inbox/checkpoint semantics and tolerate duplicate delivery.
- Schema drift creates a new readiness finding and pauses ingestion when classified breaking.
- KN-DATA-002 never rewinds a checkpoint or reactivates a revoked source. Rollback preserves immutable histories and marks derived readiness stale through future authority; source systems are never modified.

## Evidence and readiness gates

- Named owner, classification, residency, retention, and lawful/approved purpose.
- Credential and connectivity validation without secret disclosure.
- Expected/observed schema diff.
- Completeness, freshness, duplicate, null, type, sensitive-field, and provenance coverage measurements.
- Domain mapping coverage and unresolved-term report.
- Source/batch lineage from origin through normalized object.
- Read-only enforcement and egress-policy test.
- Sample acceptance by the data owner.

Production activation requires all pack-mandated readiness thresholds; warnings require explicit, expiring governance waiver.

## Profile behavior

- `minimal-local`: mounted files and local PostgreSQL/HTTP sources, manual ingestion, local PVC.
- `enterprise`: multiple connectors, scheduled/incremental workers, HA metadata store, source-specific quotas.
- `airgap-enclave`: only enclave-local endpoints or imported files/objects; selected connector images, drivers, and certificates are vendored.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: connector profiles, batches, provenance, freshness, coverage, mapping, and air-gap fixtures; no warm checkout access.
- Unit: pagination, checkpoints, schema diff, quality metrics, provenance graph, stable IDs.
- Contract: source/batch APIs, connector SDK, CloudEvents, domain mapping.
- Security: SSRF, SQL injection, path traversal, archive bombs, secret/log redaction, and write attempts. SFTP host-key-mismatch cases are retained only as non-installable comparative vectors.
- Failure: source timeout, restart after read before commit, duplicate stream event, schema drift, storage exhaustion.
- Industry: white-goods API/database/file/event sources with clean, incomplete, stale, duplicate, and unmapped variants.

## Sol-high implementation packets

1. `KN-001-foundation`: common service kernel, tenant roles/RLS, inbox/outbox, privacy-safe references, images/charts, and dependency mocks.
2. `KN-DATA-001`: clean-room connector/decoder/batch implementation, source lifecycle, controller leases/checkpoints, file/HTTP/PostgreSQL/event providers, read-only credentials, and hostile-input handling.
3. `KN-DATA-002`: atomic batches, retry/dead-letter, provenance graph, completeness/freshness/coverage/classification findings, owner approval, and white-goods source fixtures.
4. `KN-002-security-resilience`: connector SSRF/egress, tenant/store isolation, malicious files/documents, duplicate events, source/storage outages, and air-gap operation.

Each packet implements one bounded clean-room source slice and preserves raw, retrieval, memory, and runtime state separation.
