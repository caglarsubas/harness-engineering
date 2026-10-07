# Repository Plan: `mas-harness-knowledge-plane`

## Sector direction — MET-SECTOR-001

Owner decision SECTOR-D1 (October 7, 2026): banking replaces white goods as the first and only release
sector from Alpha 2 through the first enterprise release; [sector direction](../alpha-2/SECTOR_DIRECTION.md)
gives every disposition. Ontology parity, source records and cited retrieval vectors move to banking through
the unpublished proposals `IND-BANK-001`, `IND-BANK-002` and `KN-BANK-001`; the white-goods fixtures of
`KN-DOM-001`, `KN-DATA-001`, `KN-DATA-002` and `KN-RET-001` are historical. White-goods material below
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

Repository R07 retains its existing accountable ownership. Planned owner packets: `KN-DOM-ADOPT-001` (H5), `KN-DATA-ADOPT-001` (H6), `KN-RET-ADOPT-001` (H7), `KN-MEM-ADOPT-001` (H8).
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

This repository owns four separately installable harnesses: `knowledge.domain-semantic`, `knowledge.data-integration`, `knowledge.retrieval-context`, and `knowledge.memory-state`. It provides domain validation, connectors/ingestion/provenance, retrieval/context assembly, and governed memory while maintaining strict store and API boundaries.

Non-goals:

- No model hosting, workflow scheduling, arbitrary tool execution, policy authority, control-plane questionnaire, or Kubernetes reconciliation.
- Retrieval indexes, persistent memory, source/provenance data, and runtime checkpoints are never fused.
- Connectors do not mutate sources; write actions belong to execution/tool governance.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-knowledge-plane/
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
├── ci/
├── contract-mocks/
├── src/planeon_knowledge/
│   ├── common/
│   ├── domain/
│   ├── ingestion/
│   │   ├── connectors/
│   │   ├── classification.py
│   │   ├── coverage.py
│   │   ├── decoder.py
│   │   ├── evidence.py
│   │   ├── freshness.py
│   │   ├── leases.py
│   │   ├── provenance.py
│   │   ├── readiness.py
│   │   └── retries.py
│   ├── retrieval/
│   └── memory/
├── services/
│   ├── domain-service/
│   ├── connector-controller/
│   ├── ingest-worker/
│   ├── retrieval-service/
│   ├── index-worker/
│   └── memory-service/
├── migrations/
│   ├── domain/
│   ├── ingestion/readiness/
│   ├── retrieval/
│   └── memory/
├── deploy/helm/
│   ├── domain-service/
│   ├── connector-controller/
│   ├── ingest-worker/
│   ├── retrieval-service/
│   ├── index-worker/
│   └── memory-service/
├── fixtures/{attacks,connectors,domain,memory,readiness,retrieval}/
├── scripts/run_failure_campaign.py
├── docs/runbooks/
└── tests/{airgap,common,connectors,domain,memory,readiness,resilience,retrieval,security}/
```

## Deployables and toolchain

- Services: `domain-service`, `connector-controller`, `ingest-worker`, `retrieval-service`, `index-worker`, and `memory-service`; each has a separate non-root image/chart/service account.
- `KN-001` starts from the empty public repository commit `f3a3463d2fe04d4b17dc3abbebc6b3375bd6d890` and bootstraps source-only, health-only shells for exact Python 3.12.14 with no third-party dependency. It does not build an image, connect to PostgreSQL, or deploy a chart.
- The target stack for later packets remains FastAPI, Pydantic v2, psycopg 3, PostgreSQL/pgvector, RDFLib, pySHACL, jsonschema, HTTPX, cryptography, and OpenTelemetry. A later packet must admit and freeze each exact dependency before use; their mention here is not installation or execution authority for `KN-001`.
- Baseline connectors are local file, allowlisted HTTP, PostgreSQL read-only, and deterministic event fixture. New connectors use the documented SDK and separate module manifest.

### `KN-001` foundation boundary

The bootstrap produces only common canonical JSON/digest/error primitives,
server-admitted `TenantIdentity`, metadata-only `SourceReference`, `InboxRecord`
and `OutboxRecord`, dependency health, six immutable service descriptors, six
health-only ASGI adapters, four additive SQL source contracts, local synthetic
contract mocks, six source-only Containerfiles, and six disabled-by-default Helm
charts. It does not implement any endpoint listed below under “Owned APIs”; those
are allocated to later behavior packets.

Readiness is fail-closed. Each service requires its local identity-admission,
policy, contract-mock, and owned-store probes to be `READY`. Optional telemetry
may be `DEGRADED`, but that state never authorizes work. Unknown routes, methods,
bodies, query strings, caller identity, missing or malformed probes, timeouts,
and probe exceptions return bounded metadata-only failures and never trigger
network discovery or retry.

### `KN-DOM-001` domain-service boundary

`KN-DOM-001` preserves the dependency-free KN-001 root package and root lock.
RDFLib 7.6.0, pySHACL 0.40.1, and their exact eight-package runtime closure are
declared and digest/license locked only in `services/domain-service/`; acceptance
uses the preinstalled root-owned IND-WG-001 semantic toolchain without package
resolution. This prevents a later harness dependency from silently changing the
foundation closure or another service image.

Domain packages and semantic mappings are immutable digest-bound metadata.
Graph/shapes bytes are supplied transiently by an injected local exact-digest
provider and are never placed in SQL, events, evidence, errors, or logs. Only
bounded Turtle and inline-context JSON-LD are admitted. The implementation
rejects remote contexts/imports, arbitrary network/file IRIs, RDF/XML, archives,
SPARQL/JavaScript/rule-based SHACL, over-limit graphs, and any engine mode other
than the closed local RDFLib/pySHACL profile.

Version and mapping state histories are append-only. Publication requires an
already verified, digest-bound approval attestation plus an exact unexpired
policy permit. Activation and compatible rollback atomically append revisions,
evidence, and an outbox event while switching one tenant-scoped active pointer;
failure leaves the prior pointer unchanged. A policy allow, fixture, test, or
generated output is never owner approval. Runtime PostgreSQL, image, and chart
execution remain `NOT_RUN_ENV_UNAVAILABLE` for this packet.

### `KN-DATA-001` connector staging boundary

`KN-DATA-001` starts only from exact merged KN-DOM-001 commit `187a3d6...`
and exact public IND-WG-002 commit `a4d3df9...`. It keeps the root package
dependency-free and adds no source driver or network client. The existing
cumulative `make prefetch` first verifies KN-001 and the KN-DOM semantic
toolchain; connector acceptance then uses injected in-memory ports only. Public
contract and industry inputs are digest locked, while destination fixtures are
independently authored and contain no copied predecessor or warm-source bytes.

The packet owns source declaration, fail-closed validation, fenced worker
leases, four bounded read-plan adapters, strict local decoding, and immutable
staged-batch metadata. Public source bodies contain only digest references and
closed limits. Verified endpoint and secret grants are injected by the trusted
adapter boundary and bind exact organization, source, connector kind, operation,
resource digest, network policy, and expiry. The repository never discovers a
host, DNS record, filesystem root, SQL statement, topic, or Secret and never
signs or verifies these grants.

Validation also consumes an injected metadata-only domain-binding observation
that proves the source's exact domain-version and semantic-mapping digests are
ACTIVE for the same tenant. Missing, stale, superseded, inactive, or mismatched
bindings deny before connector I/O; ingestion never reads the domain schema or
discovers a domain endpoint.

FILE accepts only a grant-bound relative POSIX path and an injected regular-file
receipt. HTTP accepts only GET plans under the grant's exact authority/path and
opaque same-grant pagination tokens; redirects and absolute next links deny.
PostgreSQL accepts only a pre-authorized statement id/digest with separately
bound scalar parameters and requires a read-only, prepared, row/deadline-limited
observation. EVENT accepts only grant-bound topic/partition metadata and never
auto-commits. The core performs no socket, DNS, filesystem, database, broker, or
credential operation in this source packet.

Decoding is closed to bounded strict UTF-8 JSON, NDJSON, CSV, text, and Markdown.
It rejects duplicate JSON keys, non-finite/deep/oversized values, malformed CSV,
archives, compression, XML, YAML, executable formats, and media sniffing. Lease
history is append-only with monotonically increasing fencing tokens; stale,
expired, released, wrong-owner, or wrong-tenant workers cannot stage metadata.
Staging persists only content/schema/material/checkpoint-candidate and per-record
digests after an injected sink returns an exact tenant/source/batch-bound receipt.
No payload, field value/name, URL/path, SQL/parameter, topic, credential, or
provider message is persisted or emitted.

The packet stops at source `VALID` or `SAMPLED` and batch `STAGED`. Readiness,
owner approval, ACTIVE/DEGRADED/REVOKED sources, committed batches, checkpoint
advancement, retry/dead-letter, provenance/quality findings, and white-goods
PASS/WARN/FAIL remain KN-DATA-002 work. PostgreSQL, real source connectivity,
image/chart execution, deployment, runtime, assurance, and tenant acceptance are
separate evidence axes and remain unavailable or pending.

### `KN-DATA-002` readiness and activation boundary

`KN-DATA-002` starts only from exact merged KN-DATA-001 commit `dfa67f0...`,
exact public IND-WG-002 commit `a4d3df9...`, exact public contracts commit
`2146278...`, and the already locked TRUST-001 boundary `73802ad...`. It keeps
the root dependency-free and uses no warm checkout, network client, source,
database, queue, scheduler, package install, image build, or cluster. Public
schemas and industry fixtures are digest-pinned inputs; destination validators
and parity fixtures are independently authored.

Before activation, the packet binds the lease partition into every new staged
batch and checkpoint-candidate digest. Predecessor batches without that binding
remain readable but are permanently ineligible for assessment or commit. New
sampling may repeat from a connector source revision in `VALID` or `SAMPLED`,
retaining every existing grant, domain-binding, lease, decoder, size, staging,
and idempotency rule. Staging alone never changes the active readiness pointer.

Readiness policies are versioned, tenant-approved, digest-bound observations.
Measurement observations carry bounded counts, a latest source-observation time,
validity, and exact source/batch/material/record-set/checkpoint digests—never
payload values. Decimal-safe evaluation produces completeness, freshness,
duplicate, classification-coverage, and provenance-coverage findings. Zero
observations yields only `MISSING_DATA`; FAIL dominates WARN, WARN blocks READY,
and stale/missing input cannot pass. Source freshness is kept distinct from
future retrieval-index freshness.

Worker processing is append-only and fenced. Work moves through `PENDING`,
`CLAIMED`, `RETRY_SCHEDULED`, `SUCCEEDED`, or `DEAD_LETTERED`, with no more than
three attempts and exact retry-delay metadata of 1 then 4 seconds. The core does
not sleep or schedule external work. Exhausted and non-retryable failures create
metadata-only dead letters. Review can append `ACKNOWLEDGED`; it cannot delete,
requeue, activate, or manufacture passing evidence.

A successful assessment transaction writes the findings, exact public ten-gate
`DataReadinessAssessment`, bounded digest-only provenance DAG, verified public
`EvidenceRecord` on the `SOURCE` axis, readiness revision, work success, and
outbox event together. Operational readiness is separate from connector source
history: absent is derived `UNASSESSED`, PASS is `READY_FOR_APPROVAL`, WARN/FAIL
is `DEGRADED`, commit is `ACTIVE`, and explicit `REVOKED` dominates. Expired
policy, measurements, evidence, or approval derives effective `DEGRADED` without
rewriting history.

Commit requires an exact current PASS, an unexpired fail-closed permit, and a
separate already verified owner `APPROVE` attestation bound to the source,
partitioned batch, assessment, evidence, policy, provenance, owner digest, and
expiry. A policy allow is never owner approval, and owner approval is not tenant
acceptance. One transaction appends immutable committed-batch/checkpoint/source-
activation/provenance/evidence/idempotency/outbox records and advances only the
digest checkpoint for that partition. Stale revisions, older/equal fences,
superseded or expired evidence, approval mismatch, or commit failure leaves the
prior pointers unchanged; checkpoints never rewind.

## Owned APIs, events, and stores

The following are repository-level API ownership assignments, not `KN-001`
deliverables. Their respective later packets must define request/response,
identity, policy, idempotency, state-transition, and failure contracts before
implementation.

```text
/knowledge/v1/domains
/knowledge/v1/domains/{id}/versions
/knowledge/v1/mappings:validate
/knowledge/v1/sources
/knowledge/v1/sources/{id}:validate
/knowledge/v1/sources/{id}:sample
/knowledge/v1/sources/{id}/readiness
/knowledge/v1/sources/{id}:revoke
/knowledge/v1/staged-batches/{id}
/knowledge/v1/staged-batches/{id}:assess
/knowledge/v1/staged-batches/{id}:commit
/knowledge/v1/readiness-assessments/{id}
/knowledge/v1/dead-letters/{id}
/knowledge/v1/dead-letters/{id}:review
/knowledge/v1/retrieve
/knowledge/v1/context:assemble
/knowledge/v1/indexes
/knowledge/v1/memory:read
/knowledge/v1/memory:write
/knowledge/v1/memory:delete
```

Store ownership uses one tenant database with separate owners/RLS schemas:

- `domain`: ontology versions, semantic mappings, validation results.
- `ingestion`: source declarations, connector leases, batches, provenance, freshness, coverage, classification findings.
- `retrieval`: chunks, citations, index versions, pgvector embeddings; every index is tenant and source-version scoped.
- `memory`: memory entries, consent/purpose, TTL, deletion tombstones, and redaction receipts.

No service writes another schema. Execution-runtime checkpoints are explicitly
forbidden here; ingestion may advance only its own digest-only, partition-bound
source checkpoint after atomic batch commit. Binary source/evidence objects use
tenant PVC or tenant-supplied S3-compatible storage through references.

`KN-001` creates no binary store and no business table. It provides identical
`source_reference`, `inbox_event`, and `outbox_event` foundation tables inside
each of the four schemas, with separate NOLOGIN owner/runtime role pairs, FORCE
RLS, transaction-local organization context, append-only enforcement, and only
own-schema `SELECT`/`INSERT` runtime grants. No shared table, cross-schema grant,
`BYPASSRLS`, DDL runtime privilege, destructive down migration, database,
extension, user, PVC, bucket, or endpoint is created. PostgreSQL execution for
this packet is `NOT_RUN_ENV_UNAVAILABLE`; static contract validation cannot be
reported as runtime database proof.

Emits source/batch/provenance/freshness/index/memory/evidence events. Consumes accepted domain/data declarations, policy decisions, deletion requests, and local embedding/rerank responses. Events carry IDs/digests, not source payloads.

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

`KN-DOM-001` also owns one bounded correction to the separate
`ci/run_packet_argv.py` transport. The KN-001 bootstrap accidentally closed that
transport over KN-001's literal acceptance target list, which would reject every
later packet before the cumulative dispatcher could run. KN-DOM-001 replaces
only that literal equality test with closed generic `ARGV_ARRAY_V1` validation.
The hash-pinned packet, single deny-all-outbound process tree, exact offline
environment, local-only prefetch entry point, canary, digest rechecks, direct
argv, shell denial, and offline network/install-token denial remain mandatory.
This is not ownership of `Makefile`, `ci/run_make_target.py`, KN-001 handlers, or
future transport behavior beyond the declared closed validation contract.

The packet also corrects one KN-001 test-range defect in
`tests/common/test_security_sql_delivery.py`: the foundation ownership assertion
must enumerate the complete tree of exact merged KN-001 commit `672e73e...`, not
diff the empty base against the current HEAD. Otherwise every valid later-packet
file is falsely treated as a KN-001 file, while the pinned two-commit cumulative
checkout does not carry the older empty object needed by such a diff. The
amendment changes only the Git enumeration, retains the exact foundation object
and ancestor assertions, and checks every foundation-tree path against KN-001's
original allowed set; all other foundation security checks remain closed.

The packet owns one additional cumulative-CI correction in
`ci/handlers/prefetch.py`. At KN-DOM-001 time, the pinned checkout used
`fetch-depth: 2`; that checkout contained the KN-001 foundation parent but not
the older empty bootstrap object. The handler therefore retains the empty commit
only in its immutable predecessor-provenance lock and uses exact merged KN-001
commit `672e73e...` for its two Git object/ancestor checks. No lock, dependency,
source-presence, Python, offline, runner, or billing rule changes.

`KN-DATA-001` adds `ci/targets/kn-data-001.json`. Its packet declares the
already-owned `make prefetch` entry so the KN-001 and KN-DOM handlers execute
cumulatively before `connector-parity`, `connector-contract`, and `security`.
The new connector targets dispatch only direct Python argv into
`tests/connectors`; the packet does not edit Makefile, either generic transport,
or any predecessor descriptor/handler.

Because KN-DATA-001 is the third cumulative product commit, it also changes only
the pinned credential-free checkout's `fetch-depth` from `2` to `0`. Otherwise
the exact KN-001 foundation object required by unchanged prefetch and security
assertions is absent. Full public history is durable for later packets and adds
no credential persistence, hosted runner, artifact/cache, external action,
billable broker, cloud resource, or runtime download; every other workflow byte
and the launcher-only execution boundary remain unchanged.

The inherited `tests/common/test_security_sql_delivery.py` assertion and
`ci/zero_bill_scan.py` required-workflow marker are updated from the same literal
depth `2` to `0`; neither can remain green while pinning the superseded contract.
Those are exact guard synchronization changes, not relaxed controls. The scanner
is re-pinned at SHA-256
`cd859d5f3c8aaf1b0a5eee1b3f5f445a471c8749e0507a2749ecbb490371e509`;
its forbidden hosted-runner, credential, artifact/cache, package/container,
cloud, runtime-download, and external-telemetry checks remain byte-identical.

`KN-DATA-002` adds only `ci/targets/kn-data-002.json`. It declares the existing
`prefetch` target and registers direct Python handlers for `readiness-parity`,
`readiness-contract`, `failure-matrix`, and `security`. The security target is
cumulative, so KN-001, KN-DOM-001, KN-DATA-001, and KN-DATA-002 handlers all run
in lexical packet order. No Makefile, dispatcher, transport, prior descriptor,
workflow, scanner, or PORTING edit is authorized.

The same bootstrap packet is the only current owner of `PORTING.yaml` and
seeds a closed `NO_AUTHORIZATION` ledger. Reference/discovery-only packets cannot
edit it; a future copy transaction requires a revised `PORT_CANDIDATE` packet.

## Dependencies

- Upstream: contracts, SDK, trust policy/guardrail/evidence APIs, PostgreSQL/pgvector, OTel, tenant source endpoints, and model plane only for selected local embeddings/reranking.
- Downstream: runtime context assembly, execution workflows/tools, industry/conformance evidence.
- Trust/OPA loss fails closed for source access and memory writes/deletes. Model loss pauses indexing requiring embeddings but does not corrupt existing indexes.

`KN-001` pins the exact public contracts commit and release-manifest digests,
SDK-004 protocol commit/vector/module digests, TRUST-001 policy request/response
and client digests, and MET-003 policy/scanner/workflow digests in a local lock.
These are compatibility authorities, not mounted source dependencies. The
bootstrap uses only the standard library, local mocks, and dependency injection;
it never opens a predecessor or warm-start checkout during implementation or
acceptance.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `KN-001-foundation`: common service kernel, tenant DB roles/RLS, outbox/inbox, source-reference privacy, images/charts, and contract mocks.
2. `KN-DOM-001`: ontology versions, SHACL validation, semantic mapping, domain evidence, and white-goods ontology parity.
3. `KN-DATA-001`: connector controller/leases, file/HTTP/PostgreSQL/event connectors, decoder/batch contracts, and read-only credentials.
4. `KN-DATA-002`: provenance graph, freshness/coverage/classification assessments, readiness evidence, retry/dead-letter, and white-goods source fixtures.
5. `KN-RET-001`: chunk/index lifecycle, PostgreSQL FTS/pgvector, local embeddings/reranking, retrieval citations, context limits, and source-version invalidation.
6. `KN-MEM-001`: explicit purpose/consent write, read policy, TTL, deletion/tombstones, redaction, and proof that memory is not retrieval/runtime state.
7. `KN-002-security-resilience`: tenant/store isolation, malicious documents, connector SSRF/egress, stale indexes, outage recovery, and air-gap operation.

## Testing, verification, and acceptance

The `KN-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","common-contract"],["make","security"]]`.
Later packets add lint, type, coverage, parity, contract, local PostgreSQL,
white-goods, zero-bill, and reproducibility checks as direct argv arrays. The
executor supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and
invokes only `offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the
complete ordered list.

The KN-DOM-001 acceptance also proves that the generalized packet transport
accepts both the unchanged KN-001 sequence and KN-DOM-001's declared sequence,
while denying empty phases, malformed argv, shell/environment launchers,
recursive verification, forbidden offline tokens, execution-contract drift,
packet mutation, missing isolation identity, and leaked authority paths.
The cumulative security target additionally proves the exact KN-001 commit is
an ancestor and every path in its exact tree remains within the original
bootstrap boundary, independently of KN-DOM's packet-local path validation.
The cumulative prefetch target likewise proves that exact foundation object is
available and ancestral in the pinned two-commit checkout while preserving the
empty bootstrap SHA solely as immutable provenance.

KN-DATA-001 acceptance then proves four independently authored connector-class
vectors, closed source/API/state/grant contracts, bounded decoding and staging,
tenant-scoped lease fencing and idempotency, atomic sink-failure rollback, and
path/SSRF/SQL/event/secret/payload negative cases. Its cumulative `security`
target retains every KN-001 and KN-DOM handler plus packet-local SQL, chart,
Containerfile, zero-bill, and evidence-axis checks.

KN-DATA-002 acceptance proves partition-bound staging, repeat sampling, exact
white-goods PASS/WARN/missing/incomplete/stale/duplicate/unclassified/
unprovenanced parity, decimal findings, ten ordered public gates, bounded
provenance, public SOURCE-axis evidence, fenced three-attempt retry/dead-letter,
owner/policy separation, atomic activation, monotonic digest checkpoints,
expiry degradation, revocation dominance, tenant isolation, and static RLS/
least-privilege SQL. PostgreSQL, actual sources, images, deployment, runtime,
assurance, owner approval, and tenant acceptance remain separate and unclaimed.

`common-contract` validates the immutable upstream lock, exact Python/lock
closure, canonical JSON/digests, closed records, privacy, idempotency, health
adapters, service ownership, and synthetic mocks. `security` validates the four
SQL ownership/RLS contracts, six Containerfile/chart sources, fail-closed
readiness, negative dispatch and `PORTING.yaml` vectors, path ownership, warm
source exclusion, and zero-bill policy. The two targets are cumulative direct
argv handlers owned only by `ci/targets/kn-001.json`; neither target downloads,
builds, deploys, opens a network route, or invokes a shell command string.

The source-only acceptance records PostgreSQL, image build, Kubernetes/OpenShift
render/deployment, runtime, live security, assurance, and tenant acceptance as
`NOT_RUN_ENV_UNAVAILABLE` or pending. It may prove only source and offline
contract/unit behavior; PR, merge, artifact/SBOM, release signature, deployment,
runtime, live security, assurance, and tenant acceptance remain independent
evidence axes.

Acceptance: white-goods mock sources ingest read-only, produce complete provenance/freshness/coverage, validate domain mappings, build a versioned index, return cited tenant-isolated context, and store/delete governed memory independently. Cross-schema/tenant access, SSRF, prompt injection metadata, stale-citation use, and secret leakage are denied. All services operate with egress restricted to declared tenant sources/local dependencies.

## Release and rollback

- Each harness/deployable is an independent module release with compatible contracts and migration range.
- Index builds are create-then-swap; failed builds retain previous ready index. Ontology/mapping versions are immutable.
- DB migrations use expand/contract. Rollback selects prior images and index/version pointers; source data, memory, tombstones, and provenance are retained. Destructive deletion requires an explicit signed request and receipt.
- For `KN-001`, rollback is source-only: revert the unconsumed bootstrap before a dependent packet merges. Never run a destructive database rollback or infer that source validation created an artifact, deployment, runtime state, assurance result, or tenant decision.

## Zero-bill rules

- No hosted embeddings/vector DB/object store, crawling SaaS, remote telemetry, automatic connector discovery, or runtime downloads.
- HTTP connectors are allowlisted tenant endpoints; cloud metadata/link-local/private-network SSRF rules are enforced unless an exact tenant destination is approved.
- Self-hosted offline CI only; no GitHub storage/cache/Packages, cloud databases, scheduled ingestion, or paid evaluation APIs.
- `KN-001` CI uses only pinned credential-free checkout on ephemeral self-hosted labels and invokes the external root-owned offline launcher. It has no hosted runner, service container, Actions cache/artifact/Packages, secret, network/package setup, or retained output.
