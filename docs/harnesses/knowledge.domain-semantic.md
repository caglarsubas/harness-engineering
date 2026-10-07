# Harness Specification: `knowledge.domain-semantic`

## Sector direction — MET-SECTOR-001

Owner decision SECTOR-D1 (October 7, 2026): banking replaces white goods as the first and only release
sector from Alpha 2 through the first enterprise release; [sector direction](../alpha-2/SECTOR_DIRECTION.md)
gives every disposition. The alpha capability is a banking glossary and ontology: versioned terms with
provenance and business-question readiness, under the proposed namespace `urn:planeon:banking:*`.
White-goods material below records what was specified or built; it is historical, not current direction.

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

Planning target: `RDFLib/rdflib` + `RDFLib/pySHACL`.
Use RDFLib RDF processing and pySHACL validation for domain concepts and constraints; this is meaningful semantic-engine reuse, not a generic database count.
Platform scope: Own industry mapping, glossary/ontology version approval, provenance, business-question readiness and domain-to-data binding; do not build RDF or SHACL engines.
Delivery: `KN-DOM-ADOPT-001` (ALPHA_2, WAITING_PACKET_PUBLICATION).
Acceptance: Validate approved ontology versions, conflicting terms, missing business definitions and SHACL failures against local fixtures. No NL2SQL execution authority is implied by the paper or semantic layer.
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
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness captures a tenant's business vocabulary, canonical entities, relationships, constraints, process concepts, ownership, and versioned semantic mappings. It validates RDF/SHACL artifacts, exposes resolved domain terms, and provides the semantic baseline required before data ingestion and retrieval are certified.

It does not ingest source data, build retrieval indexes, store conversational memory, execute business rules as code, or use an LLM to declare an ontology complete. Industry packs may propose terms and shapes, but tenant owners approve them.

## Owner and deployables

- `domain-service`: versioned domain-package API, validation, publication, resolution, and compatibility checks.

The baseline implementation embeds a digest-locked RDFLib 7.6.0 and pySHACL
0.40.1 service-specific dependency unit in `domain-service`; the KN-001 root
package remains standard-library-only. No external triplestore is required for
minimal profiles.
Apache Jena is contract-only, non-installable comparative guidance in this
release; there is no selectable Jena service or repository packet.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `trust.security-safety`, `trust.observability-finops`.
- Required for production publication: `trust.governance-agentops`.
- Optional consumers: `knowledge.data-integration`, `knowledge.retrieval-context`, `execution.ml-decision`, `trust.evaluation-assurance`.
- Conflicts:
  - Two active definitions for the same canonical URI without an explicit replacement mapping.
  - Breaking removal or range change while a locked profile depends on the prior version.
  - Executable code, remote context fetches, or network imports inside a domain package.
  - Publication without named business/data owners.

Domain publication precedes data mapping, readiness approval, retrieval indexing, and model grounding.

## Provider implementations

| Provider | Use |
|---|---|
| `planeon.rdflib` | Baseline local RDF graph, JSON-LD/Turtle parsing, and term resolution |
| `planeon.pyshacl` | Mandatory SHACL validation provider |
| `planeon.jena` | Contract-only, non-installable high-scale SPARQL guidance; active selection is rejected as `PROVIDER_UNAVAILABLE` |

All import content must already be vendored and digest-bound outside this
packet. `KN-DOM-001` accepts no import statement at all: remote contexts,
`owl:imports`, and runtime network dereferencing are prohibited. A future signed
package-admission packet may define a closed vendored-import manifest without
broadening runtime egress.

## Configuration and runtime boundaries

```yaml
domain:
  id: string
  version: semver
  packageRef: oci@sha256:...
  defaultLanguage: string
  supportedLanguages: [string]
  owners: [subject-id]
  compatibility: backward | strict
validation:
  shapes: [relative-path]
  severityBlocking: [Violation]
  maxTriples: integer
imports:
  mode: vendored-only
```

- Secrets: none for the baseline. Comparative Jena guidance does not activate a credential path.
- RBAC: no Kubernetes API access. Publication requires `domain:publish`; drafts require `domain:write`; resolution requires `domain:read`.
- Network: ingress from control, data, retrieval, decision, and assurance services. Egress to PostgreSQL, policy, and OTel only.
- Storage: immutable domain packages are OCI artifacts. Metadata, version graph, validation reports, and active pointers live in domain-owned tables within the knowledge schema. No source records are stored here.

## APIs, events, and state

```text
POST /knowledge/v1/domains
GET  /knowledge/v1/domains/{id}/versions
POST /knowledge/v1/domains/{id}/versions
POST /knowledge/v1/domains/{id}/versions/{version}:validate
POST /knowledge/v1/domains/{id}/versions/{version}:publish
POST /knowledge/v1/domains/{id}/versions/{version}:resolve
GET  /knowledge/v1/domains/{id}/versions/{version}/report
```

Version states are append-only revisions: `DRAFT → VALIDATING → VALID →
AWAITING_APPROVAL → ACTIVE`. Alternatives are `INVALID`, `REJECTED`,
`SUPERSEDED`, and terminal `RETIRED`. Atomic activation appends `ACTIVE`, appends
`SUPERSEDED` for the prior active version, writes evidence/outbox/idempotency,
and changes exactly one tenant-scoped active pointer. A compatible, previously
approved `SUPERSEDED` version can be reactivated by the same atomic boundary;
metadata and prior history are never mutated or deleted.

Mapping states are `DRAFT`, `VALIDATING`, `VALID`, `INVALID`,
`AWAITING_APPROVAL`, `ACTIVE`, `REJECTED`, and `SUPERSEDED`. Every mapping binds
an exact active domain digest and contains only source-field digests, target term
IRIs, a closed transformation kind, owners, and provenance digests—never raw
schemas, fields, values, queries, formulas, or executable transformations.

Emitted:

- `domain.version.validated.v1`
- `domain.version.published.v1`
- `domain.version.rejected.v1`
- `domain.version.superseded.v1`

Consumed: `approval.decided.v1`, `module.release.revoked.v1`, and industry-pack activation notifications.

## Failures, retry, and rollback

- Parsing, SHACL, ownership, signature, or import-closure errors mark the version `INVALID` with bounded findings.
- Validation is bounded to 2 MiB per document, 4 MiB total, 50,000 data triples,
  20,000 shape triples, 128 digest-only findings, and an injected 30-second
  monotonic deadline. Report messages and offending literals are not retained.
- Validation is deterministic and safe to retry. Publication requires an idempotency key and optimistic version check.
- The active pointer changes atomically only after validation and approval.
- A failed publication retains the prior active version.
- Rollback activates a previously approved compatible version; it never mutates an immutable package.
- Compatibility is deterministic: unchanged term inventories/statements are
  `IDENTICAL`; additive terms with unchanged prior statements are
  `BACKWARD_COMPATIBLE`; removed terms or changed prior statements are
  `BREAKING`. `STRICT` accepts only identical and `BACKWARD` accepts identical
  or backward-compatible changes.
- Consumers pin a domain digest. Superseding a version does not silently change existing locked profiles.
- Excessive graph size or cyclic import manifests fail before loading the active graph.

## Evidence and readiness gates

- Named business and data owners.
- Package signature, digest, SPDX/license record, and closed import graph.
- SHACL validation report with zero blocking violations.
- Term coverage for every industry-pack mandatory concept.
- Compatibility report against the previous active version.
- Representative mapping fixtures approved by domain owners.
- Multilingual label coverage when required by the selected industry pack.

Data and retrieval harnesses cannot become production ready until they reference an `ACTIVE` domain digest and their mappings validate against it.

## Profile behavior

- `minimal-local`: RDFLib/pySHACL, one domain package, PostgreSQL metadata.
- `enterprise`: multiple bounded contexts, approval workflow, and compatibility gates. Jena remains non-installable comparative guidance.
- `airgap-enclave`: vendored contexts and imports only; no remote URI resolution.

## Tests

- Unit: parsing, URI normalization, import closure, term resolution, compatibility classification.
- Contract: JSON-LD/Turtle/SHACL golden vectors and API/event schemas.
- Security: entity expansion, malicious context URLs, archive traversal, oversized graphs, authorization.
- Lifecycle: draft, validate, approve, publish, pin, supersede, rollback.
- Industry: white-goods asset, product, process, defect, CTQ, CAPA, and provenance fixtures.
- Air gap: resolution and validation with network disabled.

## Sol-high implementation packets

1. `KN-001-foundation`: common knowledge service kernel, tenant database roles/RLS, inbox/outbox, source-reference privacy, images/charts, and contract mocks used by the domain service.
2. `KN-DOM-001`: ontology/package lifecycle, RDFLib/pySHACL validation, semantic mappings, compatibility/owner evidence, white-goods coverage, and publication/rollback. Jena remains non-installable comparative guidance outside this packet.
3. `KN-002-security-resilience`: malicious document/context defense, tenant/store isolation, domain-store outage recovery, stale/superseded consumers, and air-gap validation.

No packet may introduce remote ontology fetching or treat generative output as owner approval.

KN-DOM-001 additionally closes the bootstrap transport defect that otherwise
admits only KN-001's literal command list. Its bounded edit to
`ci/run_packet_argv.py` generalizes the command-list check without changing the
signed wrapper, deny-all-outbound session, packet digest rechecks, offline
environment, local-only prefetch, direct-argv rules, or Make dispatcher. Both
the unchanged bootstrap sequence and this packet's declared sequence must pass;
empty, shell-based, network/install-bearing, recursive, mutated, or
contract-drifted sequences must fail closed.

The same packet makes the inherited KN-001 changed-path assertion cumulative:
it enumerates the complete tree of the exact merged KN-001 commit and requires
that commit to remain an ancestor of HEAD. This avoids both later domain files
being mislabeled as bootstrap changes and dependence on the absent empty object
in the pinned two-commit checkout, without broadening either packet's
implementation ownership.

It also makes the inherited KN-001 prefetch ancestry proof compatible with the
pinned zero-bill `fetch-depth: 2` checkout. The immutable predecessor lock keeps
the empty bootstrap SHA as provenance, while the handler's two Git availability
and ancestry checks use exact merged KN-001 commit `672e73e...`, which is the
foundation parent available to both the dependent PR merge ref and later
exact-main commit. Every other prefetch and offline control remains unchanged.
