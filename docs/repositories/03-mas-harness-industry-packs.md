# Repository Plan: `mas-harness-industry-packs`

## Sector direction — MET-SECTOR-001

Owner decision SECTOR-D1 (October 7, 2026): banking replaces white goods as the first and only release
sector from Alpha 2 through the first enterprise release; [sector direction](../alpha-2/SECTOR_DIRECTION.md)
gives every disposition. The banking pack succeeds `IND-WG-001` to `IND-WG-005` through the unpublished
proposals `IND-BANK-001` to `IND-BANK-005`; every white-goods pack version (0.1.0 to 0.5.0) stays historical
source, and the IND-001 rule to admit and lock RDFLib and pySHACL now applies to `IND-BANK-001`. White-goods
material below records what was specified or built; it is historical, not current direction.

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

Repository R03 retains its existing accountable ownership. Shared responsibility: translate sector requirements into business/data/readiness and provider-selection guidance.
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

This repository owns the guided enterprise setup content: universal foundational questions, sector-specific questionnaires, ontologies, readiness thresholds, regulatory/control mappings, provider preferences, representative fixtures, and deterministic pack validation. The first supported pack is white-goods manufacturing.

Non-goals:

- No tenant answer data, UI, database, workflow execution, executable rule code, model call, or network connector.
- A pack recommends requirements and providers but cannot override platform security, compatibility, license, or zero-bill policy.
- No LLM is required to complete, validate, or compile a questionnaire.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-industry-packs/
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
├── src/planeon_industry_packs/
├── common/
├── packs/white-goods/
│   ├── pack.yaml
│   ├── pack.lock.json
│   ├── manifest.json
│   ├── questions/{business,data,governance,integrations}/
│   ├── rules/{data-readiness.json,governance.json}
│   ├── ontology/
│   ├── controls/
│   ├── data/
│   ├── provider-preferences/
│   ├── fixtures/{answers,demands,e2e,expected,governance,readiness,sources}/
├── schemas/
├── scripts/build_pack_manifest.py
├── docs/
│   ├── authoring.md
│   └── white-goods/{business-domain.md,certification.md,data-readiness.md,governance.md,profiles.md}
└── tests/
    ├── framework/
    ├── fixtures/framework/
    └── white_goods/{test_business_domain.py,test_data_readiness.py,test_e2e_fixtures.py,test_governance.py,test_profiles.py}
```

## Package, toolchain, and owned interfaces

- Distribution/import: `planeon-harness-industry-packs` / `planeon_industry_packs`.
- Base toolchain: Python 3.12.14, `uv` 0.12.7,
  `jsonschema==4.24.0`, `PyYAML==6.0.2`, and `pytest==8.4.2` in the
  development group. IND-WG-001 advances the framework distribution to 0.1.1
  and adds development-only `rdflib==7.6.0` and `pyshacl==0.40.1` with an exact
  transitive offline wheel closure. The framework runtime dependencies remain
  unchanged; packet execution never resolves or downloads a package.
- CLI: `harness-pack validate`, `harness-pack test`, `harness-pack compile-index`, and `harness-pack package`.
- Artifact: an OCI pack artifact containing only data, schemas, fixtures, documentation, and digests; no executable hook.
- Rules use only `all|any|not|eq|in|exists|gte|lte` and may emit questions, requirements, blockers, or recommendations.
- APIs/events/stores: none. Control-plane APIs serve pack content after validating a pinned pack artifact.

Every pack versions readiness thresholds for schema validity, required-field completeness, freshness, provenance coverage, duplicate rate, sensitive-data classification, ownership, retention, and access approval. Every threshold names evidence source, evaluation method, severity, waiver eligibility, and expiry.

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

## IND-001 framework contract

IND-001 binds but does not copy the public contract release. The
`common/contracts.lock.json` authority fixes contracts commit
`2146278a95344cd2a8e22596b2f315b46edffc88`, release-manifest SHA-256
`c5dd4c39d1c69d07f8d8de3d1a09584bb906172fee2d5ac20ad25ff344b0db79`,
catalog digest
`sha256:26d442c4e90a19d767d32e80ef9df3d154b3146d3238dc0eecf29ee773913a26`,
and the exact public guidance/readiness schema paths and digests. Product
acceptance receives no upstream source path and performs no network lookup.

The common journey has exactly eight stages, in this order:

1. `business-context`
2. `domain-and-outcomes`
3. `data-readiness`
4. `governance-and-regulation`
5. `integration-readiness`
6. `harness-demand`
7. `environment-and-provider-fit`
8. `evidence-and-acceptance`

`common.foundation` 1.0.0 is immutable and industry-neutral. A sector pack
binds the common pack's computed digest and uses only `APPEND_ONLY` overlay
semantics. It may add uniquely identified content to an existing stage. It may
not replace, delete, shadow, reorder, or weaken common content, and it may not
extend another sector pack. This keeps sector guidance adjustable without
letting an industry overlay bypass foundational business, data, governance, or
acceptance gates.

The loader admits only closed data/document formats and regular files under an
explicit pack root. Links, traversal, hidden or unlisted files, executable
suffixes or modes, duplicate YAML/JSON keys, custom YAML tags, unknown fields,
unsafe rule operators, templates, code, filesystem/network targets, secrets,
and LLM prompts fail closed. Rules use the eight public guidance operators and
the four public guidance actions only.

`harness-pack validate` emits deterministic validation evidence.
`compile-index` exclusively creates canonical JSON whose file records bind
path, media type, size, and SHA-256. `package` exclusively creates a fixed-
epoch, sorted, mode-0644 tar.gz containing the computed index. Neither command
overwrites, signs, publishes, deploys, or reports runtime, assurance, or tenant
acceptance. Framework wheel/sdist, index, and pack archive all require two-build
byte identity.

## Dependencies

- Upstream: pinned `mas-harness-contracts` schemas/compiler and meta taxonomy.
- Downstream: control plane consumes signed pack artifacts; conformance labs consume fixtures; knowledge/trust planes consume accepted domain/control artifacts, never pack source files directly.
- Packs cannot import one another. They extend the versioned `common` pack through declared overlay/precedence rules.

## IND-WG-001 business-domain contract

IND-WG-001 binds exact industry-pack main commit
`a626437a18cd27d75cb96e0d846f56a235313c98`, common pack digest
`3cfea19e6e0a4a653d63622e250f40001b4f8221ebab18fa5bfc1601b8eddea3`,
and the reproducible framework 0.1.0 wheel. `white-goods` is a clean-room,
Apache-2.0 sector overlay; historical `sourceReuse` entries are provenance only
and no warm checkout is observed or mounted.

The first sector slice defines business objectives, accountable roles, four
product families, manufacturing processes, quality characteristics, CTQs,
KPIs, acceptance outcomes, and synthetic answer vectors. Plant identities,
measured values, production thresholds, customer/employee data, regulatory
conclusions, and credentials remain tenant-evidence-dependent and absent.

The ontology uses `urn:planeon:white-goods:*` for domain terms. RDF-family
content may identify only the exact W3C RDF, RDFS, XSD, OWL, and SHACL
namespaces without dereferencing them. Every other remote IRI remains invalid.
SHACL validation is local-only with imports, JavaScript, SPARQL, advanced mode,
and inference disabled. A positive graph must conform and a negative graph must
produce the expected constraint components.

Framework 0.1.1 owns the narrow semantic-identifier exception. It does not
relax the general network-target prohibition and does not alter the 0.1.0 pack
format. The packet updates deterministic wheel/sdist evidence because framework
source changed; the immutable common pack and its digest do not change.

## IND-WG-002 data-readiness contract

IND-WG-002 starts only from exact merged product commit
`714e311b550798c230d440c869d36f7ad5a857b4`. It binds white-goods 0.1.0 pack
digest `cb413874a002a481a7163e6198cac277894e72a7c918085d635b1fadcf523913`,
raw `pack.yaml` SHA-256
`e20d3b6723698a298b93a8dc45743b6644d7e443e1c4fd0450a2c344a9238bf1`,
and framework 0.1.1 wheel SHA-256
`d34a1a3c523b1e60f10602fff072d5dbf83f46f2220f29a4f13b9a31facf91f4`.
It advances only the sector pack to 0.2.0. The common pack, contracts lock,
journey, ontology, business content, pack format 0.1.0, and framework 0.1.1
remain byte-identical.

The readiness assessment binds public contracts commit
`2146278a95344cd2a8e22596b2f315b46edffc88`. The authoritative schema is
`schemas/v1alpha1/readiness/data-readiness-assessment.schema.json`, SHA-256
`ffe003a1a7ec0773f49d8f394ac3dd6281114bd4335ff05c87d223412faf92a5`;
its common guidance schema is SHA-256
`4d77297073d4c2e559f1131fbada566b499197f87113f7e28b136f0b4ae5f429`.
The existing sector lock records the readiness schema under a historical
`guidance/` path but binds the correct content digest. IND-WG-002 documents the
authoritative path in a new data-only binding record. It neither edits the
predecessor lock nor copies schema bytes.

The pack carries four independently authored synthetic source classes: API,
PostgreSQL, files, and events. Each declares an owner, custodian,
classification, and local evidence id. A closed dataset lock binds every data
member's path, media type, record count, byte size, and SHA-256. Fixtures contain
no tenant, plant, customer, employee, credential, connection, endpoint, or warm-
source material.

The illustrative policy is tenant-replaceable and deterministic. PASS/WARN
bands are completeness 0.98/0.95 minimum, freshness 15/60 minutes maximum,
duplicate rate 0.01/0.02 maximum, classification coverage 1.00/0.98 minimum,
and provenance coverage 1.00/0.98 minimum. Zero observations always produce
`MISSING_DATA`. These values are test policy, not production claims.

PASS alone yields `READY`. WARN yields `BLOCKED` plus `NEEDS_INPUT`; FAIL yields
`BLOCKED` plus `BLOCKED`. Every nested `DataReadinessAssessment` contains
exactly ten ordered gates for business ownership/outcomes, data ownership,
quality, completeness, freshness, provenance, classification, integration, and
autonomy. Evidence ids, missing-gate ids, and reason codes are sorted and
unique. Missing data suppresses derived metric findings so absent observations
cannot produce misleading coverage or freshness conclusions.

Tests remain under `tests/white_goods/`, outside the distributable pack. The new
Make target is uniquely named `data-readiness`; `pack` remains owned by
IND-WG-001. Its predecessor handler is narrowed to discover only its owned
`questions/business/` paths, preventing additive data questionnaires from
changing frozen business answer-vector keys or decisions. The IND-WG-002
handler validates contract bindings, questionnaire,
source and policy closure, dataset digests/counts, every result vector, and two-
build index/archive identity without retaining an artifact. It also preserves
false publication, deployment, runtime, assurance, and tenant-acceptance flags.

## IND-WG-003 governance and integrations contract

IND-WG-003 starts only from exact merged product commit
`a4d3df9b169e95c285e22a2fdb2b4c9d711230e2`, white-goods 0.2.0 computed pack
digest `e0ad15c9da5f126c4aa20c88f75d4e9b15808ee841347ba4663dd99664248177`,
raw `pack.yaml` SHA-256
`3bc885342cd43870624a1a188851af2aa314ec333ba87cb8170597f7b3d8f674`, and
framework 0.1.1 wheel SHA-256
`d34a1a3c523b1e60f10602fff072d5dbf83f46f2220f29a4f13b9a31facf91f4`.
It advances only the sector pack to 0.3.0. Common content, contracts lock,
journey, ontology, business/data resources, pack format 0.1.0, and framework
0.1.1 stay byte-identical.

The public lifecycle binding is contracts commit
`2146278a95344cd2a8e22596b2f315b46edffc88`. It binds `ApprovalRequest`
v1alpha1 at `schemas/v1alpha1/lifecycle/approval-request.schema.json`, SHA-256
`4fe8d214a920690008a4390919acebf797b0ab4e6c649a7a88e0882f3b2a1b27`,
lifecycle common SHA-256
`dce5d8030eea3a19694511eb26513614dcc720ef4e0d650772131b14ed58f075`, and
composition common SHA-256
`11b55d3eafa8d87a90956345da0919f67478a7738d5ca118025904f8ff58b5f0`.
Although the architecture plan names `ControlRequirement` and
`IntegrationDeclaration`, their schemas are absent from this exact released
contract tree. The pack records them as `NOT_AVAILABLE_IN_BOUND_RELEASE` and
defines only pack-local, data-only requirement/declaration record sets. It
neither copies public schema bytes nor claims that these records implement an
unreleased public kind.

Four questionnaires cover regulatory applicability, action/autonomy boundary,
waiver declaration, and integration declaration. Regulatory themes are
tenant-answerable candidates for product safety, data protection,
cybersecurity, quality management, and environmental/energy governance. They
are not legal conclusions. Closed action categories are `READ_ONLY`,
`REVERSIBLE_WRITE`, `IRREVERSIBLE_WRITE`, and `UNKNOWN_SIDE_EFFECT`; closed
autonomy levels are `OBSERVE`, `RECOMMEND`, `APPROVAL_REQUIRED`, and
`BOUNDED_AUTONOMOUS`.

Write-capable compilation requires exact policy and approval references, an
unexpired `MUTATION` approval, distinct required approver quorum, durable
receipt and idempotency declarations, a scoped credential reference with access
approval, and compensation or explicit outcome review. Unknown side effects
always block. Pack content carries no credential value, endpoint, connection,
or executable connector configuration.

Waivers must bind the same control and complete scope, an unexpired `WAIVER`
approval, justification, compensating control, and non-renewable expiry. They
document an exception only: even a valid active waiver remains `BLOCKED` with
`WAIVER_DOES_NOT_SATISFY_PROMOTION` until every required control has fresh
`PASS` evidence. Expired, cross-scope, self-approved, or incomplete waivers add
their stable failure reason and never imply approval or promotion.

The pack adds four control resources, one closed governance rule, and eleven
synthetic decision fixtures. Its exact resulting inventory is 52 files and 49
resource ids. Tests remain outside the pack. The unique
`governance-integrations` Make target runs direct argv through the packet-owned
handler; cumulative acceptance also reruns pack, data-readiness, business/data
tests, dispatcher regression, deterministic index/archive checks, and zero-bill
validation. No artifact is retained or published, and deployment, runtime,
assurance, and tenant-acceptance evidence remain false.

## IND-WG-004 provider-profile contract

IND-WG-004 starts only from exact merged product commit
`219cafc97d89513e89b9f0eaa0349756a2a3954c`, white-goods 0.3.0 computed pack
digest `798665b769140b621feb0346ab37f32a6804a950b9028f71d921a5b7fc650447`,
raw `pack.yaml` SHA-256
`b21aae64acda0eb21eeb63c57aed7458d18926867e1d33e1558f1f492f7ccc67`,
its 52-file/49-resource inventory, and the unchanged framework 0.1.1 wheel. It
advances only the sector pack to 0.4.0 and adds exactly twelve data resources:
one public-contract/catalog binding, one five-profile recommendation catalog,
five full `CompileRequest` demand fixtures, and five golden-output envelopes.
The resulting closed inventory is 64 pack files and 61 resource ids.

The public authority is contracts commit
`2146278a95344cd2a8e22596b2f315b46edffc88`, release-manifest SHA-256
`c5dd4c39d1c69d07f8d8de3d1a09584bb906172fee2d5ac20ad25ff344b0db79`,
catalog digest
`sha256:26d442c4e90a19d767d32e80ef9df3d154b3146d3238dc0eecf29ee773913a26`,
and deterministic compiler source SHA-256
`0b0960c87bc1214e795144968db3976bd548c80e6002b03bc3f6e292303a764b`.
The pack binds raw composition, questionnaire, and readiness schema hashes plus
the canonical harness/provider/module catalog hashes. It copies none of those
bytes and its isolated acceptance receives no upstream repository path.

The exact profile matrix is:

| Profile | Platform | Accepted providers | Direct demand | Accepted prerequisites |
| --- | --- | --- | --- | --- |
| `minimal-arm64` | self-managed ARM64 Linux/K3s | K3s + llama.cpp | local CPU model and K3s | Security, Observability |
| `minimal-amd64` | self-managed AMD64 Linux/upstream Kubernetes | upstream Kubernetes + llama.cpp | local CPU model and Kubernetes | Security, Observability |
| `regulated-openshift` | self-managed AMD64 Linux/OpenShift | OpenShift + llama.cpp | governed action, assurance, local CPU model, OpenShift | Governance, Security, Observability |
| `silo` | self-managed AMD64 Linux/upstream Kubernetes | upstream Kubernetes + llama.cpp | read-only agent, cited retrieval, local CPU model, Kubernetes | Domain, Data Integration, Governance, Security, Observability |
| `air-gap` | air-gapped AMD64 Linux/K3s | K3s + llama.cpp | air-gap deployment, local CPU model, K3s | Security, Observability |

Each profile separates recommendation from acceptance. Compatible choices are
`PROPOSED_SELECTOR_ONLY`; a fixture becomes compilable only after its submitted
tenant demand contains exactly one selector for every active provider group.
No ranking, default, fallback, or provider availability claim can mutate a
profile. Every selected provider is public-catalog `PLANNED`, credential-free,
external-telemetry-free, runtime-download-disabled, and self-hosted
open-source/non-metered or tenant-supplied.

The profiles carry exact planning envelopes for CPU, memory, ephemeral and
model storage plus the five bounded execution-budget dimensions. Capacity still
requires tenant attestation. Isolation is deny-by-default; OpenShift requires
the signed arbitrary-UID fact, silo requires both the released compiler's
non-air-gap `connectivity.connected` fact and narrower `connectivity.silo`
fact, and air-gap requires deny-all outbound plus a tenant-supplied,
digest-pinned local OCI source. “Regulated” is a policy posture, not a legal or
compliance conclusion.

Each golden envelope captures the exact six compiler outputs—`profile.json`,
`bom.json`, `install-plan.json`, `evidence-plan.json`, `explanation.md`, and
`profile.sha256`—and their SHA-256 values. Packet acceptance reconstructs those
bytes twice in memory using `SORTED_UTF8_JSON_V1`, checks every digest and
profile reference, and proves the BOM/install plan contains only selected
modules and providers. This is a pack-local immutable golden lock, not a rerun
of upstream source and not cross-repository conformance, artifact, deployment,
runtime, assurance, or tenant-acceptance evidence.

The unique `provider-profiles` Make target dispatches directly to
`ci/handlers/ind_wg_004.py`. Cumulative acceptance reruns pack,
data-readiness, governance-integrations, all four white-goods test slices,
dispatcher regressions, two-build index/archive identity, and zero-bill
validation. Predecessor handlers/tests may change only their version,
inventory/archive expectation, packet output version, and cumulative successor
dispatch; predecessor resources, decisions, and digests stay frozen.

## IND-WG-005 certification-fixture contract

IND-WG-005 starts only from exact merged product commit
`3814e642c8c8eb9f9bf77f230930eeff209de565`, white-goods 0.4.0 computed pack
digest `38a056e7f3008aa9980fc12f1677f6f160dddb18aa156e63258921b911ab1773`,
raw `pack.yaml` SHA-256
`29e8732b5e6730ecc42e54bed8f00487ece81cde4c50fc1521f711b65240defb`,
its 64-file/61-resource inventory, reproducible archive SHA-256
`3f0a3b22e1152526324fd7f7940a8d45331b2d182da309f249ef94956476856c`,
canonical-index SHA-256
`022a9d685c52cb73dad7b51d53c4d02a0168680ad138af99503076af9bd6783b`,
and the unchanged framework 0.1.1 wheel. It advances only the sector pack to
0.5.0 and adds exactly eight data resources, producing a 72-file/69-resource
inventory.

Five synthetic scenario records close the source-level white-goods journey for
`minimal-arm64`, `minimal-amd64`, `regulated-openshift`, `silo`, and `air-gap`.
Each binds exact raw bytes for an accepted business fixture, PASS data-readiness
fixture, governance decision, provider demand, and golden output. The regulated
scenario uses the reversible-write governance vector; all others use the
read-only vector. `SOURCE_CONTRACT_READY` means only that those pack-local
records form the declared deterministic closure. It is not a campaign,
deployment, runtime observation, assurance result, compliance conclusion, or
tenant acceptance.

`pack.lock.json` binds exactly the seventy final pack members other than itself
and `manifest.json`, using lexical path records with media type, byte size, raw
SHA-256, and Apache-2.0 disposition. Its payload digest covers canonical bytes
of the algorithm, exclusions, and entry list. It deliberately omits final pack,
index, archive, lock-file, and manifest-file digests, so the committed subject
is non-recursive.

`manifest.json` binds the raw lock-file digest, its payload digest and entry
count, clean-room packet lineage, and pack license. Its artifact state is
`NOT_RETAINED`; its release-signing state is `MISSING_PLANNED`, with null
signature and signer. This makes it an unsigned deterministic source document
that a later offline release process may sign after merge. IND-WG-005 neither
creates nor verifies a signature and cannot claim an artifact, publication,
release, deployment, runtime, assurance, conformance, or tenant state.

The sixth scenario resource is a five-vector mutation catalog. Acceptance
changes only in-memory copies to prove stable denial for changed content,
missing members, undeclared members, altered payload digests, and altered
manifest-to-lock bindings. The unique `certification-fixtures` Make target
runs the packet-owned handler. Cumulative acceptance reruns all four predecessor
targets, all five white-goods test slices, dispatcher regressions, two-build
index/archive identity, and zero-bill validation. No pack artifact or signature
is retained.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `IND-001-framework`: loader, common eight-stage journey, rule/static-safety validation, overlay semantics, pack index, and authoring guide.
2. `IND-WG-001-business-domain`: white-goods objectives, roles, asset/product/process ontology, CTQs, KPIs, and representative answer sets.
3. `IND-WG-002-data-readiness`: source inventory, mock API/DB/file/event data, completeness/freshness/provenance/classification thresholds, and failure fixtures.
4. `IND-WG-003-governance-integrations`: regulatory/control mapping, autonomy/action categories, integration declarations, credential/side-effect questions, and waiver rules.
5. `IND-WG-004-provider-profiles`: minimal ARM64, minimal AMD64, regulated OpenShift, silo, and air-gap provider recommendations plus explicit accepted-selector fixtures and expected compiler outputs.
6. `IND-WG-005-certification-fixtures`: deterministic source-contract scenarios, a non-recursive payload lock, and an unsigned offline-signing-ready manifest.
7. `IND-FIX-001-fork-guard`: public-fork pre-scheduling guard for the self-hosted verifier.

## Testing, verification, and acceptance

The `IND-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","pack-framework-test"],["make","build-reproducible"],["make","zero-bill"]]`.
Later packets add lint, type, coverage, pack validation, white-goods, index, and
reproducibility checks as direct argv arrays. The executor supplies the
hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

IND-WG-001 declares `prefetchCommands: [["make","prefetch"]]` and ordered
acceptance commands for `make pack PACK=white-goods`, the exact business-domain
pytest file under the repository test tree, framework reproducibility, and
zero-bill validation. Tests remain outside `packs/white-goods` because every
path beneath a distributable pack root is closed data inventory and executable
suffixes fail closed. The
packet-owned handler verifies dependency versions, closed local SHACL settings,
pack/index/archive determinism, answer-vector decisions, and false downstream
evidence flags without retaining an artifact. Registering the packet-owned Make
descriptor also updates the existing closed descriptor-inventory regression
test; the dispatcher and bootstrap-owned Makefile remain unchanged.

Acceptance proves: the journey works without an LLM; invalid/executable rules fail closed; missing business owner or data evidence blocks approval; identical answers produce identical pack requirements; all fixtures are synthetic and license-clean; and white-goods minimal/regulated/air-gap demands compile to expected digests.

## Release and rollback

- Tag packs independently as `<industry>-vMAJOR.MINOR.PATCH`; sign the pack manifest offline and record contracts/catalog digests.
- Existing questionnaire sessions remain pinned to their starting pack version. Upgrades create a new session revision and show changed questions/findings.
- Rollback selects a prior signed pack; completed evidence is re-evaluated and marked stale where thresholds differ, never silently reclassified.

## Zero-bill rules

- Packs contain no URLs requiring paid accounts, cloud resources, API keys, remote fonts/assets, executable code, or runtime downloads.
- Provider preferences select only open-source/self-hosted defaults and pre-existing tenant infrastructure.
- Self-hosted offline CI only; no GitHub storage services, hosted runners, scheduled workflows, or external evaluation APIs.
