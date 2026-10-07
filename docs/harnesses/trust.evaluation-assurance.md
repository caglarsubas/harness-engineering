# Harness Specification: `trust.evaluation-assurance`

## Sector direction — MET-SECTOR-001

Owner decision SECTOR-D1 (October 7, 2026): banking replaces white goods as the first and only release
sector from Alpha 2 through the first enterprise release; [sector direction](../alpha-2/SECTOR_DIRECTION.md)
gives every disposition. `CONF-BANK-001` succeeds `CONF-A1-001`; `CONF-A2-001` and `CONF-WG-001` now certify
the banking agent and the banking tenant-acceptance candidate. White-goods material below records what was
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

Planning target: `UKGovernmentBEIS/inspect_ai`.
Use Inspect AI for agent/task evaluation with local models; add Ragas for RAG metrics and promptfoo for local red-team suites only after pinned-package and dependency review.
Platform scope: Own evidence schemas, immutable subjects, release gates and independence. Keep pytest for deterministic source/contract checks; it is not the agent-quality engine.
Delivery: `TRUST-EVAL-ADOPT-001` (ALPHA_2, WAITING_PACKET_PUBLICATION).
Acceptance: Test real pinned evaluation package, local dataset/model assets, reproducibility, known-failing task scores, denied network/API defaults and signed evidence separation. Research about subsampling never permits filtering mandatory acceptance/CI recipes.
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
| Plane | Trust and lifecycle |
| Owning repository | `mas-harness-trust-plane` |
| Supporting repository | `mas-harness-conformance-labs` |
| Public warm sources | `data-source-harness`; `llm_inference_engine`; non-public planning input metadata omitted |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness defines evaluation suites and evidence plans, runs deterministic and local-model evaluations, validates traces and receipts, tracks evidence freshness, compares releases, and publishes signed assurance records used by governance and promotion. It covers functional quality, safety, retrieval, data readiness, performance, resilience, isolation, deployment, and industry acceptance-candidate evidence.

It does not approve releases, waive controls, use an LLM judge as the sole authority for deterministic/security claims, mark unavailable environments as passing, or call paid evaluation/model APIs. A merge, green CI, deployment, runtime health, assurance result, and tenant acceptance remain separate evidence axes.

## Owner and deployables

- `evidence-service`: evidence-plan, record, freshness, control mapping, and query API.
- `assurance-worker`: isolated run executor for test/evaluation suites and signed report production.
- `harness-conformance`: CLI/library in `mas-harness-conformance-labs` for portable contract and deployment campaigns.

Certification runner/evaluation patterns and white-goods/local
inference/OpenShift fixtures are independent clean-room targets derived only
from released contracts and pre-recorded, digest-pinned observations;
implementation cannot access, copy, adapt, translate, or derive code from a
warm checkout.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`.
- `subjectUnderEvaluation`: `knowledge.data-integration` is required only for a campaign declaring data-readiness/dataset evaluation; `runtime.model-inference` is required only for a campaign whose explicit subject names that harness or the accepted `assurance.local-model-judge` capability.
- Other harnesses are campaign subjects, not universal installation dependencies. Each selected suite locks its subject harness/digest and declares its own conditional capabilities before scheduling.
- Subject capabilities must be a subset of accepted resolved tenant demand. A local-model judge also requires an accepted `model.local-cpu` or `model.local-gpu` demand and exactly one explicit local-backend selector; otherwise compilation returns `NEEDS_INPUT` before a campaign can be scheduled.
- Conflicts:
  - Judge/provider requires external API or undeclared network.
  - Evaluation data license, lineage, partitioning, or custody is missing.
  - Test and training/reference set contamination.
  - `NOT_RUN_ENV_UNAVAILABLE`, `MISSING`, `STALE`, or `WAIVED` coerced to `PASS`.
  - Mutable suite, dataset, model, system, or environment reference.

Evidence plan is generated with the profile; subject artifacts and test data lock before a run; governance consumes only terminal signed evidence.

## Provider implementations

- `planeon.assurance.pytest`: deterministic API, contract, state, failure, security, and deployment suites.
- Capability `assurance.local-model-judge`: optional local model judge executed by `assurance-worker` through one explicitly accepted, pinned local inference backend and calibration set; it is not a provider ID.
- Ragas and Promptfoo are deferred comparative candidates, not catalog installables or selectable providers in this release.

The canonical evidence schema remains provider-neutral. Future framework
adapters require catalog records, owned packets, and conformance evidence before
selection. Local-model judgments are accompanied by deterministic checks and
judge-version/calibration evidence.

## Configuration and runtime boundaries

```yaml
evidencePlan:
  id: string
  digest: sha256:...
  controlSetDigest: sha256:...
  campaign:
    id: string
    purpose: PRODUCTION_PROMOTION
    digest: sha256:...
  scope:
    tenantId: string
    profileDigest: sha256:...
    bundleDigest: sha256:...
    routeId: string
    routeDigest: sha256:...
    subjectType: string
    subjectId: string
    subjectVersion: string
    subjectDigest: sha256:...
  producer:
    policyId: production-assurance-trusted-producer-v1
    policyDigest: sha256:...
    signerIdentity: string
    releaseDigest: sha256:...
    signature: string
  controls:
    - controlId: string
      requiredEvidenceTypes: [string]
      maximumAgeSeconds: integer
      blockingStatuses: [MISSING, COLLECTING, WARN, FAIL, STALE, WAIVED, NOT_RUN_ENV_UNAVAILABLE]
  aggregation: ALL_REQUIRED_CONTROLS
  controlSatisfaction:
    rule: FRESH_PASS_FOR_EVERY_REQUIRED_CONTROL
    nonPassDisposition: PROMOTION_BLOCKED
    waiverEffect: DOCUMENT_EXCEPTION_ONLY_PROMOTION_REMAINS_BLOCKED
    waiverSatisfiesPromotion: false
suites:
  - id: string
    version: semver
    suiteRef: oci@sha256:...
    datasetRef: oci@sha256:...
    subjects:
      - harnessId: string
        subjectRef: oci@sha256:...
        requiredCapabilities: [string]
    provider: string
    environmentClass: static | local-runtime | kubernetes | openshift | airgap
    thresholds: {}
    timeoutSeconds: integer
    resourceEnvelope: {}
```

- Secrets: baseline has none. Target-system credentials are short-lived references scoped to the run; paid-provider/API-key variables are rejected.
- RBAC: worker receives only suite-declared read/probe permissions in a test tenant; destructive tests require an ephemeral labelled environment. Evidence signer is separate from test execution where risk requires.
- Network: PR acceptance is deny-all. A post-merge live suite runs only through
  the external root-owned `/opt/planeon/bin/harness-live-campaign-launch` under
  a platform-and-tenant dual-signed execution envelope, independently signed
  capacity authorization, local trust/revocation state, and OS/CNI
  deny-all-except-signed-proxy rules. Repository code starts only after that
  boundary exists; wildcard/discovered/cloud-management/billing endpoints are
  rejected. Air-gap campaigns physically deny external egress.
- Storage: immutable suites/datasets/reports in OCI/PVC; evidence metadata/status/digest/control mapping in evidence-owned trust tables. Sensitive samples are minimized, encrypted by tenant facilities, and never placed in events.

## APIs, events, and state

```text
POST /trust/v1/evidence-plans
GET  /trust/v1/evidence-plans/{id}
POST /trust/v1/evaluation-runs
GET  /trust/v1/evaluation-runs/{id}
POST /trust/v1/evaluation-runs/{id}:cancel
POST /trust/v1/evidence
GET  /trust/v1/evidence/{id}
GET  /trust/v1/controls/{controlId}/evidence
POST /trust/v1/evidence/{id}:invalidate
```

Run states: `QUEUED → PREPARING → RUNNING → ANALYZING → SIGNING → COMPLETED`; alternatives `FAILED`, `CANCELLED`, `TIMED_OUT`, `NOT_RUN_ENV_UNAVAILABLE`.

Evidence states: `MISSING → COLLECTING → PASS | WARN | FAIL`; then `STALE`. Controlled alternative `WAIVED` is assigned by governance and does not overwrite the underlying evidence state.

Emitted:

- `evaluation.run.started.v1`
- `evaluation.run.completed.v1`
- `evaluation.run.failed.v1`
- `evidence.recorded.v1`
- `evidence.stale.v1`
- `control.assurance.changed.v1`

Consumed: profile/bundle/module releases, installation conditions, data readiness, model routes, task/tool traces, policy results, waivers, and revocations.

## Failures, retry, and rollback

- A run locks suite, data, judge, subject, environment, and configuration digests before execution.
- Deterministic cases may retry at case granularity when failure is classified infrastructure/transient; evaluation failures do not retry into a pass.
- Lost environment or missing target yields `NOT_RUN_ENV_UNAVAILABLE`, preserving completed case evidence.
- Worker crash resumes from immutable case outputs/inbox records without duplicating signed evidence.
- Signing failure leaves the run `FAILED`; unsigned results cannot satisfy controls.
- Evidence invalidation/staleness is append-only. Re-run produces a new record; it never edits the old verdict.
- Service rollback preserves newer evidence and invalidations.
- Judge disagreement/low calibration yields `WARN`/`FAIL` per suite, never silent averaging.
- Loss or absence of inference disables local-model-judge cases immediately and records them `NOT_RUN_ENV_UNAVAILABLE`; deterministic suites and evidence intake remain available. A subject dependency outage affects only campaigns that declared that subject/capability.

## Evidence and readiness gates

Every evidence record contains:

- Tenant, subject type/ID/version/digest, profile and bundle digests, and route
  ID/digest. Every value must equal the production-gate scope; absence or a
  cross-scope match is a denial, not `WARN`.
- Suite/dataset/provider/judge/environment digests and license/custody.
- Start/end time, code commit, platform, architecture, configuration digest.
- Status, metrics, thresholds, bounded findings, artifact references, signer, and expiry.
- Source, CI, merge, artifact, signature, deployment, runtime, security/quality, and unsigned `TENANT_ACCEPTANCE_CANDIDATE` axes where applicable. A campaign never emits `TENANT_ACCEPTANCE`.

Mandatory campaigns include contract, state, tenant isolation, zero-bill/offline,
supply chain, resilience, rollback, platform, and industry acceptance-candidate evidence. A
production gate accepts only a `PRODUCTION_PROMOTION` campaign whose campaign,
evidence-plan, control-set, subject, producer-policy, and producer-release
digests are immutable SHA-256 references and whose evidence signature resolves
to the trusted-producer policy. The gate aggregates exactly the taxonomy-owned
required control IDs with `ALL_REQUIRED_CONTROLS`; it never substitutes an
unlisted control, an `ANY` result, or evidence from another campaign.

The evidence scope is the exact tuple `(tenantId, profileDigest, bundleDigest,
routeId, routeDigest, subjectType, subjectId, subjectVersion, subjectDigest)`.
Every required control must have current `PASS` evidence for that same tuple. A
waiver is a separate signed, expiring governance record. It must repeat the same
evidence-plan digest, control-set digest, campaign digest, required control ID,
and exact scope tuple. Its production effect is always
`DOCUMENT_EXCEPTION_ONLY_PROMOTION_REMAINS_BLOCKED`: it does not satisfy the
control, convert evidence to `PASS`, or authorize promotion for `MISSING`,
`COLLECTING`, `WARN`, `FAIL`, `STALE`, or `WAIVED` evidence. A broad tenant,
profile, route, subject, or campaign waiver is invalid.

## Profile behavior

- `minimal-local`: deterministic suites plus small local quality sets, local report signing, short evidence retention.
- `enterprise`: distributed workers, trace-based evaluation, local calibrated judges, promotion comparisons, longer policy-bound retention.
- `airgap-enclave`: suites, data, judge models, vulnerability database, tools, and signing trust imported; no external evaluator.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: certification runner, white-goods acceptance-candidate flows, inference API/routing tests, and OpenShift observed-vs-rendered evidence; no warm checkout access.
- Unit: evidence freshness, control aggregation, digest locks, subject harness/capability predicates, local-judge model/backend admission, retry classification, and state transitions.
- Contract: every producer/consumer API/event and portable conformance kit.
- Integrity: tampered report/dataset/subject/signature, duplicate record, invalidation and revocation.
- Methodology: leakage, train/test overlap, source confounding, judge calibration, deterministic-vs-judge disagreement.
- Failure: worker/signing/store/target outage, environment loss, timeout, partial campaign.
- Platform: local ARM64/AMD64, Kubernetes, K3s, OpenShift, physical air gap.

## Sol-high implementation packets

1. `TRUST-EVAL-001`: evidence plan/record lifecycle, freshness/control mapping, deterministic evaluators, immutable campaigns, trace ingestion, local-judge opt-in/calibration, quality methodology, signing, and reproducibility.
2. `CONF-001-kit`: portable campaign/evidence schemas, environment intake, lifecycle/event kit, honest result semantics, signing, and meta-tests.
3. `CONF-002-parity`: pre-recorded, digest-pinned vector registry, provenance hashes, clean-room parity runners, behavior-change records, and destination adapters; no warm-checkout access.
4. `CONF-A1-001`: questionnaire-to-installed white-goods business/domain/data foundation campaign.
5. `CONF-A2-001`: cited read-only white-goods model/retrieval agent with failure injection.
6. `CONF-A3-001`: approval/resume/tool receipt/compensation, sandbox, memory lifecycle, and tenant-isolation campaign.
7. `CONF-K8S-001`, `CONF-OCP-001`, and `CONF-K3S-001`: live supported-platform campaigns with per-environment results.
8. `CONF-AIR-001`: physical no-network export/import/install/runtime/upgrade evidence.
9. `CONF-SEC-001` and `CONF-UPG-001`: adversarial isolation/supply-chain campaign and crash/upgrade/rollback/retention campaign.
10. `CONF-WG-001`: complete white-goods enterprise journey producing unsigned `TENANT_ACCEPTANCE_CANDIDATE` evidence only. Independent tenant authority is the sole producer of `TENANT_ACCEPTANCE`.

Each packet names exact suites, subject digests, environment prerequisites, expected evidence axes, and must report unavailable environments honestly rather than infer success.
