# Repository Plan: `mas-harness-control-plane`

## Current source/native gate — MET-UNIFY-008

`CTRL-INTEGRATE-001` may proceed with clean-room source and isolated offline
acceptance after its remaining predecessor under the
[versioned gate decision](../alpha-2/SOURCE_NATIVE_GATE_STAGING.md). The older
early-Linux-before-coding section below is retained history. Fresh native
AMD64 foundation and exact Next.js artifact proof still gate Linux release
deployment, runtime qualification and promotion; no tenant overview runtime
or acceptance is claimed here.

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

Repository R04 retains its existing accountable ownership. Shared responsibility: Next.js/TypeScript questionnaire and onion status projections; consume trust registry without duplicating it.
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

This repository implements the guided setup portal, authenticated control API, questionnaire sessions, readiness review, tenant demand/profile lifecycle, compilation job worker, approvals, operations, immutable bundle requests, tenant organization harness overview, and separately authorized platform-operator portfolio. It is an asynchronous management plane and is never on a synchronous agent/model/tool request path.

Non-goals:

- No model inference, retrieval, memory, orchestration, tool execution, policy decision service, Kubernetes apply, artifact signing, or cloud provisioning.
- It cannot install an unlocked profile, store secret values, or silently accept compiler-proposed prerequisites.
- No Stripe, email SaaS, hosted LLM, analytics, remote font, or phone-home dependency.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-control-plane/
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
├── package.json
├── package-lock.json
├── pyproject.toml
├── uv.lock
├── ci/
├── apps/control-web/
│   └── src/
│       ├── app/api/v1alpha1/{approvals,bundles,demands,harnesses,operations,organizations,overview,planes,profiles,questionnaires,sessions}/
│       ├── app/{demands,harnesses,organizations,overview,planes,profiles,questionnaires}/
│       ├── components/harness-overview/
│       └── lib/{demands,harness-status,operations,profiles,questionnaire}/
├── contracts/{status-regression,status-integration}/
├── workers/profile-compiler/
├── packages/db/
│   └── migrations/{compiler-jobs,demand,harness-status,profile-lock,questionnaire}/
├── prisma/
├── deploy/helm/control-plane/
├── scripts/audit_dependencies.py
├── docs/security/
├── e2e/
│   ├── compiler-operation.spec.ts
│   ├── demand-approval.spec.ts
│   ├── harness-overview.spec.ts
│   ├── profile-lock.spec.ts
│   ├── questionnaire.spec.ts
│   ├── white-goods.spec.ts
│   └── security/
└── tests/{bootstrap,compiler-worker,demands,harness-status,profiles,questionnaire,security}/
```

## Deployables and toolchain

- `control-web`: Node 24.20.0 LTS, Next.js 16.3.3 Active LTS with the App Router, React 19.2, TypeScript 5, Prisma 6.19.3, PostgreSQL, AJV 8.20.0, Vitest, and Playwright. `package-lock.json` is canonical; runtime dependencies with release-blocking vulnerabilities are upgraded in a dedicated packet before Alpha 1 release.
- `profile-compiler-worker`: Python 3.12.14, `uv` 0.12.7, and no HTTP listener. `CTRL-001` is a standard-library-only inert worker with no job or database adapter; `CTRL-004` owns the exact `planeon-harness-contracts` wheel, psycopg closure, leases, compilation, and publication.
- Two separate non-root images and one chart; either deployable can scale independently.
- Every first-party browser route is TypeScript. Assets, fonts, icons, maps, and
  visualization code are bundled locally; Vercel services, hosted analytics,
  remote fonts, CDNs, runtime npm downloads, and provider-specific deployment
  adapters are prohibited. The same standalone Node image runs behind a
  tenant-controlled reverse proxy on Kubernetes, OpenShift, K3s, or an air-gapped
  cluster.

## Owned APIs, events, and stores

REST prefix `/api/v1alpha1`:

```text
GET  /questionnaires
POST /sessions
GET  /sessions/{id}
PUT  /sessions/{id}/answers
POST /sessions/{id}/review
POST /demands
GET  /demands/{id}
POST /demands/{id}/validate
POST /demands/{id}/approve
POST /demands/{id}/compile
GET  /profiles/{id}
POST /profiles/{id}/approve
POST /profiles/{id}/lock
GET  /profiles/{id}/explanation
GET  /operations/{id}
POST /bundles
GET  /approvals/{id}
POST /approvals/{id}/decision
GET  /overview
GET  /planes/{planeId}
GET  /harnesses/{harnessId}
GET  /organizations
GET  /organizations/{organizationId}/overview
```

Mutations require `Idempotency-Key`; updates require `If-Match`; long operations return `202` plus an `Operation`. Authenticated OIDC identity determines tenant and actor. Caller-supplied tenant headers are ignored/rejected.

`/overview`, `/planes/{planeId}`, and `/harnesses/{harnessId}` always derive the
organization from the authenticated tenant session. `/organizations` and
`/organizations/{organizationId}/overview` require the independent
`organization:portfolio:view` platform-operator policy, cursor pagination, and
audited organization scope. Unauthorized organization identifiers receive an
indistinguishable not-found response.

Owned PostgreSQL tables in `control` schema: `tenant`, `questionnaire_session`, `answer_revision`, `readiness_finding`, `demand`, `profile`, `profile_revision`, `prerequisite_decision`, `approval`, `operation`, `compilation_job`, `bundle_request`, `tenant_harness_status_projection`, `tenant_plane_status_projection`, `tenant_overview_projection`, `status_projection_cursor`, `status_projection_finding`, `audit_event`, `idempotency_record`, `event_outbox`, and `event_inbox`. Every tenant row has RLS, immutable tenant ID, version, timestamps, and audit linkage. Worker claims use `FOR UPDATE SKIP LOCKED` and leases. Projection ingestors are ordered and idempotent; reads bind organization, profile, bundle, release, observed generation, freshness window, and authenticated source cursors.

Emits: `demand.validated.v1`, `profile.compilation.requested.v1`, `profile.proposed.v1`, `profile.locked.v1`, `approval.requested.v1`, and operation-state events. Consumes signed `bundle.signed.v1` plus authenticated profile, distribution, installation, runtime, security, assurance, and tenant-acceptance summaries into local projections; the browser never fans out across product planes. Events contain IDs/digests only.

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

- Upstream: contracts, SDK TypeScript/Python packages, signed industry-pack artifacts, OIDC provider, PostgreSQL.
- Downstream: distribution consumes locked bundle requests; operator consumes released bundle/profile artifacts, never the live control API; conformance tests the journey.
- Trust decisions are requested through the trust API. A trust outage blocks approvals and profile locking but not read-only viewing of the last verified projection, which must be explicitly stale or source-unavailable.
- Operator/install and evidence summaries are asynchronous projection inputs, not synchronous browser dependencies. Source loss cannot fabricate current health and does not place the control plane on a runtime request path.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `CTRL-001-bootstrap-auth`: web/worker scaffold, OIDC session, tenant derivation, PostgreSQL/RLS, health/readiness, and non-root images.
2. `CTRL-FIX-001-bootstrap-lineage`: one-time correction that admits later descendant PR merge refs and additive packet-pinned dependencies while preserving every bootstrap pin.
3. `CTRL-002-questionnaire`: signed pack intake, session/answer revisions, eight-stage UI, readiness findings, ETag/idempotency, and audit.
4. `CTRL-003-demand-approval`: demand validation, prerequisite accept/reject, approval workflow, N-of-M policy hook, and lifecycle guards.
5. `CTRL-004-compiler-worker`: job/outbox schema, lease/claim, compiler invocation, atomic profile outputs, retries/dead-letter, and operation API.
6. `CTRL-005-profile-lock-bundle`: profile review/explanation, offline approval, lock digest, bundle request, and signed-bundle status.
7. `CTRL-006-security-e2e`: RLS denial, CSRF/session, tenant isolation, tamper evidence, accessibility, Playwright journey, and dependency remediation.
8. `CTRL-007-tenant-harness-overview`: ordered status projections, RLS APIs, platform-operator portfolio, tenant overview, plane/harness drill-down, interactive onion plus accessible list, stale-source behavior, WCAG 2.2 AA, and zero-public-browser-request evidence. The coding brief is [`TENANT_HARNESS_OVERVIEW.md`](../TENANT_HARNESS_OVERVIEW.md).
9. `CTRL-FIX-002-phase0-ui-security`: native-link onion semantics, explicit full-digest access, light/dark theme closure, stripe-free status treatment, and tenant-versus-platform audit-table regression coverage.

10. `CTRL-FIX-003-status-consistency`: clock-aware materialization for detail and portfolio, canonical aggregation parity using pinned CON-FIX-001 vectors, and cumulative control regressions; production policies remain denied.
11. `CTRL-INTEGRATE-001-production-overview`: explicit authenticated production composition and durable tenant projection/policy adapters, additive database migration, real route/browser tests and isolated PostgreSQL acceptance. Missing local capacity remains NOT_RUN_ENV_UNAVAILABLE; CONF-A2-001 separately certifies installed behavior.

## `CTRL-001` bootstrap authority

`CTRL-001` starts only from the exact empty public control-plane commit
`fbd3d21da70167b0819caa1dfc017e7c673a1cbe`. It binds SDK-002 neutral
telemetry, the IND-001 common journey, and MET-003 zero-bill policy by exact
public commits and raw digests, without installing or copying predecessor source.
The packet creates only the control foundation: offline OIDC admission/session
primitives, server-derived tenant context, health/readiness, an inert compiler
worker, the first additive PostgreSQL/RLS source contract, two source-only
Containerfiles, an inert Helm chart, and closed offline dispatch.

OIDC uses a regular local issuer registry with inline asymmetric public JWKS.
Remote discovery, token/userinfo calls, client secrets, symmetric keys, passwords,
and caller-selected tenants are forbidden. Authorization state, nonce, PKCE
verifier, session cookie, subject, and token identifiers are retained only as
bounded SHA-256 digests. The opaque `__Host-planeon_session` cookie is secure,
HttpOnly, SameSite=Lax, and server-side; tenant context comes from the selected
issuer binding and cannot be supplied by a body, query, header, cookie payload,
or environment default. Session revisions are append-only `ACTIVE`, `REVOKED`,
or `EXPIRED` records with atomic audit behavior.

The web surface contains only `GET /health/live` and `GET /health/ready` in this
packet. Required issuer-registry, entropy, store, audit, tenant-transaction, and
contract-lock probes must all be ready; optional telemetry can degrade without
authorizing work. The separate worker exposes only command-line health and one-
shot `IDLE_BOOTSTRAP` behavior. Questionnaire, demand, profile, compilation,
bundle, overview, plane, harness, and operator endpoints remain owned by later
packets.

The initial `control` schema contains only tenant, authorization-attempt,
session, session-revision, audit, idempotency, inbox, and outbox tables. Four
NOLOGIN roles, forced RLS, transaction-local organization context, append-only
audit/outbox triggers, and least privilege are mandatory. Static SQL and an
independent in-memory isolation model are source/contract evidence only. Actual
PostgreSQL is `NOT_RUN_ENV_UNAVAILABLE` unless acceptance receives a disposable,
credential-free local cluster; a shared host database is never mutated.

The exact Node, npm, Next.js, React, TypeScript, Prisma, AJV, Vitest, Python, and
uv versions are packet-locked. npm may populate `node_modules` only from a
preprovisioned local cache under the same deny-all-outbound launcher; no install
script, registry lookup, remote font/asset, Vercel service, hosted analytics,
image build, deployment, or retained generated artifact is permitted. Both
source-only images require external digest references, and both Helm components
are independently scalable but disabled by default.

## `CTRL-FIX-001` bootstrap-lineage correction authority

The merged CTRL-001 scaffold exposed two bootstrap-only assumptions that would
otherwise block every later packet: its prefetch gate required `HEAD^1` to be the
empty repository commit, and it required the root dependency maps to equal the
bootstrap maps byte-for-byte. A pull-request merge ref after CTRL-001 necessarily
has current `main` as first parent, and later packets may need dependencies that
their own authority and offline cache pin.

`CTRL-FIX-001` is the sole predecessor-handler correction. It keeps
`fbd3d21da70167b0819caa1dfc017e7c673a1cbe` as the one exact empty history root,
requires full non-shallow ancestry from that root, rejects Git replace/graft
authority, and retains every exact CTRL-001 runtime/dev dependency as a mandatory
subset. Additive dependencies are admitted only when a later packet pins them in
its package lock, packet-local tests, signed root-owned cache inventory, and
offline acceptance. The correction cannot edit the Makefile, dispatcher,
transport, workflow, PORTING ledger, public API, tenant state, or deployment.

## `CTRL-002` questionnaire authority

CTRL-002 consumes the exact merged CTRL-001/CTRL-FIX-001 line, the contracts
release at `2146278a95344cd2a8e22596b2f315b46edffc88`, and the white-goods
certification source at `c6513d71535d56c71869bf889169d798c7b80c9c`. The task
packet pins the questionnaire schema, contract release, pack, journey,
certification lock, artifact manifest, and accepted-pilot bytes independently.
The upstream artifact is currently unsigned and `NOT_RETAINED`; it is provenance
and cannot be presented as an admitted release.

Production intake is local-only and fail closed. A bounded gzip/tar archive,
certification lock/manifest, and Ed25519 release signature are admitted against a
local purpose/validity/revocation trust registry. Identity, archive, index, lock,
contract, journey, and resource digests must agree before YAML or questionnaire
data becomes visible. Tar paths, file kinds/modes/sizes/counts, UTF-8, duplicate
keys, aliases, custom tags, and executable content are closed. The only added
runtime package is exact `yaml` 2.9.0 (ISC, zero dependencies); Node implements
gzip, tar, digest, signature, and canonicalization from its standard library.

The eight stage IDs and order are immutable. Session creation is DRAFT revision
1, the first save starts IN_PROGRESS, review produces deterministic append-only
findings and either BLOCKED or READY_FOR_COMPILATION, and SUPERSEDED remains a
terminal state without a CTRL-002 mutation. Every mutation requires server-
derived OIDC tenant context, CSRF, and idempotency; updates also require a strong
ETag. Exact replay returns the stored response, divergent replay is 409, missing
precondition is 428, stale precondition is 412, and unknown/cross-tenant IDs share
one 404 representation. PostgreSQL source creates only questionnaire_session,
answer_revision, and readiness_finding with forced RLS and append-only history;
without a disposable credential-free local cluster its runtime axis is
`NOT_RUN_ENV_UNAVAILABLE`.

The App Router exposes a responsive `/questionnaires` entry and stable
`/questionnaires/{sessionId}/{stageId}` steps with all eight named stages,
save/resume/review, findings, and accessible loading/empty/error semantics. Full
browser/WCAG certification remains owned by CTRL-006, and the tenant onion/
portfolio overview remains owned by CTRL-007.

## Testing, verification, and acceptance

The `CTRL-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","bootstrap-e2e"],["make","zero-bill"]]`.
Later packets add lint, type, unit, integration, contract, local E2E, security,
and reproducibility checks as direct argv arrays. The executor supplies the
hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

Acceptance: a local OIDC fixture user completes a white-goods session, sees missing readiness evidence, explicitly accepts prerequisites, approves and locks a deterministic profile, requests a bundle, then sees the selected foundation status in the organization overview and navigates to its plane and harness details. Unselected harnesses remain neutral. Cross-tenant reads/writes return indistinguishable not-found responses; authorized operator portfolio reads are explicit and audited. Stale/source-unavailable summaries serve only the last verified projection with visible freshness loss. Onion/list semantics, keyboard navigation, reflow, reduced motion, and browser traffic pass their accessibility and zero-public-network assertions. Crashing the worker after commit but before publish does not lose or duplicate the operation/event.

## Release and rollback

- Web and worker images share a release version but have independent digests. Database migrations use expand/contract and remain compatible with the previous ready release.
- Rollback deploys previous images and uses only backward-compatible schema. Automatic destructive migration rollback is prohibited.
- Questionnaire/profile revisions are append-only; lifecycle correction creates a superseding revision.

## Zero-bill rules

- Local assets only; no email/SMS/analytics/payment/hosted-model calls. OIDC and PostgreSQL are tenant/operator supplied.
- CI and builds use self-hosted runners and locked local npm/uv inputs; every
  packet-declared uv argv carries `--offline`, `--frozen`, and `--no-sync`.
  There is no Actions storage/cache/Packages, scheduled workflow, or remote
  browser service.
- Bundle request cannot include cloud provisioning or paid-provider requirements; static and runtime egress tests enforce the rule.

## Early Linux implementation gate

CTRL-FIX-003 remains the next source-only status correction. CTRL-INTEGRATE-001
requires fresh CONF-LINUX-001 native Linux AMD64 baseline PASS before runtime
coding. Build Next.js standalone output and native Node dependencies in the
pinned Linux target; never copy workstation .next/node_modules. Verify container
startup, arbitrary non-root UID, read-only filesystem, PostgreSQL migration/RLS
and restart with real evidence. The overview's status model must keep Linux
qualification distinct from source, installation and tenant acceptance.

Detailed steps, cases, evidence bindings and rollback:
[Linux readiness](../alpha-2/LINUX_READINESS.md). Full Alpha-4 enterprise
certification and tenant acceptance remain independent.
