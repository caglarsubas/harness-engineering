# Repository Plan: `mas-harness-execution-plane`

## Current source/native gate — MET-UNIFY-008

`EXEC-001` may proceed with clean-room source and isolated offline acceptance
after its remaining predecessors under the
[versioned gate decision](../alpha-2/SOURCE_NATIVE_GATE_STAGING.md). The older
early-Linux-before-coding section below is retained history. Fresh native
AMD64 foundation and exact execution artifact proof still gate Linux release
deployment, runtime qualification and promotion; no side-effect authority
or tenant acceptance follows from source completion.

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

Repository R08 retains its existing accountable ownership. Planned owner packets: `EXEC-PROTO-ADOPT-001` (H9), `EXEC-TEMPORAL-001` (H10), `EXEC-SANDBOX-ADOPT-001` (H11), `EXEC-ML-ADOPT-001` (H12).
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

This repository owns four independently selectable harnesses: `execution.protocol-interoperability`, `execution.orchestration`, `execution.tool-skill-sandbox`, and `execution.ml-decision`. It implements protocol translation, durable tasks/checkpoints, governed tool plans/receipts, isolated execution, and deterministic ML/optimization decisions.

Non-goals:

- No tenant setup UI, model hosting, retrieval/index ownership, policy authoring, evidence acceptance, cluster reconciliation, or arbitrary code execution without an approved isolation provider.
- A protocol adapter never grants authority; every tool/agent call still passes trust policy and identity checks.
- Multi-agent execution is not the default; deterministic workflow, then one agent, then multiple agents only with explicit measured benefit.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-execution-plane/
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
├── src/planeon_execution/
│   ├── common/
│   ├── protocol/
│   ├── orchestration/
│   ├── tools/
│   ├── sandbox/{capabilities.py}
│   └── decision/
├── services/
│   ├── protocol-gateway/
│   ├── orchestration-api/
│   ├── orchestration-worker/
│   ├── tool-broker/
│   └── decision-service/
├── migrations/
│   ├── protocol/
│   ├── orchestration/
│   ├── tools/
│   └── decision/
├── providers/{gvisor,kata,kubernetes-job,onnxruntime,ortools,scikit-learn,wasmtime}/
├── deploy/helm/
│   ├── protocol-gateway/
│   ├── orchestration-api/
│   ├── orchestration-worker/
│   ├── tool-broker/
│   ├── sandbox/
│   └── decision-service/
├── fixtures/{decision,failures,orchestration,protocol,sandbox,sandbox-native,tools}/
├── scripts/run_failure_campaign.py
├── docs/
│   ├── native-sandbox.md
│   └── runbooks/
└── tests/{airgap,common,decision,orchestration,protocol,resilience,sandbox,sandbox-native,security,tools}/
```

## Deployables and toolchain

- Python 3.12.14, FastAPI, Pydantic v2, psycopg 3, jsonschema, cryptography, HTTPX, OpenTelemetry, MCP SDK compatible with 2026-07-28 plus 2025-11-25, and A2A v1; exact versions frozen in `uv.lock`.
- Deployables: `protocol-gateway`, `orchestration-api`, `orchestration-worker`, `tool-broker`, ephemeral `sandbox-runner` Jobs, and `decision-service`.
- Baseline durable executor uses PostgreSQL leases/outbox. Temporal is a separate optional provider module; it cannot change public task semantics.
- Sandbox providers: restricted Kubernetes Jobs for trusted actions, Wasmtime for untrusted WASM, gVisor/Kata for untrusted native code. Missing required provider makes compilation fail.

## Owned APIs, events, and stores

```text
/runtime/v1/tasks
/runtime/v1/tasks/{id}
/runtime/v1/tasks/{id}/cancel
/runtime/v1/tasks/{id}/input
/runtime/v1/tools
/runtime/v1/tools/{id}:plan
/runtime/v1/tools/{id}:execute
/runtime/v1/decisions
/runtime/v1/decisions/{id}
/mcp
/.well-known/agent-card.json
```

Task states use canonical A2A values; internal compensation is represented as task metadata plus tool execution states. Long mutations return operations/task IDs. Input/resume and cancel are idempotent. Tool executions require a plan digest, policy decision, approval where required, scoped credential reference, idempotency key, and receipt.

Owned PostgreSQL schemas/tables:

- `protocol`: capability registry/cache, negotiated versions, inbox/outbox.
- `orchestration`: task, task_event, checkpoint, lease, pending_input, retry, budget, idempotency.
- `tools`: tool_catalog, action_plan, authorization, execution, receipt, compensation, outcome_review.
- `decision`: model/artifact reference, request, result, feature/provenance references.

Emits task, approval request, tool plan/execution/receipt, compensation, protocol negotiation, decision, and evidence events. Consumes route/context references, approvals, policy decisions, model responses, and bundle revocations.

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

- Upstream: contracts, SDK, trust APIs, knowledge APIs, model API, PostgreSQL, Kubernetes API only for sandbox controller, OTel.
- Downstream: runtime gateways, external MCP/A2A clients/agents, conformance labs.
- OPA/trust loss fails closed for delegation/tools/state mutation. PostgreSQL loss rejects state changes. Model/knowledge failures follow task retry policy without losing checkpoint authority.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `EXEC-001-foundation`: common kernel, DB roles/RLS, outbox/inbox, task/event contracts, images, and state-model tests.
2. `EXEC-PROT-001`: stateless MCP, compatibility adapter, A2A v1, OpenAPI/AsyncAPI adapters, capability negotiation, auth propagation, and denial tests.
3. `EXEC-ORCH-001`: PostgreSQL tasks, leases, checkpoints, retries, input/resume/cancel, budgets, deterministic/one-agent selection, and crash recovery.
4. `EXEC-TOOL-001`: catalog, side-effect classification, plans, policy/approval, scoped credentials, receipts, idempotency, `OUTCOME_UNKNOWN`, and compensation.
5. `EXEC-SBX-001`: restricted Job and Wasmtime providers, profiles, default-deny network, resource/time limits, cleanup, and escape tests.
6. `EXEC-SBX-002`: gVisor/Kata provider manifests/capability probes; unavailable environment yields explicit non-certification.
7. `EXEC-ML-001`: scikit-learn/ONNX/OR-Tools adapters, signed artifact/provenance input, deterministic result, and evidence.
8. `EXEC-002-resilience`: duplicate/out-of-order events, crashes around commits/receipts, dependency outages, multi-tenant isolation, and air-gap campaign.

## Testing, verification, and acceptance

The `EXEC-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","state-model"],["make","security"]]`.
Later packets add lint, type, coverage, parity, contract, local integration,
sandbox, zero-bill, and reproducibility checks as direct argv arrays. The
executor supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and
invokes only `offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the
complete ordered list.

Acceptance: a read-only task retrieves cited context and uses a local model; a write action pauses for approval, resumes exactly once, records a signed receipt, and compensates when supported. Crashes at every state/receipt boundary recover without double side effect. Cross-tenant task/tool access, unauthorized protocol capability, sandbox escape, undeclared egress, and unbounded loops are denied.

## Release and rollback

- Each harness/provider image has its own digest and compatibility range. Task public semantics do not vary by orchestration provider.
- Workers use rolling, lease-aware shutdown. Upgrade must read the previous release's checkpoints/receipts.
- Rollback selects previous images; DB is expand/contract. Running tasks stay on their admitted workflow/module revision. No destructive rollback or automatic retry of `OUTCOME_UNKNOWN`.

## Zero-bill rules

- No managed workflow/queue/sandbox/optimization service, hosted agent, or remote code executor.
- Baseline PostgreSQL, local Kubernetes Jobs, Wasmtime, scikit-learn, ONNX Runtime, and OR-Tools are open-source/local. Optional providers are bundled only when license/platform checks pass.
- Self-hosted offline CI only; no cloud runners, scheduled agents, GitHub storage/Packages, API keys, public callbacks, or external telemetry.

## Early Linux implementation gate

EXEC-001 retains all original prerequisites and adds CONF-LINUX-001. Require
fresh native Linux AMD64 baseline PASS before runtime coding. Build Linux-native
workers and dependencies from pinned local inputs; prove process lifecycle,
restart/replay, tenant isolation and denied undeclared egress for each deployed
artifact. Later sandbox/agent tooling must not inherit workstation or raw
container-control privileges.

Detailed steps, cases, evidence bindings and rollback:
[Linux readiness](../alpha-2/LINUX_READINESS.md). Full Alpha-4 enterprise
certification and tenant acceptance remain independent.
