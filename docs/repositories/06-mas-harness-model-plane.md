# Repository Plan: `mas-harness-model-plane`

## Current source/native gate — MET-UNIFY-008

`MODEL-001` may proceed with clean-room source and isolated offline acceptance
after its remaining predecessors under the
[versioned gate decision](../alpha-2/SOURCE_NATIVE_GATE_STAGING.md). The older
early-Linux-before-coding section below is retained history. Fresh native
AMD64 foundation and exact inference artifact proof still gate Linux release
deployment, runtime qualification and promotion; model API fixture PASS is
not live model evidence.

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

Repository R06 retains its existing accountable ownership. Planned owner packets: `MODEL-ADOPT-001` (H2).
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

This repository owns `runtime.model-inference`: an OpenAI-compatible local inference API, backend-neutral scheduling, cancellation, batching, structured output, signed local route activation, model custody, and independently selectable Ollama, llama.cpp, and vLLM backend modules. MLX is development-only on macOS.

Non-goals:

- No hosted model provider, model marketplace, runtime weight download, control-plane UI, retrieval, orchestration, policy authority, or cross-tenant request routing.
- Models are not bundled unless their license/custody record explicitly permits redistribution.
- The API does not claim evidence acceptance; it emits observations for the trust plane.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-model-plane/
├── .github/workflows/verify.yml
├── .gitignore
├── AGENTS.md
├── CONTRIBUTING.md
├── Containerfile
├── LICENSE
├── NOTICE
├── README.md
├── SECURITY.md
├── PORTING.yaml
├── Makefile
├── pyproject.toml
├── uv.lock
├── contracts.lock.json
├── ci/
├── src/planeon_model/
│   ├── adapters/{llama_cpp.py,ollama.py,vllm.py}
│   ├── custody/
│   ├── registry/{llama_cpp.py,ollama.py,vllm.py}
│   ├── routing/
│   ├── control.py
│   ├── identity.py
│   ├── security.py
│   └── telemetry.py
├── modules/
│   ├── llama-cpp/
│   ├── ollama/
│   └── vllm/
├── deploy/helm/inference-api/
├── catalog/resource-envelopes/
├── benchmarks/
├── fixtures/{performance,routing}/
├── scripts/run_benchmark.py
├── docs/{model-custody.md,performance.md}
└── tests/
    ├── airgap/
    ├── backends/{test_llama_cpp.py,test_ollama.py,test_vllm.py}
    ├── custody/
    ├── fixtures/{llama-cpp,ollama,vllm}/
    ├── parity/
    ├── performance/
    ├── routing/
    ├── security/
    └── telemetry/
```

## Deployables and toolchain

- `inference-api`: Python 3.12.14, FastAPI, Pydantic v2, Uvicorn, HTTPX, cryptography, structlog, SSE, and OpenTelemetry, frozen in `uv.lock`.
- Backend images are separate module artifacts: `model-backend-ollama`, `model-backend-llama-cpp`, and `model-backend-vllm`. A tenant pulls only selected platforms/backends.
- CPU core supports Linux AMD64/ARM64; vLLM advertises only validated accelerator/platform combinations; MLX is never released as a Kubernetes production module.

## Owned APIs, events, and stores

Model-plane-only API:

```text
GET  /v1/models
POST /v1/chat/completions
POST /v1/responses
POST /v1/embeddings
POST /v1/rerank
GET  /healthz
GET  /readyz
GET  /metrics
```

Admin activation is a cluster-internal signed-artifact operation, not a public REST endpoint. Requests carry authenticated tenant, correlation, route, budget, and policy context from the AI gateway. Backend errors are normalized; streaming cancellation propagates to the backend.

Stores: no application database is required. Signed route/model manifests and last-known-good activation live on read-only/config PVCs; backend model weights live on tenant-controlled PVCs. An in-memory bounded queue is reconstructible. Usage/evaluation observations are emitted to trust; no authoritative usage ledger is stored here.

Emits `model.request.started.v1`, `model.usage.observed.v1`, `model.request.completed.v1`, `model.request.failed.v1`, and `model.route.observed.v1`. Consumes signed routing policy/model custody manifests and revocation updates.

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

- Alpha-2 implementation prerequisites: the approved model structural observation
  and `CON-MODEL-001` shared API/usage/vector release. MODEL-001 pins their merged
  commits and actual digests in `contracts.lock.json` and `ci/contract-snapshot/`.
  See [model prerequisite plan](../alpha-2/MODEL_PREREQUISITES.md).
- Upstream: contracts, SDK, trust policy/guardrail endpoint, selected backend, OTel Collector, and tenant model PVC.
- Downstream: runtime AI gateway, execution agents/decision services, knowledge embedding/reranking jobs, assurance worker.
- Trust loss fails closed for new requests requiring decisions; already admitted bounded streams may finish. Registry/control-plane loss does not interrupt an active signed last-known-good route.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `MODEL-001-clean-room-core`: independent shared-contract conformance, clean-room API/core scheduler/cancellation, local fixtures, explicit unavailable original-source baseline and prohibited-feature exclusion.
2. `MODEL-002-custody-routing`: model manifest/license checks, signed route activation, desired/observed/last-good behavior, revocation, and trust hook.
3. `MODEL-OLLAMA-001`: Ollama adapter/probe/backend module, AMD64/ARM64 manifests, streaming and embeddings conformance.
4. `MODEL-LLAMACPP-001`: llama.cpp adapter/backend, CPU resource envelopes, structured output, and cancellation.
5. `MODEL-VLLM-001`: vLLM adapter/backend, accelerator capability declarations, batching, rerank/embeddings where supported.
6. `MODEL-003-telemetry-security`: tenant/request identity, usage observations, content redaction, backpressure, denial, arbitrary UID, and offline startup.
7. `MODEL-004-performance`: reproducible local benchmark profiles and admission thresholds; performance results are evidence, not hardcoded marketing claims.

## Testing, verification, and acceptance

The `MODEL-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","source-parity"],["make","zero-bill"]]`.
Later packets add lint, type, coverage, contract, local-backend integration,
security, and reproducibility checks as direct argv arrays. The executor
supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

Whole-harness acceptance requires signed local route activation, invalid-signature/revocation denial, streaming/cancellation, structured outputs, embeddings, usage accuracy, queue overload behavior, arbitrary-UID startup, and successful startup/request with egress physically denied. Those checks are distributed across the owning packets, not all claimed by MODEL-001. Its retained `make source-parity` target proves independent destination contract conformance only; original source tests remain `NOT_RUN_ENV_UNAVAILABLE` and behavioral parity `NOT_ESTABLISHED`. Structural observations cannot substitute for behavioral evidence. Unavailable accelerator tests report `NOT_RUN_ENV_UNAVAILABLE`.

## Release and rollback

- `inference-api` and each backend have independent immutable image/module digests and compatibility ranges.
- Route activation is two-phase: verify/stage, then atomic active pointer; failure retains last-known-good.
- Rollback changes the profile/module digest and active policy; model PVC data is retained. No automatic weight deletion.

## Zero-bill rules

- Reject hosted-provider endpoints/API-key variables; no OpenRouter; no automatic model or tokenizer download; no usage-based service.
- Model weights, vulnerability DB, wheels, images, and tokenizers must be present in the signed bundle/PVC before startup.
- Self-hosted offline CI only, with no GitHub storage/Packages, cloud accelerators, tunnels, scheduled benchmarks, or external telemetry.

## Early Linux implementation gate

MODEL-001 retains all original prerequisites and adds CONF-LINUX-001. Require
fresh native Linux AMD64 baseline PASS before runtime coding, then test each
actual model backend/image on its declared Linux target. CPU architectures,
GPU drivers and accelerators are separate evidence axes. MLX remains macOS
development-only; no implicit model/package downloads or paid provider fallback.

Detailed steps, cases, evidence bindings and rollback:
[Linux readiness](../alpha-2/LINUX_READINESS.md). Full Alpha-4 enterprise
certification and tenant acceptance remain independent.
