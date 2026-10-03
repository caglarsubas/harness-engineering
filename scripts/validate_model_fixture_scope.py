#!/usr/bin/env python3
"""Closed model fixture scope authority; reads only committed source-free inputs."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

try:
    from safe_yaml import safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import safe_load as safe_yaml_load

try:
    from validate_model_api_inventory import amend_model_packet as amend_inventory_packet
except ModuleNotFoundError:
    from scripts.validate_model_api_inventory import amend_model_packet as amend_inventory_packet

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_RECORD = json.loads("{\"schemaVersion\":\"harness.planeon.ai/model-fixture-scope-amendment/v1\",\"authorityPacket\":\"MET-REPAIR-005\",\"approvalDate\":\"2026-09-07\",\"historicalPacketCount\":121,\"currentPacketCount\":122,\"metaBaseline\":\"a50f878296295abf42dc48093904d99f046f0d2b\",\"baseline\":{\"repository\":\"mas-harness-contracts\",\"commit\":\"fb365aabfd8c5560e064be5d97ff9f2bcc69c57c\",\"packetSha256\":\"807efc83ddd77e27e19d0e7d53811321c9b00c95972b53e78b263f385fd41d48\",\"execution\":\"LOCAL_SIGNED_HOST_OFFLINE_REPLAY\",\"passed\":758,\"failed\":0,\"skipped\":0,\"commandsCompleted\":3,\"outputSha256\":\"563390fc76763cc347c6327b7e219ae2077ad94592a061f92ee97a705fae9af7\",\"workingTreeOverlay\":false,\"trackedFilesUnchanged\":true},\"testChange\":{\"path\":\"tests/golden/test_generated_contracts.py\",\"beforeSha256\":\"856b1d14e0f4d4ee84f6c4f973db412f9905559124091355bec7de85cc818080\",\"helper\":\"_copy_generation_inputs\",\"beforeHelper\":\"def _copy_generation_inputs(destination: Path) -> None:\\n    for relative in (\\n        \\\"schemas\\\", \\\"openapi\\\", \\\"asyncapi\\\", \\\"src\\\", \\\"docs\\\",\\n        \\\"tests/fixtures/runtime\\\", \\\"tests/fixtures/status\\\", \\\"contracts/regression-inputs\\\",\\n    ):\\n        shutil.copytree(ROOT / relative, destination / relative)\\n\",\"afterHelper\":\"def _copy_generation_inputs(destination: Path) -> None:\\n    for relative in (\\n        \\\"schemas\\\", \\\"openapi\\\", \\\"asyncapi\\\", \\\"src\\\", \\\"docs\\\",\\n        \\\"tests/fixtures/runtime\\\", \\\"tests/fixtures/status\\\", \\\"contracts/regression-inputs\\\",\\n        \\\"tests/fixtures/model\\\", \\\"contracts/model-inputs\\\",\\n    ):\\n        shutil.copytree(ROOT / relative, destination / relative)\\n    shutil.copy2(ROOT / \\\"contracts/model-inputs.lock.json\\\", destination / \\\"contracts/model-inputs.lock.json\\\")\\n\",\"prefixSha256\":\"057dd3b6f8e6f97f78957ae6e359e7fda6dd03038b4e9d05bc0f6ccfbc8e0a4c\",\"suffixSha256\":\"c1cb7096aa6e2ef684e5b9533c7493974bb47d71e48ac95ae82b9c56a85b4e3b\",\"otherBytes\":\"UNCHANGED\",\"otherAssertions\":\"UNCHANGED\",\"directoryCopies\":[\"tests/fixtures/model\",\"contracts/model-inputs\"],\"fileCopies\":[\"contracts/model-inputs.lock.json\"],\"missingInputs\":\"FAIL_CLOSED\",\"diagnosis\":\"SOURCE_INSPECTION_ONLY\",\"productImplementation\":\"NOT_RUN\",\"negativeCasesOwner\":\"tests/model_api/\"},\"packetDigests\":{\"MET-REPAIR-005\":\"680335751aab8ac403f73db751d67c0ba98fce09017d51eebd7fa36d7b9fb5d0\",\"CON-MODEL-001\":\"fff08209e76c2287c257a8d37a29aba159f82019e70f51d36bcaebf9d6805f33\"},\"protectedFiles\":{\"architecture/model-fixture-inputs/CON-MODEL-001.before.yaml\":\"807efc83ddd77e27e19d0e7d53811321c9b00c95972b53e78b263f385fd41d48\",\"architecture/model-fixture-inputs/test_generated_contracts.before.txt\":\"856b1d14e0f4d4ee84f6c4f973db412f9905559124091355bec7de85cc818080\",\"architecture/readiness-repairs.json\":\"30db784918bb651cc81f26d23cb4b1d7f790ef260ef5e48a2d7ae2ae94c12a0d\",\"architecture/readiness-repair-amendment.json\":\"c3caa938557f1b9bb195188e35edc946fbdea36f0f1b235ab23f2689ffc54912\",\"architecture/linux-readiness.json\":\"2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762\",\"architecture/linux-readiness-amendment.json\":\"3a59552dbadd6a9e7579038523787926b921c35a3c71d036d2705b1c95b804a6\",\"architecture/linux-test-ownership-amendment.json\":\"5aa1e79de247ebed7550b56db48266182941232d9036840beade99fbcf11172f\",\"task-packets/MET-REPAIR-004.yaml\":\"3217293d977e25f0c6e7f6e6bb0134c27d840fd8769dc285494ecc7f351f6d94\",\"task-packets/CON-FIX-001.yaml\":\"15040a4811277880118d58121a7d23721d8a91b4ab6d3211f960189d6a351a14\",\"task-packets/CTRL-FIX-003.yaml\":\"42876f9ab5ab8c227920fe6eee3a913b72f6940a989a8d128d627fbfea43c48f\"},\"preserved\":{\"runtimeCodingRequires\":\"FRESH_NATIVE_LINUX_AMD64_PASS\",\"nativeLinuxStatus\":\"NOT_RUN_ENV_UNAVAILABLE\",\"sourceAccess\":\"PROHIBITED\",\"billingBoundary\":\"UNCHANGED\",\"rootPolicyChange\":false,\"modelEffortTransition\":\"NOT_DUE\"},\"evidenceBoundary\":\"AUTHORITY_ONLY_NOT_PRODUCT_TEST_CHANGE_MODEL_CONTRACT_RELEASE_NATIVE_LINUX_OR_TENANT_ACCEPTANCE\"}")
EXPECTED_META = json.loads("{\"id\":\"MET-REPAIR-005\",\"repository\":\"Harness-Engineering\",\"branch\":\"codex/met-repair-005-model-fixture-scope\",\"objective\":\"Publish the approved model generator-fixture input-copy exception without rewriting consumed authorities, product tests, public contracts or native runtime gates.\",\"predecessors\":[\"MET-REPAIR-004\",\"CON-FIX-001\",\"CTRL-FIX-003\"],\"allowedPaths\":[\"task-packets/MET-REPAIR-005.yaml\",\"task-packets/CON-MODEL-001.yaml\",\"task-packets/README.md\",\"architecture/model-fixture-scope-amendment.json\",\"architecture/model-fixture-inputs/CON-MODEL-001.before.yaml\",\"architecture/model-fixture-inputs/test_generated_contracts.before.txt\",\"scripts/validate_model_fixture_scope.py\",\"scripts/validate_alpha2_readiness.py\",\"scripts/validate_readiness_repairs.py\",\"scripts/validate_linux_readiness.py\",\"scripts/validate_linux_repair.py\",\"scripts/validate_linux_test_ownership.py\",\"scripts/validate_readiness.py\",\"scripts/validate_reuse.py\",\"tests/test_model_fixture_scope.py\",\"tests/test_alpha2_readiness.py\",\"tests/test_readiness_repairs.py\",\"tests/test_linux_readiness.py\",\"tests/test_linux_repair.py\",\"tests/test_linux_test_ownership.py\",\"tests/test_task_packets.py\",\"tests/test_reuse.py\",\"docs/alpha-2/MODEL_FIXTURE_SCOPE_REPAIR.md\",\"docs/alpha-2/MODEL_PREREQUISITES.md\",\"docs/alpha-2/READINESS_REPAIRS.md\",\"docs/DEVELOPMENT_STATUS.md\",\"docs/MASTER_DEVELOPMENT_PLAN.md\",\"docs/READINESS_INDEX.md\",\"docs/adr/0004-sol-high-packet-boundary.md\",\"docs/repositories/00-harness-engineering.md\",\"docs/repositories/01-mas-harness-contracts.md\"],\"warmSourceAccess\":\"PROHIBITED_DURING_IMPLEMENTATION\",\"sourceReuse\":[],\"contracts\":[\"Consumes immutable meta main a50f878296295abf42dc48093904d99f046f0d2b, CON-FIX-001 main fb365aabfd8c5560e064be5d97ff9f2bcc69c57c and CTRL-FIX-003 main 1de7c405329f4458970be0187838145b4da222d8.\",\"Produces a 122-packet catalog and one function-bounded legacy fixture path in CON-MODEL-001. Thirteen repositories, sixteen harnesses, all predecessor commands, source locks, signed runner and native Linux gates remain unchanged.\"],\"deliverables\":[\"Pin the untouched model packet, legacy test file and bytes outside _copy_generation_inputs, 758-pass baseline and source-inspection-only diagnosis in a closed additive record; preserve consumed authorities and historical failure records.\",\"Amend CON-MODEL-001 only by this predecessor, one exact allowed test path and bounded contract/deliverable/evidence additions. Permit only two added directory copies and one input-lock file copy inside _copy_generation_inputs; preserve all existing test assertions, inputs, imports and every other byte.\",\"Reconcile current counts, ownership, checkpoint and dedicated strict validators/negative tests. Existing meta test changes are limited to current catalog count, appended model predecessor and refreshed source-only status assertions; preserve all historical record values and substantive predecessor regression assertions.\",\"Run all predecessor meta/candidate suites and new independent scope mutation tests through the existing signed offline launcher. No product code or privileged operator change is part of this publication.\"],\"excluded\":[\"Product implementation or test edits; changes to consumed MET-REPAIR-001 through MET-REPAIR-004 packets, Linux records or source locks; test suppression or generator validation weakening; public API, signing, licensing, dependencies, root policy/helper/toolchain/key/sudoers changes; warm-source access; downloads; hosted runners; paid APIs; provisioning; live execution or native/tenant acceptance.\"],\"prefetchCommands\":[],\"offlineAcceptanceCommands\":[[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_reuse.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_alpha2_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_readiness_repairs.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_linux_readiness.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_linux_repair.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_linux_test_ownership.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/validate_model_fixture_scope.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"-m\",\"pytest\",\"tests\",\"ci/test_offline_runner.py\",\"ci/test_warm_snapshot.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/zero_bill_scan.py\",\".\"]],\"offlineExecution\":{\"wrapperArgv\":[\"./ci/verify-offline.sh\"],\"packetPathEnvironment\":\"HARNESS_TASK_PACKET\",\"packetPathMode\":\"HASH_PINNED_READ_ONCE_NO_CHILD_PATH\",\"commandTransport\":\"ARGV_ARRAY_V1\",\"isolation\":\"OS_ENFORCED_DENY_ALL_OUTBOUND\",\"sessionScope\":\"SINGLE_PROCESS_TREE\",\"prefetchOutsideSession\":false,\"offlineEnvironment\":{\"UV_OFFLINE\":\"1\",\"UV_FROZEN\":\"1\",\"UV_NO_SYNC\":\"1\"}},\"expectedEvidence\":[\"122 unique schema-valid, topologically indexed and path-owned packets. Exact additive delta and whole-packet pins reject omitted, widened or changed authority.\",\"Negative vectors reject changes outside the approved helper, assertion weakening, incomplete fixture copies, optional missing-input fallbacks, altered baseline evidence, false native/live PASS, command/source/runner scope changes and historical byte mutation.\",\"Baseline is 758 passed, zero failures/skips; the model-input integration finding is source inspection only, not a reproduced failure. Source/head, local offline, PR CI, merge, exact-main, Linux artifact/runtime and tenant acceptance remain separate.\"],\"rollback\":\"Revert this authority publication as one unit before the amended product packet starts. After consumption publish reviewed superseding authority; preserve historical bytes, signed activation history, product data and independent native/live gates.\"}")
EXPECTED_BEFORE = json.loads("{\"id\":\"CON-MODEL-001\",\"repository\":\"mas-harness-contracts\",\"branch\":\"codex/con-model-001-api-usage\",\"objective\":\"Publish the independent model inference API, tenant-neutral usage observations and conformance vectors consumed by MODEL-001 while retaining all predecessor release contracts.\",\"predecessors\":[\"CON-007\",\"MET-OBS-MODEL-001\",\"CON-FIX-001\",\"CTRL-FIX-003\"],\"allowedPaths\":[\"openapi/model.openapi.json\",\"schemas/v1alpha1/model/\",\"tests/model_api/\",\"tests/fixtures/model/\",\"contracts/model-inputs.lock.json\",\"contracts/model-inputs/\",\"contracts/release-manifest.json\",\"generated/\",\"scripts/generate_contracts.py\",\"scripts/check_generated.py\",\"docs/model-api.md\",\"docs/model-usage-compatibility.md\"],\"warmSourceAccess\":\"PROHIBITED_DURING_IMPLEMENTATION\",\"sourceReuse\":[],\"contracts\":[\"Consumes CON-007 signed admission, receipt and budget contracts unchanged\",\"Consumes the digest-pinned MET-OBS-MODEL-001 structural report, never a warm checkout\",\"Produces model API and usage contracts v1alpha1 with independently authored golden vectors\"],\"deliverables\":[\"OpenAPI 3.1 inference contract and closed local-ref JSON Schemas for models, chat, completions, responses, embeddings, rerank, errors, SSE events and tenant-neutral usage observations, as specified in docs/alpha-2/MODEL_PREREQUISITES.md of the meta authority.\",\"Explicit supported OpenAI-compatible subset with bounded requests, errors, cancellation/deadline and structured-output capability rules; unsupported features are rejected without external fetches.\",\"Immutable input lock/snapshot records the meta and CON-007 commits, structural report digest and independent normative references; any observed legacy field is mapped, deliberately omitted or explicitly unsupported without inferred equivalence.\",\"Positive/negative and streaming golden vectors with INDEPENDENT_CONTRACT_VECTOR provenance; no original-source execution or behavioral parity claim.\",\"Additive generated indexes and release manifest preserve every CON-007/predecessor entry; public API is described, never hosted in this packet.\"],\"excluded\":[\"Model execution, source code/test access, SDK/product changes, route activation, new authentication/signing primitives, external schema resolution, new dependencies, editing Makefile/PORTING.yaml, or original-source compatibility PASS claims.\"],\"prefetchCommands\":[],\"offlineAcceptanceCommands\":[[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/generate_contracts.py\",\"--check\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"scripts/check_generated.py\"],[\"uv\",\"run\",\"--offline\",\"--frozen\",\"--no-sync\",\"python\",\"-m\",\"pytest\",\"tests\"]],\"offlineExecution\":{\"wrapperArgv\":[\"./ci/verify-offline.sh\"],\"packetPathEnvironment\":\"HARNESS_TASK_PACKET\",\"packetPathMode\":\"HASH_PINNED_READ_ONCE_NO_CHILD_PATH\",\"commandTransport\":\"ARGV_ARRAY_V1\",\"isolation\":\"OS_ENFORCED_DENY_ALL_OUTBOUND\",\"sessionScope\":\"SINGLE_PROCESS_TREE\",\"prefetchOutsideSession\":false,\"offlineEnvironment\":{\"UV_OFFLINE\":\"1\",\"UV_FROZEN\":\"1\",\"UV_NO_SYNC\":\"1\"}},\"expectedEvidence\":[\"All inference methods and schemas resolve locally and each has independent positive/negative vectors; malformed/unknown fields, forged identity assertions, unbounded inputs, unsupported capabilities and unsafe errors are rejected.\",\"Streaming ordering, exactly one terminal result, no cross-request IDs, cancellation, usage accounting and no post-first-byte retry are specified and fixture-tested.\",\"Release manifest and input-lock digests are reproducible; all predecessor generated/runtime/compatibility tests remain green.\",\"Original-source tests remain NOT_RUN_ENV_UNAVAILABLE and original-source behavioral parity remains NOT_ESTABLISHED, distinct from destination contract conformance.\"],\"rollback\":\"Revert the unconsumed additive model-contract release; retain every predecessor schema, generated entry and signed-admission contract unchanged.\"}")
EXTRA_CONTRACTS = json.loads("[\"MET-REPAIR-005: consume the exact merged model fixture-scope amendment and its source-free inputs. The sole new legacy path is tests/golden/test_generated_contracts.py at baseline SHA-256 856b1d14e0f4d4ee84f6c4f973db412f9905559124091355bec7de85cc818080.\",\"MET-REPAIR-005: only _copy_generation_inputs may change, by copying the two added directories tests/fixtures/model and contracts/model-inputs and the file contracts/model-inputs.lock.json. Use the exact before/after helper text in architecture/model-fixture-scope-amendment.json; preserve every byte outside the helper, all existing inputs/imports and all test assertions.\"]")
EXTRA_DELIVERABLES = json.loads("[\"MET-REPAIR-005: add the exact required input copies without existence checks, optional fallbacks, broad tree copies, symlinks or missing-input suppression. Do not edit other predecessor helpers/tests or weaken release-source validation.\",\"MET-REPAIR-005: under tests/model_api/, independently check the full legacy file against its pinned source-free baseline and sole exact helper replacement; reject changed prefix/suffix/assertions and missing, extra, duplicated or conditional copies. Preserve all 758 predecessor test IDs and run them with the new suite, with no skip, xfail, deselection, monkeypatch or test-only generator behavior.\"]")
EXTRA_EVIDENCE = "MET-REPAIR-005: the untouched baseline at fb365aabfd8c5560e064be5d97ff9f2bcc69c57c passed 758 tests with zero skips/failures (local signed offline log 563390fc76763cc347c6327b7e219ae2077ad94592a061f92ee97a705fae9af7). The fixed temporary-input inventory is SOURCE_INSPECTION_ONLY, not an executed model-extension failure. Prove the exact helper-only change and complete required release-input validation before new source/CI/merge acceptance."


def same(left: Any, right: Any) -> bool:
    try:
        return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError, OverflowError, RecursionError):
        return False


def amend_model_packet(previous: dict[str, Any]) -> dict[str, Any]:
    value = deepcopy(previous)
    value["predecessors"].append("MET-REPAIR-005")
    value["allowedPaths"].append("tests/golden/test_generated_contracts.py")
    value["contracts"].extend(EXTRA_CONTRACTS)
    value["deliverables"].extend(EXTRA_DELIVERABLES)
    value["expectedEvidence"].append(EXTRA_EVIDENCE)
    return value


def validate_fixture_edit(before: Any, after: Any) -> list[str]:
    """Validate data-only candidate bytes; never import or execute this test."""
    change = EXPECTED_RECORD["testChange"]
    if not isinstance(before, bytes) or hashlib.sha256(before).hexdigest() != change["beforeSha256"]:
        return ["fixture baseline must match the pinned original bytes"]
    if not isinstance(after, bytes):
        return ["fixture candidate must be bytes"]
    old = change["beforeHelper"].encode("utf-8")
    new = change["afterHelper"].encode("utf-8")
    if before.count(old) != 1:
        return ["original helper must occur exactly once"]
    prefix, suffix = before.split(old)
    if (hashlib.sha256(prefix).hexdigest() != change["prefixSha256"]
            or hashlib.sha256(suffix).hexdigest() != change["suffixSha256"]):
        return ["fixture prefix/suffix pins differ"]
    if after != prefix + new + suffix:
        return ["only the exact required input-copy helper replacement is authorized"]
    return []


def validate_model_fixture_scope(packets: Any, record: Any, snapshots: Any) -> list[str]:
    errors: list[str] = []
    if not same(record, EXPECTED_RECORD):
        errors.append("model fixture amendment evidence or scope changed")
    if not isinstance(packets, dict):
        return [*errors, "model fixture authority requires a packet mapping"]
    if len(packets) != 194:
        errors.append("current catalog requires exactly 194 packets; fixture publication remains 122")
    if not same(packets.get("MET-REPAIR-005"), EXPECTED_META):
        errors.append("MET-REPAIR-005 whole-packet scope changed")
    if not same(packets.get("CON-MODEL-001"), amend_inventory_packet(amend_model_packet(EXPECTED_BEFORE))):
        errors.append("CON-MODEL-001 must retain every original member plus the exact additive delta")
    if not isinstance(snapshots, dict):
        return [*errors, "pinned input byte mapping required"]
    pins = {**EXPECTED_RECORD["protectedFiles"], **{
        f"task-packets/{packet_id}.yaml": digest
        for packet_id, digest in EXPECTED_RECORD["packetDigests"].items()
    }}
    if set(snapshots) != set(pins):
        errors.append("exact pinned input inventory required")
    for path, digest in pins.items():
        raw = snapshots.get(path)
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != digest:
            errors.append("missing or changed pinned input: " + path)
    return errors


def load_scope_inputs(root: Path) -> dict[str, bytes]:
    paths = [*EXPECTED_RECORD["protectedFiles"], *(
        f"task-packets/{packet_id}.yaml" for packet_id in EXPECTED_RECORD["packetDigests"]
    )]
    snapshots = {}
    for path in paths:
        # The consumed MET-REPAIR-005 packet binding is immutable historical data.
        # Current successor bytes are independently pinned by MET-REPAIR-006.
        physical_path = (
            "architecture/model-api-inventory-inputs/CON-MODEL-001.before.yaml"
            if path == "task-packets/CON-MODEL-001.yaml" else path
        )
        source = root / physical_path
        if source.is_symlink() or not source.is_file() or source.resolve() != root / physical_path:
            raise ValueError("pinned input must be a regular non-linked file: " + path)
        snapshots[path] = source.read_bytes()
    return snapshots


def main() -> int:
    try:
        packets = {p.stem: safe_yaml_load(p.read_text(encoding="utf-8"))
                   for p in sorted((ROOT / "task-packets").glob("*.yaml"))}
        record = json.loads((ROOT / "architecture/model-fixture-scope-amendment.json").read_text())
        snapshots = load_scope_inputs(ROOT)
        errors = validate_model_fixture_scope(packets, record, snapshots)
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        print("Model fixture scope unavailable: " + type(exc).__name__)
        return 1
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Model fixture authority valid: 194 packets; historical 122-packet helper grant unchanged; product/native acceptance unproven.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
