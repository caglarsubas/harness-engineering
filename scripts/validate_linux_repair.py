#!/usr/bin/env python3
"""Closed R1-R4 authority amendment. Never reads a product/warm checkout."""
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
    from validate_linux_test_ownership import PACKET_DIGESTS as TEST_OWNERSHIP_DIGESTS
except ModuleNotFoundError:
    from scripts.validate_linux_test_ownership import PACKET_DIGESTS as TEST_OWNERSHIP_DIGESTS

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_AMENDMENT = json.loads(r'''{"schemaVersion":"harness.planeon.ai/linux-readiness-amendment/v1","authorityPacket":"MET-REPAIR-003","approvalDate":"2026-09-06","historicalAuthority":"MET-LINUX-001","historicalPolicySha256":"2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762","historicalPacketCount":118,"currentPacketCount":120,"historicalCampaignPacketSha256":"d4ef0f721365240935b7b09a7f2cf4b0e6276c3e4f4f527113b0ab67e47ebdb7","packetDigests":{"MET-REPAIR-003":"6f07a6fe38f305ffc226999b19fedb5ec4082069c8d14dede36bd001e550abf1","CONF-FIX-001":"b02d7c6f2872c61fbde5be10451ac8de08e8336ee032e85b468e40dfaf8790ac","CONF-LINUX-001":"818c9bbe5c900f53201a4e34c65b5806edfe908f41e820af9d73575c68d5b704"},"baseline":{"repository":"mas-harness-conformance-labs","commit":"30877d289d389b29d3da9eb9a3c083c9ebc33382","pullRequest":3,"reviewEvidence":"SOURCE_INSPECTION_ONLY","runtimeReproduction":"NOT_RUN","files":{"schemas/v1alpha1/control-result.schema.json":"8dd30591c96d6d023d706336ceae630a838182dd0efa3e08e11e314f4594427b","src/harness_conformance/models.py":"f94ba09d491ce716875f259d81d17f38c1b7786d45db1ad700eaf9a0c7cf14a4","ci/verify-offline.sh":"3800262cd8a9386d94edc0a0350faa3796f0407298c33079badd2f90943e8ef4","ci/run_packet.py":"544ac42fc892f376b1f5b9ddafbb28e94230cfa61834a5fce89acef8d8d8b098","ci/network_canary.py":"eeaa428113c0a7a783f961c2bb0e789c26a9f983291abbdedf27b8442b2a46ad","ci/verify-live-campaign.py":"7b51484ee0f38bbfa4683be61acf8e2173bd7aee727e96443ab6ddfbc3106fb4","tests/alpha1/test_alpha1.py":"b528290f311a5e41e2b163028bb5212a022d15319a7a9fb218fd7e272480e9c7","tests/parity/test_packet_runner.py":"376766bae95b37ceef15a50377bf1ca72f093c6aaf28b020d598e6deecff7255"},"absentPaths":["tests/meta/__init__.py","tests/parity/__init__.py","tests/platform/__init__.py","ci/run_packet_argv.py"],"immutableFiles":{"Makefile":"bb652db371113bab5d9d8924f0b10b1f85793c0cc84178d447ab1095f4e7b981","ci/run_make_target.py":"0a0f5c2d6305a1772848ba2e58b8c3d17321de3fe5fdc99377515e09c1138389","toolchain.lock":"40a0cbb9fc244a8484b22494b6bfa070fbc76aec0edd86ab690026f6a8027bfc"}},"findings":[{"id":"R1","owner":"CONF-LINUX-001","status":"WAITING_IMPLEMENTATION","change":"APPEND_LINUX_READINESS_ONLY_TO_HANDLERS_AND_RESULT_ENUM"},{"id":"R2","owner":"CONF-FIX-001","status":"WAITING_IMPLEMENTATION","change":"EXPLICIT_SUITE_DISCOVERY_AND_NONZERO_INVENTORY_GUARD","consumer":"CONF-LINUX-001"},{"id":"R3","owner":"CONF-FIX-001","status":"WAITING_IMPLEMENTATION","change":"OS_BOUND_BACKEND_TRANSPORT_BRIDGE_STRICT_CANARY_AND_CHILD_ALLOWLIST"},{"id":"R4","owner":"CONF-FIX-001","status":"WAITING_IMPLEMENTATION","change":"RETIRE_UNAUTHENTICATED_LIVE_ADAPTER_NO_REPLACEMENT_AUTHORITY"}],"runnerCandidate":{"packet":"MET-LINUX-002","mergeCommit":"c37f2b72e7449f787140553beea39ebe871f35da","pullRequest":95,"requiredCiRun":34028811315,"artifactSha256":"9065b78500e6a86a4dc62e84430bc02832c131a50995754f5092b622885f2e25","exactMainLogSha256":"526ebaf3ceb2594d97af8a4741901d87a31cd81c4eca0c5823a2b598225e7bda","evidence":"SOURCE_PACKAGE_ONLY","nativeLinuxAcceptance":false},"evidenceBoundary":"AUTHORITY_ONLY_NOT_PRODUCT_FIX_NATIVE_LINUX_OR_LIVE_ACCEPTANCE","gate":{"runtimeCodingRequires":"FRESH_NATIVE_LINUX_AMD64_PASS","unavailableUnblocksRuntimeCoding":false,"nativeLinuxStatus":"NOT_RUN_ENV_UNAVAILABLE","liveBackendStatus":"NOT_RUN_ENV_UNAVAILABLE","modelEffortTransition":"NOT_DUE"}}''')
PACKET_DIGESTS = EXPECTED_AMENDMENT["packetDigests"]
CURRENT_PACKET_DIGESTS = {**PACKET_DIGESTS, **TEST_OWNERSHIP_DIGESTS}
EXTRA_PATHS = ["src/harness_conformance/models.py","schemas/v1alpha1/control-result.schema.json"]
EXTRA_DELIVERABLES = json.loads(r'''["MET-REPAIR-003 R1: src/harness_conformance/models.py may only append LINUX_READINESS to HANDLERS; every other definition and old value/order stays byte-identical. schemas/v1alpha1/control-result.schema.json may only append that value to properties.handler.enum; every other schema member stays unchanged.","MET-REPAIR-003 R2: use the complete explicit seven-command suite/campaign/evidence sequence, not unittest discovery at tests root. Preserve legacy imports and assert nonzero collection plus inventory closure of meta, parity, alpha1, runner-boundary and linux-baseline suites; no omission, silent empty run or predecessor suppression.","MET-REPAIR-003 R3-R4: require merged CONF-FIX-001 and its exact-main source evidence first. The retired inner adapter may not be re-enabled, bypassed, imported as authority or replaced by a caller-supplied verified flag; the missing external endpoint-isolation/proxy backend remains NOT_RUN_ENV_UNAVAILABLE.","MET-REPAIR-003 acceptance: unchanged legacy inputs must produce byte-identical reports/evidence; Python handler registry, campaign schema and control-result schema admit exactly the old handlers plus LINUX_READINESS. Test every excluded edit and all three registry/schema views."]''')
EXTRA_EVIDENCE = "The approved MET-REPAIR-003 amendment fixes path/test-discovery authority only; CONF-FIX-001 closes source runner defects, not native Linux or usable live execution. All original Linux mandatory-case, freshness, signature, zero-bill and independent-capacity gates remain unchanged."
CAMPAIGN_COMMANDS = json.loads(r'''[["python3","-m","unittest","discover","-s","tests/meta","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/parity","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/alpha1","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/fixes/runner_boundary","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/platform/linux_baseline","-p","test_*.py"],["make","campaign","CAMPAIGN=linux-baseline"],["make","evidence-verify","CAMPAIGN=linux-baseline"]]''')


def same(left: Any, right: Any) -> bool:
    try:
        return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return False


def packet_bytes(packet: Any) -> bytes:
    """Canonical inline-YAML projection; preserve the reviewed member order.

    This compares the whole closed packet, not only selected authority fields.
    All three amended packets use JSON-inline arrays/objects and bare identity
    scalars. Strict JSON keeps booleans distinct from integer lookalikes.
    """
    if not isinstance(packet, dict):
        raise ValueError("packet must be a mapping")
    scalar_fields = {"id", "repository", "branch", "warmSourceAccess"}
    lines = []
    for key, value in packet.items():
        if not isinstance(key, str):
            raise ValueError("non-string field")
        if key in scalar_fields:
            if not isinstance(value, str):
                raise ValueError("identity must be a string")
            rendered = value
        else:
            rendered = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        lines.append(key + ": " + rendered)
    return ("\n".join(lines) + "\n").encode("utf-8")


def amend_linux_packet(historical: dict[str, Any]) -> dict[str, Any]:
    """Apply only the approved delta to the immutable 118-packet expectation."""
    value = deepcopy(historical)
    value["predecessors"].append("CONF-FIX-001")
    value["allowedPaths"].extend(EXTRA_PATHS)
    value["offlineAcceptanceCommands"] = deepcopy(CAMPAIGN_COMMANDS)
    value["liveCampaignExecution"]["commands"] = deepcopy(CAMPAIGN_COMMANDS)
    value["deliverables"].extend(EXTRA_DELIVERABLES)
    value["expectedEvidence"].append(EXTRA_EVIDENCE)
    return value


def validate_linux_repair(packets: Any, amendment: Any, historical_policy_bytes: bytes) -> list[str]:
    errors = []
    if not same(amendment, EXPECTED_AMENDMENT):
        errors.append("Linux repair amendment changed or overstates implementation evidence")
    if not isinstance(historical_policy_bytes, bytes) or hashlib.sha256(historical_policy_bytes).hexdigest() != EXPECTED_AMENDMENT["historicalPolicySha256"]:
        errors.append("original 118-packet Linux policy must remain byte-identical")
    if not isinstance(packets, dict):
        return [*errors, "Linux repair requires a packet mapping"]
    if len(packets) != 194:
        errors.append("Current catalog requires exactly 194 packets; consumed amendment remains 120")
    for packet_id, expected_digest in CURRENT_PACKET_DIGESTS.items():
        try:
            actual = hashlib.sha256(packet_bytes(packets.get(packet_id))).hexdigest()
        except (TypeError, ValueError, UnicodeError):
            actual = None
        if actual != expected_digest:
            errors.append(packet_id + " closed approved packet scope changed")
    return errors


def main() -> int:
    try:
        packets = {p.stem: safe_yaml_load(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "task-packets").glob("*.yaml"))}
        amendment = json.loads((ROOT / "architecture/linux-readiness-amendment.json").read_text())
        errors = validate_linux_repair(packets, amendment, (ROOT / "architecture/linux-readiness.json").read_bytes())
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        print("Linux repair authority unavailable: " + type(exc).__name__)
        return 1
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Linux repair authority valid: 194 packets; 120-packet record preserved; native Linux remains unproven.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
