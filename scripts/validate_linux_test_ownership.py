#!/usr/bin/env python3
"""Closed assertion-only amendment; never reads or executes product/warm code."""
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

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_RECORD = json.loads(r'''{"schemaVersion":"harness.planeon.ai/linux-test-ownership-amendment/v1","authorityPacket":"MET-REPAIR-004","approvalDate":"2026-09-07","historicalPacketCount":120,"currentPacketCount":121,"historicalAmendmentSha256":"3a59552dbadd6a9e7579038523787926b921c35a3c71d036d2705b1c95b804a6","historicalLinuxPacketSha256":"818c9bbe5c900f53201a4e34c65b5806edfe908f41e820af9d73575c68d5b704","packetDigests":{"MET-REPAIR-004":"3217293d977e25f0c6e7f6e6bb0134c27d840fd8769dc285494ecc7f351f6d94","CONF-LINUX-001":"22f00544680f90a90b03420632bebf192a8c687549b519770fca5f98dd5fd6c9"},"sourceBaseline":{"repository":"mas-harness-conformance-labs","commit":"07453d3e6313c836426545c454380176bc2a2ee1","tree":"03524ab71fe8832b40648bd29222cd9c438d5861","pullRequest":4,"requiredCiRun":34052209212,"requiredCiJob":101537713213,"exactMainExecution":"LOCAL_SIGNED_HOST_OFFLINE_REPLAY","exactMainLogSha256":"c793655198e8e0c3dfa9f5a596618b25a579e5dffc74549bd72473847c7ec889","sourceTestsPassed":83,"sourceTestsSkipped":0,"linuxAcceptance":false,"liveAcceptance":false},"testChange":{"path":"tests/meta/test_canonical_schema.py","beforeSha256":"4ff004974fc75c6ea15010eedb9d1596c002330b33596c64a888622f0bd02c8f","method":"CanonicalSchemaTests.test_closed_vocabularies","beforeStatement":"self.assertEqual(len(HANDLERS), 5)","afterStatement":"self.assertEqual(HANDLERS, (\"STATIC_ASSERTION\", \"SCHEMA_ASSERTION\", \"LIFECYCLE_ASSERTION\", \"EVENT_ASSERTION\", \"ENVIRONMENT_CAPABILITY\", \"LINUX_READINESS\"))","otherBytes":"UNCHANGED","otherAssertions":"UNCHANGED","additionalPaths":["tests/meta/test_canonical_schema.py"],"negativeCasesOwner":"tests/platform/linux_baseline/","diagnosis":"SOURCE_INSPECTION_ONLY","productImplementation":"NOT_RUN"},"preserved":{"handlerAddition":"LINUX_READINESS_ONLY","offlineAndLiveCommands":7,"predecessorTests":83,"inventoryHelper":"UNCHANGED","runtimeCodingRequires":"FRESH_NATIVE_LINUX_AMD64_PASS","nativeLinuxStatus":"NOT_RUN_ENV_UNAVAILABLE","liveBackendStatus":"NOT_RUN_ENV_UNAVAILABLE","billingBoundary":"UNCHANGED","modelEffortTransition":"NOT_DUE"},"evidenceBoundary":"AUTHORITY_ONLY_NOT_PRODUCT_TEST_CHANGE_NATIVE_LINUX_OR_TENANT_ACCEPTANCE"}''')
PACKET_DIGESTS = EXPECTED_RECORD["packetDigests"]
EXTRA_CONTRACTS = json.loads(r'''["MET-REPAIR-004: consume merged CONF-FIX-001 main 07453d3e6313c836426545c454380176bc2a2ee1, required PR run 34052209212 and independent signed local exact-main log c793655198e8e0c3dfa9f5a596618b25a579e5dffc74549bd72473847c7ec889. Its 83 passing source tests do not qualify native Linux or grant live execution.","MET-REPAIR-004: the sole additional test path is tests/meta/test_canonical_schema.py at SHA-256 4ff004974fc75c6ea15010eedb9d1596c002330b33596c64a888622f0bd02c8f. The only allowed edit replaces self.assertEqual(len(HANDLERS), 5) inside CanonicalSchemaTests.test_closed_vocabularies with equality to the exact ordered tuple STATIC_ASSERTION, SCHEMA_ASSERTION, LIFECYCLE_ASSERTION, EVENT_ASSERTION, ENVIRONMENT_CAPABILITY, LINUX_READINESS; preserve every other byte, assertion, method and vector."]''')
EXTRA_DELIVERABLES = json.loads(r'''["MET-REPAIR-004: implement only the exact handler-tuple assertion replacement; no length-only, subset, membership, permissive range, skip or xfail substitute. Keep all original five handler names and order, RESULT_STATES and EVIDENCE_AXES assertions unchanged.","MET-REPAIR-004: add negative tests in tests/platform/linux_baseline/ proving rejected extra, missing, duplicate and reordered handlers and equality across Python HANDLERS, campaign schema and control-result schema. Reuse the unchanged runner-boundary inventory helper from the Linux-owned suite to account for all five declared roots and preserve all 83 predecessor test IDs; do not edit tests/fixes/runner_boundary/ or legacy imports.","MET-REPAIR-004: compare the corrected legacy test against the pinned original by the sole assertion replacement. Keep every other product baseline file outside the declared Linux packet scope byte-identical; the retired inner live adapter and corrected offline transport/canary remain immutable to this packet."]''')
EXTRA_EVIDENCE = "MET-REPAIR-004 authorizes one assertion-only legacy test repair and locks completed CONF-FIX-001 source evidence. It does not add handlers beyond LINUX_READINESS, relax runtime/native/signature/capacity/billing gates, rewrite historical publications, or claim Linux, live, phase or tenant acceptance."


def amend_linux_test_packet(previous: dict[str, Any]) -> dict[str, Any]:
    """Apply exactly one additive grant; never rewrite a consumed snapshot."""
    value = deepcopy(previous)
    value["predecessors"].append("MET-REPAIR-004")
    value["allowedPaths"].append("tests/meta/test_canonical_schema.py")
    value["contracts"].extend(EXTRA_CONTRACTS)
    value["deliverables"].extend(EXTRA_DELIVERABLES)
    value["expectedEvidence"].append(EXTRA_EVIDENCE)
    return value


def packet_digest(packet: Any) -> str | None:
    # Use the historical byte projection; import lazily to avoid module cycles.
    try:
        from validate_linux_repair import packet_bytes
    except ModuleNotFoundError:
        from scripts.validate_linux_repair import packet_bytes
    try:
        return hashlib.sha256(packet_bytes(packet)).hexdigest()
    except (TypeError, ValueError, UnicodeError):
        return None


def validate_linux_test_ownership(packets: Any, record: Any, historical_bytes: bytes) -> list[str]:
    errors = []
    try:
        same = json.dumps(record, sort_keys=True, allow_nan=False) == json.dumps(EXPECTED_RECORD, sort_keys=True)
    except (ValueError, TypeError):
        same = False
    if not same:
        errors.append("Linux assertion ownership record changed or claims unverified evidence")
    if not isinstance(historical_bytes, bytes) or hashlib.sha256(historical_bytes).hexdigest() != EXPECTED_RECORD["historicalAmendmentSha256"]:
        errors.append("consumed 120-packet amendment must remain byte-identical")
    if not isinstance(packets, dict):
        return [*errors, "Linux assertion ownership requires a packet mapping"]
    if len(packets) != 194:
        errors.append("Current catalog requires exactly 194 packets; Linux ownership record remains 121")
    for packet_id, expected in PACKET_DIGESTS.items():
        if packet_digest(packets.get(packet_id)) != expected:
            errors.append(packet_id + " exact assertion-only authority changed")
    return errors


def main() -> int:
    try:
        packets = {p.stem: safe_yaml_load(p.read_text()) for p in sorted((ROOT / "task-packets").glob("*.yaml"))}
        record = json.loads((ROOT / "architecture/linux-test-ownership-amendment.json").read_text())
        old = (ROOT / "architecture/linux-readiness-amendment.json").read_bytes()
        errors = validate_linux_test_ownership(packets, record, old)
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        print("Linux test ownership authority unavailable: " + type(exc).__name__)
        return 1
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Linux test ownership valid: 194 packets; historical one-assertion grant preserved; native/live acceptance unproven.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
