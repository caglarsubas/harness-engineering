#!/usr/bin/env python3
"""Validate model prerequisite authority, never source contents or live evidence."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

try:
    from safe_yaml import safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import safe_load as safe_yaml_load


ROOT = Path(__file__).resolve().parents[1]
MODEL_SOURCE = {
    "repository": "git@github.com:caglarsubas/llm_inference_engine.git",
    "commit": "6815c21cb10a4d7dc0b4804f6bb223afb4321e97",
    "path": "contracts/prometa-model-usage-v2.schema.json",
    "gitObject": "c3ac327e2989ffbbc2452209e2a32f76be911534",
}
EXPECTED_BOUNDARY = {
    "schemaVersion": "harness.planeon.ai/model-evidence-boundary/v1",
    "authorityPacket": "MET-A2-001",
    "milestone": "ALPHA_2",
    "observationPacket": "MET-OBS-MODEL-001",
    "contractPacket": "CON-MODEL-001",
    "implementationPacket": "MODEL-001",
    "source": MODEL_SOURCE,
    "evidenceKinds": {
        "structuralObservation": "DISTILLED_SCHEMA_FACTS_ONLY",
        "originalSourceTests": "NOT_RUN_ENV_UNAVAILABLE",
        "originalSourceBehavioralParity": "NOT_ESTABLISHED",
        "destinationVectors": "INDEPENDENT_CONTRACT_VECTOR",
    },
    "implementationGate": [
        "MERGED_OBSERVATION_WITH_PASS_VALIDATION",
        "MERGED_MODEL_CONTRACT_RELEASE_WITH_PASS_OFFLINE_EVIDENCE",
        "DIGEST_PINNED_CONTRACT_AND_VECTOR_SNAPSHOT",
        "EXACT_PACKET_OFFLINE_RUNNER_AUTHORITY",
    ],
    "sourceExecution": "DENIED",
    "copyAuthority": "NONE",
    "originalBaselineSubstitution": "FORBIDDEN",
    "releaseGate": "NO_ORIGINAL_SOURCE_EQUIVALENCE_CLAIM_WITHOUT_SEPARATELY_AUTHORIZED_BEHAVIORAL_EVIDENCE",
    "liveEvidence": "NOT_RUN_ENV_UNAVAILABLE",
}
OBSERVATION_PATHS = [
    "architecture/observations/model-usage-v2.json",
    "scripts/validate_model_usage_observation.py",
    "tests/test_model_usage_observation.py",
    "docs/alpha-2/model-usage-observation.md",
]
CONTRACT_PATHS = [
    "openapi/model.openapi.json", "schemas/v1alpha1/model/", "tests/model_api/",
    "tests/fixtures/model/", "contracts/model-inputs.lock.json",
    "contracts/model-inputs/", "contracts/release-manifest.json", "generated/",
    "scripts/generate_contracts.py", "scripts/check_generated.py",
    "docs/model-api.md", "docs/model-usage-compatibility.md",
    "tests/golden/test_generated_contracts.py",
    "tests/model/test_lifecycle_contracts.py",
]


def validate_model_authority(packets: dict[str, Any], boundary: Any) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    require(boundary == EXPECTED_BOUNDARY, "model evidence boundary changed or overstates source/live evidence")
    expected_predecessors = {
        "MET-A2-001": ["MET-P0-002", "CONF-A1-001"],
        "MET-OBS-MODEL-001": ["MET-A2-001"],
        "CON-MODEL-001": ["CON-007", "MET-OBS-MODEL-001", "CON-FIX-001", "CTRL-FIX-003", "MET-REPAIR-005", "MET-REPAIR-006"],
        "MODEL-001": ["SDK-003", "CON-006", "MET-002", "MET-003", "CON-MODEL-001"],
    }
    for packet_id, expected in expected_predecessors.items():
        packet = packets.get(packet_id, {})
        require(packet.get("predecessors") == expected, f"{packet_id} model prerequisite chain changed")
        if packet_id != "MET-OBS-MODEL-001":
            require(packet.get("warmSourceAccess") == "PROHIBITED_DURING_IMPLEMENTATION"
                    and "referenceObservationExecution" not in packet,
                    f"{packet_id} must not observe warm sources")
    observer = packets.get("MET-OBS-MODEL-001", {})
    require(observer.get("repository") == "Harness-Engineering"
            and observer.get("allowedPaths") == OBSERVATION_PATHS,
            "model observation repository or allowed paths widened")
    observation = observer.get("referenceObservationExecution", {})
    for key, value in {
        "repository": MODEL_SOURCE["repository"], "commit": MODEL_SOURCE["commit"],
        "sourcePaths": [MODEL_SOURCE["path"]], "sourceCodeExecution": "DENIED",
        "outputPath": OBSERVATION_PATHS[0], "copyAuthority": "NONE",
        "implementationIdentityAccess": "DENIED", "ciEvidenceUse": "FORBIDDEN",
    }.items():
        require(observation.get(key) == value, f"model observation {key} changed")
    sources = observer.get("sourceReuse", [])
    require(len(sources) == 1 and sources[0].get("repository") == MODEL_SOURCE["repository"]
            and sources[0].get("commit") == MODEL_SOURCE["commit"]
            and sources[0].get("paths") == [MODEL_SOURCE["path"]]
            and sources[0].get("reuseMode") == "REFERENCE_ONLY",
            "model observation must reference exactly one pending schema blob")
    contract = packets.get("CON-MODEL-001", {})
    require(contract.get("repository") == "mas-harness-contracts"
            and contract.get("allowedPaths") == CONTRACT_PATHS
            and contract.get("sourceReuse") == [],
            "model contract ownership or clean-room boundary changed")
    for packet_id in ("MODEL-001", "CON-MODEL-001"):
        packet = packets.get(packet_id, {})
        evidence = " ".join(packet.get("expectedEvidence", []))
        require("NOT_RUN_ENV_UNAVAILABLE" in evidence and "NOT_ESTABLISHED" in evidence,
                f"{packet_id} must retain unavailable original baseline and unestablished parity")
        require("CON-MODEL-001" in " ".join(packet.get("contracts", []))
                if packet_id == "MODEL-001" else True,
                "MODEL-001 must consume the exact model contract release")
    return errors


def validate_checkpoint(root: Path, packets: dict[str, Any]) -> list[str]:
    text = (root / "docs/DEVELOPMENT_STATUS.md").read_text(encoding="utf-8")
    errors: list[str] = []
    ids = set(re.findall(r"`([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)`", text))
    # The failed 006 and 007 candidates remain in the status ledger, not the
    # published packet catalog. The current gate validator pins both records.
    if ids - (set(packets) | {"MET-UNIFY-006", "MET-UNIFY-007"}):
        errors.append("status checkpoint names unknown packet IDs")
    for packet_id in ("MET-A2-001", "MET-OBS-MODEL-001", "CON-MODEL-001", "MODEL-001"):
        if not any(line.startswith("| Alpha 2 |") and f"`{packet_id}`" in line
                   for line in text.splitlines()):
            errors.append(f"status checkpoint lacks Alpha-2 row for {packet_id}")
    if "not a live dashboard or certification ledger" not in text:
        errors.append("status checkpoint must declare its snapshot evidence boundary")
    return errors


def main() -> int:
    try:
        packets = {path.stem: safe_yaml_load(path.read_text(encoding="utf-8"))
                   for path in (ROOT / "task-packets").glob("*.yaml")}
        boundary = json.loads((ROOT / "architecture/model-evidence-boundary.json").read_text(encoding="utf-8"))
        errors = validate_model_authority(packets, boundary) + validate_checkpoint(ROOT, packets)
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        print(f"Alpha-2 authority validation failed: {exc}")
        return 1
    for error in errors:
        print(f"ERROR: {error}")
    if not errors:
        print("Alpha-2 model prerequisite authority passed; no product, source-test or live acceptance claimed")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
