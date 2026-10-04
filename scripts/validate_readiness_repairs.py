#!/usr/bin/env python3
"""Validate corrective authority; never claim that a product repair executed."""

from __future__ import annotations

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
UV_PYTHON = ["uv", "run", "--offline", "--frozen", "--no-sync", "python"]
CONTRACT_COMMANDS = [
    [*UV_PYTHON, "scripts/generate_contracts.py", "--check"],
    [*UV_PYTHON, "scripts/check_generated.py"],
    [*UV_PYTHON, "-m", "pytest", "tests"],
]
REPAIR_PREDECESSORS = {
    "MET-REPAIR-001": ["MET-OBS-MODEL-001", "CTRL-FIX-002"],
    "CON-FIX-001": ["CON-007", "MET-REPAIR-001", "MET-REPAIR-002"],
    "CTRL-FIX-003": ["CTRL-FIX-002", "CON-FIX-001"],
    "CTRL-INTEGRATE-001": ["CTRL-FIX-003", "CONF-LINUX-001"],
}
PRODUCT_PATHS = {
    "CON-FIX-001": [
        "tests/golden/test_generated_contracts.py", "tests/runtime/test_runtime_contracts.py",
        "tests/model/test_aggregation_interoperability.py",
        "tests/fixtures/status/aggregation-interoperability.json", "contracts/regression-inputs/",
        "scripts/generate_contracts.py", "generated/", "contracts/release-manifest.json",
        "docs/regression-policy.md",
        "tests/test_command_registry.py", "tests/contract/test_taxonomy.py",
        "src/planeon_harness_contracts/state_machine.py",
    ],
    "CTRL-FIX-003": [
        "apps/control-web/src/lib/harness-status/aggregation.ts",
        "apps/control-web/src/lib/harness-status/projection-store.ts",
        "apps/control-web/src/lib/harness-status/http.ts",
        "apps/control-web/src/lib/harness-status/runtime.ts",
        "tests/harness-status/aggregation.test.ts", "tests/harness-status/projection-store.test.ts",
        "tests/harness-status/http.test.ts", "tests/harness-status/status-interoperability.test.ts",
        "contracts/status-regression/", "ci/targets/ctrl-fix-003.json", "docs/harness-overview.md",
    ],
    "CTRL-INTEGRATE-001": [
        "apps/control-web/src/lib/harness-status/", "apps/control-web/src/app/overview/",
        "apps/control-web/src/app/planes/", "apps/control-web/src/app/harnesses/",
        "apps/control-web/src/app/organizations/", "apps/control-web/src/app/api/v1alpha1/overview/",
        "apps/control-web/src/app/api/v1alpha1/planes/", "apps/control-web/src/app/api/v1alpha1/harnesses/",
        "apps/control-web/src/app/api/v1alpha1/organizations/", "packages/db/status-projections/",
        "packages/db/migrations/harness-status/002_durable_adapters.sql", "contracts/status-integration/",
        "tests/harness-status/", "e2e/harness-status-production.spec.ts",
        "ci/targets/ctrl-integrate-001.json", "docs/harness-overview.md",
        "docs/security/status-production-integration.md",
    ],
}
PRODUCT_COMMANDS = {
    "CON-FIX-001": CONTRACT_COMMANDS,
    "CTRL-FIX-003": [["make", "ctrl-fix-003-regression"], ["make", "overview-e2e"], ["make", "zero-bill"]],
    "CTRL-INTEGRATE-001": [["make", "status-integration-regression"], ["make", "status-integration-e2e"], ["make", "status-integration-postgres"], ["make", "zero-bill"]],
}
FINDING_OWNERS = {
    "R01": ("FOUNDATION_CORRECTION", "CON-FIX-001"),
    "R02": ("ALPHA_2_ENTRY", "CON-FIX-001"),
    "R03": ("ALPHA_1_CORRECTION", "CTRL-FIX-003"),
    "R04": ("ALPHA_1_CORRECTION", "CTRL-FIX-003"),
    "R05": ("ALPHA_1_CORRECTION", "CTRL-FIX-003"),
    "R06": ("ALPHA_1_INTEGRATION", "CTRL-INTEGRATE-001"),
}


def validate_repair_authority(packets: dict[str, Any], record: Any) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    if not isinstance(record, dict):
        return ["repair authority must be an object"]
    constants = {
        "schemaVersion": "harness.planeon.ai/readiness-repairs/v1",
        "authorityPacket": "MET-REPAIR-001", "reviewDate": "2026-09-05",
        "reviewMethod": "READ_ONLY_SOURCE_ANALYSIS",
        "historicalPhaseZeroPacketCount": 107,
        "historicalAlphaTwoPublicationPacketCount": 110, "currentPacketCount": 114,
        "modelCodingPrerequisites": ["CON-FIX-001", "CTRL-FIX-003"],
        "productionIntegrationOwner": "CTRL-INTEGRATE-001",
        "liveCertificationOwner": "CONF-A2-001",
        "evidenceBoundary": "AUTHORITY_ONLY_NOT_PRODUCT_FIX_OR_LIVE_ACCEPTANCE",
        "productionGate": "FRESH_INSTALLED_FOUNDATION_AND_AUTHENTICATED_DURABLE_OVERVIEW_EVIDENCE_REQUIRED",
    }
    require(set(record) == {*constants, "findings"}, "repair authority fields changed")
    for field, expected in constants.items():
        require(record.get(field) == expected, f"repair authority {field} changed")
    findings = record.get("findings")
    if not isinstance(findings, list) or len(findings) != len(FINDING_OWNERS):
        errors.append("repair authority must contain exactly six findings")
    else:
        for finding, (finding_id, (phase, owner)) in zip(findings, FINDING_OWNERS.items()):
            if not isinstance(finding, dict):
                errors.append(f"{finding_id} must be an object")
                continue
            require(set(finding) == {"id", "phase", "owner", "description", "status"}, f"{finding_id} fields changed")
            require((finding.get("id"), finding.get("phase"), finding.get("owner")) == (finding_id, phase, owner), f"{finding_id} ownership changed")
            require(finding.get("status") == "WAITING_IMPLEMENTATION", f"{finding_id} publication cannot claim a product fix")
            require(isinstance(finding.get("description"), str) and len(finding["description"]) >= 20, f"{finding_id} needs a concrete description")
    for packet_id, predecessors in REPAIR_PREDECESSORS.items():
        packet = packets.get(packet_id, {})
        require(packet.get("predecessors") == predecessors, f"{packet_id} corrective predecessors changed")
        require(packet.get("warmSourceAccess") == "PROHIBITED_DURING_IMPLEMENTATION"
                and packet.get("sourceReuse") == [] and "referenceObservationExecution" not in packet
                and "liveCampaignExecution" not in packet, f"{packet_id} cannot gain source or live authority")
        repository = ("Harness-Engineering" if packet_id == "MET-REPAIR-001" else
                      "mas-harness-contracts" if packet_id == "CON-FIX-001" else "mas-harness-control-plane")
        require(packet.get("repository") == repository, f"{packet_id} repository changed")
        if packet_id in PRODUCT_PATHS:
            require(packet.get("allowedPaths") == PRODUCT_PATHS[packet_id], f"{packet_id} path boundary changed")
            require(packet.get("offlineAcceptanceCommands") == PRODUCT_COMMANDS[packet_id], f"{packet_id} regression commands changed")
            require(packet.get("prefetchCommands") == ([] if packet_id == "CON-FIX-001" else [["make", "prefetch"]]), f"{packet_id} prefetch boundary changed")
    model = packets.get("CON-MODEL-001", {})
    require(model.get("predecessors") == ["CON-007", "MET-OBS-MODEL-001", "CON-FIX-001", "CTRL-FIX-003", "MET-REPAIR-005", "MET-REPAIR-006"], "model coding must wait for both product corrections and the fixture amendment")
    require(model.get("offlineAcceptanceCommands") == CONTRACT_COMMANDS, "model contract acceptance must run the entire contracts suite")
    live = packets.get("CONF-A2-001", {})
    require(live.get("predecessors") == ["CONF-A1-001", "KN-RET-001", "MODEL-003", "RUN-GW-002", "EXEC-PROT-001", "EXEC-ORCH-001", "CTRL-INTEGRATE-001"], "Alpha-2 certification must retain foundation and production integration gates")
    require("Fresh CONF-A1-001 installed-foundation evidence and production-overview browser/API/PostgreSQL evidence are required for live certification; missing target, signed authority or durable integration is NOT_RUN_ENV_UNAVAILABLE, never PASS." in live.get("expectedEvidence", []), "live certification must not substitute source or fixture evidence")
    return errors


AMENDMENT_PATHS = [
    "task-packets/MET-REPAIR-002.yaml",
    "task-packets/CON-FIX-001.yaml",
    "task-packets/README.md",
    "architecture/readiness-repair-amendment.json",
    "scripts/validate_readiness.py",
    "scripts/validate_reuse.py",
    "scripts/validate_readiness_repairs.py",
    "tests/test_task_packets.py",
    "tests/test_reuse.py",
    "tests/test_alpha2_readiness.py",
    "tests/test_readiness_repairs.py",
    "docs/DEVELOPMENT_STATUS.md",
    "docs/MASTER_DEVELOPMENT_PLAN.md",
    "docs/READINESS_INDEX.md",
    "docs/adr/0004-sol-high-packet-boundary.md",
    "docs/alpha-2/READINESS_REPAIRS.md",
    "docs/repositories/00-harness-engineering.md",
    "docs/repositories/01-mas-harness-contracts.md"
]
AMENDMENT_COMMANDS = [
    [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/validate_readiness.py"
    ],
    [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/validate_reuse.py"
    ],
    [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/validate_alpha2_readiness.py"
    ],
    [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/validate_readiness_repairs.py"
    ],
    [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "-m",
        "pytest",
        "tests",
        "ci/test_offline_runner.py",
        "ci/test_warm_snapshot.py"
    ],
    [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/zero_bill_scan.py",
        "."
    ]
]
SCOPE_DELIVERABLES = [
    "Correct tests/test_command_registry.py using an explicitly empty temporary registry for the bootstrap case and a separate current full-registry integration assertion; do not substitute the fixture for the current-registry check.",
    "Correct tests/contract/test_taxonomy.py using exact CON-002 descriptors with CON-002 authority and prove later-owner descriptors are rejected under that restricted authority; retain a cumulative full-registry assertion with the exact CON-002, CON-004 and CON-006 owners.",
    "Reproduce selection BLOCKED plus installation DEGRADED with CURRENT freshness and passing evidence as an independent failing vector expecting BLOCKED under docs/status-projections.md; if confirmed, change only aggregate_status so blocked selection wins over degraded installation while REVOKED and FAILED retain higher precedence.",
    "Pin baseline state_machine.py SHA-256 c18d938bbd5f9c62f25bdb01df983f3b55a16acdd2b4e610ea7b34ffbf22353b and verify bytes outside aggregate_status remain identical, including classify_freshness and every lifecycle/enum/transition definition; record the real before/after implementation digest and the exact MODEL_IMPLEMENTATION release-entry exception.",
    "Exercise the selection-by-installation precedence matrix, all required/optional evidence states, failure/revocation/freshness precedence, waiver behavior and non-contributing selections without expected values generated from aggregate_status; no skip, xfail, deselection or runtime monkeypatch may mask a regression."
]
SCOPE_EXCLUSION = "Public schema or documented status-semantic changes; state_machine.py edits outside the blocked-selection precedence correction in aggregate_status; classify_freshness, lifecycle, enum or transition changes; command_registry.py, generic CLI or command-descriptor changes; model API implementation; dependency changes; warm-source access; product consumers; Makefile/dispatcher/PORTING edits; downloads; deployment and runtime acceptance claims."
BASELINE_REQUIREMENT = "Preserve the exact CON-007 baseline result of 181 passed and three failed tests at log SHA-256 8a918152e335c0d2c48fac7072b70bc3a69acea9caaf4c4a03e9a33d939f74ec; establish the new status regression separately and require all original plus new tests to pass without weakening command-owner admission."
EXPECTED_AMENDMENT = {
    "schemaVersion": "harness.planeon.ai/readiness-repair-amendment/v1",
    "authorityPacket": "MET-REPAIR-002",
    "amendsPacket": "CON-FIX-001",
    "approvalDate": "2026-09-05",
    "historicalRepairAuthority": "MET-REPAIR-001",
    "historicalRepairRecordSha256": "30db784918bb651cc81f26d23cb4b1d7f790ef260ef5e48a2d7ae2ae94c12a0d",
    "historicalRepairPacketCount": 114,
    "currentPacketCount": 115,
    "baseline": {
        "repository": "mas-harness-contracts",
        "commit": "2146278a95344cd2a8e22596b2f315b46edffc88",
        "execution": "LOCAL_SIGNED_HOST_OFFLINE_REPLAY",
        "packetSha256": "fc10e7d4f40c3eacab69dc7d7ef3a23fffeca6e9080392ca26fd0c9c9f2ef9c5",
        "commandsCompleted": 3,
        "generationChecks": "PASS",
        "passed": 181,
        "failed": 3,
        "skipped": 0,
        "outputSha256": "8a918152e335c0d2c48fac7072b70bc3a69acea9caaf4c4a03e9a33d939f74ec",
        "failures": [
            "tests/contract/test_taxonomy.py::TaxonomyContractTests::test_registry_and_commands_have_closed_con002_authority",
            "tests/golden/test_generated_contracts.py::test_generated_outputs_are_exact_and_check_mode_passes",
            "tests/test_command_registry.py::CommandRegistryTests::test_bootstrap_cli_has_no_registered_commands"
        ]
    },
    "addedPaths": [
        "tests/test_command_registry.py",
        "tests/contract/test_taxonomy.py",
        "src/planeon_harness_contracts/state_machine.py"
    ],
    "retainedGuards": [
        "REGISTRY_FAIL_CLOSED_UNCHANGED",
        "EMPTY_AND_CURRENT_REGISTRY_TESTS_SEPARATE",
        "RESTRICTED_OWNER_REJECTION_REQUIRED",
        "FULL_SUITE_NO_SUPPRESSION",
        "PUBLIC_WIRE_AND_COMPATIBILITY_BYTES_UNCHANGED"
    ],
    "implementationException": {
        "path": "src/planeon_harness_contracts/state_machine.py",
        "function": "aggregate_status",
        "beforeSha256": "c18d938bbd5f9c62f25bdb01df983f3b55a16acdd2b4e610ea7b34ffbf22353b",
        "change": "BLOCKED_SELECTION_PRECEDES_DEGRADED_INSTALLATION",
        "expectedState": "BLOCKED",
        "higherPrecedence": [
            "REVOKED",
            "FAILED"
        ],
        "retainedDefinitionBytes": "ALL_OUTSIDE_AGGREGATE_STATUS",
        "freshnessClassifierChange": "FORBIDDEN",
        "publishedSemanticsChange": "FORBIDDEN",
        "findingEvidence": "SOURCE_REVIEW_ONLY_NEW_VECTOR_NOT_RUN",
        "productStatus": "WAITING_IMPLEMENTATION"
    },
    "evidenceBoundary": "AUTHORITY_AMENDMENT_ONLY_NOT_PRODUCT_FIX_OR_LIVE_ACCEPTANCE"
}


def validate_repair_amendment(
    packets: dict[str, Any], amendment: Any, historical_record_bytes: bytes,
) -> list[str]:
    """Close the user-approved exception without editing the historical review."""
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    try:
        same_record = json.dumps(amendment, sort_keys=True, allow_nan=False) == json.dumps(
            EXPECTED_AMENDMENT, sort_keys=True, allow_nan=False,
        )
    except (TypeError, ValueError):
        same_record = False
    require(same_record, "repair amendment evidence or scope changed")
    require(
        hashlib.sha256(historical_record_bytes).hexdigest()
        == EXPECTED_AMENDMENT["historicalRepairRecordSha256"],
        "original repair publication was rewritten",
    )
    require(len(packets) == 194, "current catalog requires exactly 194 packets; historical amendment remains 115")
    meta = packets.get("MET-REPAIR-002", {})
    require(isinstance(meta, dict), "repair amendment packet must be an object")
    if not isinstance(meta, dict):
        return errors
    for field, expected in {
        "repository": "Harness-Engineering",
        "branch": "codex/met-repair-002-contract-regression-scope",
        "predecessors": ["MET-REPAIR-001"],
        "allowedPaths": AMENDMENT_PATHS,
        "prefetchCommands": [],
        "offlineAcceptanceCommands": AMENDMENT_COMMANDS,
        "warmSourceAccess": "PROHIBITED_DURING_IMPLEMENTATION",
        "sourceReuse": [],
    }.items():
        require(meta.get(field) == expected, f"repair amendment {field} changed")
    require("liveCampaignExecution" not in meta and "referenceObservationExecution" not in meta,
            "repair amendment cannot gain source or live authority")
    fix = packets.get("CON-FIX-001", {})
    if not isinstance(fix, dict):
        return [*errors, "CON-FIX-001 must be an object"]
    require(fix.get("predecessors") == REPAIR_PREDECESSORS["CON-FIX-001"],
            "contracts correction must wait for approved amendment")
    require(fix.get("allowedPaths") == PRODUCT_PATHS["CON-FIX-001"],
            "amended product path boundary changed")
    require(fix.get("offlineAcceptanceCommands") == CONTRACT_COMMANDS
            and fix.get("prefetchCommands") == [],
            "amended product must run the complete offline suite")
    require(fix.get("excluded") == [SCOPE_EXCLUSION],
            "function-level or registry exclusion changed")
    deliverables = fix.get("deliverables", [])
    require(isinstance(deliverables, list) and deliverables[-len(SCOPE_DELIVERABLES):] == SCOPE_DELIVERABLES,
            "bounded legacy-test and implementation obligations changed")
    evidence = fix.get("expectedEvidence", [])
    require(isinstance(evidence, list) and BASELINE_REQUIREMENT in evidence,
            "baseline failures and independent status replay must be retained")
    return errors


def main() -> int:
    try:
        packets = {path.stem: safe_yaml_load(path.read_text(encoding="utf-8"))
                   for path in (ROOT / "task-packets").glob("*.yaml")}
        record = json.loads((ROOT / "architecture/readiness-repairs.json").read_text(encoding="utf-8"))
        errors = validate_repair_authority(packets, record)
        amendment = json.loads((ROOT / "architecture/readiness-repair-amendment.json").read_text(encoding="utf-8"))
        errors += validate_repair_amendment(packets, amendment, (ROOT / "architecture/readiness-repairs.json").read_bytes())
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        print(f"Readiness repair authority failed: {exc}")
        return 1
    for error in errors:
        print(f"ERROR: {error}")
    if not errors:
        print("Readiness repair authority passed; product fixes and live acceptance remain unproven")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
