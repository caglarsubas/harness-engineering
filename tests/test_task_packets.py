from __future__ import annotations

import copy
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import jsonschema

from scripts.validate_packet_ownership import validate_packet_ownership
from scripts.validate_conformance_reference_measurement import validate_dispatch_ownership
from scripts.validate_readiness import (
    DATA_HARNESS_V1_OBSERVATION_PATHS,
    EXPECTED_PACKET_COUNT,
    LIVE_CAMPAIGN_EVIDENCE_AXES,
    LIVE_CAMPAIGN_EXECUTION_BASE,
    LIVE_CAMPAIGN_PACKET_IDS,
    REFERENCE_OBSERVATION_EXECUTION_BASE,
    TREE_OBSERVATION_EXECUTION_BASE,
    TREE_OBSERVATION_PACKETS,
    load_yaml,
)


ROOT = Path(__file__).resolve().parents[1]
PACKET_DIRECTORY = ROOT / "task-packets"
PACKET_ROW_PATTERN = re.compile(
    r"^\|\s*(\d+)\s*\|\s*`([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)`\s*\|",
    re.MULTILINE,
)
ALPHA_HEADING_PATTERN = re.compile(r"^## Alpha ([1-4])\b", re.MULTILINE)


def packet_files() -> list[Path]:
    return sorted(PACKET_DIRECTORY.glob("*.yaml"))


def packets_by_id() -> dict[str, dict[str, Any]]:
    packets: dict[str, dict[str, Any]] = {}
    for path in packet_files():
        packet = load_yaml(path)
        assert isinstance(packet, dict), f"{path} is not a mapping"
        packet_id = packet.get("id")
        assert isinstance(packet_id, str), f"{path} has no string id"
        assert packet_id not in packets, f"duplicate packet id {packet_id}"
        packets[packet_id] = packet
    return packets


def task_packet_validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(
        (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def catalog_rows() -> list[tuple[int, str]]:
    readme = (PACKET_DIRECTORY / "README.md").read_text(encoding="utf-8")
    return [
        (int(order), packet_id)
        for order, packet_id in PACKET_ROW_PATTERN.findall(readme)
    ]


def test_complete_catalog_is_schema_valid_and_identity_unique() -> None:
    files = packet_files()
    packets = packets_by_id()
    validator = task_packet_validator()

    assert len(files) == EXPECTED_PACKET_COUNT == 194
    assert len(packets) == EXPECTED_PACKET_COUNT
    assert {path.stem for path in files} == set(packets)

    branches: list[str] = []
    for path in files:
        packet = packets[path.stem]
        validator.validate(packet)
        assert packet["branch"].startswith(f"codex/{path.stem.casefold()}")
        branches.append(packet["branch"])

    assert len(branches) == len(set(branches))


def test_catalog_covers_all_thirteen_repositories() -> None:
    repository_registry = load_yaml(ROOT / "architecture/repositories.yaml")
    assert isinstance(repository_registry, dict)
    registered_names = {
        repository["name"] for repository in repository_registry["repositories"]
    }
    packet_repositories = {
        packet["repository"] for packet in packets_by_id().values()
    }

    assert len(registered_names) == 13
    assert packet_repositories == registered_names


def test_predecessor_graph_is_closed_acyclic_and_indexed_topologically() -> None:
    packets = packets_by_id()
    rows = catalog_rows()
    ordered_ids = [packet_id for _, packet_id in rows]

    assert [order for order, _ in rows] == list(range(1, EXPECTED_PACKET_COUNT + 1))
    assert len(ordered_ids) == len(set(ordered_ids)) == EXPECTED_PACKET_COUNT
    assert set(ordered_ids) == set(packets)

    position = {packet_id: index for index, packet_id in enumerate(ordered_ids)}
    for packet_id, packet in packets.items():
        for predecessor in packet["predecessors"]:
            assert predecessor in packets
            assert position[predecessor] < position[packet_id]

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(packet_id: str) -> None:
        assert packet_id not in visiting, f"packet cycle reaches {packet_id}"
        if packet_id in visited:
            return
        visiting.add(packet_id)
        for predecessor in packets[packet_id]["predecessors"]:
            visit(predecessor)
        visiting.remove(packet_id)
        visited.add(packet_id)

    for packet_id in packets:
        visit(packet_id)
    assert visited == set(packets)


def test_alpha_index_partitions_every_packet_once() -> None:
    readme = (PACKET_DIRECTORY / "README.md").read_text(encoding="utf-8")
    headings = list(ALPHA_HEADING_PATTERN.finditer(readme))

    assert [match.group(1) for match in headings] == ["1", "2", "3", "4"]
    indexed: list[str] = []
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(readme)
        section = readme[heading.end() : end]
        indexed.extend(packet_id for _, packet_id in PACKET_ROW_PATTERN.findall(section))

    counts = Counter(indexed)
    assert set(counts) == set(packets_by_id())
    assert all(count == 1 for count in counts.values())


def test_packet_ownership_is_closed_for_all_123_packets() -> None:
    errors = validate_dispatch_ownership(packets_by_id())
    assert errors == []


def test_control_bootstrap_correction_is_one_closed_exception() -> None:
    packets = packets_by_id()
    correction = packets["CTRL-FIX-001"]

    assert correction["repository"] == "mas-harness-control-plane"
    assert correction["predecessors"] == ["CTRL-001"]
    assert correction["allowedPaths"] == [
        "AGENTS.md",
        "ci/handlers/prefetch.py",
        "ci/targets/ctrl-fix-001.json",
        "tests/bootstrap/test_static_contract.py",
    ]
    assert correction["prefetchCommands"] == [["make", "prefetch"]]
    assert correction["offlineAcceptanceCommands"] == [
        ["make", "prefetch-lineage-regression"],
        ["make", "bootstrap-e2e"],
        ["make", "zero-bill"],
    ]
    assert packets["CTRL-002"]["predecessors"] == ["CTRL-FIX-001", "IND-WG-005"]


def test_distribution_bootstrap_correction_is_one_closed_exception() -> None:
    packets = packets_by_id()
    correction = packets["DIST-FIX-001"]

    assert correction["repository"] == "mas-harness-distribution"
    assert correction["predecessors"] == ["DIST-001"]
    assert correction["allowedPaths"] == [
        "Makefile",
        "AGENTS.md",
        "ci/targets/dist-fix-001.json",
        "tests/bootstrap/test_dispatch.py",
    ]
    assert correction["prefetchCommands"] == [["make", "prefetch"]]
    assert correction["offlineAcceptanceCommands"] == [
        ["make", "dist-fix-regression"],
        ["make", "zero-bill"],
    ]
    assert packets["DIST-OCI-001"]["predecessors"] == ["DIST-FIX-001", "CON-005"]


def test_live_campaign_authority_is_exact_and_offline_commands_remain_primary() -> None:
    packets = packets_by_id()

    assert set(LIVE_CAMPAIGN_EVIDENCE_AXES) == LIVE_CAMPAIGN_PACKET_IDS
    assert len(LIVE_CAMPAIGN_PACKET_IDS) == 12
    for packet_id, packet in packets.items():
        live_execution = packet.get("liveCampaignExecution")
        if packet_id in LIVE_CAMPAIGN_PACKET_IDS:
            assert live_execution == {
                **LIVE_CAMPAIGN_EXECUTION_BASE,
                "allowedEvidenceAxes": LIVE_CAMPAIGN_EVIDENCE_AXES[packet_id],
                "commands": packet["offlineAcceptanceCommands"],
            }
            assert "TENANT_ACCEPTANCE" not in live_execution["allowedEvidenceAxes"]
        else:
            assert live_execution is None


def test_reference_observation_authority_is_exact_and_separate_from_implementation() -> None:
    packets = packets_by_id()
    expected = {
        **REFERENCE_OBSERVATION_EXECUTION_BASE,
        "repository": "git@github.com:caglarsubas/data-source-harness.git",
        "commit": "858281f4b845ffacfe05cdb2c40a402c237d4c54",
        "sourcePaths": DATA_HARNESS_V1_OBSERVATION_PATHS,
        "outputPath": "architecture/observations/data-harness-v1.json",
    }

    for packet_id, packet in packets.items():
        observation = packet.get("referenceObservationExecution")
        if packet_id == "MET-002":
            assert packet["warmSourceAccess"] == "AUTHORIZED_READ_ONLY_OBSERVATION"
            assert observation == expected
        elif packet_id == "MET-OBS-MODEL-001":
            assert packet["warmSourceAccess"] == "AUTHORIZED_READ_ONLY_OBSERVATION"
            assert observation == {
                **REFERENCE_OBSERVATION_EXECUTION_BASE,
                "repository": "git@github.com:caglarsubas/llm_inference_engine.git",
                "commit": "6815c21cb10a4d7dc0b4804f6bb223afb4321e97",
                "sourcePaths": ["contracts/prometa-model-usage-v2.schema.json"],
                "outputPath": "architecture/observations/model-usage-v2.json",
            }
        elif packet_id in TREE_OBSERVATION_PACKETS:
            assert packet["warmSourceAccess"] == "AUTHORIZED_READ_ONLY_OBSERVATION"
            assert observation == {
                **TREE_OBSERVATION_EXECUTION_BASE,
                **TREE_OBSERVATION_PACKETS[packet_id],
            }
            assert packet["sourceReuse"] == []
        else:
            assert packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
            assert observation is None


def test_task_packet_schema_rejects_legacy_shell_and_unknown_authority() -> None:
    validator = task_packet_validator()
    canonical = packets_by_id()["MET-004"]

    invalid_variants = []

    legacy = copy.deepcopy(canonical)
    legacy["acceptanceCommands"] = ["pytest"]
    invalid_variants.append(legacy)

    shell = copy.deepcopy(canonical)
    shell["offlineAcceptanceCommands"] = [["bash", "-c", "pytest"]]
    invalid_variants.append(shell)

    unsafe_path = copy.deepcopy(canonical)
    unsafe_path["allowedPaths"] = ["../outside"]
    invalid_variants.append(unsafe_path)

    widened_live_authority = copy.deepcopy(canonical)
    widened_live_authority["liveCampaignExecution"] = {
        **LIVE_CAMPAIGN_EXECUTION_BASE,
        "allowedEvidenceAxes": ["TENANT_ACCEPTANCE"],
        "commands": canonical["offlineAcceptanceCommands"],
    }
    invalid_variants.append(widened_live_authority)

    for invalid in invalid_variants:
        assert list(validator.iter_errors(invalid))
