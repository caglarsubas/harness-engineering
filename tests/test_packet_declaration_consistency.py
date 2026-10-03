"""Additive document regressions; historical test modules retain exact identities."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re
from typing import Any

import pytest

from scripts.validate_readiness import extract_packet_ids, load_yaml

ROOT = Path(__file__).resolve().parents[1]
PACKET_DIRECTORY = ROOT / "task-packets"


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


# Match the existing readiness parser boundaries, not introductory/history prose.
PLAN_TITLE_PATTERN = re.compile(r"^# Repository Plan: `([^`]+)`\s*$", re.MULTILINE)
PLAN_PACKETS_PATTERN = re.compile(r"^## PR packets\s*$([\s\S]*?)(?=^## |\Z)", re.MULTILINE)
PLAN_TREE_PATTERN = re.compile(
    r"^## Repository structure[^\n]*\n[\s\S]*?```text\n(.*?)\n```",
    re.MULTILINE | re.DOTALL,
)
PLAN_ROOT_PATTERN = re.compile(r"[├└]── ([^/]+?)(?:/|$)")
CATALOG_OWNER_PATTERN = re.compile(
    r"^\|\s*(\d+)\s*\|\s*`([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)`\s*\|\s*`([^`]+)`\s*\|",
    re.MULTILINE,
)


def _assert_semantic_catalog_consistency(
    packets: dict[str, dict[str, Any]], plans: list[str], readme: str,
) -> None:
    """Pure document checks; no recursive validator, subprocess or acceptance."""
    physical_owners = {packet_id: packet["repository"] for packet_id, packet in packets.items()}
    plan_owners: dict[str, str] = {}
    root_sets: dict[str, set[str]] = {}
    for text in plans:
        titles = PLAN_TITLE_PATTERN.findall(text)
        assert len(titles) == 1, "canonical repository title"
        repository = titles[0]
        assert repository not in root_sets, "duplicate repository title"
        sections = PLAN_PACKETS_PATTERN.findall(text)
        assert len(sections) == 1, "canonical PR packets section"
        for packet_id in extract_packet_ids(sections[0]):
            assert packet_id not in plan_owners, "duplicate declared packet"
            plan_owners[packet_id] = repository
        trees = PLAN_TREE_PATTERN.findall(text)
        assert len(trees) == 1, "canonical fenced tree"
        root_sets[repository] = {
            match.group(1)
            for line in trees[0].splitlines()[1:]
            if (match := PLAN_ROOT_PATTERN.match(line)) is not None
        }
    assert plan_owners == physical_owners, "canonical packet owners differ"
    assert set(root_sets) == set(physical_owners.values()), "repository membership differs"

    rows = CATALOG_OWNER_PATTERN.findall(readme)
    assert [int(order) for order, _, _ in rows] == list(range(1, len(packets) + 1)), "ordered index differs"
    indexed_owners = {packet_id: owner for _, packet_id, owner in rows}
    assert len(rows) == len(indexed_owners), "duplicate indexed packet"
    assert indexed_owners == physical_owners, "indexed packet owners differ"
    positions = {packet_id: index for index, (_, packet_id, _) in enumerate(rows)}
    for packet_id, packet in packets.items():
        for predecessor in packet["predecessors"]:
            assert predecessor in positions and positions[predecessor] < positions[packet_id], "predecessor order differs"
    for repository, declared_roots in root_sets.items():
        authorized_roots = {
            Path(path).parts[0]
            for packet in packets.values() if packet["repository"] == repository
            for path in packet["allowedPaths"]
        }
        assert declared_roots == authorized_roots, "exact repository roots differ"


def _semantic_catalog_fixture():
    packets = {
        "MET-001": {"repository": "Harness-Engineering", "predecessors": [], "allowedPaths": ["tests/"]},
        "MET-PERF-022": {"repository": "Harness-Engineering", "predecessors": ["MET-001"], "allowedPaths": ["conftest.py"]},
    }
    plan = """# Repository Plan: `Harness-Engineering`

## Current narrative
Current candidate `MET-PERF-022`; historical `MET-PERF-020` and `MET-PERF-021`.

## Repository structure and exact tree
```text
Harness-Engineering/
├── tests/
│   └── nested-only.py
└── conftest.py
```

## PR packets
1. `MET-001-foundation`: accepted predecessor.
2. `MET-PERF-022`: current candidate.

## History
Historical `MET-PERF-020` and `MET-PERF-021` are not current declarations.
"""
    readme = """Historical `MET-PERF-020` is not indexed.
| 1 | `MET-001` | `Harness-Engineering` | accepted |
| 2 | `MET-PERF-022` | `Harness-Engineering` | current |
"""
    return packets, plan, readme


def test_semantic_plan_patterns_match_readiness_source_boundaries() -> None:
    # Data inspection binds these regressions to the production parser literals.
    tree = ast.parse((ROOT / "scripts/validate_readiness.py").read_text(encoding="utf-8"))
    literals = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    for pattern in (PLAN_TITLE_PATTERN, PLAN_PACKETS_PATTERN, PLAN_TREE_PATTERN, PLAN_ROOT_PATTERN):
        assert pattern.pattern in literals


def test_current_plan_owners_index_and_root_trees_match_physical_packets() -> None:
    plans = sorted((ROOT / "docs/repositories").glob("*.md"))
    assert len(plans) == 13
    _assert_semantic_catalog_consistency(
        packets_by_id(), [path.read_text(encoding="utf-8") for path in plans],
        (PACKET_DIRECTORY / "README.md").read_text(encoding="utf-8"),
    )


def test_semantic_catalog_ignores_history_intro_and_nested_tree_entries() -> None:
    packets, plan, readme = _semantic_catalog_fixture()
    _assert_semantic_catalog_consistency(packets, [plan], readme)


@pytest.mark.parametrize("mutation,expected", [
    ("stale_same_count", "canonical packet owners differ"),
    ("intro_only", "canonical packet owners differ"),
    ("missing_root", "exact repository roots differ"),
    ("extra_root", "exact repository roots differ"),
    ("duplicate_declared", "duplicate declared packet"),
    ("wrong_plan_owner", "canonical packet owners differ"),
    ("wrong_index_owner", "indexed packet owners differ"),
    ("stale_index_same_count", "indexed packet owners differ"),
    ("duplicate_index", "duplicate indexed packet"),
    ("predecessor_after", "predecessor order differs"),
    ("duplicate_section", "canonical PR packets section"),
])
def test_semantic_catalog_rejects_documentation_drift(mutation, expected) -> None:
    packets, plan, readme = _semantic_catalog_fixture()
    if mutation == "stale_same_count":
        plan = plan.replace("2. `MET-PERF-022`", "2. `MET-PERF-020`")
    elif mutation == "intro_only":
        plan = plan.replace("2. `MET-PERF-022`: current candidate.\n", "")
    elif mutation == "missing_root":
        plan = plan.replace("└── conftest.py\n", "")
    elif mutation == "extra_root":
        plan = plan.replace("└── conftest.py", "├── extra.py\n└── conftest.py")
    elif mutation == "duplicate_declared":
        plan = plan.replace("2. `MET-PERF-022`", "2. `MET-001`")
    elif mutation == "wrong_plan_owner":
        plan = plan.replace("# Repository Plan: `Harness-Engineering`", "# Repository Plan: `other-repo`")
    elif mutation == "wrong_index_owner":
        readme = readme.replace("| `Harness-Engineering` | current", "| `other-repo` | current")
    elif mutation == "stale_index_same_count":
        readme = readme.replace("| `MET-PERF-022` |", "| `MET-PERF-020` |")
    elif mutation == "duplicate_index":
        readme = readme.replace("| `MET-PERF-022` |", "| `MET-001` |")
    elif mutation == "predecessor_after":
        readme = readme.replace("| 1 | `MET-001`", "| 1 | `MET-PERF-022`").replace("| 2 | `MET-PERF-022`", "| 2 | `MET-001`")
    elif mutation == "duplicate_section":
        plan += "\n## PR packets\n"
    else:
        raise AssertionError("unhandled mutation")
    with pytest.raises(AssertionError, match=expected):
        _assert_semantic_catalog_consistency(packets, [plan], readme)


HISTORICAL_TEST_NAMES = (
    "test_complete_catalog_is_schema_valid_and_identity_unique",
    "test_catalog_covers_all_thirteen_repositories",
    "test_predecessor_graph_is_closed_acyclic_and_indexed_topologically",
    "test_alpha_index_partitions_every_packet_once",
    "test_packet_ownership_is_closed_for_all_123_packets",
    "test_control_bootstrap_correction_is_one_closed_exception",
    "test_distribution_bootstrap_correction_is_one_closed_exception",
    "test_live_campaign_authority_is_exact_and_offline_commands_remain_primary",
    "test_reference_observation_authority_is_exact_and_separate_from_implementation",
    "test_task_packet_schema_rejects_legacy_shell_and_unknown_authority",
)
ACCEPTED_TEST_MODULE_SHA256 = "7d559e7e6000ba3734c0598c03d938cc24efc74a4cd3e8d758bcb8092a8a819c"
CATALOG_SCALAR_CURRENT = b"assert len(files) == EXPECTED_PACKET_COUNT == 194"
CATALOG_SCALAR_ACCEPTED = b"assert len(files) == EXPECTED_PACKET_COUNT == 190"


def _assert_exact_historical_test_module(raw: bytes) -> None:
    # Hash current source after the sole declared scalar substitution. Never
    # import/execute a snapshot or accept inherited names merely as a subset.
    names = tuple(node.name for node in ast.parse(raw).body
                  if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and node.name.startswith("test_"))
    assert names == HISTORICAL_TEST_NAMES, "historical test identities/order differ"
    assert raw.count(CATALOG_SCALAR_CURRENT) == 1, "historical catalog scalar differs"
    accepted_view = raw.replace(CATALOG_SCALAR_CURRENT, CATALOG_SCALAR_ACCEPTED, 1)
    assert hashlib.sha256(accepted_view).hexdigest() == ACCEPTED_TEST_MODULE_SHA256, "historical test bodies/imports differ"


def test_protected_module_retains_exact_historical_identities_and_bodies() -> None:
    _assert_exact_historical_test_module((ROOT / "tests/test_task_packets.py").read_bytes())


@pytest.mark.parametrize("mutation", ["addition", "removal", "rename", "order", "body"])
def test_protected_module_rejects_identity_order_and_body_drift(mutation: str) -> None:
    raw = (ROOT / "tests/test_task_packets.py").read_bytes()
    _assert_exact_historical_test_module(raw)
    nodes = [node for node in ast.parse(raw).body
             if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]
    first, second = nodes[:2]
    lines = raw.splitlines(keepends=True)
    if mutation == "addition":
        changed = raw + b"\n\ndef test_unreviewed_addition():\n    assert True\n"
    elif mutation == "removal":
        changed = b"".join(lines[:first.lineno - 1] + lines[first.end_lineno:])
    elif mutation == "rename":
        changed = raw.replace(("def " + first.name).encode(), b"def test_renamed", 1)
    elif mutation == "order":
        changed = b"".join(lines[:first.lineno - 1]
                           + lines[second.lineno - 1:second.end_lineno]
                           + lines[first.end_lineno:second.lineno - 1]
                           + lines[first.lineno - 1:first.end_lineno]
                           + lines[second.end_lineno:])
    elif mutation == "body":
        before = b"assert len(packets) == EXPECTED_PACKET_COUNT"
        assert raw.count(before) == 1
        changed = raw.replace(before, b"assert len(packets) >= EXPECTED_PACKET_COUNT", 1)
    else:
        raise AssertionError("unhandled mutation")
    with pytest.raises(AssertionError, match="historical"):
        _assert_exact_historical_test_module(changed)


def test_semantic_module_remains_selected_by_both_declared_suite_arguments() -> None:
    # Static recipe protection is not proof that pytest collected or ran a case.
    packet = load_yaml(PACKET_DIRECTORY / "MET-PERF-028.yaml")
    outer = packet["offlineAcceptanceCommands"][-2]
    assert outer == ["uv", "run", "--offline", "--frozen", "--no-sync", "python",
                     "-m", "pytest", "tests", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]
    tree = ast.parse((ROOT / "tests/linux_runner/test_build_and_predecessors.py").read_bytes())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == "test_full_predecessor_suites_and_validators_remain_green"]
    assert len(functions) == 1
    assignments = [node for node in functions[0].body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "commands"
                           for target in node.targets)]
    assert len(assignments) == 1
    value = assignments[0].value
    assert isinstance(value, ast.List) and len(value.elts) == 1
    command = value.elts[0]
    assert isinstance(command, ast.List)
    assert ast.dump(command.elts[0]) == ast.dump(ast.parse("sys.executable", mode="eval").body)
    assert all(isinstance(arg, ast.Constant) and isinstance(arg.value, str)
               for arg in command.elts[1:])
    assert [arg.value for arg in command.elts[1:]] == [
        "-m", "pytest", "-rs", "tests", "--ignore=tests/linux_runner",
        "ci/test_offline_runner.py", "ci/test_warm_snapshot.py",
    ]
    own_path = Path(__file__).resolve().relative_to(ROOT)
    assert own_path == Path("tests/test_packet_declaration_consistency.py")
    assert own_path.name.startswith("test_") and own_path.parent == Path("tests")
