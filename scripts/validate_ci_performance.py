#!/usr/bin/env python3
"""Closed performance authority; no cached acceptance or snapshot execution."""
from __future__ import annotations

import ast
from pathlib import Path

import yaml

try:
    from safe_yaml import safe_load
    from validate_proxy_contract import canonical, digest, parse, regular_bytes
    from validate_successor_inventory import packet_semantics
except ModuleNotFoundError:
    from scripts.safe_yaml import safe_load
    from scripts.validate_proxy_contract import canonical, digest, parse, regular_bytes
    from scripts.validate_successor_inventory import packet_semantics

try:
    from validate_credential_ordering import historical_bytes, current_test_bytes, validate_additions as ordering_additions
except ImportError:
    from scripts.validate_credential_ordering import historical_bytes, current_test_bytes, validate_additions as ordering_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/ci-performance-amendment.json"
BEFORE_PATH = "architecture/ci-performance-inputs/tests.before.json"
RECORD_SHA256 = "c533d6afdb7c8afc72a80a249d05e9812e18cd1aa6d54f9df7e3b1f4a158c5c3"
PACKET_SHA256 = "e5d8e021c7e779040118b8ba71fb45ec14d7a5a4e39386a2580ff4f1eb821284"
ADDITIONS = ("MET-PERF-001",)
CURRENT_PACKET_COUNT = 194
HISTORICAL_PACKET_COUNT = 139
SUCCESSOR_ADDITIONS = ("MET-REPAIR-012", "CONF-FIX-005", "MET-REPAIR-013", "MET-REPAIR-014", "MET-REPAIR-015", "MET-PERF-002", "CONF-PERF-001", "MET-PERF-003", "CONF-PERF-002", "MET-PERF-004", "CONF-PERF-003", "MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001", "MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pinned(record):
    require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256,
            "exact approved performance authority required")


def validate_additions(packets):
    try:
        require(type(packets) is dict and digest(canonical(packets.get("MET-PERF-001"))) == PACKET_SHA256,
                "exact performance packet required")
        return []
    except (ValueError, TypeError, RecursionError):
        return ["unreviewed performance packet"]


def load_performance_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    paths = {**record["protectedFiles"], **record["inputFiles"]}
    inputs = {path: regular_bytes(root, path) for path in paths}
    current_tests = {path: regular_bytes(root, path) for path in record["mechanicalTestUpdates"]}
    return record, inputs, current_tests


def expected_test_source(before, rule):
    require(type(before) is bytes and type(rule) is dict
            and set(rule) == {"safeParserReference", "catalogScalar"}
            and all(type(value) is bool for value in rule.values()), "closed test transformation")
    result = before
    if rule["safeParserReference"]:
        require(result.count(b"import yaml\n") == 1 and b"yaml.safe_load(" in result,
                "exact original parser import required")
        result = result.replace(b"import yaml\n",
            b"import yaml\nfrom scripts.safe_yaml import safe_load as safe_yaml_load\n")
        result = result.replace(b"yaml.safe_load(", b"safe_yaml_load(")
    if rule["catalogScalar"]:
        require(b"== 138" in result, "original current-catalog assertion required")
        result = result.replace(b"== 138", ("== " + str(HISTORICAL_PACKET_COUNT)).encode())
    return result


def expected_current_test_source(before, rule):
    """Keep historical reconstruction; apply only the pinned successor recipe."""
    try:
        from validate_credential_lifecycle import reconcile_meta_test_bytes
    except ImportError:
        from scripts.validate_credential_lifecycle import reconcile_meta_test_bytes
    return reconcile_meta_test_bytes(expected_test_source(before, rule))


def test_definitions(raw):
    tree = ast.parse(raw)
    # Read AST names only. Never execute the stored previous test source.
    names = []
    def visit(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("test_"):
                    names.append(prefix + node.name)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
    visit(tree.body)
    require(len(names) == len(set(names)), "duplicate test identity")
    return names


def validate_test_preservation(record, before_raw, current_tests):
    try:
        pinned(record)
        require(type(before_raw) is bytes and digest(before_raw) == record["inputFiles"][BEFORE_PATH],
                "exact previous test bytes required")
        before = parse(before_raw)
        require(before["baseCommit"] == record["baseCommit"], "test checkpoint identity")
        rules = record["mechanicalTestUpdates"]
        require(type(current_tests) is dict and set(current_tests) == set(rules) == set(before["files"]),
                "exact previous/current test inventory")
        for path, rule in rules.items():
            original = before["files"][path].encode()
            require(type(current_tests[path]) is bytes
                    and current_tests[path] == expected_current_test_source(original, rule),
                    "previous test bytes changed: " + path)
            require(test_definitions(original) == test_definitions(current_tests[path]),
                    "previous test identity changed")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError):
        return ["previous tests differ beyond exact safe-parser/catalog substitutions"]


def validate_ci_performance(packets, record, inputs, current_tests):
    try:
        pinned(record)
        errors = validate_additions(packets)
        pins = {**record["protectedFiles"], **record["inputFiles"]}
        require(type(inputs) is dict and set(inputs) == set(pins), "complete independent input inventory")
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(historical_bytes(path, inputs[path])) == checksum,
                    "protected input changed: " + path)
            if path.startswith("task-packets/"):
                require(canonical(packets[Path(path).stem]) == packet_semantics(inputs[path]),
                        "packet semantics differ from current bytes")
        previous = {Path(path).stem for path in record["protectedFiles"] if path.startswith("task-packets/")}
        require(len(previous) == 138 and len(packets) == CURRENT_PACKET_COUNT
                and set(packets) == previous | set(ADDITIONS) | set(SUCCESSOR_ADDITIONS)
                    | {"MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"},
                "138 exact predecessors, performance packet and two exact credential packets")
        try:
            from validate_credential_lifecycle import validate_additions as credential_additions
        except ImportError:
            from scripts.validate_credential_lifecycle import validate_additions as credential_additions
        errors.extend(credential_additions(packets))
        errors.extend(ordering_additions(packets))
        packet = packets["MET-PERF-001"]
        prefix = ["uv", "run", "--offline", "--frozen", "--no-sync", "python"]
        previous_commands = packets["MET-REPAIR-011"]["offlineAcceptanceCommands"]
        expected = [prefix + ["ci/measure_yaml_parsing.py"], *previous_commands[:-2],
                    prefix + ["scripts/validate_ci_performance.py"], *previous_commands[-2:]]
        require(packet["offlineAcceptanceCommands"] == expected and len(expected) == 19,
                "complete declared replay/validator commands required")
        errors.extend(validate_test_preservation(record, inputs[BEFORE_PATH], current_tests))
        return errors
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError, yaml.YAMLError):
        return ["invalid bounded CI-performance authority"]


def main():
    try:
        packets = {p.stem: safe_load(regular_bytes(ROOT, str(p.relative_to(ROOT))))
                   for p in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_ci_performance(packets, *load_performance_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        errors = ["performance authority unavailable"]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("CI performance authority valid: 194 packets; historical 139 authority and all prior tests/both complete replays preserved; no native acceptance.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
