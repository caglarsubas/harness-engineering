"""Exact source lineage for MET-LINUX-004; no installed-host acceptance."""
import ast
from copy import deepcopy
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_linux_runner_contract as linux
from scripts import validate_ci_runner_admission as runner
from scripts import validate_unified_roadmap as roadmap
from scripts.safe_yaml import safe_load


def packets():
    return {path.stem: safe_load(path.read_bytes())
            for path in (linux.ROOT / "task-packets").glob("*.yaml")}


def changed_test():
    return next(path for path in linux._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert linux.validate() is None
    current = packets()
    accepted = linux.historical_catalog(current)
    assert len(current) == 191 and len(accepted) == 190
    assert set(accepted) == set(current) - {linux.NEW_PACKET}
    assert len(runner.historical_catalog(current)) == 189
    assert len(roadmap.historical_catalog(current)) == 188
    for name, expected in linux.authority()["baselinePackets"].items():
        assert linux.digest(linux.regular_bytes("task-packets/" + name + ".yaml")) == expected
    for path, rule in linux._PROJECTION_RULES.items():
        raw = linux.regular_bytes(path)
        assert linux.digest(raw) == rule["afterSha256"]
        before = linux.historical_bytes(path, raw)
        assert linux.digest(before) == rule["beforeSha256"]
        assert linux.historical_bytes(path, before) == before


@pytest.mark.parametrize("fault", ["missing_new", "missing_old", "extra", "new_payload", "old_payload", "projected"])
def test_catalog_refuses_all_packet_substitution_and_loss(fault):
    current = deepcopy(packets())
    if fault == "missing_new":
        current.pop(linux.NEW_PACKET)
    elif fault == "missing_old":
        current.pop("MET-RUNNER-001")
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    elif fault == "projected":
        current = linux.historical_catalog(current)
    else:
        name = linux.NEW_PACKET if fault == "new_payload" else "MET-001"
        current[name]["objective"] += " unreviewed"
    with pytest.raises(ValueError):
        linux.historical_catalog(current)


def test_every_predecessor_payload_is_checked_without_a_verdict_cache():
    current = packets()
    linux.historical_catalog(current)
    for name in sorted(linux.authority()["baselinePackets"]):
        original = current[name]
        current[name] = dict(original, objective=original["objective"] + " unreviewed")
        with pytest.raises(ValueError, match="changed packet payload"):
            linux.historical_catalog(current)
        current[name] = original


def test_acceptance_retains_every_inherited_command_and_wrapper():
    current = packets()
    packet, predecessor = current[linux.NEW_PACKET], current["MET-RUNNER-001"]
    commands = packet["offlineAcceptanceCommands"]
    assert len(commands) == 53
    assert commands[:-3] + commands[-2:] == predecessor["offlineAcceptanceCommands"]
    assert commands[-3][-1] == linux.VALIDATOR_PATH
    assert packet["offlineExecution"] == predecessor["offlineExecution"]
    assert packet["sourceReuse"] == packet["prefetchCommands"] == []
    assert "liveCampaignExecution" not in packet


def test_exact_inverse_and_forward_test_round_trip_across_layers():
    path = changed_test()
    current = linux.regular_bytes(path)
    before = linux.historical_bytes(path, current)
    assert before != current
    assert linux.historical_test_bytes(current) == before
    assert linux.current_test_bytes(before) == current
    assert linux.current_test_bytes(before + b" ") == before + b" "
    runner_before = runner.historical_bytes(path, current)
    assert runner.current_test_bytes(runner_before) == current
    roadmap_before = roadmap.historical_bytes(path, current)
    assert roadmap.current_test_bytes(roadmap_before) == current
    with pytest.raises(ValueError, match="unreviewed current source"):
        linux.historical_bytes(path, current + b" ")


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "runner_old", "roadmap_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = linux.regular_bytes(path)
    before = linux.historical_bytes(path, raw)
    current_packets = packets()
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_runner = runner.historical_bytes(roadmap.MASTER_PATH, master_raw)
    old_roadmap = roadmap.historical_bytes(roadmap.MASTER_PATH, roadmap.regular_bytes(roadmap.MASTER_PATH))
    calls = {
        "authority": linux.authority,
        "changed": lambda: linux.historical_bytes(path, raw),
        "old_bytes": lambda: linux.historical_bytes(path, before),
        "unchanged": lambda: linux.historical_bytes("architecture/repositories.yaml", b"unrelated"),
        "historical_test": lambda: linux.historical_test_bytes(raw),
        "current_test": lambda: linux.current_test_bytes(before),
        "catalog": lambda: linux.historical_catalog(current_packets),
        "runner_old": lambda: runner.historical_bytes(roadmap.MASTER_PATH, old_runner),
        "roadmap_old": lambda: roadmap.historical_bytes(roadmap.MASTER_PATH, old_roadmap),
    }
    calls[route]()
    original = linux.regular_bytes

    def changed_reader(relative):
        value = original(relative)
        return value + b" " if relative == linux.AUTHORITY_PATH else value

    monkeypatch.setattr(linux, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="Linux runner history authority digest"):
        calls[route]()


def test_catalog_uses_only_pinned_parsed_data_and_checks_each_input_again(monkeypatch):
    current = packets()

    def unexpected_yaml(_raw):
        pytest.fail("catalog projection must not reparse every predecessor YAML")

    monkeypatch.setattr(linux, "safe_load", unexpected_yaml)
    assert len(linux.historical_catalog(current)) == 190
    current["MET-001"]["objective"] += " changed after a successful call"
    with pytest.raises(ValueError, match="changed packet payload"):
        linux.historical_catalog(current)


def test_validator_checks_current_disk_packet_bytes_after_parsing(monkeypatch):
    original = linux.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == "task-packets/MET-001.yaml" else raw

    monkeypatch.setattr(linux, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="packet YAML drift"):
        linux.validate()


@pytest.mark.parametrize("mutation", ["append", "duplicate_literal"])
def test_normalized_validator_pin_rejects_source_mutation(monkeypatch, mutation):
    original = linux.regular_bytes

    def changed_reader(path):
        raw = original(path)
        if path == linux.VALIDATOR_PATH:
            raw += (b"\n# unreviewed\n" if mutation == "append" else
                    b'\nAUTHORITY_SHA256 = "' + linux.AUTHORITY_SHA256.encode() + b'"\n')
        return raw

    monkeypatch.setattr(linux, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="Linux runner validator drift"):
        linux.validate()


@pytest.mark.parametrize("fault", ["duplicate", "boolean", "negative", "out_of_bounds", "encoding", "empty", "overlap"])
def test_inverse_parser_refuses_ambiguous_or_unbounded_hunks(monkeypatch, fault):
    record = deepcopy(linux.authority())
    path = next(iter(record["changedFiles"]))
    hunks = record["changedFiles"][path]["reverseHunks"]
    if fault == "duplicate":
        hunks.insert(0, deepcopy(hunks[0]))
    elif fault == "boolean":
        hunks[0]["at"] = True
    elif fault == "negative":
        hunks[0]["at"] = -1
    elif fault == "out_of_bounds":
        hunks[0]["at"] = linux.MAX_FILE_BYTES + 1
    elif fault == "encoding":
        hunks[0]["insertBase64"] += "!"
    elif fault == "empty":
        hunks[0]["insertBase64"] = hunks[0]["removeBase64"]
    else:
        hunks[:] = [{"at": 0, "removeBase64": "YWJj", "insertBase64": "eA=="},
                    {"at": 1, "removeBase64": "Yg==", "insertBase64": "eQ=="}]
    monkeypatch.setattr(linux, "authority", lambda: record)
    with pytest.raises(ValueError):
        linux._rules()


def test_inverse_rules_and_packet_expectations_are_immutable():
    path = next(iter(linux._PROJECTION_RULES))
    with pytest.raises(TypeError):
        linux._PROJECTION_RULES[path] = {}
    with pytest.raises(TypeError):
        linux._PROJECTION_RULES[path]["afterSha256"] = "0" * 64
    with pytest.raises(TypeError):
        linux._PACKET_RULES["MET-001"] = ("0" * 64, "0" * 64)
    raw = linux.regular_bytes(path)
    with pytest.raises(ValueError, match="inverse hunk current bytes"):
        linux._inverse(raw, ((0, b"not-current", b"old"),))
    with pytest.raises(ValueError, match="inverse hunk bounds"):
        linux._inverse(raw, ((len(raw) + 1, b"", b"old"),))


def test_ambiguous_test_projections_are_refused(monkeypatch):
    path = changed_test()
    current = linux.regular_bytes(path)
    before = linux.historical_bytes(path, current)
    rules = dict(linux._PROJECTION_RULES)
    rules["tests/ambiguous_unreviewed.py"] = rules[path]
    monkeypatch.setattr(linux, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="ambiguous current test"):
        linux.historical_test_bytes(current)
    with pytest.raises(ValueError, match="ambiguous predecessor test"):
        linux.current_test_bytes(before)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_authority_parser_rejects_duplicate_and_nonfinite_data(raw):
    with pytest.raises(ValueError):
        linux.parse(raw)


@pytest.mark.parametrize("route", [linux.historical_test_bytes, linux.current_test_bytes])
def test_mutable_test_input_is_refused(route):
    with pytest.raises(ValueError, match="test bytes required"):
        route(bytearray(b"mutable"))


@pytest.mark.parametrize("path", ["/absolute", "../outside", "a/../b", "a//b", "a\\b", "a\nb"])
def test_untrusted_source_paths_are_refused(path):
    with pytest.raises(ValueError, match="relative source path"):
        linux.historical_bytes(path, b"input")


def test_unlinked_bounded_source_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(linux, "ROOT", tmp_path)
    original = tmp_path / "plain"
    original.write_bytes(b"source")
    assert linux.regular_bytes("plain") == b"source"
    (tmp_path / "alias").symlink_to(original)
    with pytest.raises(ValueError, match="bounded regular source file"):
        linux.regular_bytes("alias")
    os.link(original, tmp_path / "hardlink")
    with pytest.raises(ValueError, match="bounded regular source file"):
        linux.regular_bytes("plain")
    (tmp_path / "outside").mkdir()
    (tmp_path / "ancestor").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ValueError, match="linked source ancestor"):
        linux.regular_bytes("ancestor/file")


def test_source_read_detects_concurrent_change(tmp_path, monkeypatch):
    monkeypatch.setattr(linux, "ROOT", tmp_path)
    target = tmp_path / "plain"
    target.write_bytes(b"source")
    original = Path.read_bytes

    def racing_read(path):
        raw = original(path)
        if path == target:
            target.write_bytes(b"changed and longer")
        return raw

    monkeypatch.setattr(Path, "read_bytes", racing_read)
    with pytest.raises(ValueError, match="source changed during read"):
        linux.regular_bytes("plain")


def test_changed_historical_tests_retain_their_test_identities():
    def identities(raw):
        names = []

        def visit(nodes, prefix=""):
            for node in nodes:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                    names.append(prefix + node.name)
                elif isinstance(node, ast.ClassDef):
                    visit(node.body, prefix + node.name + ".")

        visit(ast.parse(raw).body)
        assert len(names) == len(set(names))
        return set(names)

    for path in linux._PROJECTION_RULES:
        if path.startswith("tests/") and path.endswith(".py"):
            current = linux.regular_bytes(path)
            before = linux.historical_bytes(path, current)
            assert identities(before) <= identities(current), path


def test_new_projection_has_no_predecessor_validator_import():
    tree = ast.parse(linux.regular_bytes(linux.VALIDATOR_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert "validate_" not in (node.module or "")
        elif isinstance(node, ast.Import):
            assert all("validate_" not in alias.name for alias in node.names)
