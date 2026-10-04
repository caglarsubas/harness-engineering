"""Exact source lineage for MET-VERIFY-001; no verifier-host or native acceptance."""
import ast
from copy import deepcopy
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_owner_verifier as verifier
from scripts import validate_linux_runner_contract as linux
from scripts import validate_packet_schema_performance as performance
from scripts import validate_ci_runner_admission as runner
from scripts import validate_unified_roadmap as roadmap
from scripts.safe_yaml import safe_load


def packets():
    return {path.stem: safe_load(path.read_bytes())
            for path in (verifier.ROOT / "task-packets").glob("*.yaml")}


def layer_packets():
    # The newer MET-PERF-029 layer is projected away before this layer's payload checks.
    return verifier.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in verifier._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert verifier.validate() is None
    current = packets()
    accepted = verifier.historical_catalog(current)
    assert len(current) == 194 and len(accepted) == 192
    assert set(accepted) == set(current) - {verifier.NEW_PACKET, verifier.successor.NEW_PACKET}
    assert len(linux.historical_catalog(current)) == 191
    assert len(performance.historical_catalog(current)) == 190
    assert len(runner.historical_catalog(current)) == 189
    assert len(roadmap.historical_catalog(current)) == 188
    for name, expected in verifier.authority()["baselinePackets"].items():
        assert verifier.digest(verifier.regular_bytes("task-packets/" + name + ".yaml")) == expected
    for path, rule in verifier._PROJECTION_RULES.items():
        raw = verifier.successor.historical_bytes(path, verifier.regular_bytes(path))
        assert verifier.digest(raw) == rule["afterSha256"]
        before = verifier.historical_bytes(path, raw)
        assert verifier.digest(before) == rule["beforeSha256"]
        assert verifier.historical_bytes(path, before) == before


@pytest.mark.parametrize("fault", ["missing_new", "missing_old", "extra", "new_payload", "old_payload", "projected"])
def test_catalog_refuses_all_packet_substitution_and_loss(fault):
    current = deepcopy(layer_packets())
    if fault == "missing_new":
        current.pop(verifier.NEW_PACKET)
    elif fault == "missing_old":
        current.pop("MET-RUNNER-001")
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    elif fault == "projected":
        current = verifier.historical_catalog(deepcopy(packets()))
    else:
        name = verifier.NEW_PACKET if fault == "new_payload" else "MET-001"
        current[name]["objective"] += " unreviewed"
    with pytest.raises(ValueError):
        verifier.validate_packet_payloads(current)


def test_every_predecessor_payload_is_checked_without_a_verdict_cache():
    current = layer_packets()
    verifier.validate_packet_payloads(current)
    for name in sorted(verifier.authority()["baselinePackets"]):
        original = current[name]
        current[name] = dict(original, objective=original["objective"] + " unreviewed")
        with pytest.raises(ValueError, match="changed packet payload"):
            verifier.validate_packet_payloads(current)
        current[name] = original


def test_acceptance_retains_every_inherited_command_and_wrapper():
    current = packets()
    packet, predecessor = current[verifier.NEW_PACKET], current[verifier.PREVIOUS_PACKET]
    commands = packet["offlineAcceptanceCommands"]
    assert len(commands) == 55
    assert commands[:-3] + commands[-2:] == predecessor["offlineAcceptanceCommands"]
    assert commands[-3][-1] == verifier.VALIDATOR_PATH
    assert packet["offlineExecution"] == predecessor["offlineExecution"]
    assert packet["sourceReuse"] == packet["prefetchCommands"] == []
    assert "liveCampaignExecution" not in packet


def test_exact_inverse_and_forward_test_round_trip_across_layers():
    path = changed_test()
    current = verifier.regular_bytes(path)
    before = verifier.historical_bytes(path, current)
    assert before != current
    assert verifier.historical_test_bytes(current) == before
    assert verifier.current_test_bytes(before) == current
    assert verifier.current_test_bytes(before + b" ") == before + b" "
    linux_before = linux.historical_bytes(path, current)
    assert linux.current_test_bytes(linux_before) == current
    performance_before = performance.historical_bytes(path, current)
    assert performance.current_test_bytes(performance_before) == current
    runner_before = runner.historical_bytes(path, current)
    assert runner.current_test_bytes(runner_before) == current
    roadmap_before = roadmap.historical_bytes(path, current)
    assert roadmap.current_test_bytes(roadmap_before) == current
    with pytest.raises(ValueError, match="unreviewed current source"):
        verifier.historical_bytes(path, current + b" ")


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "linux_old", "performance_old", "runner_old", "roadmap_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = verifier.regular_bytes(path)
    before = verifier.historical_bytes(path, raw)
    current_packets = packets()
    layer = layer_packets()
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_linux = linux.historical_bytes(roadmap.MASTER_PATH, master_raw)
    old_performance = performance.historical_bytes(roadmap.MASTER_PATH, master_raw)
    old_runner = runner.historical_bytes(roadmap.MASTER_PATH, master_raw)
    old_roadmap = roadmap.historical_bytes(roadmap.MASTER_PATH, roadmap.regular_bytes(roadmap.MASTER_PATH))
    calls = {
        "authority": verifier.authority,
        "changed": lambda: verifier.historical_bytes(path, raw),
        "old_bytes": lambda: verifier.historical_bytes(path, before),
        "unchanged": lambda: verifier.historical_bytes("architecture/repositories.yaml", b"unrelated"),
        "historical_test": lambda: verifier.historical_test_bytes(raw),
        "current_test": lambda: verifier.current_test_bytes(before),
        "catalog": lambda: verifier.historical_catalog(current_packets),
        "payloads": lambda: verifier.validate_packet_payloads(layer),
        "linux_old": lambda: linux.historical_bytes(roadmap.MASTER_PATH, old_linux),
        "performance_old": lambda: performance.historical_bytes(roadmap.MASTER_PATH, old_performance),
        "runner_old": lambda: runner.historical_bytes(roadmap.MASTER_PATH, old_runner),
        "roadmap_old": lambda: roadmap.historical_bytes(roadmap.MASTER_PATH, old_roadmap),
    }
    calls[route]()
    original = verifier.regular_bytes

    def changed_reader(relative):
        value = original(relative)
        return value + b" " if relative == verifier.AUTHORITY_PATH else value

    monkeypatch.setattr(verifier, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="owner verifier history authority digest"):
        calls[route]()


def test_catalog_uses_only_pinned_parsed_data_and_checks_each_input_again(monkeypatch):
    current = layer_packets()
    verifier._packet_rules()

    def unexpected_yaml(_raw):
        pytest.fail("catalog projection must not reparse every predecessor YAML")

    monkeypatch.setattr(verifier, "safe_load", unexpected_yaml)
    assert verifier.validate_packet_payloads(current) is None
    current["MET-001"]["objective"] += " changed after a successful call"
    with pytest.raises(ValueError, match="changed packet payload"):
        verifier.validate_packet_payloads(current)


def test_historical_catalog_reuses_frozen_packet_pins_but_rechecks_authority(monkeypatch):
    current = packets()

    def unexpected(*_args, **_kwargs):
        pytest.fail("historical traversal must not reparse authority or packet YAML")

    monkeypatch.setattr(verifier, "authority", unexpected)
    monkeypatch.setattr(verifier, "safe_load", unexpected)
    assert len(verifier.historical_catalog(current)) == 192


def test_historical_catalog_does_not_initialize_predecessor_packet_rules(monkeypatch):
    current = packets()
    verifier._packet_rules_for.cache_clear()
    original = verifier.regular_bytes
    packet_reads = []

    def counted(path):
        if path.startswith("task-packets/"):
            packet_reads.append(path)
        return original(path)

    monkeypatch.setattr(verifier, "regular_bytes", counted)
    assert len(verifier.historical_catalog(current)) == 192
    assert packet_reads == ["task-packets/" + verifier.NEW_PACKET + ".yaml"]
    assert verifier._packet_rules_for.cache_info().currsize == 0


def test_full_packet_expectations_initialize_once_and_remain_immutable(monkeypatch):
    verifier._packet_rules_for.cache_clear()
    original = verifier.safe_load
    parsed = []

    def counted(raw):
        parsed.append(raw)
        return original(raw)

    monkeypatch.setattr(verifier, "safe_load", counted)
    rules = verifier._packet_rules()
    assert len(rules) == 193 and len(parsed) == 192
    assert verifier._packet_rules() is rules and len(parsed) == 192
    with pytest.raises(TypeError):
        rules["MET-001"] = ("0" * 64, "0" * 64)


def test_first_full_packet_check_refuses_changed_old_yaml(monkeypatch):
    current = layer_packets()
    verifier._packet_rules_for.cache_clear()
    original = verifier.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == "task-packets/MET-001.yaml" else raw

    monkeypatch.setattr(verifier, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="packet YAML drift: MET-001"):
        verifier.validate_packet_payloads(current)
    assert verifier._packet_rules_for.cache_info().currsize == 0


def test_cached_expected_rules_do_not_cache_payload_or_authority_verdict(monkeypatch):
    current = layer_packets()
    verifier.validate_packet_payloads(current)
    current["MET-001"]["objective"] += " unreviewed"
    with pytest.raises(ValueError, match="changed packet payload: MET-001"):
        verifier.validate_packet_payloads(current)
    original = verifier.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == verifier.AUTHORITY_PATH else raw

    monkeypatch.setattr(verifier, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="owner verifier history authority digest"):
        verifier.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    verifier.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "owner-verifier-authority.json").write_bytes(
        verifier.regular_bytes(verifier.AUTHORITY_PATH))
    (tmp_path / "task-packets").mkdir()
    monkeypatch.setattr(verifier, "ROOT", tmp_path)
    with pytest.raises(FileNotFoundError):
        verifier.validate_packet_payloads(current)


@pytest.mark.parametrize("fault", ["opaque", "cycle", "changed"])
def test_historical_traversal_leaves_predecessor_refusal_to_its_owner(fault):
    current = packets()
    if fault == "opaque":
        current["MET-001"] = object()
    elif fault == "cycle":
        cycle = {}
        cycle["self"] = cycle
        current["MET-001"] = cycle
    else:
        current["MET-001"]["objective"] += " changed"
    previous = verifier.historical_catalog(current)
    assert previous["MET-001"] is current["MET-001"]
    with pytest.raises(ValueError, match="changed packet payload"):
        verifier.validate_packet_payloads(verifier.successor.historical_catalog(current))


@pytest.mark.parametrize("fault", ["payload", "yaml"])
def test_historical_traversal_freshly_checks_its_own_packet(monkeypatch, fault):
    current = packets()
    if fault == "payload":
        current[verifier.NEW_PACKET]["objective"] += " changed"
    else:
        original = verifier.regular_bytes

        def changed_reader(path):
            raw = original(path)
            return raw + b" " if path == "task-packets/" + verifier.NEW_PACKET + ".yaml" else raw

        monkeypatch.setattr(verifier, "regular_bytes", changed_reader)
    with pytest.raises(ValueError):
        verifier.historical_catalog(current)


def test_validator_checks_current_disk_packet_bytes_after_parsing(monkeypatch):
    original = verifier.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == "task-packets/MET-001.yaml" else raw

    monkeypatch.setattr(verifier, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="packet YAML drift"):
        verifier.validate()


@pytest.mark.parametrize("mutation", ["append", "duplicate_literal"])
def test_normalized_validator_pin_rejects_source_mutation(monkeypatch, mutation):
    original = verifier.regular_bytes

    def changed_reader(path):
        raw = original(path)
        if path == verifier.VALIDATOR_PATH:
            raw += (b"\n# unreviewed\n" if mutation == "append" else
                    b'\nAUTHORITY_SHA256 = "' + verifier.AUTHORITY_SHA256.encode() + b'"\n')
        return raw

    monkeypatch.setattr(verifier, "regular_bytes", changed_reader)
    # The newer MET-PERF-029 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_owner_verifier.py"):
        verifier.validate()


@pytest.mark.parametrize("fault", ["duplicate", "boolean", "negative", "out_of_bounds", "encoding", "empty", "overlap"])
def test_inverse_parser_refuses_ambiguous_or_unbounded_hunks(monkeypatch, fault):
    record = deepcopy(verifier.authority())
    path = next(iter(record["changedFiles"]))
    hunks = record["changedFiles"][path]["reverseHunks"]
    if fault == "duplicate":
        hunks.insert(0, deepcopy(hunks[0]))
    elif fault == "boolean":
        hunks[0]["at"] = True
    elif fault == "negative":
        hunks[0]["at"] = -1
    elif fault == "out_of_bounds":
        hunks[0]["at"] = verifier.MAX_FILE_BYTES + 1
    elif fault == "encoding":
        hunks[0]["insertBase64"] += "!"
    elif fault == "empty":
        hunks[0]["insertBase64"] = hunks[0]["removeBase64"]
    else:
        hunks[:] = [{"at": 0, "removeBase64": "YWJj", "insertBase64": "eA=="},
                    {"at": 1, "removeBase64": "Yg==", "insertBase64": "eQ=="}]
    monkeypatch.setattr(verifier, "authority", lambda: record)
    with pytest.raises(ValueError):
        verifier._rules()


def test_inverse_rules_and_packet_expectations_are_immutable():
    path = next(iter(verifier._PROJECTION_RULES))
    with pytest.raises(TypeError):
        verifier._PROJECTION_RULES[path] = {}
    with pytest.raises(TypeError):
        verifier._PROJECTION_RULES[path]["afterSha256"] = "0" * 64
    with pytest.raises(TypeError):
        verifier._PACKET_BYTE_RULES["MET-001"] = "0" * 64
    with pytest.raises(TypeError):
        verifier._packet_rules()["MET-001"] = ("0" * 64, "0" * 64)
    raw = verifier.regular_bytes(path)
    with pytest.raises(ValueError, match="inverse hunk current bytes"):
        verifier._inverse(raw, ((0, b"not-current", b"old"),))
    with pytest.raises(ValueError, match="inverse hunk bounds"):
        verifier._inverse(raw, ((len(raw) + 1, b"", b"old"),))


def test_ambiguous_test_projections_are_refused(monkeypatch):
    path = changed_test()
    current = verifier.regular_bytes(path)
    before = verifier.historical_bytes(path, current)
    rules = dict(verifier._PROJECTION_RULES)
    rules["tests/ambiguous_unreviewed.py"] = rules[path]
    monkeypatch.setattr(verifier, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="ambiguous current test"):
        verifier.historical_test_bytes(current)
    with pytest.raises(ValueError, match="ambiguous predecessor test"):
        verifier.current_test_bytes(before)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_authority_parser_rejects_duplicate_and_nonfinite_data(raw):
    with pytest.raises(ValueError):
        verifier.parse(raw)


@pytest.mark.parametrize("route", [verifier.historical_test_bytes, verifier.current_test_bytes])
def test_mutable_test_input_is_refused(route):
    with pytest.raises(ValueError, match="test bytes required"):
        route(bytearray(b"mutable"))


@pytest.mark.parametrize("path", ["/absolute", "../outside", "a/../b", "a//b", "a\\b", "a\nb"])
def test_untrusted_source_paths_are_refused(path):
    with pytest.raises(ValueError, match="relative source path"):
        verifier.historical_bytes(path, b"input")


def test_unlinked_bounded_source_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "ROOT", tmp_path)
    original = tmp_path / "plain"
    original.write_bytes(b"source")
    assert verifier.regular_bytes("plain") == b"source"
    (tmp_path / "alias").symlink_to(original)
    with pytest.raises(ValueError, match="bounded regular source file"):
        verifier.regular_bytes("alias")
    os.link(original, tmp_path / "hardlink")
    with pytest.raises(ValueError, match="bounded regular source file"):
        verifier.regular_bytes("plain")
    (tmp_path / "outside").mkdir()
    (tmp_path / "ancestor").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ValueError, match="linked source ancestor"):
        verifier.regular_bytes("ancestor/file")


def test_source_read_detects_concurrent_change(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "ROOT", tmp_path)
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
        verifier.regular_bytes("plain")


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

    for path in verifier._PROJECTION_RULES:
        if path.startswith("tests/") and path.endswith(".py"):
            current = verifier.regular_bytes(path)
            before = verifier.historical_bytes(path, current)
            assert identities(before) <= identities(current), path


def test_new_projection_has_no_predecessor_validator_import():
    tree = ast.parse(verifier.regular_bytes(verifier.VALIDATOR_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert "validate_" not in (node.module or "")
        elif isinstance(node, ast.Import):
            # Only the newer successor layer may be imported, never a predecessor.
            assert all("validate_" not in alias.name or alias.name == "validate_linear_history_rechecks"
                       for alias in node.names)
