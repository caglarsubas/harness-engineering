"""Exact source lineage for MET-PERF-029 and linear authority rechecks; no acceptance claims."""
import ast
from copy import deepcopy
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_linear_history_rechecks as recheck
from scripts import validate_owner_verifier as verifier
from scripts import validate_linux_runner_contract as linux
from scripts import validate_packet_schema_performance as performance
from scripts import validate_ci_runner_admission as runner
from scripts import validate_unified_roadmap as roadmap
from scripts.safe_yaml import safe_load


def packets():
    return {path.stem: safe_load(path.read_bytes())
            for path in (recheck.ROOT / "task-packets").glob("*.yaml")}


def changed_test():
    return next(path for path in recheck._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert recheck.validate() is None
    current = packets()
    accepted = recheck.historical_catalog(current)
    assert len(current) == 194 and len(accepted) == 193
    assert set(accepted) == set(current) - {recheck.NEW_PACKET}
    assert len(verifier.historical_catalog(current)) == 192
    assert len(linux.historical_catalog(current)) == 191
    assert len(performance.historical_catalog(current)) == 190
    assert len(runner.historical_catalog(current)) == 189
    assert len(roadmap.historical_catalog(current)) == 188
    for name, expected in recheck.authority()["baselinePackets"].items():
        assert recheck.digest(recheck.regular_bytes("task-packets/" + name + ".yaml")) == expected
    for path, rule in recheck._PROJECTION_RULES.items():
        raw = recheck.regular_bytes(path)
        assert recheck.digest(raw) == rule["afterSha256"]
        before = recheck.historical_bytes(path, raw)
        assert recheck.digest(before) == rule["beforeSha256"]
        assert recheck.historical_bytes(path, before) == before


@pytest.mark.parametrize("fault", ["missing_new", "missing_old", "extra", "new_payload", "old_payload", "projected"])
def test_catalog_refuses_all_packet_substitution_and_loss(fault):
    current = deepcopy(packets())
    if fault == "missing_new":
        current.pop(recheck.NEW_PACKET)
    elif fault == "missing_old":
        current.pop("MET-RUNNER-001")
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    elif fault == "projected":
        current = recheck.historical_catalog(current)
    else:
        name = recheck.NEW_PACKET if fault == "new_payload" else "MET-001"
        current[name]["objective"] += " unreviewed"
    with pytest.raises(ValueError):
        recheck.validate_packet_payloads(current)


def test_every_predecessor_payload_is_checked_without_a_verdict_cache():
    current = packets()
    recheck.validate_packet_payloads(current)
    for name in sorted(recheck.authority()["baselinePackets"]):
        original = current[name]
        current[name] = dict(original, objective=original["objective"] + " unreviewed")
        with pytest.raises(ValueError, match="changed packet payload"):
            recheck.validate_packet_payloads(current)
        current[name] = original


def test_acceptance_retains_every_inherited_command_and_wrapper():
    current = packets()
    packet, predecessor = current[recheck.NEW_PACKET], current[recheck.PREVIOUS_PACKET]
    commands = packet["offlineAcceptanceCommands"]
    assert len(commands) == 56
    assert commands[:-3] + commands[-2:] == predecessor["offlineAcceptanceCommands"]
    assert commands[-3][-1] == recheck.VALIDATOR_PATH
    assert packet["offlineExecution"] == predecessor["offlineExecution"]
    assert packet["sourceReuse"] == packet["prefetchCommands"] == []
    assert "liveCampaignExecution" not in packet


def test_exact_inverse_and_forward_test_round_trip_across_layers():
    path = changed_test()
    current = recheck.regular_bytes(path)
    before = recheck.historical_bytes(path, current)
    assert before != current
    assert recheck.historical_test_bytes(current) == before
    assert recheck.current_test_bytes(before) == current
    assert recheck.current_test_bytes(before + b" ") == before + b" "
    verifier_before = verifier.historical_bytes(path, current)
    assert verifier.current_test_bytes(verifier_before) == current
    linux_before = linux.historical_bytes(path, current)
    assert linux.current_test_bytes(linux_before) == current
    performance_before = performance.historical_bytes(path, current)
    assert performance.current_test_bytes(performance_before) == current
    runner_before = runner.historical_bytes(path, current)
    assert runner.current_test_bytes(runner_before) == current
    roadmap_before = roadmap.historical_bytes(path, current)
    assert roadmap.current_test_bytes(roadmap_before) == current
    with pytest.raises(ValueError, match="unreviewed current source"):
        recheck.historical_bytes(path, current + b" ")


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "verifier_old", "linux_old", "performance_old", "runner_old", "roadmap_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = recheck.regular_bytes(path)
    before = recheck.historical_bytes(path, raw)
    current_packets = packets()
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_verifier = verifier.historical_bytes(roadmap.MASTER_PATH, master_raw)
    old_linux = linux.historical_bytes(roadmap.MASTER_PATH, master_raw)
    old_performance = performance.historical_bytes(roadmap.MASTER_PATH, master_raw)
    old_runner = runner.historical_bytes(roadmap.MASTER_PATH, master_raw)
    old_roadmap = roadmap.historical_bytes(roadmap.MASTER_PATH, roadmap.regular_bytes(roadmap.MASTER_PATH))
    calls = {
        "authority": recheck.authority,
        "changed": lambda: recheck.historical_bytes(path, raw),
        "old_bytes": lambda: recheck.historical_bytes(path, before),
        "unchanged": lambda: recheck.historical_bytes("architecture/repositories.yaml", b"unrelated"),
        "historical_test": lambda: recheck.historical_test_bytes(raw),
        "current_test": lambda: recheck.current_test_bytes(before),
        "catalog": lambda: recheck.historical_catalog(current_packets),
        "payloads": lambda: recheck.validate_packet_payloads(current_packets),
        "verifier_old": lambda: verifier.historical_bytes(roadmap.MASTER_PATH, old_verifier),
        "linux_old": lambda: linux.historical_bytes(roadmap.MASTER_PATH, old_linux),
        "performance_old": lambda: performance.historical_bytes(roadmap.MASTER_PATH, old_performance),
        "runner_old": lambda: runner.historical_bytes(roadmap.MASTER_PATH, old_runner),
        "roadmap_old": lambda: roadmap.historical_bytes(roadmap.MASTER_PATH, old_roadmap),
    }
    calls[route]()
    original = recheck.regular_bytes

    def changed_reader(relative):
        value = original(relative)
        return value + b" " if relative == recheck.AUTHORITY_PATH else value

    monkeypatch.setattr(recheck, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="linear recheck history authority digest"):
        calls[route]()


def test_catalog_uses_only_pinned_parsed_data_and_checks_each_input_again(monkeypatch):
    current = packets()
    recheck._packet_rules()

    def unexpected_yaml(_raw):
        pytest.fail("catalog projection must not reparse every predecessor YAML")

    monkeypatch.setattr(recheck, "safe_load", unexpected_yaml)
    assert recheck.validate_packet_payloads(current) is None
    current["MET-001"]["objective"] += " changed after a successful call"
    with pytest.raises(ValueError, match="changed packet payload"):
        recheck.validate_packet_payloads(current)


def test_historical_catalog_reuses_frozen_packet_pins_but_rechecks_authority(monkeypatch):
    current = packets()

    def unexpected(*_args, **_kwargs):
        pytest.fail("historical traversal must not reparse authority or packet YAML")

    monkeypatch.setattr(recheck, "authority", unexpected)
    monkeypatch.setattr(recheck, "safe_load", unexpected)
    assert len(recheck.historical_catalog(current)) == 193


def test_historical_catalog_does_not_initialize_predecessor_packet_rules(monkeypatch):
    current = packets()
    recheck._packet_rules_for.cache_clear()
    original = recheck.regular_bytes
    packet_reads = []

    def counted(path):
        if path.startswith("task-packets/"):
            packet_reads.append(path)
        return original(path)

    monkeypatch.setattr(recheck, "regular_bytes", counted)
    assert len(recheck.historical_catalog(current)) == 193
    assert packet_reads == ["task-packets/" + recheck.NEW_PACKET + ".yaml"]
    assert recheck._packet_rules_for.cache_info().currsize == 0


def test_full_packet_expectations_initialize_once_and_remain_immutable(monkeypatch):
    recheck._packet_rules_for.cache_clear()
    original = recheck.safe_load
    parsed = []

    def counted(raw):
        parsed.append(raw)
        return original(raw)

    monkeypatch.setattr(recheck, "safe_load", counted)
    rules = recheck._packet_rules()
    assert len(rules) == 194 and len(parsed) == 193
    assert recheck._packet_rules() is rules and len(parsed) == 193
    with pytest.raises(TypeError):
        rules["MET-001"] = ("0" * 64, "0" * 64)


def test_first_full_packet_check_refuses_changed_old_yaml(monkeypatch):
    current = packets()
    recheck._packet_rules_for.cache_clear()
    original = recheck.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == "task-packets/MET-001.yaml" else raw

    monkeypatch.setattr(recheck, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="packet YAML drift: MET-001"):
        recheck.validate_packet_payloads(current)
    assert recheck._packet_rules_for.cache_info().currsize == 0


def test_cached_expected_rules_do_not_cache_payload_or_authority_verdict(monkeypatch):
    current = packets()
    recheck.validate_packet_payloads(current)
    current["MET-001"]["objective"] += " unreviewed"
    with pytest.raises(ValueError, match="changed packet payload: MET-001"):
        recheck.validate_packet_payloads(current)
    original = recheck.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == recheck.AUTHORITY_PATH else raw

    monkeypatch.setattr(recheck, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="linear recheck history authority digest"):
        recheck.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = packets()
    recheck.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "linear-history-rechecks-authority.json").write_bytes(
        recheck.regular_bytes(recheck.AUTHORITY_PATH))
    (tmp_path / "task-packets").mkdir()
    monkeypatch.setattr(recheck, "ROOT", tmp_path)
    with pytest.raises(FileNotFoundError):
        recheck.validate_packet_payloads(current)


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
    previous = recheck.historical_catalog(current)
    assert previous["MET-001"] is current["MET-001"]
    with pytest.raises(ValueError, match="changed packet payload"):
        recheck.validate_packet_payloads(current)


@pytest.mark.parametrize("fault", ["payload", "yaml"])
def test_historical_traversal_freshly_checks_its_own_packet(monkeypatch, fault):
    current = packets()
    if fault == "payload":
        current[recheck.NEW_PACKET]["objective"] += " changed"
    else:
        original = recheck.regular_bytes

        def changed_reader(path):
            raw = original(path)
            return raw + b" " if path == "task-packets/" + recheck.NEW_PACKET + ".yaml" else raw

        monkeypatch.setattr(recheck, "regular_bytes", changed_reader)
    with pytest.raises(ValueError):
        recheck.historical_catalog(current)


def test_validator_checks_current_disk_packet_bytes_after_parsing(monkeypatch):
    original = recheck.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == "task-packets/MET-001.yaml" else raw

    monkeypatch.setattr(recheck, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="packet YAML drift"):
        recheck.validate()


@pytest.mark.parametrize("mutation", ["append", "duplicate_literal"])
def test_normalized_validator_pin_rejects_source_mutation(monkeypatch, mutation):
    original = recheck.regular_bytes

    def changed_reader(path):
        raw = original(path)
        if path == recheck.VALIDATOR_PATH:
            raw += (b"\n# unreviewed\n" if mutation == "append" else
                    b'\nAUTHORITY_SHA256 = "' + recheck.AUTHORITY_SHA256.encode() + b'"\n')
        return raw

    monkeypatch.setattr(recheck, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="linear recheck validator drift"):
        recheck.validate()


@pytest.mark.parametrize("fault", ["duplicate", "boolean", "negative", "out_of_bounds", "encoding", "empty", "overlap"])
def test_inverse_parser_refuses_ambiguous_or_unbounded_hunks(monkeypatch, fault):
    record = deepcopy(recheck.authority())
    path = next(iter(record["changedFiles"]))
    hunks = record["changedFiles"][path]["reverseHunks"]
    if fault == "duplicate":
        hunks.insert(0, deepcopy(hunks[0]))
    elif fault == "boolean":
        hunks[0]["at"] = True
    elif fault == "negative":
        hunks[0]["at"] = -1
    elif fault == "out_of_bounds":
        hunks[0]["at"] = recheck.MAX_FILE_BYTES + 1
    elif fault == "encoding":
        hunks[0]["insertBase64"] += "!"
    elif fault == "empty":
        hunks[0]["insertBase64"] = hunks[0]["removeBase64"]
    else:
        hunks[:] = [{"at": 0, "removeBase64": "YWJj", "insertBase64": "eA=="},
                    {"at": 1, "removeBase64": "Yg==", "insertBase64": "eQ=="}]
    monkeypatch.setattr(recheck, "authority", lambda: record)
    with pytest.raises(ValueError):
        recheck._rules()


def test_inverse_rules_and_packet_expectations_are_immutable():
    path = next(iter(recheck._PROJECTION_RULES))
    with pytest.raises(TypeError):
        recheck._PROJECTION_RULES[path] = {}
    with pytest.raises(TypeError):
        recheck._PROJECTION_RULES[path]["afterSha256"] = "0" * 64
    with pytest.raises(TypeError):
        recheck._PACKET_BYTE_RULES["MET-001"] = "0" * 64
    with pytest.raises(TypeError):
        recheck._packet_rules()["MET-001"] = ("0" * 64, "0" * 64)
    raw = recheck.regular_bytes(path)
    with pytest.raises(ValueError, match="inverse hunk current bytes"):
        recheck._inverse(raw, ((0, b"not-current", b"old"),))
    with pytest.raises(ValueError, match="inverse hunk bounds"):
        recheck._inverse(raw, ((len(raw) + 1, b"", b"old"),))


def test_ambiguous_test_projections_are_refused(monkeypatch):
    path = changed_test()
    current = recheck.regular_bytes(path)
    before = recheck.historical_bytes(path, current)
    rules = dict(recheck._PROJECTION_RULES)
    rules["tests/ambiguous_unreviewed.py"] = rules[path]
    monkeypatch.setattr(recheck, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="ambiguous current test"):
        recheck.historical_test_bytes(current)
    with pytest.raises(ValueError, match="ambiguous predecessor test"):
        recheck.current_test_bytes(before)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_authority_parser_rejects_duplicate_and_nonfinite_data(raw):
    with pytest.raises(ValueError):
        recheck.parse(raw)


@pytest.mark.parametrize("route", [recheck.historical_test_bytes, recheck.current_test_bytes])
def test_mutable_test_input_is_refused(route):
    with pytest.raises(ValueError, match="test bytes required"):
        route(bytearray(b"mutable"))


@pytest.mark.parametrize("path", ["/absolute", "../outside", "a/../b", "a//b", "a\\b", "a\nb"])
def test_untrusted_source_paths_are_refused(path):
    with pytest.raises(ValueError, match="relative source path"):
        recheck.historical_bytes(path, b"input")


def test_unlinked_bounded_source_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(recheck, "ROOT", tmp_path)
    original = tmp_path / "plain"
    original.write_bytes(b"source")
    assert recheck.regular_bytes("plain") == b"source"
    (tmp_path / "alias").symlink_to(original)
    with pytest.raises(ValueError, match="bounded regular source file"):
        recheck.regular_bytes("alias")
    os.link(original, tmp_path / "hardlink")
    with pytest.raises(ValueError, match="bounded regular source file"):
        recheck.regular_bytes("plain")
    (tmp_path / "outside").mkdir()
    (tmp_path / "ancestor").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ValueError, match="linked source ancestor"):
        recheck.regular_bytes("ancestor/file")


def test_source_read_detects_concurrent_change(tmp_path, monkeypatch):
    monkeypatch.setattr(recheck, "ROOT", tmp_path)
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
        recheck.regular_bytes("plain")


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

    for path in recheck._PROJECTION_RULES:
        if path.startswith("tests/") and path.endswith(".py"):
            current = recheck.regular_bytes(path)
            before = recheck.historical_bytes(path, current)
            assert identities(before) <= identities(current), path


def test_new_projection_has_no_predecessor_validator_import():
    tree = ast.parse(recheck.regular_bytes(recheck.VALIDATOR_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert "validate_" not in (node.module or "")
        elif isinstance(node, ast.Import):
            assert all("validate_" not in alias.name for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (recheck, verifier, linux, performance, runner):
        original = module.regular_bytes

        def counted(relative, _module=module, _original=original):
            if relative == _module.AUTHORITY_PATH:
                counts[_module.__name__] = counts.get(_module.__name__, 0) + 1
            return _original(relative)

        monkeypatch.setattr(module, "regular_bytes", counted)
    return counts


@pytest.mark.parametrize("route", ["changed", "old_bytes", "unchanged", "historical_test", "current_test"])
def test_every_newer_authority_is_read_exactly_once_per_route(monkeypatch, route):
    """Linear rechecks: one fresh complete read of each authority per public call."""
    path = changed_test()
    raw = recheck.regular_bytes(path)
    before = runner.historical_bytes(path, raw)
    counts = _count_authority_reads(monkeypatch)
    calls = {
        "changed": lambda: runner.historical_bytes(path, raw),
        "old_bytes": lambda: runner.historical_bytes(path, before),
        "unchanged": lambda: runner.historical_bytes("architecture/repositories.yaml", b"unrelated"),
        "historical_test": lambda: runner.historical_test_bytes(raw),
        "current_test": lambda: runner.current_test_bytes(before),
    }
    calls[route]()
    expected = {module.__name__: 1 for module in (recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected
