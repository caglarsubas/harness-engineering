"""Exact source lineage for MET-SECTOR-001; owner decision SECTOR-D1 records banking, nothing built."""
import ast
import json
import re
from copy import deepcopy
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_sector_direction as profile
from scripts import validate_selinux_matrix as sprofile
from scripts import validate_i07_policy_write as wprofile
from scripts import validate_projection_reuse as rprofile
from scripts import validate_i05_gate_channel as gprofile
from scripts import validate_i06_backend_profile as iprofile
from scripts import validate_native_profile_v2 as nprofile
from scripts import validate_host_interface_resolution as resolution
from scripts import validate_dedicated_verifier_account as account
from scripts import validate_isolated_network_canary as canary
from scripts import validate_isolated_offline_runner as isolated
from scripts import validate_portable_warm_snapshot_temp as portable
from scripts import validate_in_session_predecessor_proof as proof
from scripts import validate_linear_history_rechecks as recheck
from scripts import validate_owner_verifier as verifier
from scripts import validate_linux_runner_contract as linux
from scripts import validate_packet_schema_performance as performance
from scripts import validate_ci_runner_admission as runner
from scripts import validate_unified_roadmap as roadmap
from scripts.safe_yaml import safe_load


def packets():
    return {path.stem: safe_load(path.read_bytes())
            for path in (profile.ROOT / "task-packets").glob("*.yaml")}


def layer_packets():
    # The newer MET-PERF-032 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 213 and len(accepted) == 206
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET,
                                            profile.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.NEW_PACKET}
    assert len(sprofile.historical_catalog(current)) == 205
    assert len(wprofile.historical_catalog(current)) == 204
    assert len(rprofile.historical_catalog(current)) == 203
    assert len(gprofile.historical_catalog(current)) == 202
    assert len(iprofile.historical_catalog(current)) == 201
    assert len(nprofile.historical_catalog(current)) == 200
    assert len(resolution.historical_catalog(current)) == 199
    assert len(account.historical_catalog(current)) == 198
    assert len(canary.historical_catalog(current)) == 197
    assert len(isolated.historical_catalog(current)) == 196
    assert len(portable.historical_catalog(current)) == 195
    assert len(proof.historical_catalog(current)) == 194
    assert len(recheck.historical_catalog(current)) == 193
    assert len(verifier.historical_catalog(current)) == 192
    assert len(linux.historical_catalog(current)) == 191
    assert len(performance.historical_catalog(current)) == 190
    assert len(runner.historical_catalog(current)) == 189
    assert len(roadmap.historical_catalog(current)) == 188
    for name, expected in profile.authority()["baselinePackets"].items():
        assert profile.digest(profile.regular_bytes("task-packets/" + name + ".yaml")) == expected
    for path, rule in profile._PROJECTION_RULES.items():
        raw = profile.successor.historical_bytes(path, profile.regular_bytes(path))
        assert profile.digest(raw) == rule["afterSha256"]
        before = profile.historical_bytes(path, raw)
        assert profile.digest(before) == rule["beforeSha256"]
        assert profile.historical_bytes(path, before) == before


@pytest.mark.parametrize("fault", ["missing_new", "missing_old", "extra", "new_payload", "old_payload", "projected"])
def test_catalog_refuses_all_packet_substitution_and_loss(fault):
    current = deepcopy(layer_packets())
    if fault == "missing_new":
        current.pop(profile.NEW_PACKET)
    elif fault == "missing_old":
        current.pop("MET-RUNNER-001")
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    elif fault == "projected":
        current = profile.historical_catalog(deepcopy(packets()))
    else:
        name = profile.NEW_PACKET if fault == "new_payload" else "MET-001"
        current[name]["objective"] += " unreviewed"
    with pytest.raises(ValueError):
        profile.validate_packet_payloads(current)


def test_every_predecessor_payload_is_checked_without_a_verdict_cache():
    current = layer_packets()
    profile.validate_packet_payloads(current)
    for name in sorted(profile.authority()["baselinePackets"]):
        original = current[name]
        current[name] = dict(original, objective=original["objective"] + " unreviewed")
        with pytest.raises(ValueError, match="changed packet payload"):
            profile.validate_packet_payloads(current)
        current[name] = original


def test_acceptance_retains_every_inherited_command_and_wrapper():
    current = packets()
    packet, predecessor = current[profile.NEW_PACKET], current[profile.PREVIOUS_PACKET]
    commands = packet["offlineAcceptanceCommands"]
    assert len(commands) == 64 and commands == predecessor["offlineAcceptanceCommands"]
    assert not any(profile.VALIDATOR_PATH in argv for argv in commands)
    assert commands[-2][-3:] == ["tests", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]
    assert packet["offlineExecution"] == predecessor["offlineExecution"]
    assert packet["sourceReuse"] == packet["prefetchCommands"] == []
    assert "liveCampaignExecution" not in packet


def test_exact_inverse_and_forward_test_round_trip_across_layers():
    path = changed_test()
    current = profile.regular_bytes(path)
    before = profile.historical_bytes(path, current)
    assert before != current
    assert profile.historical_test_bytes(current) == before
    assert profile.current_test_bytes(before) == current
    assert profile.current_test_bytes(before + b" ") == before + b" "
    sprofile_before = sprofile.historical_bytes(path, current)
    assert sprofile.current_test_bytes(sprofile_before) == current
    wprofile_before = wprofile.historical_bytes(path, current)
    assert wprofile.current_test_bytes(wprofile_before) == current
    rprofile_before = rprofile.historical_bytes(path, current)
    assert rprofile.current_test_bytes(rprofile_before) == current
    gprofile_before = gprofile.historical_bytes(path, current)
    assert gprofile.current_test_bytes(gprofile_before) == current
    iprofile_before = iprofile.historical_bytes(path, current)
    assert iprofile.current_test_bytes(iprofile_before) == current
    nprofile_before = nprofile.historical_bytes(path, current)
    assert nprofile.current_test_bytes(nprofile_before) == current
    resolution_before = resolution.historical_bytes(path, current)
    assert resolution.current_test_bytes(resolution_before) == current
    account_before = account.historical_bytes(path, current)
    assert account.current_test_bytes(account_before) == current
    canary_before = canary.historical_bytes(path, current)
    assert canary.current_test_bytes(canary_before) == current
    isolated_before = isolated.historical_bytes(path, current)
    assert isolated.current_test_bytes(isolated_before) == current
    portable_before = portable.historical_bytes(path, current)
    assert portable.current_test_bytes(portable_before) == current
    proof_before = proof.historical_bytes(path, current)
    assert proof.current_test_bytes(proof_before) == current
    recheck_before = recheck.historical_bytes(path, current)
    assert recheck.current_test_bytes(recheck_before) == current
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
        profile.historical_bytes(path, current + b" ")


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "sprofile_old", "wprofile_old", "rprofile_old", "gprofile_old", "iprofile_old", "nprofile_old", "resolution_old", "account_old", "canary_old", "isolated_old", "portable_old", "proof_old", "recheck_old", "verifier_old", "linux_old", "performance_old", "runner_old", "roadmap_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_sprofile = sprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sprofile_old" else None
    old_wprofile = wprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "wprofile_old" else None
    old_rprofile = rprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "rprofile_old" else None
    old_gprofile = gprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "gprofile_old" else None
    old_iprofile = iprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "iprofile_old" else None
    old_nprofile = nprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "nprofile_old" else None
    old_resolution = resolution.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "resolution_old" else None
    old_account = account.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "account_old" else None
    old_canary = canary.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "canary_old" else None
    old_isolated = isolated.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "isolated_old" else None
    old_portable = portable.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "portable_old" else None
    old_proof = proof.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "proof_old" else None
    old_recheck = recheck.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "recheck_old" else None
    old_verifier = verifier.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "verifier_old" else None
    old_linux = linux.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "linux_old" else None
    old_performance = performance.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "performance_old" else None
    old_runner = runner.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "runner_old" else None
    old_roadmap = roadmap.historical_bytes(roadmap.MASTER_PATH, roadmap.regular_bytes(roadmap.MASTER_PATH)) if route == "roadmap_old" else None
    calls = {
        "authority": profile.authority,
        "changed": lambda: profile.historical_bytes(path, raw),
        "old_bytes": lambda: profile.historical_bytes(path, before),
        "unchanged": lambda: profile.historical_bytes("architecture/repositories.yaml", b"unrelated"),
        "historical_test": lambda: profile.historical_test_bytes(raw),
        "current_test": lambda: profile.current_test_bytes(before),
        "catalog": lambda: profile.historical_catalog(current_packets),
        "payloads": lambda: profile.validate_packet_payloads(layer),
        "sprofile_old": lambda: sprofile.historical_bytes(roadmap.MASTER_PATH, old_sprofile),
        "wprofile_old": lambda: wprofile.historical_bytes(roadmap.MASTER_PATH, old_wprofile),
        "rprofile_old": lambda: rprofile.historical_bytes(roadmap.MASTER_PATH, old_rprofile),
        "gprofile_old": lambda: gprofile.historical_bytes(roadmap.MASTER_PATH, old_gprofile),
        "iprofile_old": lambda: iprofile.historical_bytes(roadmap.MASTER_PATH, old_iprofile),
        "nprofile_old": lambda: nprofile.historical_bytes(roadmap.MASTER_PATH, old_nprofile),
        "resolution_old": lambda: resolution.historical_bytes(roadmap.MASTER_PATH, old_resolution),
        "account_old": lambda: account.historical_bytes(roadmap.MASTER_PATH, old_account),
        "canary_old": lambda: canary.historical_bytes(roadmap.MASTER_PATH, old_canary),
        "isolated_old": lambda: isolated.historical_bytes(roadmap.MASTER_PATH, old_isolated),
        "portable_old": lambda: portable.historical_bytes(roadmap.MASTER_PATH, old_portable),
        "proof_old": lambda: proof.historical_bytes(roadmap.MASTER_PATH, old_proof),
        "recheck_old": lambda: recheck.historical_bytes(roadmap.MASTER_PATH, old_recheck),
        "verifier_old": lambda: verifier.historical_bytes(roadmap.MASTER_PATH, old_verifier),
        "linux_old": lambda: linux.historical_bytes(roadmap.MASTER_PATH, old_linux),
        "performance_old": lambda: performance.historical_bytes(roadmap.MASTER_PATH, old_performance),
        "runner_old": lambda: runner.historical_bytes(roadmap.MASTER_PATH, old_runner),
        "roadmap_old": lambda: roadmap.historical_bytes(roadmap.MASTER_PATH, old_roadmap),
    }
    calls[route]()
    original = profile.regular_bytes

    def changed_reader(relative):
        value = original(relative)
        return value + b" " if relative == profile.AUTHORITY_PATH else value

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="sector direction history authority digest"):
        calls[route]()


def test_catalog_uses_only_pinned_parsed_data_and_checks_each_input_again(monkeypatch):
    current = layer_packets()
    profile._packet_rules()

    def unexpected_yaml(_raw):
        pytest.fail("catalog projection must not reparse every predecessor YAML")

    monkeypatch.setattr(profile, "safe_load", unexpected_yaml)
    assert profile.validate_packet_payloads(current) is None
    current["MET-001"]["objective"] += " changed after a successful call"
    with pytest.raises(ValueError, match="changed packet payload"):
        profile.validate_packet_payloads(current)


def test_historical_catalog_reuses_frozen_packet_pins_but_rechecks_authority(monkeypatch):
    current = packets()

    def unexpected(*_args, **_kwargs):
        pytest.fail("historical traversal must not reparse authority or packet YAML")

    monkeypatch.setattr(profile, "authority", unexpected)
    monkeypatch.setattr(profile, "safe_load", unexpected)
    assert len(profile.historical_catalog(current)) == 206


def test_historical_catalog_does_not_initialize_predecessor_packet_rules(monkeypatch):
    current = packets()
    profile._packet_rules_for.cache_clear()
    original = profile.regular_bytes
    packet_reads = []

    def counted(path):
        if path.startswith("task-packets/"):
            packet_reads.append(path)
        return original(path)

    monkeypatch.setattr(profile, "regular_bytes", counted)
    assert len(profile.historical_catalog(current)) == 206
    assert packet_reads == ["task-packets/" + profile.NEW_PACKET + ".yaml"]
    assert profile._packet_rules_for.cache_info().currsize == 0


def test_full_packet_expectations_initialize_once_and_remain_immutable(monkeypatch):
    profile._packet_rules_for.cache_clear()
    original = profile.safe_load
    parsed = []

    def counted(raw):
        parsed.append(raw)
        return original(raw)

    monkeypatch.setattr(profile, "safe_load", counted)
    rules = profile._packet_rules()
    assert len(rules) == 207 and len(parsed) == 206
    assert profile._packet_rules() is rules and len(parsed) == 206
    with pytest.raises(TypeError):
        rules["MET-001"] = ("0" * 64, "0" * 64)


def test_first_full_packet_check_refuses_changed_old_yaml(monkeypatch):
    current = layer_packets()
    profile._packet_rules_for.cache_clear()
    original = profile.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == "task-packets/MET-001.yaml" else raw

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="packet YAML drift: MET-001"):
        profile.validate_packet_payloads(current)
    assert profile._packet_rules_for.cache_info().currsize == 0


def test_cached_expected_rules_do_not_cache_payload_or_authority_verdict(monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    current["MET-001"]["objective"] += " unreviewed"
    with pytest.raises(ValueError, match="changed packet payload: MET-001"):
        profile.validate_packet_payloads(current)
    original = profile.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == profile.AUTHORITY_PATH else raw

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="sector direction history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "sector-direction-authority.json").write_bytes(
        profile.regular_bytes(profile.AUTHORITY_PATH))
    (tmp_path / "task-packets").mkdir()
    monkeypatch.setattr(profile, "ROOT", tmp_path)
    with pytest.raises(FileNotFoundError):
        profile.validate_packet_payloads(current)


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
    previous = profile.historical_catalog(current)
    assert previous["MET-001"] is current["MET-001"]
    with pytest.raises(ValueError, match="changed packet payload"):
        profile.validate_packet_payloads(profile.successor.historical_catalog(current))


@pytest.mark.parametrize("fault", ["payload", "yaml"])
def test_historical_traversal_freshly_checks_its_own_packet(monkeypatch, fault):
    current = packets()
    if fault == "payload":
        current[profile.NEW_PACKET]["objective"] += " changed"
    else:
        original = profile.regular_bytes

        def changed_reader(path):
            raw = original(path)
            return raw + b" " if path == "task-packets/" + profile.NEW_PACKET + ".yaml" else raw

        monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError):
        profile.historical_catalog(current)


def test_validator_checks_current_disk_packet_bytes_after_parsing(monkeypatch):
    original = profile.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == "task-packets/MET-001.yaml" else raw

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="packet YAML drift"):
        profile.validate()


@pytest.mark.parametrize("mutation", ["append", "duplicate_literal"])
def test_normalized_validator_pin_rejects_source_mutation(monkeypatch, mutation):
    original = profile.regular_bytes

    def changed_reader(path):
        raw = original(path)
        if path == profile.VALIDATOR_PATH:
            raw += (b"\n# unreviewed\n" if mutation == "append" else
                    b'\nAUTHORITY_SHA256 = "' + profile.AUTHORITY_SHA256.encode() + b'"\n')
        return raw

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    # The newer MET-PERF-032 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_sector_direction.py"):
        profile.validate()


@pytest.mark.parametrize("fault", ["duplicate", "boolean", "negative", "out_of_bounds", "encoding", "empty", "overlap"])
def test_inverse_parser_refuses_ambiguous_or_unbounded_hunks(monkeypatch, fault):
    record = deepcopy(profile.authority())
    path = next(iter(record["changedFiles"]))
    hunks = record["changedFiles"][path]["reverseHunks"]
    if fault == "duplicate":
        hunks.insert(0, deepcopy(hunks[0]))
    elif fault == "boolean":
        hunks[0]["at"] = True
    elif fault == "negative":
        hunks[0]["at"] = -1
    elif fault == "out_of_bounds":
        hunks[0]["at"] = profile.MAX_FILE_BYTES + 1
    elif fault == "encoding":
        hunks[0]["insertBase64"] += "!"
    elif fault == "empty":
        hunks[0]["insertBase64"] = hunks[0]["removeBase64"]
    else:
        hunks[:] = [{"at": 0, "removeBase64": "YWJj", "insertBase64": "eA=="},
                    {"at": 1, "removeBase64": "Yg==", "insertBase64": "eQ=="}]
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError):
        profile._rules()


def test_inverse_rules_and_packet_expectations_are_immutable():
    path = next(iter(profile._PROJECTION_RULES))
    with pytest.raises(TypeError):
        profile._PROJECTION_RULES[path] = {}
    with pytest.raises(TypeError):
        profile._PROJECTION_RULES[path]["afterSha256"] = "0" * 64
    with pytest.raises(TypeError):
        profile._PACKET_BYTE_RULES["MET-001"] = "0" * 64
    with pytest.raises(TypeError):
        profile._packet_rules()["MET-001"] = ("0" * 64, "0" * 64)
    raw = profile.regular_bytes(path)
    with pytest.raises(ValueError, match="inverse hunk current bytes"):
        profile._inverse(raw, ((0, b"not-current", b"old"),))
    with pytest.raises(ValueError, match="inverse hunk bounds"):
        profile._inverse(raw, ((len(raw) + 1, b"", b"old"),))


def test_ambiguous_test_projections_are_refused(monkeypatch):
    path = changed_test()
    current = profile.regular_bytes(path)
    before = profile.historical_bytes(path, current)
    rules = dict(profile._PROJECTION_RULES)
    rules["tests/ambiguous_unreviewed.py"] = rules[path]
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="ambiguous current test"):
        profile.historical_test_bytes(current)
    with pytest.raises(ValueError, match="ambiguous predecessor test"):
        profile.current_test_bytes(before)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_authority_parser_rejects_duplicate_and_nonfinite_data(raw):
    with pytest.raises(ValueError):
        profile.parse(raw)


@pytest.mark.parametrize("route", [profile.historical_test_bytes, profile.current_test_bytes])
def test_mutable_test_input_is_refused(route):
    with pytest.raises(ValueError, match="test bytes required"):
        route(bytearray(b"mutable"))


@pytest.mark.parametrize("path", ["/absolute", "../outside", "a/../b", "a//b", "a\\b", "a\nb"])
def test_untrusted_source_paths_are_refused(path):
    with pytest.raises(ValueError, match="relative source path"):
        profile.historical_bytes(path, b"input")


def test_unlinked_bounded_source_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(profile, "ROOT", tmp_path)
    original = tmp_path / "plain"
    original.write_bytes(b"source")
    assert profile.regular_bytes("plain") == b"source"
    (tmp_path / "alias").symlink_to(original)
    with pytest.raises(ValueError, match="bounded regular source file"):
        profile.regular_bytes("alias")
    os.link(original, tmp_path / "hardlink")
    with pytest.raises(ValueError, match="bounded regular source file"):
        profile.regular_bytes("plain")
    (tmp_path / "outside").mkdir()
    (tmp_path / "ancestor").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ValueError, match="linked source ancestor"):
        profile.regular_bytes("ancestor/file")


def test_source_read_detects_concurrent_change(tmp_path, monkeypatch):
    monkeypatch.setattr(profile, "ROOT", tmp_path)
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
        profile.regular_bytes("plain")


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

    for path in profile._PROJECTION_RULES:
        if path.startswith("tests/") and path.endswith(".py"):
            current = profile.regular_bytes(path)
            before = profile.historical_bytes(path, current)
            assert identities(before) <= identities(current), path


def test_new_projection_has_no_predecessor_validator_import():
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert "validate_" not in (node.module or "")
        elif isinstance(node, ast.Import):
            # Only the newer successor layer may be imported, never a predecessor.
            assert all("validate_" not in alias.name or alias.name == "validate_verify_headroom"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    raw = profile.regular_bytes(path)
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


def _era():
    # This packet's reviewed bytes through the validator's own reviewed_era (bridged by a newer layer).
    record = profile.authority()
    return record, profile.reviewed_era(record)


def _with_sector(era, change):
    value = json.loads(era[profile.SECTOR_PATH])
    change(value)
    changed = dict(era)
    changed[profile.SECTOR_PATH] = json.dumps(value).encode("utf-8")
    return changed


def _successor(sector, name):
    return next(row for row in sector["successorProposals"] if row["id"] == name)


def test_decision_record_holds_against_accepted_packets_and_documents():
    record, era = _era()
    assert profile.validate_sector_direction(record, era, packets()) is None
    sector = json.loads(era[profile.SECTOR_PATH])
    assert sector["decision"]["sector"] == "banking" and sector["decision"]["previousSector"] == "white-goods"
    dispositions = sector["publishedPacketDispositions"]
    assert len(dispositions) == 28
    kinds = {}
    for name, row in dispositions.items():
        kinds.setdefault(row["disposition"], set()).add(name)
    assert kinds["ID_RETAINED_SCOPE_RETARGETED"] == {"CONF-A2-001", "CONF-WG-001"}
    assert kinds["SECTOR_FIXTURES_HISTORICAL"] == {"CTRL-002", "CTRL-006", "DIST-004", "KN-DATA-001", "KN-DATA-002",
                                                   "KN-DOM-001", "KN-RET-001"}
    assert kinds["OBLIGATION_TRANSFERRED"] == {"IND-001"} and kinds["HISTORICAL_EVIDENCE"] == {"CONF-002"}
    assert len(kinds["WARM_SOURCE_REFERENCE_ONLY"]) == 11
    assert {row["id"]: row["supersedes"] for row in sector["successorProposals"]} == {
        "IND-BANK-001": "IND-WG-001", "IND-BANK-002": "IND-WG-002", "IND-BANK-003": "IND-WG-003",
        "IND-BANK-004": "IND-WG-004", "IND-BANK-005": "IND-WG-005", "KN-BANK-001": None, "CTRL-BANK-001": None,
        "DIST-BANK-001": None, "CONF-BANK-001": "CONF-A1-001"}
    assert {"CONF-LINUX-001", "CONF-FIX-001", "MET-A2-001", "TRUST-FIX-001", "IND-FIX-001"} \
        <= set(sector["retainedPredecessorEdges"]["dependents"])
    assert set(sector["nonClaims"].values()) == {False}


def test_disposition_set_is_recomputed_from_the_accepted_packet_bytes():
    record, era = _era()
    pattern = re.compile(profile.SECTOR_PATTERN)
    expected = {name for name in record["baselinePackets"]
                if pattern.search(profile.regular_bytes("task-packets/" + name + ".yaml").decode("utf-8"))}
    assert set(json.loads(era[profile.SECTOR_PATH])["publishedPacketDispositions"]) == expected
    for change in (lambda s: s["publishedPacketDispositions"].pop("KN-MEM-001"),
                   lambda s: s["publishedPacketDispositions"].update({"MET-001": {
                       "disposition": "HISTORICAL_EVIDENCE", "note": "unrelated"}})):
        with pytest.raises(ValueError, match="exactly one disposition"):
            profile.validate_sector_direction(record, _with_sector(era, change), packets())


@pytest.mark.parametrize("change,message", [
    (lambda s: s["decision"].update(sector="white-goods"), "owner decision SECTOR-D1"),
    (lambda s: s["decision"].update(appliesThrough="ALPHA_4"), "owner decision SECTOR-D1"),
    (lambda s: s["decision"].update(decidedBy="AGENT"), "owner decision SECTOR-D1"),
    (lambda s: s["decision"].update(statement="White goods stays first; banking later."), "owner decision SECTOR-D1"),
    (lambda s: s["domainSemantic"].update(alphaCapability="White-goods glossary and ontology versions"),
     "banking domain-semantic scope"),
    (lambda s: s.update(detectionPattern="(?i)white goods"), "fixed white-goods detection pattern"),
    (lambda s: s["nonClaims"].update(bankingPackBuilt=True), "cannot overclaim"),
    (lambda s: s["nonClaims"].update(tenantAcceptance=True), "cannot overclaim"),
    (lambda s: s["nonClaims"].pop("catalogChanged"), "cannot overclaim"),
    (lambda s: s["successorProposals"][0].update(executionAuthority="GRANTED"), "without execution authority"),
    (lambda s: s["successorProposals"][0].update(publishedPacket=True), "without execution authority"),
    (lambda s: s["successorProposals"][0].update(id="IND-WG-001"), "new successor identity"),
    (lambda s: s["successorProposals"][1].update(predecessorIds=["IND-BANK-005"]), "earlier successors"),
    (lambda s: s["successorProposals"][0].update(predecessorIds=["IND-WG-001"]), "retained accepted packets"),
    (lambda s: _successor(s, "CONF-BANK-001")["predecessorIds"].append("CONF-A1-001"), "retained accepted packets"),
    (lambda s: s["successorProposals"].pop(), "names its successor"),
    (lambda s: _successor(s, "KN-BANK-001")["replacesInputsOf"].remove("KN-RET-001"), "banking replacements: KN-RET-001"),
    (lambda s: _successor(s, "CTRL-BANK-001").update(replacesInputsOf=["CTRL-002", "CTRL-006", "KN-MEM-001"]),
     "banking replacements: KN-MEM-001|only historical sector fixtures"),
    (lambda s: _successor(s, "DIST-BANK-001").update(replacesInputsOf=[]), "supersedes a packet or replaces"),
    (lambda s: s["publishedPacketDispositions"].update({"IND-WG-001": {
        "disposition": "WARM_SOURCE_REFERENCE_ONLY", "note": "dropped"}}), "supersedes a packet or replaces|one successor"),
    (lambda s: s["publishedPacketDispositions"].update({"CONF-A2-001": {
        "disposition": "SUPERSEDED_BY_SUCCESSOR", "successor": "IND-BANK-001"}}), "keep their IDs"),
    (lambda s: s["publishedPacketDispositions"].update({"KN-DOM-001": {
        "disposition": "ID_RETAINED_SCOPE_RETARGETED", "newScope": "banking", "requires": "a revision amendment"}}),
     "keep their IDs"),
    (lambda s: s["publishedPacketDispositions"]["CONF-WG-001"].update(requires="none"), "revision amendment"),
    (lambda s: s["publishedPacketDispositions"]["IND-001"].update(transfersTo="IND-WG-001"), "transferred obligation"),
    (lambda s: s["publishedPacketDispositions"].update({"KN-RET-001": {
        "disposition": "WARM_SOURCE_REFERENCE_ONLY", "note": "only an example"}}), "only historical sector fixtures"),
    (lambda s: s["retainedPredecessorEdges"]["dependents"].pop("CONF-LINUX-001"), "accepted edge"),
    (lambda s: s["retainedPredecessorEdges"].update(rule="Superseded packets no longer count."), "accepted edge"),
    (lambda s: s["unchangedAuthorities"].pop("architecture/services.yaml"), "closed unchanged authorities"),
    (lambda s: s["unchangedAuthorities"]["architecture/providers.yaml"].update(sha256="0" * 64), "changed by this packet"),
    (lambda s: s["unchangedAuthorities"]["docs/PROVIDER_MODULE_CATALOG.md"].update(role="SNAPSHOT"),
     "changed by this packet"),
    (lambda s: s["catalogFollowUps"].append({"path": "architecture/taxonomy.yaml", "current": "white-goods",
                                             "proposed": "banking"}), "existing catalog text"),
    (lambda s: s["catalogFollowUps"].append({"path": "architecture/providers.yaml",
                                             "current": "white-goods.nonexistent", "proposed": "banking"}),
     "existing catalog text"),
    (lambda s: s["catalogFollowUps"].pop(), "has a follow-up: docs/PROVIDER_MODULE_CATALOG.md"),
    (lambda s: s["directionDocs"].remove("docs/alpha-2/SECTOR_DIRECTION.md"), "sorted direction documents"),
    (lambda s: s.update(extra=True), "closed sector direction record"),
])
def test_record_cannot_overclaim_or_drop_a_disposition(change, message):
    record, era = _era()
    with pytest.raises(ValueError, match=message):
        profile.validate_sector_direction(record, _with_sector(era, change), packets())


def test_duplicate_or_nonfinite_record_members_are_refused():
    record, era = _era()
    raw = era[profile.SECTOR_PATH]
    for bad, message in ((raw.replace(b'"schemaVersion"', b'"detectionPattern": "x", "schemaVersion"', 1),
                          "duplicate sector direction member"),
                         (raw.replace(b'"date": "2026-10-07"', b'"date": NaN', 1), "nonfinite sector direction number")):
        assert bad != raw
        with pytest.raises(ValueError, match=message):
            profile.validate_sector_direction(record, {**era, profile.SECTOR_PATH: bad}, packets())


def test_master_plan_must_name_banking_as_the_first_sector_pack():
    record, era = _era()
    master = era[profile.MASTER_PATH]
    old = master.replace(b"The first sector pack is banking", b"The first sector pack is white goods", 1)
    assert old != master
    with pytest.raises(ValueError, match="first sector pack"):
        profile.validate_sector_direction(record, {**era, profile.MASTER_PATH: old}, packets())


@pytest.mark.parametrize("path", ["docs/repositories/03-mas-harness-industry-packs.md",
                                  "docs/harnesses/knowledge.domain-semantic.md", "docs/SCOPE_PROVENANCE.md"])
def test_direction_documents_must_carry_the_decision(path):
    record, era = _era()
    assert path in era
    with pytest.raises(ValueError, match="direction document names SECTOR-D1"):
        profile.validate_sector_direction(record, {**era, path: era[path].replace(b"SECTOR-D1", b"SECTOR-XX")},
                                          packets())


def test_a_catalog_entry_without_a_follow_up_is_refused():
    record, era = _era()
    path = "architecture/services.yaml"
    added = era[path] + b"# industry.white-goods-extra\n"
    sector = json.loads(era[profile.SECTOR_PATH])
    sector["unchangedAuthorities"][path]["sha256"] = profile.digest(added)
    changed = {**era, path: added, profile.SECTOR_PATH: json.dumps(sector).encode("utf-8")}
    with pytest.raises(ValueError, match="has a follow-up: architecture/services.yaml"):
        profile.validate_sector_direction(record, changed, packets())


def test_catalogs_snapshots_and_published_packets_stay_untouched():
    record, era = _era()
    sector = json.loads(era[profile.SECTOR_PATH])
    assert set(sector["unchangedAuthorities"]) == set(profile.REQUIRED_UNCHANGED)
    for path, row in sector["unchangedAuthorities"].items():
        assert path not in record["changedFiles"] and path not in record["newFiles"]
        assert profile.digest(era[path]) == row["sha256"]
    assert not any(path.startswith("task-packets/") and path != "task-packets/README.md"
                   for path in record["changedFiles"])
    assert set(record["newFiles"]) == {profile.SECTOR_PATH, profile.SECTOR_DOC, "tests/test_sector_direction.py"}


def test_reviewed_bytes_is_the_only_era_read():
    # A newer layer's bridge wraps reviewed_bytes; every era read must go through it.
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    era = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "reviewed_era")
    calls = {getattr(node.func, "id", "") for node in ast.walk(era) if isinstance(node, ast.Call)}
    assert "reviewed_bytes" in calls and "regular_bytes" not in calls
