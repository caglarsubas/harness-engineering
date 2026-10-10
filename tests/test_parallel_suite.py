"""Exact source lineage for MET-PERF-035; the parallel-suite changes keep every validator and refusal."""
import ast
import json
from copy import deepcopy
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_parallel_suite as profile
from scripts import validate_selinux_matrix_v2 as yprofile
from scripts import validate_admission_channel_v3 as xprofile
from scripts import validate_i07_policy_write_v2 as pprofile
from scripts import validate_admission_semantics_v2 as aprofile
from scripts import validate_i06_backend_profile_v2 as vprofile
from scripts import validate_i05_gate_channel_v2 as cprofile
from scripts import validate_native_profile_v3 as qprofile
from scripts import validate_verify_headroom as hprofile
from scripts import validate_sector_direction as dprofile
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
    # The newer MET-PERF-036 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 225 and len(accepted) == 215
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET,
                                            profile.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
    assert len(yprofile.historical_catalog(current)) == 214
    assert len(xprofile.historical_catalog(current)) == 213
    assert len(pprofile.historical_catalog(current)) == 212
    assert len(aprofile.historical_catalog(current)) == 211
    assert len(vprofile.historical_catalog(current)) == 210
    assert len(cprofile.historical_catalog(current)) == 209
    assert len(qprofile.historical_catalog(current)) == 208
    assert len(hprofile.historical_catalog(current)) == 207
    assert len(dprofile.historical_catalog(current)) == 206
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
    yprofile_before = yprofile.historical_bytes(path, current)
    assert yprofile.current_test_bytes(yprofile_before) == current
    xprofile_before = xprofile.historical_bytes(path, current)
    assert xprofile.current_test_bytes(xprofile_before) == current
    pprofile_before = pprofile.historical_bytes(path, current)
    assert pprofile.current_test_bytes(pprofile_before) == current
    aprofile_before = aprofile.historical_bytes(path, current)
    assert aprofile.current_test_bytes(aprofile_before) == current
    vprofile_before = vprofile.historical_bytes(path, current)
    assert vprofile.current_test_bytes(vprofile_before) == current
    cprofile_before = cprofile.historical_bytes(path, current)
    assert cprofile.current_test_bytes(cprofile_before) == current
    qprofile_before = qprofile.historical_bytes(path, current)
    assert qprofile.current_test_bytes(qprofile_before) == current
    hprofile_before = hprofile.historical_bytes(path, current)
    assert hprofile.current_test_bytes(hprofile_before) == current
    dprofile_before = dprofile.historical_bytes(path, current)
    assert dprofile.current_test_bytes(dprofile_before) == current
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "yprofile_old", "xprofile_old", "pprofile_old", "aprofile_old", "vprofile_old", "cprofile_old", "qprofile_old", "hprofile_old", "dprofile_old", "sprofile_old", "wprofile_old", "rprofile_old", "gprofile_old", "iprofile_old", "nprofile_old", "resolution_old", "account_old", "canary_old", "isolated_old", "portable_old", "proof_old", "recheck_old", "verifier_old", "linux_old", "performance_old", "runner_old", "roadmap_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_yprofile = yprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "yprofile_old" else None
    old_xprofile = xprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "xprofile_old" else None
    old_pprofile = pprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "pprofile_old" else None
    old_aprofile = aprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "aprofile_old" else None
    old_vprofile = vprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "vprofile_old" else None
    old_cprofile = cprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "cprofile_old" else None
    old_qprofile = qprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "qprofile_old" else None
    old_hprofile = hprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "hprofile_old" else None
    old_dprofile = dprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "dprofile_old" else None
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
        "yprofile_old": lambda: yprofile.historical_bytes(roadmap.MASTER_PATH, old_yprofile),
        "xprofile_old": lambda: xprofile.historical_bytes(roadmap.MASTER_PATH, old_xprofile),
        "pprofile_old": lambda: pprofile.historical_bytes(roadmap.MASTER_PATH, old_pprofile),
        "aprofile_old": lambda: aprofile.historical_bytes(roadmap.MASTER_PATH, old_aprofile),
        "vprofile_old": lambda: vprofile.historical_bytes(roadmap.MASTER_PATH, old_vprofile),
        "cprofile_old": lambda: cprofile.historical_bytes(roadmap.MASTER_PATH, old_cprofile),
        "qprofile_old": lambda: qprofile.historical_bytes(roadmap.MASTER_PATH, old_qprofile),
        "hprofile_old": lambda: hprofile.historical_bytes(roadmap.MASTER_PATH, old_hprofile),
        "dprofile_old": lambda: dprofile.historical_bytes(roadmap.MASTER_PATH, old_dprofile),
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
    with pytest.raises(ValueError, match="parallel suite history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 215


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
    assert len(profile.historical_catalog(current)) == 215
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
    assert len(rules) == 216 and len(parsed) == 215
    assert profile._packet_rules() is rules and len(parsed) == 215
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
    with pytest.raises(ValueError, match="parallel suite history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "parallel-suite-authority.json").write_bytes(
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
    # The newer MET-PERF-036 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_parallel_suite.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_selinux_replay"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


SHARED_TESTS = {"tests/test_credential_lifecycle.py": ("test_every_input_pin_is_enforced",
                                                       {"historical_bytes", "validate_additions"}),
                "tests/test_credential_ordering.py": ("test_each_locked_input_is_checked_and_unknown_or_missing_files_refuse",
                                                      {"broker_history"})}
PARALLEL_FILES = ("ci/parallel_suite.py", "ci/parallel_suite_weights.json")
LOADER = next(path for path, pins in profile.SOURCE_PINS.items() if set(pins) == {"<whole file>"} and path not in PARALLEL_FILES)
SCOPED_FIXTURES = ("tests/test_linux_repair.py", "tests/test_model_api_inventory.py", "tests/test_linux_test_ownership.py",
                   "tests/test_model_fixture_scope.py")


def test_parallel_suite_sources_are_exactly_the_reviewed_text():
    assert profile.validate_parallel_suite() is None
    assert set(profile.SOURCE_PINS) == set(SHARED_TESTS) | set(SCOPED_FIXTURES) | set(PARALLEL_FILES) | {LOADER}
    record = profile.authority()
    assert set(profile.SOURCE_PINS) <= set(record["changedFiles"]) | set(record["newFiles"])


@pytest.mark.parametrize("path,old,new", [
    ("tests/test_credential_lifecycle.py", b'    share_exact_projections(monkeypatch, lifecycle, "validate_additions")\n', b""),
    ("tests/test_credential_lifecycle.py", b"    monkeypatch.undo()\n    assert lifecycle.historical_bytes",
     b"    assert lifecycle.historical_bytes"),
    ("tests/test_credential_ordering.py", b"    monkeypatch.undo()\n    assert ordering.broker_history",
     b"    assert ordering.broker_history"),
    ("tests/test_credential_ordering.py", b"        if key not in seen:\n", b"        if key not in seen or True:\n"),
    ("tests/test_linux_repair.py", b"    return deepcopy(_inputs_read_once)\n", b"    return _inputs_read_once\n"),
    ("tests/test_model_fixture_scope.py", b'@pytest.fixture(scope="module")\ndef _inputs_read_once',
     b'@pytest.fixture(scope="session")\ndef _inputs_read_once'),
    ("ci/parallel_suite.py", b"WORKERS = 4\n", b"WORKERS = 8\n"),
    ("ci/parallel_suite.py", b"        if whens != expected:\n", b"        if whens != expected and False:\n"),
    ("ci/parallel_suite_weights.json", b'"tests/test_credential_lifecycle.py": ', b'"tests/test_credential_lifecycle.py": 1e-9 + '),
])
def test_parallel_suite_sources_cannot_drift(monkeypatch, path, old, new):
    original = profile.reviewed_bytes

    def changed(target):
        raw = original(target)
        if target != path:
            return raw
        assert raw.count(old) == 1
        return raw.replace(old, new)

    monkeypatch.setattr(profile, "reviewed_bytes", changed)
    with pytest.raises(ValueError, match="unreviewed parallel-suite source"):
        profile.validate_parallel_suite()


def _validator_calls(nodes):
    return [node for node in nodes if isinstance(node, ast.Call)
            and (getattr(node.func, "id", "") or getattr(node.func, "attr", "")).startswith("validate_")]


@pytest.mark.parametrize("path", sorted(SHARED_TESTS))
def test_shared_projections_are_proven_first_and_undone_before_a_fresh_validation(path):
    """Structure only; the exact pins above remain the primary guard of these two tests."""
    name, shared = SHARED_TESTS[path]
    tree = ast.parse(profile.reviewed_bytes(path))
    users = {node.name for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
             and any(getattr(call.func, "id", "") == "share_exact_projections"
                     for call in ast.walk(node) if isinstance(call, ast.Call))}
    assert name in users
    node = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name][0]
    calls = [call for call in ast.walk(node) if isinstance(call, ast.Call)]
    shares = [call for call in calls if getattr(call.func, "id", "") == "share_exact_projections"]
    undos = [call for call in calls if getattr(call.func, "attr", "") == "undo"]
    assert len(undos) == 1 and all(call.args and ast.unparse(call.args[0]) == "monkeypatch" for call in shares)
    assert {ast.literal_eval(call.args[2]) if len(call.args) > 2 else "historical_bytes" for call in shares} == shared
    # The first validation runs under the wrapper and must pass before any refusal is asserted.
    asserts = [stmt for stmt in node.body if isinstance(stmt, ast.Assert) and _validator_calls(ast.walk(stmt.test))]
    first = asserts[0]
    assert max(call.lineno for call in shares) < first.lineno == min(call.lineno for call in _validator_calls(calls))
    assert ast.unparse(first.test).endswith("== []")
    # The wrapper is undone once, and the test ends with a fresh validation that must pass.
    assert all(call.lineno < undos[0].lineno for call in shares)
    assert asserts[-1] is node.body[-1] and asserts[-1].lineno > undos[0].lineno
    assert ast.unparse(asserts[-1].test).endswith("== []")


def test_scoped_fixtures_hand_each_test_its_own_copy():
    for path in SCOPED_FIXTURES:
        tree = ast.parse(profile.reviewed_bytes(path))
        fixtures = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        once, each = fixtures["_inputs_read_once"], fixtures["inputs"]
        assert [ast.unparse(d) for d in once.decorator_list] == ["pytest.fixture(scope='module')"]
        assert [ast.unparse(d) for d in each.decorator_list] == ["pytest.fixture"]
        assert ast.unparse(each.args) == "_inputs_read_once"
        assert ast.unparse(each.body[-1]) == "return deepcopy(_inputs_read_once)"


import importlib.util as _importlib_util
import re as _re
import subprocess as _subprocess
import sys as _sys


def _load(name, path):
    spec = _importlib_util.spec_from_file_location(name, profile.ROOT / path)
    module = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUITE = _load("_met_perf_035_parallel_suite_copy", "ci/parallel_suite.py")


def test_parallel_suite_constants_weights_and_session_loading(request):
    linux = _load("_met_perf_035_linux_conftest_copy", "tests/linux_runner/conftest.py")
    assert SUITE.WORKERS == 4
    assert linux.PREDECESSOR_PROOF_NODE in SUITE.PARENT_NODES and len(SUITE.PARENT_NODES) == 3
    weights = json.loads(profile.reviewed_bytes(SUITE.WEIGHTS_PATH))
    assert weights and all(type(name) is str and name.endswith(".py") and type(value) in (int, float) and value >= 0
                           for name, value in weights.items())
    assert request.config.pluginmanager.get_plugin("ci.parallel_suite") is not None


def test_accounting_refuses_partial_duplicate_or_misordered_phases():
    passed = [("setup", "passed"), ("call", "passed"), ("teardown", "passed")]
    assert SUITE.account({"a": passed, "b": [("setup", "skipped"), ("teardown", "passed")]}) == []
    for forged in ([], passed[:1], passed[:2], passed + passed[2:], passed[:2] + passed[1:],
                   [("setup", "failed"), ("call", "passed"), ("teardown", "passed")],
                   [("teardown", "passed"), ("setup", "passed"), ("call", "passed")], [("setup", "skipped")]):
        assert SUITE.account({"a": passed, "b": forged}) == ["node b reported %s" % [when for when, _ in forged]]


def test_worker_exit_passes_only_with_its_own_failures():
    assert SUITE.worker_exit_problem("w", 0, 0) is None and SUITE.worker_exit_problem("w", 1, 2) is None
    for code, failed in ((1, 0), (2, 0), (3, 0), (4, 1), (5, 0), (-9, 0), (-15, 3)):
        assert SUITE.worker_exit_problem("w", code, failed) is not None


_SCRATCH = {
    "tests/test_a.py": "import unittest, warnings, pytest\n@pytest.mark.parametrize('i', range(6))\ndef test_ok(i):\n"
                       "    assert i >= 0\ndef test_skip():\n    pytest.skip('s')\nclass T(unittest.TestCase):\n"
                       "    def test_unit_skip(self):\n        self.skipTest('u')\n@pytest.mark.xfail\ndef test_xfail():\n"
                       "    assert False\ndef test_warns():\n    warnings.warn('careful', UserWarning)\n",
    "tests/test_b.py": "import os, time\ndef test_maybe_crash():\n    fault = os.environ.get('SCRATCH_FAULT')\n"
                       "    if fault in ('crash', 'forge') and os.environ.get('PLANEON_PARALLEL_SUITE_SERIAL'):\n"
                       "        os._exit(0)\n    if fault == 'hang':\n        open(os.environ['SCRATCH_PID'], 'w').write(str(os.getpid()))\n"
                       "        time.sleep(float(os.environ.get('SCRATCH_SLEEP', '60')))\ndef test_after():\n    assert os.environ.get('SCRATCH_FAULT') != 'forge'\n",
    "tests/test_c.py": "import os\ndef test_maybe_fail():\n    assert os.environ.get('SCRATCH_FAULT') != 'fail'\n"
                       "def test_nested_pytest_is_serial_and_never_a_worker():\n"
                       "    import ci.parallel_suite as suite\n"
                       "    assert 'PLANEON_PARALLEL_SUITE_ASSIGNMENT' not in os.environ\n"
                       "    if suite._sink is not None:\n"
                       "        assert os.environ.get('PLANEON_PARALLEL_SUITE_SERIAL') == '1'\n"
                       "def test_forge_another_workers_node():\n    if os.environ.get('SCRATCH_FAULT') not in ('forge', 'garbage'):\n"
                       "        return\n    import ci.parallel_suite as suite\n    from _pytest.reports import TestReport\n"
                       "    if os.environ['SCRATCH_FAULT'] == 'garbage':\n        suite._sink.write('not json\\n')\n        return\n"
                       "    for when in ('setup', 'call', 'teardown'):\n"
                       "        report = TestReport('tests/test_b.py::test_after', ('tests/test_b.py', 5, 'test_after'), {}, 'passed', None, when)\n"
                       "        suite._write({'kind': 'report', 'data': suite._config.hook.pytest_report_to_serializable(config=suite._config, report=report)})\n",
}


def _scratch_env(tmp_path, fault, ini="", serial=False, extra_env=None):
    for name, text in _SCRATCH.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    # The plugin is loaded from the ini, as in the repository, so that a command line of paths alone runs in parallel.
    (tmp_path / "pytest.ini").write_text("[pytest]\naddopts = -p no:cacheprovider -p ci.parallel_suite %s\n" % ini)
    (tmp_path / "tmp").mkdir(exist_ok=True)
    env = {key: value for key, value in os.environ.items()
           if key not in (SUITE.SERIAL_ENV, SUITE.ASSIGNMENT_ENV, "PYTEST_ADDOPTS")}
    env.update(PYTHONPATH=str(profile.ROOT), SCRATCH_FAULT=fault, PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp_path / "tmp"),
               **({SUITE.SERIAL_ENV: "1"} if serial else {}), **(extra_env or {}))
    (tmp_path / "args.txt").write_text("-W error::UserWarning\n--runxfail\ntests\n")
    return env


def _scratch_run(tmp_path, fault, ini="", cli=(), serial=False, extra_env=None, wait=True, python_flags=(), paths=("tests",)):
    env = _scratch_env(tmp_path, fault, ini, serial, extra_env)
    argv = [_sys.executable, *python_flags, "-m", "pytest", *cli, *paths]
    if not wait:
        return _subprocess.Popen(argv, cwd=tmp_path, env=env, stdout=_subprocess.PIPE, stderr=_subprocess.STDOUT, text=True)
    return _subprocess.run(argv, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=180)


def _final(result):
    lines = [line.strip("= ") for line in result.stdout.splitlines() if " in " in line and ("passed" in line or "failed" in line)]
    return _re.sub(r" in [0-9.]+s.*$", "", lines[-1]) if lines else None


@pytest.mark.parametrize("fault,ini,cli,flags,paths", [
    ("none", "", (), (), ("tests",)), ("none", "-ra", (), (), ("tests",)), ("none", "-vv -rs", (), (), ("tests",)),
    ("fail", "", (), (), ("tests",)), ("none", "", ("-W", "error::UserWarning"), (), ("tests",)),
    # An @argument file, an interpreter flag and a node ID must not weaken or break the run.
    ("none", "", (), (), ("@args.txt",)), ("none", "", (), ("-W", "error::UserWarning"), ("tests",)),
    ("none", "", (), (), ("tests/test_c.py::test_maybe_fail",)),
])
def test_parallel_matches_serial_rc_and_summary(tmp_path, fault, ini, cli, flags, paths):
    # Skips under -ra/-vv need the report's tuple types; the warning must reach the summary; a command-line option
    # keeps the run serial.
    (tmp_path / "s").mkdir()
    (tmp_path / "p").mkdir()
    serial = _scratch_run(tmp_path / "s", fault, ini, cli, serial=True, python_flags=flags, paths=paths)
    parallel = _scratch_run(tmp_path / "p", fault, ini, cli, python_flags=flags, paths=paths)
    assert (parallel.returncode, _final(parallel)) == (serial.returncode, _final(serial))
    assert "INCOMPLETE" not in parallel.stdout and "INTERNALERROR" not in parallel.stdout and "Traceback" not in parallel.stdout
    assert serial.returncode in (0, 1) and _final(serial)


def test_a_worker_that_exits_early_fails_closed_without_echoing_worker_output(tmp_path):
    result = _scratch_run(tmp_path, "crash")
    assert result.returncode == 1 and "parallel-suite-incomplete" in _final(result)
    assert "tests/test_b.py::test_after reported []" in result.stdout and "in flight: worker" in result.stdout
    # Only the parent's own summary line: no worker summary, diagnostics record or log tail reaches the output.
    summaries = [line for line in result.stdout.splitlines() if _re.search(r"\d+ (passed|failed).* in [0-9.]+s", line)]
    assert len(summaries) == 1 and "PYTEST_DIAGNOSTIC" not in result.stdout
    assert list((tmp_path / "tmp").glob("planeon-parallel-suite.*")), "the work directory stays for diagnosis"


@pytest.mark.parametrize("fault,problem", [("forge", "for a node it does not own: 'tests/test_b.py::test_after'"),
                                           ("garbage", "undecodable record")])
def test_forged_or_undecodable_streams_fail_closed(tmp_path, fault, problem):
    result = _scratch_run(tmp_path, fault)
    assert result.returncode == 1 and problem in result.stdout and "parallel-suite-incomplete" in _final(result)


def test_a_passing_session_removes_its_work_directory(tmp_path):
    assert _scratch_run(tmp_path, "none").returncode == 0
    assert not list((tmp_path / "tmp").glob("planeon-parallel-suite.*"))


def test_sigterm_to_the_parent_kills_its_workers(tmp_path):
    import signal as _signal
    import time as _time
    pid_file = tmp_path / "worker.pid"
    parent = _scratch_run(tmp_path, "hang", extra_env={"SCRATCH_PID": str(pid_file)}, wait=False)
    for _ in range(300):
        if pid_file.exists() and pid_file.read_text():
            break
        _time.sleep(0.05)
    worker = int(pid_file.read_text())
    parent.send_signal(_signal.SIGTERM)
    output, _ = parent.communicate(timeout=60)
    assert parent.returncode != 0 and "parallel-suite-interrupted" in output
    for _ in range(100):
        try:
            os.kill(worker, 0)
        except ProcessLookupError:
            break
        _time.sleep(0.05)
    else:
        os.kill(worker, _signal.SIGKILL)
        raise AssertionError("worker outlived its parent")


def test_an_inherited_ignored_hangup_stays_ignored(tmp_path):
    import signal as _signal
    import time as _time
    pid_file = tmp_path / "worker.pid"
    env = _scratch_env(tmp_path, "hang", extra_env={"SCRATCH_PID": str(pid_file), "SCRATCH_SLEEP": "3"})
    # Start the run with SIGHUP ignored, as nohup does; a hangup must then not interrupt the parent or its workers.
    ignored = _subprocess.Popen(
        [_sys.executable, "-c", "import os, signal, sys; signal.signal(signal.SIGHUP, signal.SIG_IGN); "
                                "os.execv(sys.executable, [sys.executable, '-m', 'pytest', 'tests'])"],
        cwd=tmp_path, env=env, stdout=_subprocess.PIPE, stderr=_subprocess.STDOUT, text=True)
    for _ in range(300):
        if pid_file.exists() and pid_file.read_text():
            break
        _time.sleep(0.05)
    ignored.send_signal(_signal.SIGHUP)
    output, _ = ignored.communicate(timeout=60)
    assert ignored.returncode == 0 and "interrupted" not in output, output[-2000:]


def test_deadline_fits_inside_the_verify_budget():
    # argv 1-62 take about 2 minutes, so a 600 s worker deadline fires before the local 750 s and trusted 900 s caps.
    assert SUITE.DEADLINE_SECONDS == 600


_SESSION_ATTRIBUTES = {"session", "pluginmanager", "stats", "testscollected", "testsfailed", "terminalreporter",
                       "listchain", "getparent", "iter_parents"}


def _session_reads(tree):
    for node in ast.walk(tree):
        # A hook implementation (a conftest recorder, for example) can collect session-wide results.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("pytest_"):
            return True
        if isinstance(node, ast.Attribute) and (node.attr in _SESSION_ATTRIBUTES or node.attr.startswith("_planeon_")):
            return True
        if (isinstance(node, ast.Call) and getattr(node.func, "id", "") in ("getattr", "hasattr", "setattr")
                and len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
                and (node.args[1].value in _SESSION_ATTRIBUTES or str(node.args[1].value).startswith("_planeon_"))):
            return True
    return False


def test_only_the_predecessor_proof_reads_the_whole_session():
    """Any new test, conftest or helper that reads session-wide state must be reviewed for PARENT_NODES (and listed)."""
    readers = set()
    for path in sorted([*(profile.ROOT / "tests").rglob("*.py"), *(profile.ROOT / "ci").glob("test_*.py"),
                        profile.ROOT / "conftest.py"]):
        if _session_reads(ast.parse(path.read_text())):
            readers.add(path.relative_to(profile.ROOT).as_posix())
    assert readers == SESSION_READERS


SESSION_READERS = {
    # The in-session predecessor proof: runs in the parent (PARENT_NODES).
    "tests/linux_runner/test_build_and_predecessors.py",
    # Registers the PredecessorOutcomes recorder that the proof reads; replayed reports reach it in the parent.
    "tests/linux_runner/conftest.py",
    # Looks up the capture manager for the diagnostics sink; reads no session results.
    "conftest.py",
    # This layer's test: checks only that the parallel-suite plugin is registered.
    "tests/test_parallel_suite.py",
}


def _live_writers(tree):
    """Module functions that write past output capture, directly or through a helper of the same module."""
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}

    def direct(function):
        for node in ast.walk(function):
            if isinstance(node, ast.Attribute) and node.attr == "disabled" and getattr(node.value, "id", "") in ("capsys", "capfd"):
                return True
            if isinstance(node, ast.Attribute) and node.attr in ("__stdout__", "__stderr__"):
                return True
            if (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "write"
                    and getattr(node.func.value, "id", "") == "os" and node.args
                    and isinstance(node.args[0], ast.Constant) and node.args[0].value in (1, 2)):
                return True
        return False

    writers = {name for name, function in functions.items() if direct(function)}
    while True:
        more = {name for name, function in functions.items() if name not in writers
                and any(isinstance(node, ast.Call) and getattr(node.func, "id", "") in writers for node in ast.walk(function))}
        if not more:
            return {name for name in writers if name.startswith("test_")}
        writers |= more


def test_every_test_that_writes_past_capture_runs_in_the_parent():
    """Live output from a worker would land in its log; such tests, and the session reader, are exactly PARENT_NODES."""
    writers = set()
    for path in sorted([*(profile.ROOT / "tests").rglob("test_*.py"), *(profile.ROOT / "ci").glob("test_*.py")]):
        rel = path.relative_to(profile.ROOT).as_posix()
        writers |= {rel + "::" + name for name in _live_writers(ast.parse(path.read_text()))}
    linux = _load("_met_perf_035_linux_conftest_copy2", "tests/linux_runner/conftest.py")
    assert set(SUITE.PARENT_NODES) == writers | {linux.PREDECESSOR_PROOF_NODE}
