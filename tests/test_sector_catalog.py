"""Exact source lineage for MET-SECTOR-002; the sector catalog overlay keeps every catalog byte and validator."""
import ast
import json
from copy import deepcopy
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_sector_catalog as profile
from scripts import validate_selinux_replay as tprofile
from scripts import validate_parallel_suite as zprofile
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
    # The newer MET-ENFORCE-017 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 225 and len(accepted) == 217
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET,
                                            profile.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
    assert len(tprofile.historical_catalog(current)) == 216
    assert len(zprofile.historical_catalog(current)) == 215
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
    tprofile_before = tprofile.historical_bytes(path, current)
    assert tprofile.current_test_bytes(tprofile_before) == current
    zprofile_before = zprofile.historical_bytes(path, current)
    assert zprofile.current_test_bytes(zprofile_before) == current
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "tprofile_old", "zprofile_old", "yprofile_old", "xprofile_old", "pprofile_old", "aprofile_old", "vprofile_old", "cprofile_old", "qprofile_old", "hprofile_old", "dprofile_old", "sprofile_old", "wprofile_old", "rprofile_old", "gprofile_old", "iprofile_old", "nprofile_old", "resolution_old", "account_old", "canary_old", "isolated_old", "portable_old", "proof_old", "recheck_old", "verifier_old", "linux_old", "performance_old", "runner_old", "roadmap_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_tprofile = tprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "tprofile_old" else None
    old_zprofile = zprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "zprofile_old" else None
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
        "tprofile_old": lambda: tprofile.historical_bytes(roadmap.MASTER_PATH, old_tprofile),
        "zprofile_old": lambda: zprofile.historical_bytes(roadmap.MASTER_PATH, old_zprofile),
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
    with pytest.raises(ValueError, match="sector catalog history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 217


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
    assert len(profile.historical_catalog(current)) == 217
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
    assert len(rules) == 218 and len(parsed) == 217
    assert profile._packet_rules() is rules and len(parsed) == 217
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
    with pytest.raises(ValueError, match="sector catalog history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "sector-catalog-authority.json").write_bytes(
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
    # The newer MET-ENFORCE-017 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_sector_catalog.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_seccomp_allowlists"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


import fnmatch
import hashlib as _hashlib
import yaml as _yaml

from scripts import sector_catalog as overlay_module

CATALOGS = ("architecture/providers.yaml", "architecture/services.yaml", "docs/PROVIDER_MODULE_CATALOG.md")
CATALOG_NAMES = (*CATALOGS, "providers.yaml", "services.yaml", "PROVIDER_MODULE_CATALOG.md")
BASE_DIGESTS = ("9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02",
                "857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6",
                "1723f1ea35ecc87529c2d680f7e51fda61923a368f1e241b7a82982b10935b1d")
PUBLIC_API = frozenset({"effective_bytes", "effective_catalog"})
MODULE_NAMES = ("sector_catalog", "scripts.sector_catalog")
CATALOG_BASENAMES = ("providers.yaml", "services.yaml", "PROVIDER_MODULE_CATALOG.md")
CATALOG_DIRS = frozenset({"architecture", "docs"})
LISTING_FUNCTIONS = frozenset({("os", "walk"), ("os", "listdir"), ("os", "scandir"), ("glob", "glob"), ("glob", "iglob")})
EXCLUDED_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"})
LITERAL_READERS = frozenset({
    "scripts/sector_catalog.py",
    "scripts/validate_provider_adoption.py",
    "scripts/validate_readiness.py",
    "scripts/validate_reuse.py",
    "scripts/validate_sector_direction.py",
    "scripts/zero_bill_scan.py",
    "tests/test_architecture.py",
    "tests/test_provider_adoption.py",
    "tests/test_readiness.py",
    "tests/test_sector_catalog.py",
    "tests/test_sector_direction.py",
    "tests/test_validator_units.py",
    "tests/test_zero_bill.py",
})
GLOB_READERS = frozenset({
    "ci/lock_warm_snapshot.py",
    "ci/measure_yaml_parsing.py",
    "scripts/zero_bill_scan.py",
    "tests/test_ci_performance.py",
    "tests/test_sector_catalog.py",
})
ROUND_COPIES = {
    "architecture/sector-catalog/round1/sector_catalog.py": "59ed665f3ac0a17063003207f7967bb8f630d8488901fa835fcd1ff1484821d7",
    "architecture/sector-catalog/round2/sector_catalog.py": "dedde19a726d891599b6f1694cb3371c1c2381aa1c57960636b692c955865ac8",
    "architecture/sector-catalog/round3/sector_catalog.py": "f8cc94dbece287c32fd5afe5df196859e3020910d770ee16f6082f50f4f56751",
}
PINNING_RECORDS = frozenset({
    "architecture/backend-timing-authority.json",
    "architecture/broker-handoff-amendment.json",
    "architecture/canonical-repair-plan-authority.json",
    "architecture/catalog-traversal-authority.json",
    "architecture/ci-performance-amendment.json",
    "architecture/completion-profiling-authority.json",
    "architecture/conformance-completion-authority.json",
    "architecture/conformance-consumer-closure-inputs/consumer-sources.json",
    "architecture/conformance-consumer-closure-inputs/product-before.json",
    "architecture/conformance-consumer-closure.json",
    "architecture/conformance-performance-amendment.json",
    "architecture/conformance-performance-followup-inputs/product-before.json",
    "architecture/conformance-performance-followup.json",
    "architecture/conformance-performance-inputs/product-before.json",
    "architecture/conformance-publication-authority.json",
    "architecture/conformance-reference-measurement.json",
    "architecture/conformance-successor-checkpoint-inputs/product-before.json",
    "architecture/conformance-successor-checkpoint.json",
    "architecture/credential-lifecycle-amendment.json",
    "architecture/credential-lifecycle-inputs/before.json",
    "architecture/credential-ordering-amendment.json",
    "architecture/custody-handoff-amendment.json",
    "architecture/enforcement-integration-authority.json",
    "architecture/host-interface-authority.json",
    "architecture/live-backend-roadmap.json",
    "architecture/local-acceptance-authority.json",
    "architecture/native-qualification-amendment.json",
    "architecture/observation-enforcement-authority.json",
    "architecture/packet-scalar-amendment.json",
    "architecture/policy-observation-amendment.json",
    "architecture/provider-adoption-authority.json",
    "architecture/proxy-contract-amendment.json",
    "architecture/proxy-diagnostics-authority.json",
    "architecture/research-adoption-authority.json",
    "architecture/sector-catalog/overlay.json",
    "architecture/sector-catalog/round1/overlay.json",
    "architecture/sector-catalog/round2/overlay.json",
    "architecture/sector-catalog/round3/overlay.json",
    "architecture/sector-direction.json",
    "architecture/successor-inventory-amendment.json",
    "architecture/validation-performance-authority.json",
})
NAMING_RECORDS = frozenset({
    "architecture/backend-timing-authority.json",
    "architecture/broker-handoff-amendment.json",
    "architecture/broker-handoff-inputs/meta-before.json",
    "architecture/canonical-repair-plan-authority.json",
    "architecture/catalog-traversal-authority.json",
    "architecture/ci-performance-amendment.json",
    "architecture/ci-performance-inputs/tests.before.json",
    "architecture/completion-profiling-authority.json",
    "architecture/conformance-completion-authority.json",
    "architecture/conformance-consumer-closure-inputs/consumer-sources.json",
    "architecture/conformance-consumer-closure-inputs/meta-before.json",
    "architecture/conformance-consumer-closure-inputs/product-before.json",
    "architecture/conformance-consumer-closure.json",
    "architecture/conformance-performance-amendment.json",
    "architecture/conformance-performance-followup-inputs/meta-before.json",
    "architecture/conformance-performance-followup-inputs/product-before.json",
    "architecture/conformance-performance-followup.json",
    "architecture/conformance-performance-inputs/meta-before.json",
    "architecture/conformance-performance-inputs/product-before.json",
    "architecture/conformance-publication-authority.json",
    "architecture/conformance-reference-measurement-inputs/meta-before.json",
    "architecture/conformance-reference-measurement.json",
    "architecture/conformance-successor-checkpoint-inputs/meta-before.json",
    "architecture/conformance-successor-checkpoint-inputs/product-before.json",
    "architecture/conformance-successor-checkpoint.json",
    "architecture/credential-lifecycle-amendment.json",
    "architecture/credential-lifecycle-inputs/before.json",
    "architecture/credential-lifecycle-inputs/meta-tests.before.json",
    "architecture/credential-ordering-amendment.json",
    "architecture/credential-ordering-inputs/meta-before.json",
    "architecture/custody-handoff-amendment.json",
    "architecture/enforcement-integration-authority.json",
    "architecture/host-interface-authority.json",
    "architecture/live-backend-roadmap.json",
    "architecture/local-acceptance-authority.json",
    "architecture/native-qualification-amendment.json",
    "architecture/native-qualification-inputs/meta-before.json",
    "architecture/observation-enforcement-authority.json",
    "architecture/packet-scalar-amendment.json",
    "architecture/policy-observation-amendment.json",
    "architecture/provider-adoption-authority.json",
    "architecture/proxy-contract-amendment.json",
    "architecture/proxy-diagnostics-authority.json",
    "architecture/research-adoption-authority.json",
    "architecture/sector-catalog/README.md",
    "architecture/sector-catalog/overlay.json",
    "architecture/sector-catalog/round1/README.md",
    "architecture/sector-catalog/round1/overlay.json",
    "architecture/sector-catalog/round2/README.md",
    "architecture/sector-catalog/round2/overlay.json",
    "architecture/sector-catalog/round3/README.md",
    "architecture/sector-catalog/round3/overlay.json",
    "architecture/sector-direction.json",
    "architecture/successor-inventory-amendment.json",
    "architecture/validation-performance-authority.json",
    "architecture/w02-notes-errata/round1/docs/MASTER_DEVELOPMENT_PLAN.md",
    "architecture/w02-notes-errata/round2/docs/MASTER_DEVELOPMENT_PLAN.md",
    "architecture/w02-notes-errata/round2/docs/repositories/00-harness-engineering.md",
    "architecture/w02-notes-errata/round3/docs/MASTER_DEVELOPMENT_PLAN.md",
    "architecture/w02-notes-errata/round3/docs/repositories/00-harness-engineering.md",
    "architecture/w02-notes-errata/round4/docs/MASTER_DEVELOPMENT_PLAN.md",
    "architecture/w02-notes-errata/round4/docs/repositories/00-harness-engineering.md",
    "architecture/w02-notes-errata/round5/docs/MASTER_DEVELOPMENT_PLAN.md",
    "architecture/w02-notes-errata/round5/docs/repositories/00-harness-engineering.md",
})


def _era_packets():
    # This era's packet set: the newer MET-ENFORCE-017 packet is projected away first.
    return frozenset(layer_packets())


def test_sector_catalog_overlay_holds_for_this_era():
    assert profile.validate_sector_catalog(_era_packets()) is None
    assert overlay_module.effective_bytes("architecture/services.yaml").count(b"banking semantic vectors") == 1


def test_the_era_module_is_executed_from_reviewed_bytes(monkeypatch):
    original = profile.reviewed_bytes

    def changed(path):
        raw = original(path)
        return raw + b"\nraise ValueError('era module executed')\n" if path == profile.MODEL_PATH else raw

    monkeypatch.setattr(profile, "reviewed_bytes", changed)
    with pytest.raises(ValueError, match="era module executed"):
        profile.validate_sector_catalog(_era_packets())


def test_a_later_successor_leaves_this_era_valid_through_projection(monkeypatch):
    original = profile.regular_bytes
    era = {path: original(path) for path in (overlay_module.OVERLAY_PATH, "architecture/providers.yaml",
                                             "docs/repositories/11-mas-harness-distribution.md")}
    later = {overlay_module.OVERLAY_PATH: era[overlay_module.OVERLAY_PATH].replace(b'"approach": "', b'"approach": "Rebased. ', 1),
             "architecture/providers.yaml": era["architecture/providers.yaml"] + b"\n# a later catalog revision\n",
             "docs/repositories/11-mas-harness-distribution.md": era["docs/repositories/11-mas-harness-distribution.md"] + b"\n"}
    # The later tree on disk: a rebased overlay, a changed catalog and R11, and a published IND-BANK-005.
    monkeypatch.setattr(profile, "regular_bytes", lambda path: later.get(path) or original(path))
    with pytest.raises(ValueError):
        profile.validate_sector_catalog(_era_packets() | {"IND-BANK-005"})
    # A bridged successor projects its own edits away first, and its new packet is not in this era's set.
    monkeypatch.setattr(profile, "reviewed_bytes", lambda path: era[path] if path in later else original(path))
    assert profile.validate_sector_catalog(_era_packets()) is None


@pytest.mark.parametrize("path,old,new", [
    ("architecture/sector-catalog/status.json", b'"ADOPTED_FOR_SOURCE_PUBLICATION"', b'"CANDIDATE"'),
    ("architecture/sector-catalog/status.json", b'"7766016e7c85ebdce5669c79e28a79dc35c5269b"', b'"0ec8039b7e730e464a46e9f1b293a00330a5fee3"'),
    ("architecture/sector-catalog/review-round4.json", b'"verdict": "PASS_FOR_SOURCE_PUBLICATION"', b'"verdict": "CHANGES_REQUIRED"'),
    ("architecture/sector-catalog/review-round4.json", b'"severity": "NOTE"', b'"severity": "MAJOR"'),
])
def test_the_adoption_records_bind_the_reviewed_subject(monkeypatch, path, old, new):
    original = profile.reviewed_bytes

    def changed(target):
        raw = original(target)
        if target != path:
            return raw
        assert old in raw
        return raw.replace(old, new, 1)

    monkeypatch.setattr(profile, "reviewed_bytes", changed)
    with pytest.raises(ValueError):
        profile.validate_sector_catalog(_era_packets())


def test_reviewed_bytes_is_the_only_semantic_read():
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    names = {"_era_model", "validate_sector_catalog_status", "validate_sector_catalog"}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            used = {name.id for name in ast.walk(node) if isinstance(name, ast.Name)}
            attributes = {attribute.attr for attribute in ast.walk(node) if isinstance(attribute, ast.Attribute)}
            assert not used & {"regular_bytes", "open"} and not attributes & {"read_bytes", "read_text", "open"}


def _files(suffixes, top=""):
    root = profile.ROOT / top if top else profile.ROOT
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(profile.ROOT)
        if any(part in EXCLUDED_DIRS for part in rel.parts) or not path.is_file() or path.is_symlink():
            continue
        if suffixes is None or path.suffix in suffixes:
            yield rel.as_posix(), path


def test_only_the_frozen_readers_name_the_catalogs():
    readers = {rel for rel, path in _files({".py"}) if any(name.encode() in path.read_bytes() for name in CATALOG_NAMES)}
    assert readers == LITERAL_READERS | set(ROUND_COPIES)
    for rel, expected in ROUND_COPIES.items():
        assert _hashlib.sha256((profile.ROOT / rel).read_bytes()).hexdigest() == expected


def _constants(node):
    return [item.value for item in ast.walk(node) if isinstance(item, ast.Constant) and isinstance(item.value, str)]


def _listing_names(tree):
    """Local names of the os and glob modules and of their listing functions, through any import form."""
    modules, functions = {}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update({alias.asname or alias.name: alias.name for alias in node.names if alias.name in ("os", "glob")})
        elif isinstance(node, ast.ImportFrom) and node.module in ("os", "glob"):
            functions.update({alias.asname or alias.name: (node.module, alias.name) for alias in node.names
                              if (node.module, alias.name) in LISTING_FUNCTIONS})
    return modules, functions


def _listing(call, modules, functions):
    """(receiver, pattern directory, descending) of a listing that can yield a catalog file; None otherwise."""
    func = call.func
    first = call.args[0] if call.args else None
    if isinstance(func, ast.Name) and func.id in functions:
        module, name = functions[func.id]
    elif (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in modules
          and (modules[func.value.id], func.attr) in LISTING_FUNCTIONS):
        module, name = modules[func.value.id], func.attr
    elif isinstance(func, ast.Attribute) and func.attr in ("glob", "rglob", "iterdir", "walk") and not (
            isinstance(func.value, ast.Name) and (func.value.id == "ast" or func.value.id in modules)):
        module, name = None, func.attr
    else:
        return None
    if module == "glob":
        receiver, pattern, descending = None, first, True
    elif module == "os":
        receiver, pattern, descending = first, None, name == "walk"
    else:
        receiver, descending = func.value, name in ("rglob", "walk")
        pattern = first if name in ("glob", "rglob") else None
    directory = None
    if isinstance(pattern, ast.Constant) and isinstance(pattern.value, str):
        if not any(fnmatch.fnmatch(base, pattern.value.rsplit("/", 1)[-1]) for base in CATALOG_BASENAMES):
            return None
        if "/" in pattern.value:
            directory, descending = pattern.value.rsplit("/", 1)[0], True
        descending = descending or "**" in pattern.value
    elif module == "glob":
        directory = ""
    return receiver, directory, descending


def _bindings(tree):
    """Constants a name may hold: loop and comprehension targets over literals, and simple assignments."""
    bound = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.comprehension)) and isinstance(node.target, ast.Name):
            bound.setdefault(node.target.id, []).extend(_constants(node.iter))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bound.setdefault(target.id, []).extend(_constants(node.value))
    return bound


def _lists_a_catalog_directory(raw):
    """A static tripwire, not a proof: a listing whose root may be architecture/ or docs/, or that descends from an
    unknown, current or wildcard root, counts as a catalog listing."""
    tree = ast.parse(raw)
    modules, functions = _listing_names(tree)
    bound = _bindings(tree)
    for call in ast.walk(tree):
        found = _listing(call, modules, functions) if isinstance(call, ast.Call) else None
        if found is None:
            continue
        receiver, directory, descending = found
        roots = _constants(receiver) if receiver is not None else []
        for name in ast.walk(receiver) if receiver is not None else ():
            if isinstance(name, ast.Name):
                roots += bound.get(name.id, [])
        if directory is not None:
            roots.append(directory)
        tops = {root.strip("/").split("/")[0] if descending else root.strip("/") for root in roots}
        if tops & CATALOG_DIRS:
            return True
        if descending and (not roots or tops & {"", ".", ".."} or any(set(top) & set("*?[") for top in tops)):
            return True
    return False


# The scans cover every Python file in the checkout outside EXCLUDED_DIRS, tracked or not.
def test_only_the_frozen_readers_list_the_catalog_directories():
    assert {rel for rel, path in _files({".py"}) if _lists_a_catalog_directory(path.read_bytes())} == GLOB_READERS


@pytest.mark.parametrize("source,lists", [
    ("list((ROOT / 'architecture').glob('*.yaml'))", True),
    ("list(ROOT.glob('architecture/*.yaml'))", True),
    ("list(ROOT.glob('docs/*.md'))", True),
    ("for folder in ('architecture', 'policies'):\n    list((ROOT / folder).rglob('*.yaml'))", True),
    ("import os\nlist(os.walk('.'))", True),
    ("import os\nlist(os.walk(ROOT / 'docs'))", True),
    ("import os as o\no.listdir('architecture')", True),
    ("from os import scandir as s\ns('docs')", True),
    ("import glob\nglob.glob('**/*.yaml', recursive=True)", True),
    ("from glob import glob\nglob('*/*.yaml')", True),
    ("import glob as g\ng.iglob('architecture/*.yaml')", True),
    ("list(Path('.').rglob('*.yaml'))", True),
    ("list(ROOT.walk())", True),
    ("list((ROOT / 'docs').iterdir())", True),
    ("list((ROOT / 'architecture').glob('*.json'))", False),
    ("list((ROOT / 'task-packets').glob('*.yaml'))", False),
    ("list((ROOT / 'architecture/sector-catalog').glob('*.yaml'))", False),
    ("import os\nos.listdir('task-packets')", False),
    ("import ast\nlist(ast.walk(ast.parse('x')))", False),
])
def test_the_listing_tripwire_flags_the_catalog_directories(source, lists):
    assert _lists_a_catalog_directory(source.encode()) is lists


def test_the_records_that_pin_or_name_the_catalogs_are_frozen():
    pinning, naming = set(), set()
    for rel, path in _files(None, "architecture"):
        if rel.endswith(".py"):
            continue
        raw = path.read_bytes()
        if any(digest.encode() in raw for digest in BASE_DIGESTS):
            pinning.add(rel)
        if any(name.encode() in raw for name in CATALOGS):
            naming.add(rel)
    assert pinning == PINNING_RECORDS
    assert naming == NAMING_RECORDS


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return base and base + "." + node.attr
    return None


def _consumer_violations(raw):
    """Uses of the overlay module other than reads of its two public functions (a static tripwire, not a proof)."""
    tree = ast.parse(raw)
    module_strings = tuple(name + "." for name in MODULE_NAMES)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    bound, violations = set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bound |= {alias.asname or alias.name for alias in node.names
                      if alias.name.rsplit(".", 1)[-1] == "sector_catalog"}
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").rsplit(".", 1)[-1] == "sector_catalog":
                violations += [node.lineno for alias in node.names if alias.name not in PUBLIC_API]
            bound |= {alias.asname or alias.name for alias in node.names if alias.name == "sector_catalog"}
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in MODULE_NAMES or node.value.startswith(module_strings):
                violations.append(node.lineno)
    # The module object may appear only as the receiver of a public attribute read: no other attribute, no
    # assignment or deletion, and no passing it to setattr, getattr, vars, monkeypatch or mock.patch.object.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Name, ast.Attribute)) and _dotted(node) in bound:
            use = parents.get(node)
            if not (isinstance(use, ast.Attribute) and use.value is node and use.attr in PUBLIC_API
                    and isinstance(use.ctx, ast.Load)):
                violations.append(node.lineno)
    return violations


def test_consumers_use_only_the_public_overlay_api():
    exempt = {"scripts/sector_catalog.py", "scripts/validate_sector_catalog.py", "tests/test_sector_catalog.py", *ROUND_COPIES}
    for rel, path in _files({".py"}):
        if rel not in exempt:
            assert _consumer_violations(path.read_bytes()) == [], rel


@pytest.mark.parametrize("source,allowed", [
    ("from scripts import sector_catalog as sc\nsc.effective_bytes('architecture/services.yaml')", True),
    ("from scripts.sector_catalog import effective_catalog\neffective_catalog('architecture/providers.yaml')", True),
    ("import scripts.sector_catalog\nscripts.sector_catalog.effective_bytes('x')", True),
    ("from scripts import sector_catalog as sc\ndef test(monkeypatch):\n    monkeypatch.setattr(sc, 'ROOT', None)", False),
    ("import scripts.sector_catalog\nscripts.sector_catalog.check(None, None)", False),
    ("from unittest import mock\nfrom scripts import sector_catalog as sc\nmock.patch.object(sc, 'ROOT', None)", False),
    ("import importlib\nimportlib.import_module('scripts.sector_catalog').check", False),
    ("__import__('sector_catalog')", False),
    ("from scripts import sector_catalog as sc\ngetattr(sc, 'disk_reader')", False),
    ("from scripts import sector_catalog as sc\nvars(sc)['ROOT'] = None", False),
    ("from scripts import sector_catalog as sc\nsc.ROOT = None", False),
    ("from scripts import sector_catalog as sc\nsc.effective_bytes = None", False),
    ("from scripts import sector_catalog as sc\nalias = sc", False),
    ("from scripts.sector_catalog import *", False),
    ("from scripts.sector_catalog import check as effective", False),
    ("from unittest import mock\nmock.patch('scripts.sector_catalog.ROOT', None)", False),
    ("from . import sector_catalog\nsector_catalog.check(None, None)", False),
])
def test_the_consumer_tripwire_refuses_non_public_use(source, allowed):
    assert (_consumer_violations(source.encode()) == []) is allowed


def _readiness_errors(monkeypatch, apply_deferred=False):
    from scripts import validate_readiness as readiness
    effective = {path: overlay_module.effective_bytes(path) for path in CATALOGS}
    if apply_deferred:
        effective["architecture/providers.yaml"] = effective["architecture/providers.yaml"].replace(
            b"packs/white-goods/manifest.json", b"packs/banking/manifest.json")
    base_load, base_text = readiness.load_yaml, Path.read_text

    def rel(path):
        return Path(path).resolve().relative_to(readiness.ROOT.resolve()).as_posix()

    def load(path):
        name = rel(path)
        return _yaml.load(effective[name], Loader=readiness.UniqueKeySafeLoader) if name in effective else base_load(path)

    def text(self, *args, **kwargs):
        try:
            name = rel(self)
        except ValueError:
            name = None
        return effective[name].decode("utf-8") if name in effective else base_text(self, *args, **kwargs)

    monkeypatch.setattr(readiness, "load_yaml", load)
    monkeypatch.setattr(Path, "read_text", text)
    validation = readiness.Validation()
    readiness.validate_provider_catalog(validation, readiness.EXPECTED_REPOSITORIES)
    readiness.validate_services(validation)
    return validation.errors


def test_readiness_catalog_semantics_hold_on_the_effective_catalogs(monkeypatch):
    assert _readiness_errors(monkeypatch) == []


def test_applying_the_deferred_pack_path_gives_exactly_the_bound_packet_error(monkeypatch):
    errors = _readiness_errors(monkeypatch, apply_deferred=True)
    assert len(errors) == 1 and "packs/banking/manifest.json" in errors[0] and "IND-WG-005" in errors[0]
