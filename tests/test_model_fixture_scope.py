"""Independent mutation tests for the model fixture-copy authority, not product tests."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_model_fixture_scope import (
    EXPECTED_BEFORE, EXPECTED_META, EXPECTED_RECORD, amend_model_packet,
    validate_fixture_edit, validate_model_fixture_scope,
    load_scope_inputs,
)
from scripts.validate_model_api_inventory import amend_model_packet as amend_inventory_packet

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def inputs():
    packets = {p.stem: safe_yaml_load(p.read_text()) for p in (ROOT / "task-packets").glob("*.yaml")}
    record = json.loads((ROOT / "architecture/model-fixture-scope-amendment.json").read_text())
    return packets, record, load_scope_inputs(ROOT)


def test_current_authority_and_historical_bytes_agree(inputs):
    packets, record, snapshots = inputs
    assert validate_model_fixture_scope(*inputs) == []
    assert len(packets) == 194
    assert record["historicalPacketCount"] == 121
    assert record["baseline"]["passed"] == 758
    assert record["baseline"]["failed"] == record["baseline"]["skipped"] == 0
    assert record["testChange"]["diagnosis"] == "SOURCE_INSPECTION_ONLY"
    assert record["testChange"]["productImplementation"] == "NOT_RUN"
    before = safe_yaml_load(snapshots["architecture/model-fixture-inputs/CON-MODEL-001.before.yaml"])
    assert before == EXPECTED_BEFORE
    unchanged = deepcopy(before)
    after = amend_model_packet(before)
    assert before == unchanged
    assert after == safe_yaml_load(snapshots["task-packets/CON-MODEL-001.yaml"])
    assert amend_inventory_packet(after) == packets["CON-MODEL-001"]
    assert after["predecessors"] == before["predecessors"] + ["MET-REPAIR-005"]
    assert after["allowedPaths"] == before["allowedPaths"] + ["tests/golden/test_generated_contracts.py"]
    for field in before:
        if field not in {"predecessors", "allowedPaths", "contracts", "deliverables", "expectedEvidence"}:
            assert after[field] == before[field], field
    for field in ("contracts", "deliverables", "expectedEvidence"):
        assert after[field][:len(before[field])] == before[field]


def candidate_pair(inputs):
    _, _, snapshots = inputs
    before = snapshots["architecture/model-fixture-inputs/test_generated_contracts.before.txt"]
    # Independently authored edit, not obtained from amend_model_packet or its expected helper.
    start = before.index(b"def _copy_generation_inputs(")
    end = before.index(b"\n\n\ndef _stage_outputs(", start)
    body = before[start:end]
    body = body.replace(
        b'        "tests/fixtures/runtime", "tests/fixtures/status", "contracts/regression-inputs",',
        b'        "tests/fixtures/runtime", "tests/fixtures/status", "contracts/regression-inputs",\n'
        b'        "tests/fixtures/model", "contracts/model-inputs",',
    )
    body += (b'\n    shutil.copy2(ROOT / "contracts/model-inputs.lock.json", '
             b'destination / "contracts/model-inputs.lock.json")')
    return before, before[:start] + body + before[end:]


def test_exact_helper_candidate_preserves_all_other_bytes(inputs):
    before, after = candidate_pair(inputs)
    assert validate_fixture_edit(before, after) == []
    change = EXPECTED_RECORD["testChange"]
    old = change["beforeHelper"].encode()
    prefix, suffix = before.split(old)
    assert hashlib.sha256(prefix).hexdigest() == change["prefixSha256"]
    assert hashlib.sha256(suffix).hexdigest() == change["suffixSha256"]
    assert after == prefix + change["afterHelper"].encode() + suffix
    assert change["directoryCopies"] == ["tests/fixtures/model", "contracts/model-inputs"]
    assert change["fileCopies"] == ["contracts/model-inputs.lock.json"]
    assert change["otherBytes"] == change["otherAssertions"] == "UNCHANGED"
    assert change["missingInputs"] == "FAIL_CLOSED"


@pytest.mark.parametrize("mutation", [
    "no-edit", "prefix", "suffix", "assertion", "missing-model", "missing-lock",
    "missing-snapshot", "extra-copy", "duplicate-copy", "conditional", "whole-tree", "skip",
])
def test_forbidden_legacy_changes_are_rejected(inputs, mutation):
    before, after = candidate_pair(inputs)
    if mutation == "no-edit":
        after = before
    elif mutation == "prefix":
        after = b"# changed\n" + after
    elif mutation == "suffix":
        after += b"\n"
    elif mutation == "assertion":
        after = after.replace(b"assert MANDATORY_OUTPUTS <= actual", b"assert True")
    elif mutation == "missing-model":
        after = after.replace(b'"tests/fixtures/model", ', b"")
    elif mutation == "missing-lock":
        after = after.replace(b"    shutil.copy2(", b"    # shutil.copy2(")
    elif mutation == "missing-snapshot":
        after = after.replace(b', "contracts/model-inputs"', b"")
    elif mutation == "extra-copy":
        after = after.replace(b'"tests/fixtures/model",', b'"tests/fixtures/model", "tests/other",')
    elif mutation == "duplicate-copy":
        after = after.replace(b'"tests/fixtures/model",', b'"tests/fixtures/model", "tests/fixtures/model",')
    elif mutation == "conditional":
        after = after.replace(b"        shutil.copytree(", b"        if (ROOT / relative).exists(): shutil.copytree(")
    elif mutation == "whole-tree":
        after = after.replace(b'"contracts/model-inputs"', b'"contracts"')
    else:
        after = after.replace(b"def test_added_local_api", b"@pytest.mark.skip\ndef test_added_local_api")
    assert validate_fixture_edit(before, after)


@pytest.mark.parametrize("value", [None, [], {}, True, 122, float("nan"), "bytes"])
def test_malformed_records_and_fixture_bytes_fail_closed(inputs, value):
    packets, record, snapshots = inputs
    assert validate_model_fixture_scope(value, record, snapshots)
    assert validate_model_fixture_scope(packets, value, snapshots)
    assert validate_model_fixture_scope(packets, record, value)
    before, after = candidate_pair(inputs)
    assert validate_fixture_edit(value, after)
    assert validate_fixture_edit(before, value)


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-005", "CON-MODEL-001"])
@pytest.mark.parametrize("field", list(EXPECTED_META))
def test_every_packet_member_is_required(inputs, packet_id, field):
    packets, record, snapshots = inputs
    del packets[packet_id][field]
    assert validate_model_fixture_scope(packets, record, snapshots)


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-005", "CON-MODEL-001"])
@pytest.mark.parametrize("path", ["tests/", "tests/golden/", "Makefile", "PORTING.yaml", "src/", ".github/workflows/verify.yml"])
def test_no_broad_or_unrelated_path_grant(inputs, packet_id, path):
    packets, record, snapshots = inputs
    packets[packet_id]["allowedPaths"].append(path)
    assert validate_model_fixture_scope(packets, record, snapshots)


@pytest.mark.parametrize("field", list(EXPECTED_RECORD))
def test_each_record_field_is_required(inputs, field):
    packets, record, snapshots = inputs
    del record[field]
    assert validate_model_fixture_scope(packets, record, snapshots)


@pytest.mark.parametrize("path", list(EXPECTED_RECORD["protectedFiles"]) + [
    "task-packets/MET-REPAIR-005.yaml", "task-packets/CON-MODEL-001.yaml",
])
def test_missing_or_changed_historical_and_current_bytes_fail(inputs, path):
    packets, record, snapshots = inputs
    changed = dict(snapshots)
    del changed[path]
    assert validate_model_fixture_scope(packets, record, changed)
    snapshots[path] += b"\n"
    assert validate_model_fixture_scope(packets, record, snapshots)


@pytest.mark.parametrize("path,value", [
    (["baseline", "failed"], 2), (["baseline", "passed"], 0),
    (["baseline", "workingTreeOverlay"], 0), (["baseline", "commit"], "0" * 40),
    (["testChange", "diagnosis"], "REPRODUCED_FAILURE"),
    (["testChange", "productImplementation"], "PASS"),
    (["testChange", "otherAssertions"], "REWRITE"),
    (["testChange", "afterHelper"], "pass\n"),
    (["preserved", "nativeLinuxStatus"], "PASS"),
    (["preserved", "rootPolicyChange"], True),
    (["preserved", "runtimeCodingRequires"], "SOURCE_MERGE"),
])
def test_no_false_failure_runtime_or_broader_authority(inputs, path, value):
    packets, record, snapshots = inputs
    target = record
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert validate_model_fixture_scope(packets, record, snapshots)


def test_commands_execution_identity_and_count_cannot_change(inputs):
    packets, record, snapshots = inputs
    for field, value in (
        ("offlineAcceptanceCommands", [["python", "-m", "pytest", "tests/model_api"]]),
        ("prefetchCommands", [["make", "prefetch"]]),
        ("sourceReuse", [{}]), ("referenceObservationExecution", {}),
        ("liveCampaignExecution", {}), ("unknown", True),
    ):
        changed = deepcopy(packets)
        changed["CON-MODEL-001"][field] = value
        assert validate_model_fixture_scope(changed, record, snapshots)
    changed = deepcopy(packets)
    changed["CON-MODEL-001"]["offlineExecution"]["prefetchOutsideSession"] = 0
    assert validate_model_fixture_scope(changed, record, snapshots)
    del packets["MET-REPAIR-005"]
    assert validate_model_fixture_scope(packets, record, snapshots)


def test_current_checkpoint_separates_source_from_native_acceptance():
    status = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text()
    assert "| Alpha 2 authority | `MET-REPAIR-006` | DONE" in status
    assert "| Alpha 2 authority | `MET-REPAIR-005` | DONE" in status
    assert "| Alpha 2 authority | `MET-REPAIR-004` | DONE" in status
    assert "| Alpha 2 early gate | `CONF-LINUX-001` | WAITING — native qualification" in status
    assert "| Alpha 2 | `CON-MODEL-001` | DONE" in status
    assert "not a live dashboard or certification ledger" in status
