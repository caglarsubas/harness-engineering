"""Independent authority/predicate mutations. Never execute stored product tests."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_model_api_inventory import (
    EXPECTED_BEFORE, EXPECTED_META, EXPECTED_RECORD, amend_model_packet,
    load_inventory_inputs, validate_inventory_edit, validate_model_api_inventory,
)
from scripts.validate_model_fixture_scope import load_scope_inputs, validate_model_fixture_scope

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "control-plane.openapi.json", "distribution.openapi.json",
    "operator.openapi.json", "status.openapi.json", "trust.openapi.json",
)


@pytest.fixture
def inputs():
    packets = {p.stem: safe_yaml_load(p.read_text()) for p in (ROOT / "task-packets").glob("*.yaml")}
    record = json.loads((ROOT / "architecture/model-api-inventory-amendment.json").read_text())
    return packets, record, load_inventory_inputs(ROOT)


def candidate_pair(inputs):
    before = inputs[2]["architecture/model-api-inventory-inputs/test_lifecycle_contracts.before.txt"]
    # Construct the sole replacement independently from the validator's constants.
    start = before.index(b"    assert [path.name for path in paths] == [\n")
    end = before.index(b"    for path in paths:\n", start)
    replacement = b"    assert {\n"
    replacement += b"".join(('        "' + name + '",\n').encode() for name in REQUIRED)
    replacement += b"    } <= {path.name for path in paths}\n"
    return before, before[:start] + replacement + before[end:]


def test_current_authority_and_preserved_failure_evidence(inputs):
    packets, record, snapshots = inputs
    assert validate_model_api_inventory(*inputs) == []
    assert len(packets) == 194
    assert record["historicalPacketCount"] == 122
    assert record["baseline"]["passed"] == 758
    assert record["baseline"]["failed"] == record["baseline"]["skipped"] == 0
    assert record["draft"]["passed"] == 1048
    assert record["draft"]["failed"] == 1
    assert record["draft"]["skipped"] == 0
    assert record["draft"]["predecessorTestIds"] == 758
    assert record["draft"]["newTestIds"] == 291
    assert record["draft"]["ciStatus"] == "CANCELLED_NOT_PASS"
    assert record["draft"]["prState"] == "DRAFT_UNMERGED"
    assert record["testChange"]["diagnosis"] == "REPRODUCED_FIXED_INVENTORY_FAILURE"
    assert record["testChange"]["noServerFinding"] == "SOURCE_INSPECTION_ONLY_REMOVED_FROM_NEW_API"
    assert record["testChange"]["productPredicateEdit"] == "NOT_RUN"
    before = safe_yaml_load(snapshots["architecture/model-api-inventory-inputs/CON-MODEL-001.before.yaml"])
    assert before == EXPECTED_BEFORE
    unchanged = deepcopy(before)
    after = amend_model_packet(before)
    assert before == unchanged
    assert after == packets["CON-MODEL-001"]
    assert after["predecessors"] == before["predecessors"] + ["MET-REPAIR-006"]
    assert after["allowedPaths"] == before["allowedPaths"] + ["tests/model/test_lifecycle_contracts.py"]
    for field in before:
        if field not in {"predecessors", "allowedPaths", "contracts", "deliverables", "expectedEvidence"}:
            assert after[field] == before[field], field
    for field in ("contracts", "deliverables", "expectedEvidence"):
        assert after[field][:len(before[field])] == before[field]


def test_exact_predicate_and_all_other_bytes(inputs):
    before, after = candidate_pair(inputs)
    assert validate_inventory_edit(before, after) == []
    change = EXPECTED_RECORD["testChange"]
    prefix, suffix = before.split(change["beforePredicate"].encode())
    assert hashlib.sha256(prefix).hexdigest() == change["prefixSha256"]
    assert hashlib.sha256(suffix).hexdigest() == change["suffixSha256"]
    assert after == prefix + change["afterPredicate"].encode() + suffix
    assert change["requiredApis"] == list(REQUIRED)
    assert change["otherBytes"] == change["otherAssertions"] == "UNCHANGED"
    assert change["checksApplyTo"] == "EVERY_DISCOVERED_API"


@pytest.mark.parametrize("extra", [(), ("model.openapi.json",), ("model.openapi.json", "future.openapi.json")])
def test_membership_semantics_are_additive_not_a_fixed_six(extra):
    # Independent data-only semantic vectors; no product test import or execution.
    observed = set(REQUIRED + extra)
    assert set(REQUIRED) <= observed


@pytest.mark.parametrize("missing", REQUIRED)
def test_missing_predecessor_api_never_satisfies_the_required_inventory(missing):
    observed = set(REQUIRED + ("model.openapi.json", "future.openapi.json")) - {missing}
    assert not set(REQUIRED) <= observed


@pytest.mark.parametrize("missing", REQUIRED)
def test_no_required_api_may_be_removed_from_the_predicate(inputs, missing):
    before, after = candidate_pair(inputs)
    altered = after.replace(('        "' + missing + '",\n').encode(), b"", 1)
    assert altered != after
    assert validate_inventory_edit(before, altered)


@pytest.mark.parametrize("old,new", [
    (b"    assert {\n", b"    assert True or {\n"),
    (b"} <= {path.name for path in paths}", b"} == {path.name for path in paths}"),
    (b"} <= {path.name for path in paths}", b"} <= {path.name for path in paths} and len(paths) == 6"),
    (b"for path in paths:\n", b"for path in paths[:5]:\n"),
    (b'glob("*.json")', b'glob("control-plane*.json")'),
    (b'assert document["openapi"] == "3.1.1"', b'assert document["openapi"]'),
    (b'assert "servers" not in document', b'assert True'),
    (b'assert document["paths"]', b'assert True'),
    (b'assert not relative.startswith(("http://", "https://"))', b'assert True'),
    (b'assert (path.parent / relative).resolve().is_file()', b'assert True'),
    (b"test_five_openapi_documents", b"test_six_openapi_documents"),
    (b"def test_five_openapi_documents", b"@pytest.mark.skip\ndef test_five_openapi_documents"),
])
def test_safety_identity_discovery_and_fixed_count_mutations_fail(inputs, old, new):
    before, after = candidate_pair(inputs)
    altered = after.replace(old, new, 1)
    assert altered != after
    assert validate_inventory_edit(before, altered)


@pytest.mark.parametrize("where", ["prefix", "suffix", "no-edit"])
def test_every_other_byte_is_immutable(inputs, where):
    before, after = candidate_pair(inputs)
    changed = {"prefix": b"# changed\n" + after, "suffix": after + b"\n", "no-edit": before}[where]
    assert validate_inventory_edit(before, changed)


@pytest.mark.parametrize("value", [None, [], {}, True, 130, float("nan"), "bytes"])
def test_malformed_shapes_fail_closed(inputs, value):
    packets, record, snapshots = inputs
    assert validate_model_api_inventory(value, record, snapshots)
    assert validate_model_api_inventory(packets, value, snapshots)
    assert validate_model_api_inventory(packets, record, value)
    before, after = candidate_pair(inputs)
    assert validate_inventory_edit(value, after)
    assert validate_inventory_edit(before, value)


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-006", "CON-MODEL-001"])
@pytest.mark.parametrize("field", list(EXPECTED_META))
def test_every_packet_member_is_required(inputs, packet_id, field):
    packets, record, snapshots = inputs
    del packets[packet_id][field]
    assert validate_model_api_inventory(packets, record, snapshots)


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-006", "CON-MODEL-001"])
@pytest.mark.parametrize("path", ["tests/", "tests/model/", "Makefile", "PORTING.yaml", "src/", ".github/workflows/verify.yml"])
def test_no_broad_or_unrelated_authority(inputs, packet_id, path):
    packets, record, snapshots = inputs
    packets[packet_id]["allowedPaths"].append(path)
    assert validate_model_api_inventory(packets, record, snapshots)


@pytest.mark.parametrize("field", list(EXPECTED_RECORD))
def test_every_record_binding_is_required(inputs, field):
    packets, record, snapshots = inputs
    del record[field]
    assert validate_model_api_inventory(packets, record, snapshots)


@pytest.mark.parametrize("path", list(EXPECTED_RECORD["protectedFiles"]) + [
    "task-packets/MET-REPAIR-006.yaml", "task-packets/CON-MODEL-001.yaml",
])
def test_exact_current_and_historical_byte_pins(inputs, path):
    packets, record, snapshots = inputs
    missing = dict(snapshots)
    del missing[path]
    assert validate_model_api_inventory(packets, record, missing)
    snapshots[path] += b"\n"
    assert validate_model_api_inventory(packets, record, snapshots)


@pytest.mark.parametrize("path,value", [
    (["draft", "failed"], 0), (["draft", "passed"], 1049),
    (["draft", "ciStatus"], "PASS"), (["draft", "runnerAssigned"], 0),
    (["draft", "workingTreeOverlay"], 0), (["draft", "commit"], "0" * 40),
    (["testChange", "diagnosis"], "SOURCE_INSPECTION_ONLY"),
    (["testChange", "noServerFinding"], "REPRODUCED_FAILURE"),
    (["testChange", "productPredicateEdit"], "PASS"),
    (["testChange", "otherAssertions"], "REWRITE"),
    (["testChange", "checksApplyTo"], "ORIGINAL_FIVE_ONLY"),
    (["preserved", "nativeLinuxStatus"], "PASS"),
    (["preserved", "rootPolicyChange"], True),
])
def test_no_false_pass_or_broader_evidence(inputs, path, value):
    packets, record, snapshots = inputs
    target = record
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert validate_model_api_inventory(packets, record, snapshots)


def test_previous_fixture_grant_is_consumed_not_weakened(inputs):
    packets, _, _ = inputs
    record = json.loads((ROOT / "architecture/model-fixture-scope-amendment.json").read_text())
    snapshots = load_scope_inputs(ROOT)
    assert validate_model_fixture_scope(packets, record, snapshots) == []
    assert hashlib.sha256(snapshots["task-packets/CON-MODEL-001.yaml"]).hexdigest() == record["packetDigests"]["CON-MODEL-001"]
    packets["CON-MODEL-001"]["deliverables"].append("arbitrary future test rewrite")
    assert validate_model_fixture_scope(packets, record, snapshots)


def test_commands_runner_inventory_and_unknown_fields_remain_closed(inputs):
    packets, record, snapshots = inputs
    for field, value in (
        ("offlineAcceptanceCommands", [["python", "-m", "pytest", "tests/model_api"]]),
        ("prefetchCommands", [["make", "prefetch"]]),
        ("sourceReuse", [{}]), ("unknown", True),
        ("referenceObservationExecution", {}), ("liveCampaignExecution", {}),
    ):
        changed = deepcopy(packets)
        changed["CON-MODEL-001"][field] = value
        assert validate_model_api_inventory(changed, record, snapshots)
    changed = deepcopy(packets)
    changed["CON-MODEL-001"]["offlineExecution"]["prefetchOutsideSession"] = 0
    assert validate_model_api_inventory(changed, record, snapshots)
    assert validate_model_api_inventory(packets, record, {**snapshots, "extra": b""})
    del packets["MET-REPAIR-006"]
    assert validate_model_api_inventory(packets, record, snapshots)


def test_missing_or_linked_input_is_not_followed(tmp_path):
    with pytest.raises(ValueError):
        load_inventory_inputs(tmp_path)
    first = next(iter(EXPECTED_RECORD["protectedFiles"]))
    target = tmp_path / first
    target.parent.mkdir(parents=True)
    target.symlink_to(ROOT / first)
    with pytest.raises(ValueError):
        load_inventory_inputs(tmp_path)


def test_checkpoint_keeps_product_and_native_gates_open():
    text = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text()
    assert "| Alpha 2 authority | `MET-REPAIR-006` | DONE" in text
    assert "| Alpha 2 authority | `MET-REPAIR-005` | DONE" in text
    assert "| Alpha 2 | `CON-MODEL-001` | DONE" in text
    assert "| Alpha 2 early gate | `CONF-LINUX-001` | WAITING — native qualification" in text
    assert "not a live dashboard or certification ledger" in text
    assert "1048 passed, one failed, zero skipped" in text
    assert "normal model-contract completeness review" in text
