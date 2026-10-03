"""Independent negatives for the one-statement MET-REPAIR-004 grant."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_linux_readiness import EXPECTED_PACKETS, validate_linux_readiness
from scripts.validate_linux_repair import (
    EXPECTED_AMENDMENT as HISTORICAL, amend_linux_packet, packet_bytes, validate_linux_repair,
)
from scripts.validate_linux_test_ownership import (
    EXPECTED_RECORD, PACKET_DIGESTS, amend_linux_test_packet, validate_linux_test_ownership,
)
from scripts.validate_packet_ownership import validate_packet_ownership
from scripts.validate_conformance_reference_measurement import validate_dispatch_ownership

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def inputs():
    packets = {p.stem: safe_yaml_load(p.read_text()) for p in (ROOT / "task-packets").glob("*.yaml")}
    record = json.loads((ROOT / "architecture/linux-test-ownership-amendment.json").read_text())
    previous = (ROOT / "architecture/linux-readiness-amendment.json").read_bytes()
    return packets, record, previous


def test_current_and_historical_authorities_agree_without_rewriting_history(inputs):
    packets, record, previous = inputs
    assert validate_linux_test_ownership(packets, record, previous) == []
    assert validate_dispatch_ownership(packets) == []
    original = (ROOT / "architecture/linux-readiness.json").read_bytes()
    assert validate_linux_readiness(packets, json.loads(original)) == []
    assert validate_linux_repair(packets, json.loads(previous), original) == []
    assert len(packets) == 194
    assert json.loads(previous)["currentPacketCount"] == 120
    assert json.loads(original)["currentPacketCount"] == 118
    assert record["testChange"]["productImplementation"] == "NOT_RUN"
    assert record["sourceBaseline"]["sourceTestsPassed"] == 83
    assert record["sourceBaseline"]["sourceTestsSkipped"] == 0


def test_exact_additive_delta_preserves_every_other_member(inputs):
    packets, record, _ = inputs
    previous = amend_linux_packet(EXPECTED_PACKETS["CONF-LINUX-001"])
    before = deepcopy(previous)
    result = amend_linux_test_packet(previous)
    assert previous == before
    assert packets["CONF-LINUX-001"] == result
    assert hashlib.sha256(packet_bytes(previous)).hexdigest() == record["historicalLinuxPacketSha256"]
    assert result["predecessors"] == previous["predecessors"] + ["MET-REPAIR-004"]
    assert result["allowedPaths"] == previous["allowedPaths"] + ["tests/meta/test_canonical_schema.py"]
    for field in previous:
        if field not in {"predecessors", "allowedPaths", "contracts", "deliverables", "expectedEvidence"}:
            assert result[field] == previous[field], field
    for field in ("contracts", "deliverables", "expectedEvidence"):
        assert result[field][:len(previous[field])] == previous[field]
    assert result["liveCampaignExecution"]["commands"] == result["offlineAcceptanceCommands"]
    assert len(result["offlineAcceptanceCommands"]) == 7


@pytest.mark.parametrize("packet_id", tuple(PACKET_DIGESTS))
def test_current_packet_digests_bind_exact_file_bytes(inputs, packet_id):
    packets, _, _ = inputs
    raw = (ROOT / "task-packets" / (packet_id + ".yaml")).read_bytes()
    assert packet_bytes(packets[packet_id]) == raw
    assert hashlib.sha256(raw).hexdigest() == PACKET_DIGESTS[packet_id]


def test_consumed_meta_and_conformance_packets_stay_exact(inputs):
    packets, _, _ = inputs
    for packet_id in ("MET-REPAIR-003", "CONF-FIX-001"):
        assert hashlib.sha256(packet_bytes(packets[packet_id])).hexdigest() == HISTORICAL["packetDigests"][packet_id]


@pytest.mark.parametrize("packet_id", tuple(PACKET_DIGESTS))
@pytest.mark.parametrize("field", ["id", "repository", "branch", "objective", "predecessors",
    "allowedPaths", "warmSourceAccess", "sourceReuse", "contracts", "deliverables", "excluded",
    "prefetchCommands", "offlineAcceptanceCommands", "offlineExecution", "expectedEvidence", "rollback"])
def test_every_authority_field_is_mandatory(inputs, packet_id, field):
    packets, record, previous = inputs
    del packets[packet_id][field]
    assert validate_linux_test_ownership(packets, record, previous)


@pytest.mark.parametrize("packet_id", tuple(PACKET_DIGESTS))
@pytest.mark.parametrize("path", ["tests/", "tests/meta/", "tests/fixes/runner_boundary/",
    "ci/verify-live-campaign.py", "Makefile", "PORTING.yaml", "toolchain.lock",
    ".github/workflows/verify.yml", "schemas/", "src/"])
def test_no_extra_path_or_root_directory_authority(inputs, packet_id, path):
    packets, record, previous = inputs
    packets[packet_id]["allowedPaths"].append(path)
    assert validate_linux_test_ownership(packets, record, previous)


@pytest.mark.parametrize("statement", [
    "self.assertEqual(len(HANDLERS), 6)", "self.assertGreaterEqual(len(HANDLERS), 5)",
    'self.assertIn("LINUX_READINESS", HANDLERS)', "self.assertTrue(set(HANDLERS))", "pass",
])
def test_length_subset_membership_or_missing_assertion_is_not_the_grant(inputs, statement):
    packets, record, previous = inputs
    record["testChange"]["afterStatement"] = statement
    assert validate_linux_test_ownership(packets, record, previous)


def test_replacement_is_exact_ordered_six_tuple_and_preserves_other_bytes(inputs):
    _, record, _ = inputs
    change = record["testChange"]
    assert change["method"] == "CanonicalSchemaTests.test_closed_vocabularies"
    assert change["beforeStatement"] == "self.assertEqual(len(HANDLERS), 5)"
    assert change["afterStatement"] == ('self.assertEqual(HANDLERS, ("STATIC_ASSERTION", "SCHEMA_ASSERTION", '
        '"LIFECYCLE_ASSERTION", "EVENT_ASSERTION", "ENVIRONMENT_CAPABILITY", "LINUX_READINESS"))')
    assert change["otherBytes"] == change["otherAssertions"] == "UNCHANGED"
    assert change["negativeCasesOwner"] == "tests/platform/linux_baseline/"


@pytest.mark.parametrize("field", tuple(EXPECTED_RECORD))
def test_every_record_binding_is_mandatory(inputs, field):
    packets, record, previous = inputs
    del record[field]
    assert validate_linux_test_ownership(packets, record, previous)


@pytest.mark.parametrize("path,value", [
    (["sourceBaseline", "commit"], "0" * 40),
    (["sourceBaseline", "exactMainLogSha256"], "0" * 64),
    (["sourceBaseline", "requiredCiRun"], 0),
    (["sourceBaseline", "sourceTestsPassed"], 0),
    (["sourceBaseline", "linuxAcceptance"], True),
    (["sourceBaseline", "liveAcceptance"], True),
    (["testChange", "otherBytes"], "ANY"),
    (["testChange", "otherAssertions"], "REWRITE"),
    (["testChange", "beforeSha256"], "0" * 64),
    (["testChange", "productImplementation"], "PASS"),
    (["testChange", "diagnosis"], "RUNTIME_PROVEN"),
    (["preserved", "inventoryHelper"], "MUTABLE"),
    (["preserved", "predecessorTests"], 0),
    (["preserved", "nativeLinuxStatus"], "PASS"),
    (["preserved", "liveBackendStatus"], "PASS"),
    (["preserved", "billingBoundary"], "ALLOW"),
    (["preserved", "runtimeCodingRequires"], "SOURCE_MERGE"),
])
def test_source_pins_do_not_become_runtime_or_broader_authority(inputs, path, value):
    packets, record, previous = inputs
    target = record
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert validate_linux_test_ownership(packets, record, previous)


@pytest.mark.parametrize("index", range(7))
def test_every_campaign_command_remains_mandatory(inputs, index):
    packets, record, previous = inputs
    for field in ("offlineAcceptanceCommands", "liveCampaignExecution"):
        changed = deepcopy(packets)
        value = changed["CONF-LINUX-001"][field]
        (value if isinstance(value, list) else value["commands"]).pop(index)
        assert validate_linux_test_ownership(changed, record, previous)


@pytest.mark.parametrize("packet_id", tuple(PACKET_DIGESTS))
def test_no_new_execution_source_or_skipped_predecessor(inputs, packet_id):
    packets, record, previous = inputs
    for field, value in (("referenceObservationExecution", {}), ("unknown", True),
                         ("prefetchCommands", [["make", "prefetch"]]), ("sourceReuse", [{}]),
                         ("predecessors", []), ("warmSourceAccess", "AUTHORIZED_READ_ONLY_OBSERVATION")):
        changed = deepcopy(packets)
        changed[packet_id][field] = value
        assert validate_linux_test_ownership(changed, record, previous)
    changed = deepcopy(packets)
    changed[packet_id]["offlineExecution"]["prefetchOutsideSession"] = 0
    assert validate_linux_test_ownership(changed, record, previous)


def test_authority_packet_has_no_live_execution(inputs):
    packets, record, previous = inputs
    packets["MET-REPAIR-004"]["liveCampaignExecution"] = deepcopy(packets["CONF-LINUX-001"]["liveCampaignExecution"])
    assert validate_linux_test_ownership(packets, record, previous)


@pytest.mark.parametrize("value", [None, [], "", True, 121, {}, float("nan")])
def test_malformed_values_fail_closed(inputs, value):
    packets, record, previous = inputs
    assert validate_linux_test_ownership(value, record, previous)
    assert validate_linux_test_ownership(packets, value, previous)
    assert validate_linux_test_ownership(packets, record, value)


def test_historical_bytes_unknown_fields_and_count_changes_fail(inputs):
    packets, record, previous = inputs
    assert validate_linux_test_ownership(packets, record, previous + b"\n")
    changed = deepcopy(record)
    changed["unknown"] = True
    assert validate_linux_test_ownership(packets, changed, previous)
    packets.pop("MET-REPAIR-004")
    assert validate_linux_test_ownership(packets, record, previous)


def test_phase_checkpoint_owns_current_status_not_native_claims(inputs):
    status = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text()
    assert "| Alpha 2 authority | `MET-REPAIR-004` | DONE" in status
    assert "| Alpha 2 correction | `CONF-FIX-001` | DONE" in status
    guide = (ROOT / "docs/alpha-2/LINUX_TEST_OWNERSHIP_REPAIR.md").read_text()
    for required in ("SOURCE_INSPECTION_ONLY", "NOT_RUN_ENV_UNAVAILABLE", "No model-effort transition", "121"):
        assert required in guide
