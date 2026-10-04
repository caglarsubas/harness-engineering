"""Independent scope/discovery/evidence negatives for MET-REPAIR-003."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_linux_readiness import EXPECTED_PACKETS, validate_linux_readiness
from scripts.validate_linux_repair import (
    CAMPAIGN_COMMANDS, EXPECTED_AMENDMENT, PACKET_DIGESTS, CURRENT_PACKET_DIGESTS,
    amend_linux_packet, packet_bytes, validate_linux_repair,
)
from scripts.validate_packet_ownership import validate_packet_ownership
from scripts.validate_conformance_reference_measurement import validate_dispatch_ownership
from scripts.validate_linux_test_ownership import amend_linux_test_packet

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def inputs():
    packets = {p.stem: safe_yaml_load(p.read_text()) for p in (ROOT / "task-packets").glob("*.yaml")}
    record = json.loads((ROOT / "architecture/linux-readiness-amendment.json").read_text())
    return packets, record, (ROOT / "architecture/linux-readiness.json").read_bytes()


def test_current_amendment_is_complete_and_historical_policy_unchanged(inputs):
    packets, record, raw = inputs
    assert validate_linux_repair(packets, record, raw) == []
    assert validate_linux_readiness(packets, json.loads(raw)) == []
    assert validate_dispatch_ownership(packets) == []
    assert len(packets) == 194
    assert record["currentPacketCount"] == 120  # Consumed record is immutable.
    assert json.loads(raw)["currentPacketCount"] == 118
    assert record["baseline"]["reviewEvidence"] == "SOURCE_INSPECTION_ONLY"
    assert record["baseline"]["runtimeReproduction"] == "NOT_RUN"
    assert record["runnerCandidate"]["nativeLinuxAcceptance"] is False
    assert record["gate"]["nativeLinuxStatus"] == "NOT_RUN_ENV_UNAVAILABLE"
    assert all(f["status"] == "WAITING_IMPLEMENTATION" for f in record["findings"])


@pytest.mark.parametrize("packet_id", tuple(PACKET_DIGESTS))
def test_packet_projection_matches_actual_bytes(inputs, packet_id):
    packets, _, _ = inputs
    raw = (ROOT / "task-packets" / (packet_id + ".yaml")).read_bytes()
    assert packet_bytes(packets[packet_id]) == raw
    assert hashlib.sha256(raw).hexdigest() == CURRENT_PACKET_DIGESTS[packet_id]
    if packet_id == "CONF-LINUX-001":
        historical = amend_linux_packet(EXPECTED_PACKETS[packet_id])
        assert hashlib.sha256(packet_bytes(historical)).hexdigest() == PACKET_DIGESTS[packet_id]


@pytest.mark.parametrize("packet_id", tuple(PACKET_DIGESTS))
@pytest.mark.parametrize("field", ["id", "repository", "branch", "objective", "predecessors",
    "allowedPaths", "warmSourceAccess", "sourceReuse", "contracts", "deliverables", "excluded",
    "prefetchCommands", "offlineAcceptanceCommands", "offlineExecution", "expectedEvidence", "rollback"])
def test_every_authority_field_required(inputs, packet_id, field):
    packets, record, raw = inputs
    del packets[packet_id][field]
    assert validate_linux_repair(packets, record, raw)


@pytest.mark.parametrize("packet_id", tuple(PACKET_DIGESTS))
@pytest.mark.parametrize("path", ["Makefile", "ci/", "src/", "PORTING.yaml",
    ".github/workflows/verify.yml", "toolchain.lock", "schemas/"])
def test_no_extra_path_or_broad_directory_grant(inputs, packet_id, path):
    packets, record, raw = inputs
    packets[packet_id]["allowedPaths"].append(path)
    assert validate_linux_repair(packets, record, raw)


@pytest.mark.parametrize("packet_id", tuple(PACKET_DIGESTS))
@pytest.mark.parametrize("field,value", [
    ("sourceReuse", [{"reuseMode": "COPY_AUTHORIZED"}]),
    ("warmSourceAccess", "AUTHORIZED_READ_ONLY_OBSERVATION"),
    ("referenceObservationExecution", {}),
    ("unexpected", True),
    ("prefetchCommands", [["make", "prefetch"]]),
    ("repository", "a-different-product"),
    ("excluded", []),
])
def test_no_extra_source_execution_or_scope_authority(inputs, packet_id, field, value):
    packets, record, raw = inputs
    packets[packet_id][field] = value
    assert validate_linux_repair(packets, record, raw)


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-003", "CONF-FIX-001"])
def test_authority_and_corrective_packets_cannot_gain_live_execution(inputs, packet_id):
    packets, record, raw = inputs
    packets[packet_id]["liveCampaignExecution"] = deepcopy(packets["CONF-LINUX-001"]["liveCampaignExecution"])
    assert validate_linux_repair(packets, record, raw)


@pytest.mark.parametrize("packet_id", tuple(PACKET_DIGESTS))
def test_omitted_predecessor_and_weakened_boolean_rejected(inputs, packet_id):
    packets, record, raw = inputs
    changed = deepcopy(packets)
    changed[packet_id]["predecessors"].pop()
    assert validate_linux_repair(changed, record, raw)
    packets[packet_id]["offlineExecution"]["prefetchOutsideSession"] = 0
    assert validate_linux_repair(packets, record, raw)


@pytest.mark.parametrize("index", range(7))
def test_each_campaign_command_is_mandatory_offline_and_live(inputs, index):
    packets, record, raw = inputs
    for field in ("offlineAcceptanceCommands", "liveCampaignExecution"):
        changed = deepcopy(packets)
        commands = (changed["CONF-LINUX-001"][field] if field == "offlineAcceptanceCommands"
                    else changed["CONF-LINUX-001"][field]["commands"])
        commands.pop(index)
        assert validate_linux_repair(changed, record, raw)
        assert validate_linux_readiness(changed, json.loads(raw))


def test_discovery_has_explicit_roots_without_legacy_import_changes(inputs):
    packets, _, _ = inputs
    roots = ["tests/meta", "tests/parity", "tests/alpha1",
             "tests/fixes/runner_boundary", "tests/platform/linux_baseline"]
    for command, root in zip(CAMPAIGN_COMMANDS[:5], roots, strict=True):
        assert command == ["python3", "-m", "unittest", "discover", "-s", root, "-p", "test_*.py"]
    assert packets["CONF-FIX-001"]["offlineAcceptanceCommands"] == CAMPAIGN_COMMANDS[:4]
    assert packets["CONF-LINUX-001"]["liveCampaignExecution"]["commands"] == CAMPAIGN_COMMANDS
    for packet_id in ("CONF-FIX-001", "CONF-LINUX-001"):
        paths = packets[packet_id]["allowedPaths"]
        assert "tests/alpha1/test_alpha1.py" not in paths
        assert "tests/platform/__init__.py" not in paths  # No top-level platform shadowing.
    assert "tests/parity/test_packet_runner.py" in packets["CONF-FIX-001"]["allowedPaths"]


def test_campaign_delta_is_exact_not_replacement_authority(inputs):
    packets, _, _ = inputs
    old = EXPECTED_PACKETS["CONF-LINUX-001"]
    snapshot = deepcopy(old)
    expected = amend_linux_packet(old)
    assert old == snapshot
    assert packets["CONF-LINUX-001"] == amend_linux_test_packet(expected)
    assert expected["allowedPaths"] == old["allowedPaths"] + [
        "src/harness_conformance/models.py", "schemas/v1alpha1/control-result.schema.json"]
    for key in ("contracts", "excluded", "rollback", "sourceReuse", "offlineExecution"):
        assert expected[key] == old[key]
    old_live = deepcopy(old["liveCampaignExecution"])
    new_live = deepcopy(expected["liveCampaignExecution"])
    del old_live["commands"], new_live["commands"]
    assert old_live == new_live


@pytest.mark.parametrize("index", range(4))
def test_finding_cannot_be_claimed_fixed_or_reproduced(inputs, index):
    packets, record, raw = inputs
    record["findings"][index]["status"] = "DONE"
    assert validate_linux_repair(packets, record, raw)


@pytest.mark.parametrize("field", ["historicalPolicySha256", "historicalCampaignPacketSha256",
    "baseline", "runnerCandidate", "gate", "evidenceBoundary", "packetDigests"])
def test_record_binding_or_evidence_loss_fails(inputs, field):
    packets, record, raw = inputs
    del record[field]
    assert validate_linux_repair(packets, record, raw)


@pytest.mark.parametrize("value", [True, 120, "PASS", {}, [], None, float("nan")])
def test_false_native_or_malformed_evidence_rejected(inputs, value):
    packets, record, raw = inputs
    assert validate_linux_repair(value, record, raw)
    assert validate_linux_repair(packets, value, raw)
    record["runnerCandidate"]["nativeLinuxAcceptance"] = value
    assert validate_linux_repair(packets, record, raw)


def test_original_linux_policy_bytes_are_not_rewritten(inputs):
    packets, record, raw = inputs
    assert validate_linux_repair(packets, record, raw + b"\n")
    changed = json.loads(raw)
    changed["gate"]["status"] = "PASS"
    assert validate_linux_repair(packets, record, json.dumps(changed).encode())


def test_corrective_boundary_retains_no_executable_live_authority(inputs):
    packets, _, _ = inputs
    fix = packets["CONF-FIX-001"]
    assert fix["allowedPaths"] == [
        "ci/verify-offline.sh", "ci/run_packet.py", "ci/run_packet_argv.py",
        "ci/network_canary.py", "ci/verify-live-campaign.py",
        "tests/parity/test_packet_runner.py", "tests/fixes/runner_boundary/",
        "docs/reports/runner-boundary-repair.md",
    ]
    rules = " ".join(fix["deliverables"])
    for phrase in ("EPERM/EACCES", "no unknown credential/path inheritance",
                   "DIRECT_LIVE_ADAPTER_FORBIDDEN", "remove all subprocess/exec execution",
                   "model OS/backend explicitly", "no missing", "nonzero"):
        if phrase == "no missing":
            assert "missing suite" in " ".join(fix["expectedEvidence"]).lower()
        else:
            assert phrase in rules


def test_catalog_checkpoint_and_source_only_phase_labels_exist(inputs):
    _, _, _ = inputs
    status = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text()
    assert "| Alpha 2 authority | `MET-REPAIR-003` | DONE" in status
    assert "| Alpha 2 correction | `CONF-FIX-001` | DONE" in status
    assert "| Alpha 2 authority | `MET-REPAIR-004` | DONE" in status
    assert "not a live dashboard or certification ledger" in status
    guide = (ROOT / "docs/alpha-2/LINUX_READINESS_REPAIRS.md").read_text()
    for finding in ("R1", "R2", "R3", "R4"):
        assert finding in guide
    assert "SOURCE_INSPECTION_ONLY" in guide
    assert "No model-effort transition" in guide
