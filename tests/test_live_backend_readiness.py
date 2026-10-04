"""Independent mutations of the source-only roadmap, never native execution."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_live_backend_readiness import (
    NEW_IDS, RUNTIME_GATED, load_live_inputs, regular_bytes,
    validate_live_backend_readiness,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def inputs():
    packets = {p.stem: safe_yaml_load(p.read_text()) for p in (ROOT / "task-packets").glob("*.yaml")}
    record, raw = load_live_inputs(ROOT)
    return packets, record, raw


def test_exact_catalog_and_real_source_checkpoint(inputs):
    packets, record, raw = inputs
    assert validate_live_backend_readiness(*inputs) == []
    assert len(packets) == 194 and len(raw) == 156
    assert record["historicalPacketCount"] == 123
    assert (record["repositoryCount"], record["harnessCount"]) == (13, 16)
    assert [c["passed"] for c in record["checkpoints"]] == [1295, 1175, 120]
    assert [c["skipped"] for c in record["checkpoints"]] == [10, 0, 0]
    assert all(c["evidenceClass"] == "SOURCE_CI_MERGE_LOCAL_EXACT_MAIN_ONLY"
               for c in record["checkpoints"])


@pytest.mark.parametrize("packet_id", NEW_IDS)
@pytest.mark.parametrize("field,value", [
    ("allowedPaths", ["src/"]),
    ("predecessors", []),
    ("sourceReuse", [{"copy": True}]),
    ("warmSourceAccess", "AUTHORIZED_READ_ONLY_OBSERVATION"),
    ("prefetchCommands", [["make", "prefetch"]]),
    ("offlineAcceptanceCommands", [["python3", "-c", "print('PASS')"]]),
    ("contracts", []),
    ("deliverables", []),
    ("excluded", []),
    ("expectedEvidence", ["native PASS"]),
    ("rollback", "destroy all capacity"),
    ("branch", "main"),
])
def test_each_new_packet_is_a_whole_closed_grant(inputs, packet_id, field, value):
    packets, record, raw = inputs
    changed = deepcopy(packets)
    changed[packet_id][field] = value
    assert validate_live_backend_readiness(changed, record, raw)


@pytest.mark.parametrize("packet_id", ["CONF-LINUX-001", "CON-MODEL-001",
                                      "MET-REPAIR-006", *RUNTIME_GATED])
def test_consumed_packets_are_not_silently_amended(inputs, packet_id):
    packets, record, raw = inputs
    changed = deepcopy(packets)
    changed[packet_id]["predecessors"].append("CONF-LIVE-006")
    assert validate_live_backend_readiness(changed, record, raw)


@pytest.mark.parametrize("operation", ["remove", "extra", "reorder", "seven", "split"])
def test_full_cumulative_command_set_cannot_drift(inputs, operation):
    packets, record, raw = inputs
    changed = deepcopy(packets)
    commands = changed["CONF-LIVE-006"]["offlineAcceptanceCommands"]
    if operation == "remove":
        commands.pop(0)
    elif operation == "extra":
        commands.append(["make", "campaign", "CAMPAIGN=alpha1"])
    elif operation == "reorder":
        commands.reverse()
    elif operation == "seven":
        del commands[5]
    else:
        changed["CONF-LIVE-006"]["liveCampaignExecution"]["commands"] = commands[:5]
    assert validate_live_backend_readiness(changed, record, raw)


@pytest.mark.parametrize("path,value", [
    ((section, field), value)
    for section, field, expected in (
        ("gates", "sourceSuccessIsNativeAcceptance", False),
        ("gates", "unavailableUnblocks", False),
        ("session", "nonceReuse", False),
        ("session", "dataOnlyNeverAuthority", True),
        ("session", "crashConsumesNonce", True),
        ("session", "expiryTerminatesDescendants", True),
    )
    for value in (not expected, 0, 1, None, "PASS")
])
def test_boolean_and_integer_authority_confusion_is_rejected(inputs, path, value):
    packets, record, raw = inputs
    changed = deepcopy(record)
    changed[path[0]][path[1]] = value
    assert validate_live_backend_readiness(packets, changed, raw)


@pytest.mark.parametrize("field,value", [
    ("cases", []), ("architectures", ["arm64"]), ("signerPurposes", ["PLATFORM_RELEASE"]),
    ("transport", "RAW_KUBERNETES_SOCKET"), ("installationAuthority", "CODING_AGENT"),
    ("scope", "LIVE_EXECUTION"), ("repositoryCount", 14), ("harnessCount", 17),
    ("currentPacketCount", 123), ("protectedFiles", {}), ("packetSpecifications", {}),
    ("checkpoints", []), ("extra", True),
])
def test_closed_record_rejects_matrix_authority_or_evidence_drift(inputs, field, value):
    packets, record, raw = inputs
    changed = deepcopy(record)
    changed[field] = value
    assert validate_live_backend_readiness(packets, changed, raw)


@pytest.mark.parametrize("operation", ["missing", "extra", "modified", "wrong_type"])
def test_protected_raw_bytes_are_not_just_semantic_yaml(inputs, operation):
    packets, record, raw = inputs
    changed = dict(raw)
    path = "task-packets/CONF-LINUX-001.yaml"
    if operation == "missing":
        del changed[path]
    elif operation == "extra":
        changed["architecture/unreviewed.json"] = b"{}"
    elif operation == "modified":
        changed[path] += b"\n"
    else:
        changed[path] = changed[path].decode()
    assert validate_live_backend_readiness(packets, record, changed)


@pytest.mark.parametrize("value", [None, [], True, 0, float("nan"), {"extra": True}])
def test_malformed_record_fails_closed(inputs, value):
    assert validate_live_backend_readiness(inputs[0], value, inputs[2])


def test_unknown_missing_packet_and_cycle_fail_closed(inputs):
    packets, record, raw = inputs
    changed = deepcopy(packets)
    del changed["CONF-LIVE-004"]
    assert validate_live_backend_readiness(changed, record, raw)
    changed = deepcopy(packets)
    changed["CONF-LIVE-007"] = deepcopy(changed["CONF-LIVE-006"])
    assert validate_live_backend_readiness(changed, record, raw)
    changed = deepcopy(packets)
    changed["CONF-LIVE-001"]["predecessors"] = ["CONF-LIVE-006"]
    assert validate_live_backend_readiness(changed, record, raw)


def test_no_source_completion_promotes_native_or_tenant_acceptance(inputs):
    record = inputs[1]
    gates = record["gates"]
    assert gates["sourceOnlyExceptions"] == list(NEW_IDS[1:])
    assert gates["runtimeBlockedPackets"] == list(RUNTIME_GATED)
    assert gates["nextAfterSourceChain"] == "EXTERNAL_NATIVE_QUALIFICATION"
    assert gates["runtimeCodingRequires"] == "FRESH_NATIVE_LINUX_AMD64_PASS"
    assert gates["maximumEvidenceAgeHours"] == 168
    assert gates["nativeStatus"] == dict(amd64="NOT_RUN_ENV_UNAVAILABLE",
                                        arm64="NOT_RUN_ENV_UNAVAILABLE")
    assert gates["tenantAcceptanceOwner"] == "INDEPENDENT_TENANT_SIGNER"


def test_legacy_and_successor_verifiers_are_separately_owned(inputs):
    specs = inputs[1]["packetSpecifications"]
    assert "src/harness_conformance/live_backend_authority.py" in specs["CONF-LIVE-001"]["allowedPaths"]
    assert "src/harness_conformance/live_backend_evidence.py" in specs["CONF-LIVE-006"]["allowedPaths"]
    prohibited = {"Makefile", "PORTING.yaml", "ci/build_live_launcher.py",
                  "src/harness_conformance/live.py",
                  "src/harness_conformance/linux_readiness.py"}
    for packet_id in NEW_IDS[1:]:
        paths = specs[packet_id]["allowedPaths"]
        assert not (set(paths) & prohibited)
        assert all(not p.startswith("tests/meta/") for p in paths)
        assert all(not p.endswith("/") for p in paths)


def test_no_links_or_path_escape_in_preserved_inputs(tmp_path):
    target = tmp_path / "regular"
    target.write_bytes(b"data")
    (tmp_path / "link").symlink_to(target)
    for relative in ("../regular", "/regular", "link", "./regular", "a//b"):
        with pytest.raises((OSError, ValueError)):
            regular_bytes(tmp_path, relative)
    directory = tmp_path / "directory"
    directory.mkdir()
    (directory / "file").write_bytes(b"x")
    (tmp_path / "parentlink").symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError):
        regular_bytes(tmp_path, "parentlink/file")
    with pytest.raises((OSError, ValueError)):
        load_live_inputs(tmp_path)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"protectedFiles":{"../secret":"x"}}'])
def test_malformed_or_unpinned_record_cannot_control_input_reads(tmp_path, raw):
    directory = tmp_path / "architecture"
    directory.mkdir()
    (directory / "live-backend-roadmap.json").write_bytes(raw)
    with pytest.raises(ValueError):
        load_live_inputs(tmp_path)


def test_current_status_preserves_history_and_labels_next_work():
    text = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text()
    current = text.split("## Historical MET-REPAIR-008 publication checkpoint")[0]
    assert "during `MET-REPAIR-010` publication" in current
    assert "| Alpha 2 authority | `MET-LIVE-001` | DONE" in current
    assert "| Alpha 2 | `CON-MODEL-001` | DONE" in current
    assert "Historical MET-REPAIR-006 publication checkpoint" in text
    assert "1048 passed, one failed, zero skipped" in text
    assert "NOT_RUN_ENV_UNAVAILABLE" in text
    assert "| Alpha 2 backend | `CONF-LIVE-001` | DONE" in current
    assert "| Alpha 2 backend | `CONF-LIVE-002` | DONE" in current
    for packet_id in NEW_IDS[3:]:
        assert f"| Alpha 2 backend | `{packet_id}` | WAITING" in current
