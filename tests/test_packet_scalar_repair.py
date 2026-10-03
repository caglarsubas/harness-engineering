"""Independent scope/byte mutations; stored product code is inert, never run."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_packet_scalar_repair import (
    ADDITIONS, RECORD_PATH, load_scalar_inputs, regular_bytes, validate_edit,
    validate_scalar_repair,
)

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOTS = {
    "ci/run_packet.py": "architecture/packet-scalar-inputs/run_packet.before.txt",
    "tests/platform/linux_baseline/test_linux_inventory.py":
        "architecture/packet-scalar-inputs/test_linux_inventory.before.txt",
}


@pytest.fixture(scope="module")
def inputs():
    packets = {p.stem: safe_yaml_load(p.read_bytes()) for p in (ROOT / "task-packets").glob("*.yaml")}
    return packets, *load_scalar_inputs(ROOT)


def test_closed_catalog_preserves_164_files_and_all_130_packet_bytes(inputs):
    packets, record, raw = inputs
    assert validate_scalar_repair(*inputs) == []
    assert len(packets) == 194 and len(record["protectedFiles"]) == 164 and len(raw) == 169
    assert len([p for p in record["protectedFiles"] if p.startswith("task-packets/")]) == 130
    assert record["repositoryCount"] == 13 and record["harnessCount"] == 16
    assert record["liveDeclarationCount"] == 12
    assert all("liveCampaignExecution" not in packets[p] for p in ADDITIONS)


@pytest.mark.parametrize("packet_id", ADDITIONS)
@pytest.mark.parametrize("field,value", [
    ("allowedPaths", ["ci/"]), ("predecessors", []), ("sourceReuse", [{"copy": True}]),
    ("warmSourceAccess", "AUTHORIZED_READ_ONLY_OBSERVATION"), ("branch", "main"),
    ("prefetchCommands", [["make", "prefetch"]]), ("contracts", []),
    ("deliverables", []), ("expectedEvidence", ["native PASS"]), ("excluded", []),
    ("offlineExecution", {}), ("offlineAcceptanceCommands", [["python3", "-c", "pass"]]),
    ("rollback", "erase all"), ("liveCampaignExecution", {}),
])
def test_each_new_packet_remains_an_exact_whole_grant(inputs, packet_id, field, value):
    packets, record, raw = inputs
    changed = deepcopy(packets)
    changed[packet_id][field] = value
    assert validate_scalar_repair(changed, record, raw)


@pytest.mark.parametrize("packet_id", ["MET-LIVE-001", "CONF-LINUX-001", "CON-MODEL-001",
                                      *(f"CONF-LIVE-{i:03}" for i in range(1, 7))])
def test_old_packet_semantics_and_exact_serialization_cannot_change(inputs, packet_id):
    packets, record, raw = inputs
    changed = deepcopy(packets)
    changed[packet_id]["predecessors"].append("CONF-FIX-002")
    assert validate_scalar_repair(changed, record, raw)
    modified = dict(raw)
    modified["task-packets/" + packet_id + ".yaml"] += b"\n"
    assert validate_scalar_repair(packets, record, modified)


@pytest.mark.parametrize("path", list(SNAPSHOTS))
def test_exact_two_product_transformations_are_data_only_and_preserve_other_bytes(inputs, path):
    _, record, raw = inputs
    source = raw[SNAPSHOTS[path]]
    change = record["changes"][path]
    old, new = change["beforeBlock"].encode(), change["afterBlock"].encode()
    assert source.count(old) == 1
    after = source.replace(old, new, 1)
    assert validate_edit(path, source, after, record) == []
    assert hashlib.sha256(after).hexdigest() == change["afterSha256"]
    assert after.replace(new, old, 1) == source


@pytest.mark.parametrize("path", list(SNAPSHOTS))
@pytest.mark.parametrize("mutation", ["prefix", "suffix", "old", "missing", "duplicate", "weaken", "wrong_type", "source"])
def test_product_edits_reject_every_unapproved_byte_change(inputs, path, mutation):
    _, record, raw = inputs
    before = raw[SNAPSHOTS[path]]
    change = record["changes"][path]
    old, new = change["beforeBlock"].encode(), change["afterBlock"].encode()
    after = before.replace(old, new, 1)
    if mutation == "prefix":
        after = b"# unauthorized\n" + after
    elif mutation == "suffix":
        after += b"\n"
    elif mutation == "old":
        after = before
    elif mutation == "missing":
        after = before.replace(old, b"", 1)
    elif mutation == "duplicate":
        after = before.replace(old, new + new, 1)
    elif mutation == "weaken":
        after = before.replace(old, b"                    pass\n", 1)
    elif mutation == "wrong_type":
        after = after.decode()
    else:
        before += b"\n"
    assert validate_edit(path, before, after, record)


def test_guard_does_not_add_mutable_exemption_or_rewrite_original_inventory(inputs):
    _, record, raw = inputs
    new = record["changes"]["tests/platform/linux_baseline/test_linux_inventory.py"]["afterBlock"]
    assert 'if file == "ci/run_packet.py":' in new
    assert record["changes"]["ci/run_packet.py"]["afterSha256"] in new
    assert 'self.assertEqual(blob(actual), expected["blob"])' in new
    assert "mutable" not in new and "continue" not in new and "pass" not in new
    baseline = json.loads(raw["architecture/packet-scalar-inputs/baseline.json"])
    assert len(baseline["files"]) == 103
    assert sum(map(len, baseline["tests"].values())) == 120
    assert [baseline["suites"][r]["testCount"] for r in baseline["suiteRoots"]] == [37, 14, 9, 23, 37]


def test_all_six_real_packet_scalar_views_are_pinned_without_executing_parser(inputs):
    packets, record, raw = inputs
    for packet_id, text in record["publishedBackendPackets"].items():
        assert text.encode() == raw["task-packets/" + packet_id + ".yaml"]
        # Independently parse declarative authority only; not the stored product code.
        document = safe_yaml_load(text)
        assert document == packets[packet_id]
        for field in ("id", "repository", "warmSourceAccess"):
            line = next(line for line in text.splitlines() if line.startswith(field + ":"))
            assert json.loads(line.split(":", 1)[1]) == document[field]
        assert len(document["offlineAcceptanceCommands"]) == 8
    assert len(record["publishedBackendPackets"]) == 6


@pytest.mark.parametrize("field,value", [
    ("changes", {}), ("protectedFiles", {}), ("inputFiles", {}), ("packetSpecifications", {}),
    ("sourceBaseline", {}), ("failedDraft", {"accepted": True}), ("dispatchGate", {}),
    ("publishedBackendPackets", {}), ("currentPacketCount", 130), ("repositoryCount", 14),
    ("harnessCount", 17), ("liveDeclarationCount", 13), ("scope", "LIVE"),
    ("productImplementation", "PASS"), ("installationAuthority", "CODING_AGENT"), ("extra", True),
])
def test_record_mutations_fail_closed(inputs, field, value):
    packets, record, raw = inputs
    changed = deepcopy(record)
    changed[field] = value
    assert validate_scalar_repair(packets, changed, raw)


@pytest.mark.parametrize("path,value", [
    (("dispatchGate", "nativeAcceptance"), True),
    (("dispatchGate", "rewritePacketYaml"), True),
    (("dispatchGate", "consumerCommands"), 7),
    (("dispatchGate", "consumerRoots"), 5),
    (("dispatchGate", "requiresCompletedPacket"), "CONF-LIVE-001"),
    (("dispatchGate", "additionalAllowedPaths"), ["src/"]),
    (("failedDraft", "testsExecuted"), 120),
    (("failedDraft", "commandsExecuted"), 8),
    (("failedDraft", "ciStatus"), "PASS"),
])
def test_no_gate_cycle_path_expansion_or_false_evidence_promotion(inputs, path, value):
    packets, record, raw = inputs
    changed = deepcopy(record)
    changed[path[0]][path[1]] = value
    assert validate_scalar_repair(packets, changed, raw)


@pytest.mark.parametrize("operation", ["missing", "extra", "bytes", "type", "rename_packet"])
def test_missing_extra_rewritten_or_mistyped_inputs_reject(inputs, operation):
    packets, record, raw = inputs
    changed = dict(raw)
    path = "architecture/packet-scalar-inputs/run_packet.before.txt"
    if operation == "missing":
        del changed[path]
    elif operation == "extra":
        changed["arbitrary"] = b"bytes"
    elif operation == "bytes":
        changed[path] += b"\n"
    elif operation == "type":
        changed[path] = changed[path].decode()
    else:
        packets = dict(packets)
        packets["CONF-FIX-003"] = packets.pop("CONF-FIX-002")
    assert validate_scalar_repair(packets, record, changed)


@pytest.mark.parametrize("value", [None, [], True, 0, "record", float("nan")])
def test_malformed_record_input_and_unknown_edit_path_are_rejected(inputs, value):
    packets, record, raw = inputs
    assert validate_scalar_repair(packets, value, raw)
    assert validate_scalar_repair(packets, record, value)
    assert validate_edit("arbitrary.py", b"", b"", record)


def test_no_source_execution_primitive_or_unpinned_path_loading(tmp_path):
    text = (ROOT / "scripts/validate_packet_scalar_repair.py").read_text()
    import ast
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"exec", "eval", "compile", "__import__"}
    (tmp_path / "architecture").mkdir()
    for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"inputFiles":{"../secret":"digest"}}'):
        (tmp_path / RECORD_PATH).write_bytes(raw)
        with pytest.raises(ValueError):
            load_scalar_inputs(tmp_path)
    target = tmp_path / "regular"
    target.write_bytes(b"data")
    (tmp_path / "link").symlink_to(target)
    for relative in ("link", "../regular", "/regular", "a//b"):
        with pytest.raises((OSError, ValueError)):
            regular_bytes(tmp_path, relative)


def test_status_and_consumer_reconciliation_remain_separate_from_product_acceptance(inputs):
    packets, record, _ = inputs
    gate = record["dispatchGate"]
    assert gate["requiresCompletedPacket"] == "CONF-FIX-002"
    assert "CONF-LIVE-001" not in packets["CONF-FIX-002"]["predecessors"]
    assert gate["originalBaselineHistory"] == "PRESERVE_ALL_103_FILE_HASHES_AND_120_TEST_IDS"
    assert gate["additionalAllowedPaths"] == [] and gate["nativeAcceptance"] is False
    assert record["failedDraft"]["testsExecuted"] == record["failedDraft"]["commandsExecuted"] == 0
    text = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text()
    current = text.split("## Historical MET-REPAIR-008 publication checkpoint")[0]
    assert "during `MET-REPAIR-010` publication" in current
    assert "| Alpha 2 authority | `MET-LIVE-001` | DONE" in current
    assert "| Alpha 2 backend | `CONF-LIVE-001` | DONE" in current
    assert "| Alpha 2 backend | `CONF-LIVE-003` | WAITING" in current
    assert "CANCELLED_NOT_PASS" in text
