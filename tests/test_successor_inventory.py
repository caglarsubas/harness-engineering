"""Independent data-model composition checks; no product source is executed."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_successor_inventory import (
    ADDITIONS, BASELINE_PATH, LAUNCHER_BEFORE_PATH, RECORD_PATH, TEST_BEFORE_PATH,
    canonical, corrected_test, digest, load_successor_inputs, parse_hook_proof,
    regular_bytes, validate_composition, validate_hook, validate_successor_inventory,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def inputs():
    packets = {p.stem: safe_yaml_load(p.read_bytes()) for p in (ROOT / "task-packets").glob("*.yaml")}
    return packets, *load_successor_inputs(ROOT)


def vector(inputs, stage):
    _, record, raw = inputs
    baseline = json.loads(raw[BASELINE_PATH])
    before, launcher = raw[TEST_BEFORE_PATH], raw[LAUNCHER_BEFORE_PATH]
    corrected = before
    for hunk in record["change"]["hunks"]:
        corrected = corrected.replace(hunk["beforeBlock"].encode(), hunk["afterBlock"].encode(), 1)
    observed = {path: {"path": path, "mode": meta["mode"], "size": meta["size"], "sha256": meta["sha256"],
                       "kind": "file", "nlink": 1, "linkedAncestry": False} for path, meta in baseline["files"].items()}
    observed[record["change"]["path"]].update(size=len(corrected), sha256=digest(corrected))
    paths = set(record["repairPaths"])
    for item in record["stages"][:stage]:
        paths.update(item["paths"])
    for path in paths - set(observed):
        value = ("INERT UNIT SOURCE " + path + "\n").encode()
        observed[path] = {"path": path, "mode": "100644", "size": len(value), "sha256": digest(value),
                          "kind": "file", "nlink": 1, "linkedAncestry": False}
    after, proof = launcher, None
    if stage == 6:
        hook = record["hook"]
        # Never compiled or run: this string checks only byte-region composition.
        replacement = "        result = {\"status\": \"NOT_RUN_ENV_UNAVAILABLE\"}\n"
        after = launcher.replace(hook["beforeBlock"].encode(), replacement.encode(), 1)
        proof = {"schemaVersion": hook["proofSchemaVersion"], "evidenceClass": "SOURCE_DELTA_ONLY",
                 **{key: hook[key] for key in ("packetId", "packetSha256", "path", "beforeSha256", "prefixSha256", "suffixSha256")},
                 "replacement": replacement, "afterSha256": digest(after)}
        observed[hook["path"]].update(size=len(after), sha256=digest(after))
    return [list(observed.values()), record, baseline, before, launcher, after, proof]


def test_exact_catalog_checkpoint_and_historical_inventory(inputs):
    packets, record, raw = inputs
    assert validate_successor_inventory(*inputs) == []
    assert len(packets) == 194 and len(record["protectedFiles"]) == 170 and len(raw) == 175
    baseline = json.loads(raw[BASELINE_PATH])
    historical = json.loads(baseline["historical103Raw"])
    assert len(baseline["files"]) == 106 and sum(map(len, baseline["tests"].values())) == 150
    assert len(historical["files"]) == 103 and sum(map(len, historical["tests"].values())) == 120
    for path, ids in historical["tests"].items():
        assert baseline["tests"][path] == ids
    assert digest(baseline["historical103Raw"].encode()) == baseline["historical103Sha256"]
    assert record["checkpoint"]["main"] == baseline["commit"] == "8519225b1564834fab5bcd001c263688e6fba7fe"
    assert record["checkpoint"]["ci"]["runId"] == 34137197794
    assert record["checkpoint"]["mainReplay"]["logSha256"] == "c6d01559a6704cc9ffa0c817c49f081517cf8ddddafab0dbb68673c43d02e7b5"
    assert record["diagnosis"]["testsExecuted"] == 0 and record["productImplementation"] == "NOT_RUN"


@pytest.mark.parametrize("stage,count", enumerate([110, 120, 127, 135, 141, 146, 151]))
def test_all_seven_complete_source_stage_compositions(inputs, stage, count):
    args = vector(inputs, stage)
    result = validate_composition(*args)
    assert result == {"stage": stage, "baselineFiles": 106, "trackedFiles": count,
                      "evidenceClass": "SOURCE_INVENTORY_ONLY", "nativeAcceptance": False}


def test_frozen_predecessor_predicate_rejects_legitimate_next_packet(inputs):
    _, record, raw = inputs
    baseline = json.loads(raw[BASELINE_PATH])
    new = set(record["stages"][0]["paths"])
    assert len(new) == 10 and not new & set(baseline["files"])
    assert len(set(baseline["files"]) | new) == 116
    assert set(baseline["files"]) | new != set(baseline["files"])
    assert b'self.assertEqual(set(files), set(BASELINE["files"]) | ADDED_PATHS)' in raw[TEST_BEFORE_PATH]


@pytest.mark.parametrize("stage", range(7))
def test_every_missing_path_and_each_unknown_addition_refuse(inputs, stage):
    args = vector(inputs, stage)
    for index in range(len(args[0])):
        changed = deepcopy(args)
        changed[0].pop(index)
        with pytest.raises(ValueError):
            validate_composition(*changed)
    changed = deepcopy(args)
    changed[0].append(dict(changed[0][0], path="arbitrary.txt"))
    with pytest.raises(ValueError):
        validate_composition(*changed)


@pytest.mark.parametrize("stage", range(1, 7))
def test_partial_and_out_of_order_stage_paths_never_select_a_stage(inputs, stage):
    args = vector(inputs, 0)
    desired = set(args[1]["stages"][stage - 1]["paths"]) - set(args[2]["files"])
    all_rows = {r["path"]: r for r in vector(inputs, 6)[0]}
    if stage > 1:
        args[0].extend(all_rows[p] for p in desired)
        with pytest.raises(ValueError):
            validate_composition(*args)
    args = vector(inputs, stage)
    args[0] = [r for r in args[0] if r["path"] != sorted(desired)[0]]
    with pytest.raises(ValueError):
        validate_composition(*args)


@pytest.mark.parametrize("field,value", [("sha256", "0" * 64), ("size", 17), ("mode", "100755")])
def test_every_original_file_remains_byte_size_and_mode_guarded(inputs, field, value):
    args = vector(inputs, 0)
    for index, row in enumerate(args[0]):
        if row["path"] not in args[2]["files"]:
            continue
        changed = deepcopy(args)
        changed[0][index][field] = value if value != row[field] else ("100644" if field == "mode" else 18)
        with pytest.raises(ValueError):
            validate_composition(*changed)


@pytest.mark.parametrize("field,value", [("path", "../escape"), ("path", "/absolute"), ("path", "a//b"),
    ("kind", "symlink"), ("kind", "directory"), ("nlink", 2), ("nlink", True), ("linkedAncestry", True),
    ("linkedAncestry", 0), ("size", True), ("size", -1), ("size", 16777217), ("mode", "120000"), ("sha256", None)])
def test_nonregular_or_malformed_rows_refuse(inputs, field, value):
    args = vector(inputs, 0)
    args[0][0][field] = value
    with pytest.raises(ValueError):
        validate_composition(*args)


def test_duplicate_extra_and_mistyped_rows_refuse(inputs):
    for operation in ("duplicate", "extra", "missing", "type"):
        args = vector(inputs, 0)
        if operation == "duplicate":
            args[0].append(dict(args[0][0]))
        elif operation == "extra":
            args[0][0]["verified"] = True
        elif operation == "missing":
            del args[0][0]["mode"]
        else:
            args[0] = {}
        with pytest.raises(ValueError):
            validate_composition(*args)


@pytest.mark.parametrize("stage", range(6))
def test_early_hook_proof_or_launcher_change_cannot_be_authorized(inputs, stage):
    for change in ("proof", "bytes", "both_before_and_after"):
        args = vector(inputs, stage)
        if change == "proof":
            args[6] = vector(inputs, 6)[6]
        else:
            args[5] += b"\n"
            if change == "both_before_and_after":
                args[4] = args[5]
        with pytest.raises(ValueError):
            validate_composition(*args)


def test_final_stage_without_explicit_proof_refuses(inputs):
    args = vector(inputs, 6)
    args[6] = None
    with pytest.raises(ValueError):
        validate_composition(*args)


@pytest.mark.parametrize("field", ["schemaVersion", "evidenceClass", "packetId", "packetSha256", "path",
                                  "beforeSha256", "prefixSha256", "suffixSha256", "afterSha256"])
@pytest.mark.parametrize("value", ["WRONG", None, 1, True, [], {}])
def test_every_hook_proof_binding_and_type_refuses(inputs, field, value):
    args = vector(inputs, 6)
    args[6][field] = value
    with pytest.raises((ValueError, UnicodeError)):
        validate_composition(*args)


@pytest.mark.parametrize("replacement", ["", "pass\n", "        pass", "        pass\r\n", "        \0\n", "        é\n", "        " + "x" * 8192 + "\n"])
def test_hook_replacement_cannot_escape_its_bounded_indented_region(inputs, replacement):
    args = vector(inputs, 6)
    args[6]["replacement"] = replacement
    with pytest.raises((ValueError, UnicodeError)):
        validate_composition(*args)


@pytest.mark.parametrize("mutation", ["prefix", "suffix", "old", "before", "extra", "missing", "replacement"])
def test_launcher_context_and_closed_proof_cannot_be_weakened(inputs, mutation):
    args = vector(inputs, 6)
    if mutation == "prefix": args[5] = b"# other\n" + args[5]
    elif mutation == "suffix": args[5] += b"\n"
    elif mutation == "old": args[5] = args[4]
    elif mutation == "before": args[4] += b"\n"
    elif mutation == "extra": args[6]["verified"] = True
    elif mutation == "missing": del args[6]["afterSha256"]
    else: args[6]["replacement"] += "        pass\n"
    with pytest.raises(ValueError): validate_composition(*args)


def test_fenced_source_proof_is_closed_and_data_only(inputs):
    proof = vector(inputs, 6)[6]
    document = b"# Source checkpoint\n\n```harness-launcher-source-proof\n" + canonical(proof) + b"\n```\n"
    assert parse_hook_proof(document) == proof
    for closing in (b"```not-a-fence\n", b"```\r\n", b"```extra"):
        with pytest.raises(ValueError):
            parse_hook_proof(document[:-4] + closing)
    for changed in (b"", document + document, document[:-5], b"x" * 262145,
                    b'```harness-launcher-source-proof\n{"x":1,"x":2}\n```',
                    b'```harness-launcher-source-proof\n{"x":NaN}\n```',
                    document.replace(b'"SOURCE_DELTA_ONLY"', b'true')):
        with pytest.raises(ValueError): parse_hook_proof(changed)


def test_exact_three_hunks_preserve_all_original_scalar_test_methods(inputs):
    _, record, raw = inputs
    before = raw[TEST_BEFORE_PATH]
    after = corrected_test(before, record)
    assert len(record["change"]["hunks"]) == 3
    assert digest(after) == "e1491e4407ff6d221871b45bbd775beb28afba11d418ae001847a512bb4b6fe6"
    import re
    methods = lambda data: re.findall(rb"^    def (test_[A-Za-z0-9_]+)\(", data, re.M)
    assert methods(before) == methods(after) and len(methods(before)) == 30
    for changed in (before+b"\n", before[:-1], b"", None):
        with pytest.raises(ValueError): corrected_test(changed, record)
    reversed_bytes = after
    for hunk in reversed(record["change"]["hunks"]):
        reversed_bytes = reversed_bytes.replace(hunk["afterBlock"].encode(), hunk["beforeBlock"].encode(), 1)
    assert reversed_bytes == before


@pytest.mark.parametrize("packet", ADDITIONS)
@pytest.mark.parametrize("field,value", [("allowedPaths", ["tests/"]), ("predecessors", []), ("sourceReuse", [{}]),
    ("offlineAcceptanceCommands", []), ("offlineExecution", {}), ("prefetchCommands", [["curl"]]), ("contracts", []),
    ("deliverables", []), ("expectedEvidence", ["PASS"]), ("excluded", []), ("rollback", "erase"),
    ("branch", "main"), ("warmSourceAccess", "COPY_AUTHORIZED"), ("liveCampaignExecution", {})])
def test_new_packet_grants_are_exact(inputs, packet, field, value):
    packets, record, raw = inputs
    changed = deepcopy(packets)
    changed[packet][field] = value
    assert validate_successor_inventory(changed, record, raw)


@pytest.mark.parametrize("field", ["change", "stages", "repairPaths", "repairTestIds", "stageCounts", "hook", "checkpoint", "diagnosis", "dispatchGate", "productImplementation", "protectedFiles", "inputFiles", "nativeAcceptance"])
def test_record_mutation_cannot_expand_scope_or_promote_evidence(inputs, field):
    packets, record, raw = inputs
    changed = deepcopy(record)
    changed[field] = "UNAUTHORIZED"
    assert validate_successor_inventory(packets, changed, raw)
    with pytest.raises(ValueError): corrected_test(raw[TEST_BEFORE_PATH], changed)


@pytest.mark.parametrize("operation", ["missing", "extra", "byte", "type", "packet", "packet_bytes", "baseline", "hook"])
def test_pinned_authority_inputs_and_original_packet_bytes_are_immutable(inputs, operation):
    packets, record, raw = inputs
    changed, packet_copy = dict(raw), deepcopy(packets)
    if operation == "missing": del changed[TEST_BEFORE_PATH]
    elif operation == "extra": changed["arbitrary.txt"] = b"data"
    elif operation == "byte": changed[TEST_BEFORE_PATH] += b"\n"
    elif operation == "type": changed[TEST_BEFORE_PATH] = changed[TEST_BEFORE_PATH].decode()
    elif operation == "packet": packet_copy["CONF-LIVE-001"]["predecessors"].append("CONF-FIX-003")
    elif operation == "packet_bytes": changed["task-packets/CONF-LIVE-001.yaml"] += b"\n"
    elif operation == "baseline": changed[BASELINE_PATH] += b"\n"
    else: changed[LAUNCHER_BEFORE_PATH] += b"\n"
    assert validate_successor_inventory(packet_copy, record, changed)


def test_unpinned_json_never_controls_input_paths_or_source_execution(tmp_path):
    (tmp_path / "architecture").mkdir()
    for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"inputFiles":{"../secret":"x"}}'):
        (tmp_path / RECORD_PATH).write_bytes(raw)
        with pytest.raises(ValueError): load_successor_inputs(tmp_path)
    path = tmp_path / "plain"
    path.write_bytes(b"data")
    (tmp_path / "link").symlink_to(path)
    for relative in ("link", "../plain", "/plain", "a//b"):
        with pytest.raises((ValueError, OSError)): regular_bytes(tmp_path, relative)
    import ast
    tree = ast.parse((ROOT / "scripts/validate_successor_inventory.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"exec", "eval", "compile", "__import__"}


def test_current_status_and_scope_do_not_claim_product_or_native_acceptance(inputs):
    packets, record, _ = inputs
    assert record["dispatchGate"]["requiresCompletedPacket"] == "CONF-FIX-003"
    assert record["dispatchGate"]["consumerAllowedPathsUnchanged"] is True
    assert record["dispatchGate"]["consumerRoots"] == 6 and record["dispatchGate"]["consumerCommands"] == 8
    assert not record["nativeAcceptance"] and record["installationAuthority"] == "NONE"
    assert all("liveCampaignExecution" not in packets[p] for p in ADDITIONS)
    text = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text()
    current = text.split("## Historical MET-REPAIR-008 publication checkpoint")[0]
    assert "during `MET-REPAIR-010` publication" in current
    assert "| Alpha 2 correction | `CONF-FIX-002` | DONE" in current
    assert "| Alpha 2 correction | `CONF-FIX-003` | DONE" in current
    assert "| Alpha 2 backend | `CONF-LIVE-003` | WAITING" in current
    assert "SOURCE_INSPECTION_ONLY" in text and "CANCELLED_NOT_PASS" in text


def test_actual_authority_file_links_and_linked_ancestry_refuse(tmp_path):
    import os
    directory = tmp_path / "real"
    directory.mkdir()
    source = directory / "input"
    source.write_bytes(b"inert data")
    assert regular_bytes(tmp_path, "real/input") == b"inert data"
    (tmp_path / "alias").symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError):
        regular_bytes(tmp_path, "alias/input")
    os.link(source, directory / "hard")
    for relative in ("real/input", "real/hard", "real"):
        with pytest.raises(ValueError):
            regular_bytes(tmp_path, relative)


@pytest.mark.parametrize("packet", ADDITIONS)
def test_predecessor_catalog_validators_require_exact_successor_grants(inputs, packet):
    from scripts.validate_packet_scalar_repair import load_scalar_inputs, validate_scalar_repair
    from scripts.validate_live_backend_readiness import load_live_inputs, validate_live_backend_readiness
    changed = deepcopy(inputs[0])
    changed[packet]["allowedPaths"].append("UNAUTHORIZED/")
    assert validate_scalar_repair(changed, *load_scalar_inputs(ROOT))
    assert validate_live_backend_readiness(changed, *load_live_inputs(ROOT))
