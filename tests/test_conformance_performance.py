"""Independent performance authority/scope negatives; no product code execution."""
import ast
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from scripts.validate_conformance_performance_followup import historical_bytes as followup_history

from scripts.safe_yaml import safe_load
from scripts.validate_conformance_performance import (
    ROOT, BEFORE_PATH, PRODUCT_PATH, RECORD_SHA256, apply_recipe, canonical,
    current_test_bytes, digest, historical_bytes, load_inputs, region, test_ids as ids,
    validate_additions, validate_authority, validate_product_delta,
)


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/"task-packets").glob("*.yaml")}
    return packets,*load_inputs(ROOT)


def test_current_catalog_preserves_all_old_packets_and_full_commands(authority):
    packets, record, inputs = authority
    assert validate_authority(*authority) == []
    assert len(packets) == 194
    assert len([p for p in record["protectedFiles"] if p.startswith("task-packets/") and p.endswith(".yaml")]) == 144
    assert len(packets["MET-PERF-002"]["offlineAcceptanceCommands"]) == 24
    assert len(packets["CONF-PERF-001"]["offlineAcceptanceCommands"]) == 8
    assert record["sourceBaseline"]["files"] == 127 and record["sourceBaseline"]["tests"] == 327
    assert record["stages"] == [110,120,127,135,141,146,151]
    assert len(record["productPaths"]) == 6
    assert all(p in json.loads(inputs[PRODUCT_PATH])["files"] for p in record["productPaths"])
    assert record["measurement"]["functionAttribution"] == "NOT_YET_MEASURED"


def test_every_current_meta_byte_precedes_historical_reconstruction(authority):
    _,record,inputs = authority
    before = json.loads(inputs[BEFORE_PATH])["files"]
    for path, rule in record["metaRecipes"].items():
        raw = before[path].encode()
        assert apply_recipe(raw, rule) == followup_history(path, inputs[path])
        assert historical_bytes(path, inputs[path]) == raw
        if path.startswith("tests/"):
            assert ids(raw) == ids(inputs[path])
            assert current_test_bytes(raw) == inputs[path]
        with pytest.raises(ValueError):
            historical_bytes(path, inputs[path]+b"\n")
    for path in record["unchangedTests"]:
        assert current_test_bytes(followup_history(path, inputs[path])) == inputs[path]


@pytest.mark.parametrize("fault",["packet","old-packet","source","missing","extra","before","product-before","record","command","timeout","native"])
def test_authority_inputs_and_boundaries_fail_closed(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == "packet": packets["CONF-PERF-001"]["allowedPaths"].append("src/other.py")
    if fault == "old-packet": inputs["task-packets/CONF-LIVE-003.yaml"] += b" "
    if fault == "source": inputs["scripts/validate_readiness.py"] += b"\n"
    if fault == "missing": inputs.pop(PRODUCT_PATH)
    if fault == "extra": inputs["arbitrary"] = b""
    if fault == "before": inputs[BEFORE_PATH] += b" "
    if fault == "product-before": inputs[PRODUCT_PATH] += b" "
    if fault == "record": record["productPaths"].append("Makefile")
    if fault == "command": packets["CONF-PERF-001"]["offlineAcceptanceCommands"].pop()
    if fault == "timeout": record["preserved"]["trustedSeconds"] += 1
    if fault == "native": record["preserved"]["nativeAcceptance"] = True
    assert validate_authority(packets,record,inputs)


def sample(authority):
    _,record,inputs = authority
    before = json.loads(inputs[PRODUCT_PATH])["files"]
    doc = "docs/live-backend/linux-boundary.md"
    supervisor = "tests/live_backend/test_supervisor.py"
    after = {p:r.encode() for p,r in before.items()}
    rows = {}
    for path,spec in record["productRegions"].items():
        if path == doc:
            continue
        raw = after[path]
        regions = {}
        for name in spec["regions"]:
            start,end,_ = region(raw,name)
            regions[name] = raw[start:end].decode()
        addition = "\nclass PerformanceScopeOnlyTests(unittest.TestCase):\n    def test_independent_scope_example(self):\n        self.assertEqual(1, 1)\n" if path == supervisor else ""
        after[path] += addition.encode()
        rows[path] = dict(regions=regions,append=addition,afterSha256=digest(after[path]),constant=None)
    rows["tests/live_backend/_inventory.py"]["constant"] = digest(after["tests/platform/linux_baseline/_successor_inventory.py"])
    proof = dict(schemaVersion="planeon.conformance-performance-delta/v1",evidenceClass="SOURCE_DELTA_ONLY",
                 packetId="CONF-PERF-001",authorityDigest=RECORD_SHA256,baseCommit=record["sourceBaseline"]["commit"],
                 sources=rows,newTestIds=["PerformanceScopeOnlyTests.test_independent_scope_example"],
                 beforeSources={p:r for p,r in before.items() if p != doc},documentSuffix="\nScope-only synthetic data; not a performance pass.\n")
    after[doc] += proof["documentSuffix"].encode()+b"\n\x60\x60\x60harness-performance-source-proof\n"+canonical(proof)+b"\n\x60\x60\x60\n"
    return after,proof


def test_acyclic_profile_only_data_is_not_optimized_or_native_acceptance(authority):
    _,record,inputs = authority
    after,proof = sample(authority)
    assert validate_product_delta(after,proof,record,inputs[PRODUCT_PATH]) == []
    assert "docs/live-backend/linux-boundary.md" not in proof["sources"]
    assert proof["evidenceClass"] == "SOURCE_DELTA_ONLY"
    assert record["preserved"]["nativeAcceptance"] is False


@pytest.mark.parametrize("fault",["outside-crypto","old-body","doc-prefix","extra-path","missing-path","wrong-region",
    "region-name","runtime-import","runtime-call","helper-pin","before","after-digest","new-id","extra-proof","self-digest",
    "snapshot","oversize","skip","collection"])
def test_product_scope_rejects_tampering_before_history(authority,fault):
    _,record,inputs = authority
    after,proof = sample(authority)
    crypto = "src/harness_conformance/crypto.py"
    supervisor = "tests/live_backend/test_supervisor.py"
    doc = "docs/live-backend/linux-boundary.md"
    if fault == "outside-crypto": after[crypto] += b"\n"
    if fault == "old-body": after[supervisor] = after[supervisor].replace(b"self.assert",b"self.changed",1)
    if fault == "doc-prefix": after[doc] = b"\n"+after[doc]
    if fault == "extra-path": after["src/other.py"] = b""
    if fault == "missing-path": after.pop(crypto)
    if fault == "wrong-region": proof["sources"][crypto]["regions"]["verify"] = "def verify():\n    return True\n"
    if fault == "region-name": proof["sources"][crypto]["regions"]["_add"] = "def replacement(left, right):\n    return left\n"
    if fault == "runtime-import": proof["sources"][crypto]["regions"]["_add"] = proof["sources"][crypto]["regions"]["_add"].replace("    x1, y1 = left","    import os\n    x1, y1 = left")
    if fault == "runtime-call": proof["sources"][crypto]["regions"]["_add"] = proof["sources"][crypto]["regions"]["_add"].replace("pow(","cached(",1)
    if fault == "helper-pin": proof["sources"]["tests/live_backend/_inventory.py"]["constant"] = "0"*64
    if fault == "before": proof["baseCommit"] = "0"*40
    if fault == "after-digest": proof["sources"][crypto]["afterSha256"] = "0"*64
    if fault == "new-id": proof["newTestIds"] = []
    if fault == "extra-proof": proof["unknown"] = True
    if fault == "self-digest": proof["sources"][doc] = {}
    if fault == "snapshot": proof["beforeSources"][crypto] += "\n"
    if fault == "oversize": proof["sources"][supervisor]["append"] = "x"*131073
    if fault == "skip": proof["sources"][supervisor]["append"] += "\n@unittest.skip('hidden')\ndef test_hidden():\n    pass\n"
    if fault == "collection": proof["sources"][supervisor]["append"] += "\ndef load_tests(loader, tests, pattern):\n    return tests\n"
    # Recompute actual candidate bytes and checksums for malformed but scoped
    # edits. These cases must fail the relevant guard, not a stale checksum.
    if fault in {"region-name", "runtime-import", "runtime-call", "helper-pin", "oversize", "skip", "collection"}:
        before = json.loads(inputs[PRODUCT_PATH])["files"]
        path = crypto if fault in {"region-name", "runtime-import", "runtime-call"} else (
            "tests/live_backend/_inventory.py" if fault == "helper-pin" else supervisor)
        row = proof["sources"][path]
        current = before[path].encode()
        spans = [(region(current, name)[:2], value.encode()) for name, value in row["regions"].items()]
        for (start, end), value in sorted(spans, reverse=True):
            current = current[:start] + value + current[end:]
        if row["constant"] is not None:
            current = re.sub(rb'^HELPER_SHA256 = "[0-9a-f]{64}"$',
                ('HELPER_SHA256 = "'+row["constant"]+'"').encode(), current, flags=re.M)
        after[path] = current + row["append"].encode()
        row["afterSha256"] = digest(after[path])
    # Keep document assembly consistent so source-oracle negatives do not pass
    # merely because an earlier proof-document equality catches changed JSON.
    if fault != "doc-prefix" and doc in after:
        before_doc = json.loads(inputs[PRODUCT_PATH])["files"][doc].encode()
        after[doc] = before_doc+proof["documentSuffix"].encode()+b"\n\x60\x60\x60harness-performance-source-proof\n"+canonical(proof)+b"\n\x60\x60\x60\n"
    assert validate_product_delta(after,proof,record,inputs[PRODUCT_PATH])


def test_validator_is_data_only_and_does_not_import_execute_or_profile_product():
    tree = ast.parse((ROOT/"scripts/validate_conformance_performance.py").read_bytes())
    forbidden = {"exec","eval","compile","__import__","Popen","system","CDLL","socket","syscall"}
    for node in ast.walk(tree):
        if isinstance(node,ast.Call):
            name = node.func.id if isinstance(node.func,ast.Name) else getattr(node.func,"attr","")
            assert name not in forbidden
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            names = [n.name for n in node.names] if isinstance(node,ast.Import) else [node.module or ""]
            assert not any(n.startswith(("harness_conformance","subprocess","ctypes","socket","cProfile")) for n in names)


def test_roadmap_keeps_draft_and_source_native_gates_separate():
    guide = (ROOT/"docs/alpha-2/CONFORMANCE_PERFORMANCE_REPAIR.md").read_text()
    for text in ("NOT_YET_MEASURED","CANCELLED_NOT_PASS","SOURCE_DELTA_ONLY","327",
                 "750 seconds","0.85","CONF-LIVE-003","NOT_RUN_ENV_UNAVAILABLE","effort transition NOT_DUE"):
        assert text in guide
    status = (ROOT/"docs/DEVELOPMENT_STATUS.md").read_text().split("## Historical MET-PERF-002 publication checkpoint\n",1)[1].split("## Historical MET-REPAIR-015")[0]
    assert "MET-PERF-002 | ONGOING" in status
    assert "CONF-PERF-001 | WAITING" in status
    assert "PR12 | WAITING" in status
