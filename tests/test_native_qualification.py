"""Independent qualification DATA tests; no kernel/syscall or product execution."""
import ast
from copy import deepcopy
import json
from pathlib import Path

import jsonschema
import pytest

from scripts.validate_conformance_performance import historical_bytes as performance_history

from scripts.safe_yaml import safe_load
from scripts.validate_native_qualification import (
    BEFORE_PATH,SCHEMA_PATH,VECTORS_PATH,CHECKPOINT_PATH,ROLES,HOOKS,
    _shape,_tests,apply_recipe,canonical,current_test_bytes,digest,historical_bytes,
    load_qualification_inputs,validate_additions,validate_capture,validate_record,
    validate_qualification_authority,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/"task-packets").glob("*.yaml")}
    return packets,*load_qualification_inputs(ROOT)


@pytest.fixture(scope="module")
def data(authority):
    return json.loads(authority[2][SCHEMA_PATH]),json.loads(authority[2][VECTORS_PATH])


def test_exact_catalog_recipe_and_unchanged_product_checkpoint(authority):
    packets,record,inputs = authority
    assert validate_qualification_authority(*authority) == []
    assert len(packets) == 194
    assert sum(p.startswith("task-packets/") for p in record["protectedFiles"]) == 143
    assert len(packets["MET-REPAIR-015"]["offlineAcceptanceCommands"]) == 23
    checkpoint = json.loads(inputs[CHECKPOINT_PATH])
    assert checkpoint["commit"] == "9df7dd7f2df8ac64096ef37d8df259761947d552"
    assert len(checkpoint["files"]) == 127
    assert sum(map(len,checkpoint["tests"].values())) == 327
    assert record["stages"] == [110,120,127,135,141,146,151]
    assert all(len(d["commands"]) == 8 for d in record["dispatch"].values())


@pytest.mark.parametrize("index",range(4))
def test_both_architectures_and_resource_modes_are_consistent_data_only(data,index):
    schema,vectors = data
    sample = vectors["positive"][index]
    assert validate_record(sample["record"],sample["profile"],sample["endpoints"],schema) == []
    for capture in sample["captures"]:
        assert validate_capture(sample["record"],capture,capture["role"],schema) == []
    assert vectors["nativeAcceptance"] is vectors["tenantAcceptance"] is False
    assert vectors["evidenceClass"] == "DATA_CHECK_ONLY"


def objects(value,path=()):
    if type(value) is dict:
        yield path,value
        for key,item in value.items(): yield from objects(item,path+(key,))
    elif type(value) is list:
        for key,item in enumerate(value): yield from objects(item,path+(key,))


@pytest.mark.parametrize("variant",["record","capture"])
def test_all_closed_nested_objects_reject_extra_missing_and_wrong_typed_fields(data,variant):
    schema,vectors = data
    sample = vectors["positive"][0]
    value = sample["record"] if variant == "record" else sample["captures"][0]
    for path,mapping in objects(value):
        for key in [None,*mapping]:
            changed = deepcopy(value)
            target = changed
            for part in path: target = target[part]
            if key is None: target["unknown"] = True
            else: del target[key]
            with pytest.raises((ValueError,jsonschema.ValidationError)): _shape(changed,variant,schema)
        for key in mapping:
            changed = deepcopy(value)
            target = changed
            for part in path: target = target[part]
            target[key] = {"truthy":True}
            with pytest.raises((ValueError,jsonschema.ValidationError)): _shape(changed,variant,schema)


@pytest.mark.parametrize("fault",["profile","scope","endpoint-ip","endpoint-port","extra-network",
    "worker-network","server-network","self-digest","release-digest","duplicate-file",
    "missing-interpreter","unowned-file","digest-conflation","traversal","segment-overflow",
    "wrong-program-type","instruction-size","odd-epoch","bad-window"])
def test_expected_record_never_expands_signed_scope_or_qualifies_a_declaration(data,fault):
    schema,vectors = data
    sample = vectors["positive"][0]
    record = deepcopy(sample["record"])
    server = record["roles"]["SERVER"]
    if fault == "profile": record["profileDigest"] = "sha256:"+"0"*64
    if fault == "scope": record["scope"]["tenantId"] = "another"
    if fault == "endpoint-ip": record["endpointTuples"][0]["ipAddress"] = "127.0.0.3"
    if fault == "endpoint-port": record["endpointTuples"][0]["port"] += 1
    if fault == "extra-network": server["outboundEndpointIds"] = ["unapproved"]
    if fault == "worker-network": record["roles"]["WORKER"]["outboundEndpointIds"] = ["unit-proxy"]
    if fault == "server-network": server["outboundEndpointIds"] = [sample["profile"]["binding"]["endpointId"]]
    if fault in ("self-digest","release-digest"): record[fault] = "sha256:"+"a"*64
    if fault == "duplicate-file": record["files"].append(deepcopy(record["files"][0]))
    if fault == "missing-interpreter": server["filePaths"].remove(server["interpreterPath"])
    if fault == "unowned-file":
        row = deepcopy(record["files"][0]); row["path"] = "/opt/planeon/unowned"; record["files"].append(row)
    if fault == "digest-conflation": record["files"][0]["verityDigest"] = record["files"][0]["sha256"]
    if fault == "traversal": record["files"][0]["path"] = "/opt/planeon/../unowned"
    if fault == "segment-overflow": record["files"][1]["executableSegments"][0]["length"] = 8192
    if fault == "wrong-program-type": server["bpfPrograms"]["INET_SOCK_CREATE"]["programType"] = 18
    if fault == "instruction-size": server["bpfPrograms"]["INET4_BIND"]["instructionBytes"] = 9
    if fault == "odd-epoch": record["selinux"]["status"]["sequence"] = 3
    if fault == "bad-window": record["scope"]["expiresAt"] = record["scope"]["validFrom"]
    assert validate_record(record,sample["profile"],sample["endpoints"],schema)


@pytest.mark.parametrize("role",ROLES)
@pytest.mark.parametrize("fault",["policy-bytes","enforce","before-epoch","after-epoch","policy-aba",
    "boot","kernel","namespace","cgroup","label","uid","verity","content","inode-map",
    "missing-file","extra-map","effective-filter","local-filter","bpf-map","offload",
    "redacted-program","expired","deadline","slow-read","native-pass"])
def test_current_kernel_capture_mismatches_fail_for_every_role(data,role,fault):
    schema,vectors = data
    sample = vectors["positive"][1]
    capture = deepcopy(next(c for c in sample["captures"] if c["role"] == role))
    if fault == "policy-bytes": capture["kernelPolicyDigest"] = "sha256:"+"0"*64
    if fault == "enforce": capture["selinuxBefore"]["enforcing"] = 0
    if fault == "before-epoch": capture["selinuxBefore"]["sequence"] += 2
    if fault == "after-epoch": capture["selinuxAfter"]["sequence"] += 2
    if fault == "policy-aba":
        capture["selinuxBefore"]["sequence"] += 4; capture["selinuxAfter"]["sequence"] += 4
    if fault == "boot": capture["host"]["bootId"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    if fault == "kernel": capture["host"]["kernelRelease"] = "other-kernel"
    if fault == "namespace": capture["process"]["namespaceInodes"]["mnt"] += 1
    if fault == "cgroup": capture["process"]["cgroup"]["inode"] += 1
    if fault == "label": capture["process"]["processLabel"] = "unconfined"
    if fault == "uid": capture["process"]["uid"] += 1
    if fault == "verity": capture["files"][0]["measuredVerity"] = capture["files"][0]["contentDigest"]
    if fault == "content": capture["files"][0]["contentDigest"] = "sha256:"+"0"*64
    if fault == "inode-map": capture["executableMaps"][0]["inode"] += 1
    if fault == "missing-file": capture["files"].pop()
    if fault == "extra-map": capture["executableMaps"].append(deepcopy(capture["executableMaps"][0]))
    program = capture["bpfPrograms"][HOOKS[0]]
    if fault == "effective-filter": program["effectiveIds"].append(9999)
    if fault == "local-filter": program["localIds"] = [9999]
    if fault == "bpf-map": program["program"]["mapIds"] = [1]
    if fault == "offload": program["program"]["ifindex"] = 1
    if fault == "redacted-program": program["program"]["instructionBytes"] = 0
    if fault == "expired": capture["observedAt"] = sample["record"]["scope"]["expiresAt"]
    if fault == "deadline": capture["inspectionFinishedMs"] = capture["deadlineMs"]
    if fault == "slow-read": capture["inspectionFinishedMs"] = capture["inspectionStartedMs"]+2001
    if fault == "native-pass": capture["evidenceClass"] = "NATIVE_PASS"
    assert validate_capture(sample["record"],capture,role,schema)


@pytest.mark.parametrize("fault",["pid","start","file-inode","clock","monotonic","renewed-deadline"])
def test_retained_capture_detects_replacement_and_rollback(data,fault):
    schema,vectors = data
    sample = vectors["positive"][0]
    previous = sample["captures"][0]
    current = deepcopy(previous)
    current.update(inspectionStartedMs=1200,inspectionFinishedMs=1300,observedAt="2026-09-08T00:00:02Z")
    assert validate_capture(sample["record"],current,"SERVER",schema,previous) == []
    if fault == "pid": current["process"]["pid"] += 1
    if fault == "start": current["process"]["startTicks"] += 1
    if fault == "file-inode":
        current["files"][0]["inode"] += 1
    if fault == "clock": current["observedAt"] = "2026-09-08T00:00:00Z"
    if fault == "monotonic": current["inspectionStartedMs"] = 1000
    if fault == "renewed-deadline": current["deadlineMs"] += 1
    assert validate_capture(sample["record"],current,"SERVER",schema,previous)


@pytest.mark.parametrize("pretend",[True,{"qualified":True},["SIGNED","SECURE"],lambda:True])
def test_boolean_callback_or_trace_cannot_replace_record_or_capture(data,pretend):
    schema,vectors = data
    sample = vectors["positive"][0]
    assert validate_record(pretend,sample["profile"],sample["endpoints"],schema)
    assert validate_capture(sample["record"],pretend,"SERVER",schema)


def test_all_exact_current_bytes_are_checked_before_historical_reconstruction(authority):
    _,record,inputs = authority
    before = json.loads(inputs[BEFORE_PATH])["files"]
    for path,rule in record["metaRecipes"].items():
        raw = before[path].encode()
        assert apply_recipe(raw,rule) == performance_history(path, inputs[path])
        assert historical_bytes(path,inputs[path]) == raw
        if path.startswith("tests/"):
            assert _tests(raw) == _tests(inputs[path])
            assert current_test_bytes(raw) == inputs[path]
        with pytest.raises(ValueError): historical_bytes(path,inputs[path]+b"\n# changed\n")
    for path,checksum in record["unchangedTests"].items():
        assert digest(performance_history(path, inputs[path])) == checksum
        assert current_test_bytes(performance_history(path, inputs[path])) == inputs[path]


@pytest.mark.parametrize("fault",["packet","protected","before","schema","vectors","record","extra","missing"])
def test_authority_scope_and_all_source_inputs_fail_closed(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == "packet": packets["MET-REPAIR-015"]["contracts"].append("unreviewed")
    if fault == "protected": inputs["task-packets/CONF-LIVE-003.yaml"] += b" "
    if fault == "before": inputs[BEFORE_PATH] += b" "
    if fault == "schema": inputs[SCHEMA_PATH] += b" "
    if fault == "vectors": inputs[VECTORS_PATH] += b" "
    if fault == "record": record["nativeAcceptance"] = True
    if fault == "extra": inputs["unknown"] = b"x"
    if fault == "missing": del inputs[CHECKPOINT_PATH]
    assert validate_qualification_authority(packets,record,inputs)


def test_source_oracle_has_no_native_io_product_import_or_snapshot_execution():
    source = (ROOT/"scripts/validate_native_qualification.py").read_bytes()
    tree = ast.parse(source)
    forbidden = {"exec","eval","compile","__import__","socket","connect","Popen","system","syscall","ioctl","CDLL","mmap"}
    for node in ast.walk(tree):
        if isinstance(node,ast.Call):
            name = node.func.id if isinstance(node.func,ast.Name) else getattr(node.func,"attr","")
            assert name not in forbidden
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node,ast.Import) else [node.module or ""]
            assert not any(n.startswith(("harness_conformance","ctypes","subprocess","socket")) for n in names)


def test_qualification_guide_closes_bootstrap_and_native_boundaries():
    guide = (ROOT/"docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md").read_text()
    for text in ("SELINUX_FSVERITY_CGROUP_BPF_V1","preflightEvidenceDigest",
                 "FS_IOC_MEASURE_VERITY","BPF_F_QUERY_EFFECTIVE","REGISTER_PRIVATE_EXPEDITED",
                 "no self/circular digest","NOT_RUN_ENV_UNAVAILABLE","check_self()",
                 "check_peer(role, retained_peer)","before opening the observer"):
        assert text in guide
    status = (ROOT/"docs/DEVELOPMENT_STATUS.md").read_text().split("## Historical MET-REPAIR-015 publication checkpoint\n",1)[1].split("## Historical MET-REPAIR-014")[0]
    assert "during `MET-REPAIR-015` publication" in status
    assert "MET-REPAIR-014 / PR109 | DONE_SOURCE_GATES" in status
    assert "MET-REPAIR-015 | ONGOING" in status
    assert "effort transition NOT_DUE" in status
