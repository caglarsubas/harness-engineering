"""Independent follow-up data tests. Product snapshots are never executed."""
import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import re

import pytest

from scripts.validate_conformance_consumer_closure import historical_bytes as closure_history

from scripts.safe_yaml import safe_load
from scripts.validate_conformance_performance_followup import (
    ROOT, BEFORE_PATH, PRODUCT_PATH, RECORD_SHA256, apply_recipe, canonical,
    current_test_bytes, digest, historical_bytes, load_inputs, reconstruct_product,
    region, regular_bytes, test_ids as ids, validate_additions, validate_authority, validate_product_delta,
    validate_dispatch_ownership,
)

DOC = "docs/live-backend/linux-boundary.md"
SUPERVISOR = "tests/live_backend/test_supervisor.py"
CRYPTO = "src/harness_conformance/crypto.py"
HELPER = "tests/platform/linux_baseline/_successor_inventory.py"
IMPORTER = "tests/live_backend/_inventory.py"
SCALAR = "tests/platform/linux_baseline/test_packet_scalars.py"
SUCCESSOR = "tests/platform/linux_baseline/test_successor_inventory.py"


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/"task-packets").glob("*.yaml")}
    return packets,*load_inputs(ROOT)


def test_exact_catalog_preserves_every_old_yaml_and_authority(authority):
    packets, record, inputs = authority
    assert validate_authority(*authority) == []
    assert len(packets) == 194
    old = [p for p in record["protectedFiles"] if p.startswith("task-packets/") and p.endswith(".yaml")]
    assert len(old) == 146
    for path in old:
        assert digest(inputs[path]) == record["protectedFiles"][path]
    assert len(packets["MET-PERF-003"]["offlineAcceptanceCommands"]) == 25
    assert packets["CONF-PERF-002"]["offlineAcceptanceCommands"] == packets["CONF-PERF-001"]["offlineAcceptanceCommands"]
    assert len(packets["CONF-PERF-002"]["offlineAcceptanceCommands"]) == 8
    assert "CONF-PERF-001" not in packets["CONF-PERF-002"]["predecessors"]
    assert record["dispatch"]["CONF-PERF-001"] == "SUPERSEDED_UNACCEPTED_HISTORY"
    assert record["sourceBaseline"]["files"] == 127 and record["sourceBaseline"]["tests"] == 327
    assert record["stages"] == [110,120,127,135,141,146,151]
    assert record["preserved"]["nestedSeconds"] == 420
    assert record["preserved"]["trustedSeconds"] == 900
    assert record["preserved"]["workflowMinutes"] == 15
    assert record["preserved"]["nativeAcceptance"] is record["preserved"]["tenantAcceptance"] is False


def test_every_current_meta_byte_is_validated_before_history(authority):
    _, record, inputs = authority
    before = json.loads(inputs[BEFORE_PATH])["files"]
    for path, rule in record["metaRecipes"].items():
        raw = before[path].encode()
        assert apply_recipe(raw, rule) == closure_history(path, inputs[path])
        assert historical_bytes(path, inputs[path]) == raw
        if path.startswith("tests/"):
            assert ids(raw) == ids(inputs[path])
            assert current_test_bytes(raw) == inputs[path]
        with pytest.raises(ValueError):
            historical_bytes(path, inputs[path]+b"\n")
    for path in record["unchangedTests"]:
        assert current_test_bytes(closure_history(path, inputs[path])) == inputs[path]


def test_exact_bridges_preserve_old_oracles_and_only_change_historical_operands(authority):
    _, record, inputs = authority
    before = json.loads(inputs[PRODUCT_PATH])["files"]
    assert set(record["accountingBridges"]) == {SCALAR, SUCCESSOR}
    assert len(before) == len(record["productPaths"]) == 8
    assert set(before) == {DOC,SUPERVISOR,CRYPTO,HELPER,IMPORTER,SCALAR,SUCCESSOR,
                           "tests/platform/linux_baseline/test_linux_inventory.py"}
    for path, bridge in record["accountingBridges"].items():
        raw = before[path].encode()
        start,end,_ = region(raw,bridge["region"])
        old = raw[start:end].decode()
        assert digest(old.encode()) == bridge["beforeSha256"]
        if path == SCALAR:
            expected = old.replace('        for path, change in FIXTURE["changes"].items():',
                '        helper = load_local("performance_historical_consumer", "tests/platform/linux_baseline/_successor_inventory.py")\n'
                '        _, historical_sources, _ = helper.performance_current(ROOT)\n'
                '        for path, change in FIXTURE["changes"].items():').replace(
                'check_edit(path, before, regular(path).read_bytes())','check_edit(path, before, historical_sources[path])')
        else:
            expected = old.replace('        historical = json.loads',
                '        _, historical_sources, _ = HELPER.performance_current(ROOT)\n        historical = json.loads').replace(
                'self.assertEqual(sha((ROOT / path).read_bytes()), checksum)',
                'self.assertEqual(sha(historical_sources[path]), checksum)')
        assert bridge["after"] == expected
        assert digest(expected.encode()) == bridge["afterSha256"]
        assert record["productRegions"][path]["fixedRegions"] == {bridge["region"]:expected}
        assert record["productRegions"][path]["append"] == 0
    assert record["consumerGraph"] == ["original-linux-91","scalar-exact-edit","successor-exact-history",
        "cumulative-106-stages","backend-110","supervisor-120","custody-279","credential-305",
        "accepted-127-327","actual-six-root-discovery"]


def test_partial_measurement_never_becomes_baseline_or_algorithm_authority(authority):
    _, record, _ = authority
    measurement, profiling = record["measurement"], record["profiling"]
    assert measurement["functionAttribution"] == "NOT_YET_MEASURED"
    assert measurement["baselineAccepted"] is measurement["algorithmSelected"] is False
    assert [a["status"] for a in measurement["attempts"]] == ["FAIL_ACCOUNTING","TIMEOUT_NOT_PASS"]
    assert measurement["ci"]["status"] == "CANCELLED_QUEUED_NO_RUNNER_NOT_PASS"
    assert measurement["ci"]["runnerId"] == 0
    assert profiling == dict(subcalls=False,builtins=True,defaultTimer=True,scope="FULL_SUPERVISOR_MODULE",
        requiredFunctions=["_add","_scalar_mult","sign","verify","builtins.pow"],fullBaselineRequired=True,
        partialMayAuthorizeOptimization=False,crossCallCacheAllowed=False,fullProductCommandsRequired=8,
        workloadMedianRatio=0.85,candidateTrustedSeconds=750)


def test_supersession_retains_generic_checks_and_only_closes_exact_pair(authority):
    from scripts.validate_packet_ownership import validate_packet_ownership
    packets, _, _ = authority
    generic = validate_packet_ownership(packets)
    assert len(generic) == 118
    assert all(any(pair in error for pair in ("CONF-BENCH-001 and CONF-PERF-001", "CONF-BENCH-001 and CONF-PERF-002", "CONF-BENCH-001 and CONF-PERF-003", "CONF-BENCH-001 and CONF-PERF-004", "CONF-PERF-001 and CONF-PERF-002", "CONF-PERF-001 and CONF-PERF-003", "CONF-PERF-001 and CONF-PERF-004", "CONF-PERF-002 and CONF-PERF-003", "CONF-PERF-002 and CONF-PERF-004", "CONF-PERF-003 and CONF-PERF-004", "CONF-BENCH-001 and CONF-FIX-006", "CONF-FIX-006 and CONF-PERF-001", "CONF-FIX-006 and CONF-PERF-002", "CONF-FIX-006 and CONF-PERF-003", "CONF-DIAG-001 and CONF-LIVE-003", "CONF-DIAG-002 and CONF-LIVE-003", "CONF-BENCH-002 and CONF-FIX-007", "CONF-BENCH-002 and CONF-LIVE-003", "CONF-BENCH-002 and CONF-PERF-006", "CONF-FIX-007 and CONF-PERF-006", "CONF-BENCH-002 and CONF-BENCH-003", "CONF-BENCH-003 and CONF-FIX-007", "CONF-BENCH-003 and CONF-LIVE-003", "CONF-BENCH-003 and CONF-PERF-006", "CONF-BENCH-002 and CONF-FIX-008", "CONF-BENCH-003 and CONF-FIX-008", "CONF-DIAG-003 and CONF-FIX-008", "CONF-FIX-007 and CONF-FIX-008", "CONF-DIAG-003 and CONF-DIAG-004", "CONF-DIAG-004 and CONF-FIX-007", "CONF-BENCH-002 and CONF-FIX-009", "CONF-BENCH-003 and CONF-FIX-009", "CONF-DIAG-003 and CONF-FIX-009", "CONF-FIX-007 and CONF-FIX-009", "CONF-BENCH-002 and CONF-FIX-010", "CONF-BENCH-003 and CONF-FIX-010", "CONF-DIAG-003 and CONF-FIX-010", "CONF-FIX-007 and CONF-FIX-010")) for error in generic)
    assert validate_dispatch_ownership(packets) == []
    assert "CONF-PERF-001" not in packets["CONF-PERF-002"]["predecessors"]


@pytest.mark.parametrize("fault", ["old-path", "new-path", "old-command", "new-command", "old-repo",
    "new-predecessor", "missing-old", "missing-new", "unrelated-overlap", "unrelated-make"])
def test_supersession_never_suppresses_changed_packets_or_other_ownership_errors(authority, fault):
    from scripts.validate_packet_ownership import validate_packet_ownership
    packets = deepcopy(authority[0])
    if fault == "old-path": packets["CONF-PERF-001"]["allowedPaths"].append("outside.py")
    if fault == "new-path": packets["CONF-PERF-002"]["allowedPaths"].append("outside.py")
    if fault == "old-command": packets["CONF-PERF-001"]["offlineAcceptanceCommands"].pop()
    if fault == "new-command": packets["CONF-PERF-002"]["offlineAcceptanceCommands"].pop()
    if fault == "old-repo": packets["CONF-PERF-001"]["repository"] = "Harness-Engineering"
    if fault == "new-predecessor": packets["CONF-PERF-002"]["predecessors"].append("CONF-PERF-001")
    if fault == "missing-old": packets.pop("CONF-PERF-001")
    if fault == "missing-new": packets.pop("CONF-PERF-002")
    if fault == "unrelated-overlap":
        packets["UNRELATED-001"] = dict(repository="mas-harness-conformance-labs",
            predecessors=[], allowedPaths=["src/harness_conformance/crypto.py"])
    if fault == "unrelated-make": packets["CONF-FIX-005"]["offlineAcceptanceCommands"].append(["make", "bad;target"])
    result = validate_dispatch_ownership(packets)
    assert result
    unrelated = [error for error in validate_packet_ownership(packets)
                 if not any(pair in error for pair in ("CONF-BENCH-001 and CONF-PERF-001", "CONF-BENCH-001 and CONF-PERF-002", "CONF-BENCH-001 and CONF-PERF-003", "CONF-BENCH-001 and CONF-PERF-004", "CONF-PERF-001 and CONF-PERF-002", "CONF-PERF-001 and CONF-PERF-003", "CONF-PERF-001 and CONF-PERF-004", "CONF-PERF-002 and CONF-PERF-003", "CONF-PERF-002 and CONF-PERF-004", "CONF-PERF-003 and CONF-PERF-004", "CONF-BENCH-001 and CONF-FIX-006", "CONF-FIX-006 and CONF-PERF-001", "CONF-FIX-006 and CONF-PERF-002", "CONF-FIX-006 and CONF-PERF-003", "CONF-DIAG-001 and CONF-LIVE-003", "CONF-DIAG-002 and CONF-LIVE-003", "CONF-BENCH-002 and CONF-FIX-007", "CONF-BENCH-002 and CONF-LIVE-003", "CONF-BENCH-002 and CONF-PERF-006", "CONF-FIX-007 and CONF-PERF-006", "CONF-BENCH-002 and CONF-BENCH-003", "CONF-BENCH-003 and CONF-FIX-007", "CONF-BENCH-003 and CONF-LIVE-003", "CONF-BENCH-003 and CONF-PERF-006", "CONF-BENCH-002 and CONF-FIX-008", "CONF-BENCH-003 and CONF-FIX-008", "CONF-DIAG-003 and CONF-FIX-008", "CONF-FIX-007 and CONF-FIX-008", "CONF-DIAG-003 and CONF-DIAG-004", "CONF-DIAG-004 and CONF-FIX-007", "CONF-BENCH-002 and CONF-FIX-009", "CONF-BENCH-003 and CONF-FIX-009", "CONF-DIAG-003 and CONF-FIX-009", "CONF-FIX-007 and CONF-FIX-009", "CONF-BENCH-002 and CONF-FIX-010", "CONF-BENCH-003 and CONF-FIX-010", "CONF-DIAG-003 and CONF-FIX-010", "CONF-FIX-007 and CONF-FIX-010"))]
    assert set(unrelated) <= set(result)


@pytest.mark.parametrize("fault",["packet","old-yaml","source","missing","extra","before","product-before","record",
    "command","timeout","native","partial","cache","profile","bridge","dispatch"])
def test_authority_and_measurement_boundaries_fail_closed(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == "packet": packets["CONF-PERF-002"]["allowedPaths"].append("src/other.py")
    if fault == "old-yaml": inputs["task-packets/CONF-PERF-001.yaml"] += b" "
    if fault == "source": inputs["scripts/validate_readiness.py"] += b"\n"
    if fault == "missing": inputs.pop(PRODUCT_PATH)
    if fault == "extra": inputs["arbitrary"] = b""
    if fault == "before": inputs[BEFORE_PATH] += b" "
    if fault == "product-before": inputs[PRODUCT_PATH] += b" "
    if fault == "record": record["productPaths"].append("Makefile")
    if fault == "command": packets["CONF-PERF-002"]["offlineAcceptanceCommands"].pop()
    if fault == "timeout": record["preserved"]["trustedSeconds"] += 1
    if fault == "native": record["preserved"]["nativeAcceptance"] = True
    if fault == "partial": record["profiling"]["partialMayAuthorizeOptimization"] = True
    if fault == "cache": record["profiling"]["crossCallCacheAllowed"] = True
    if fault == "profile": record["profiling"]["builtins"] = False
    if fault == "bridge": record["productRegions"][SUCCESSOR].pop("fixedRegions")
    if fault == "dispatch": packets["CONF-PERF-002"]["predecessors"].append("CONF-PERF-001")
    assert validate_authority(packets,record,inputs)


def rebuild_source(before, row):
    # Independent test assembly, without calling the oracle under test.
    raw = before
    spans = [(region(before,name)[:2],value.encode()) for name,value in row["regions"].items()]
    for (start,end),value in sorted(spans,reverse=True):
        raw = raw[:start]+value+raw[end:]
    if row["constant"] is not None:
        raw = re.sub(rb'^HELPER_SHA256 = "[0-9a-f]{64}"$', ('HELPER_SHA256 = "'+row["constant"]+'"').encode(), raw, flags=re.M)
    return raw + row["append"].encode()


def reseal(after, proof, before):
    for path,row in proof["sources"].items():
        after[path] = rebuild_source(before[path].encode(),row)
        row["afterSha256"] = digest(after[path])
    after[DOC] = before[DOC].encode()+proof["documentSuffix"].encode()+b"\n```harness-performance-source-proof\n"+canonical(proof)+b"\n```\n"


def sample(authority):
    _,record,inputs = authority
    before = json.loads(inputs[PRODUCT_PATH])["files"]
    rows = {}
    for path,spec in record["productRegions"].items():
        if path == DOC:
            continue
        raw = before[path].encode()
        regions = {name:raw[slice(*region(raw,name)[:2])].decode() for name in spec["regions"]}
        if "fixedRegions" in spec:
            regions = deepcopy(spec["fixedRegions"])
        addition = "\nclass FollowupScopeOnlyTests(unittest.TestCase):\n    def test_independent_scope_example(self):\n        self.assertEqual(1, 1)\n" if path == SUPERVISOR else ""
        rows[path] = dict(regions=regions,append=addition,afterSha256="",constant=None)
    rows[IMPORTER]["constant"] = digest(before[HELPER].encode())
    proof = dict(schemaVersion="planeon.conformance-performance-delta/v2",evidenceClass="SOURCE_DELTA_ONLY",
        packetId="CONF-PERF-002",authorityDigest=RECORD_SHA256,baseCommit=record["sourceBaseline"]["commit"],sources=rows,
        newTestIds=["FollowupScopeOnlyTests.test_independent_scope_example"],
        beforeSources={p:r for p,r in before.items() if p != DOC},documentSuffix="\nSynthetic scope data, not acceptance.\n")
    after = {}
    reseal(after,proof,before)
    return after,proof,before


def test_exact_eight_path_proof_accepts_only_scope_not_execution(authority):
    _,record,inputs = authority
    after,proof,_ = sample(authority)
    assert validate_product_delta(after,proof,record,inputs[PRODUCT_PATH]) == []
    assert len(after) == 8 and len(proof["sources"]) == 7
    assert DOC not in proof["sources"] and proof["evidenceClass"] == "SOURCE_DELTA_ONLY"


@pytest.mark.parametrize("fault",["scalar-original","successor-original","scalar-bypass","successor-current-disk",
    "successor-expected","bridge-extra","bridge-append","old-assertion","runtime-import","runtime-call","helper-pin",
    "skip","xfail","collection","shadow","oversize","missing-id","extra-id","duplicate-id"])
def test_resealed_source_mutations_fail_intended_scope_guards(authority,fault):
    _,record,inputs = authority
    after,proof,before = sample(authority)
    rows = proof["sources"]
    scalar_name = record["accountingBridges"][SCALAR]["region"]
    successor_name = record["accountingBridges"][SUCCESSOR]["region"]
    if fault in ("scalar-original","successor-original"):
        path,name = (SCALAR,scalar_name) if fault == "scalar-original" else (SUCCESSOR,successor_name)
        raw = before[path].encode()
        rows[path]["regions"][name] = raw[slice(*region(raw,name)[:2])].decode()
    if fault == "scalar-bypass": rows[SCALAR]["regions"][scalar_name] = rows[SCALAR]["regions"][scalar_name].replace('check_edit(path, before, historical_sources[path])','check_edit(path, before, before)')
    if fault == "successor-current-disk": rows[SUCCESSOR]["regions"][successor_name] = rows[SUCCESSOR]["regions"][successor_name].replace('sha(historical_sources[path])','sha((ROOT / path).read_bytes())')
    if fault == "successor-expected": rows[SUCCESSOR]["regions"][successor_name] = rows[SUCCESSOR]["regions"][successor_name].replace(', checksum)',', sha(historical_sources[path]))')
    if fault == "bridge-extra": rows[SCALAR]["regions"][scalar_name] += '        x = 1\n'
    if fault == "bridge-append": rows[SUCCESSOR]["append"] = '\n# unapproved extra\n'
    if fault == "old-assertion":
        name = 'SupervisorPredecessorTests.test_immediate_120_file_216_id_checkpoint_and_older_stages_are_immutable'
        rows[SUPERVISOR]["regions"][name] = rows[SUPERVISOR]["regions"][name].replace('self.assertEqual','self.assertNotEqual',1)
    if fault == "runtime-import": rows[CRYPTO]["regions"]["_add"] = rows[CRYPTO]["regions"]["_add"].replace('    x1, y1 = left','    import os\n    x1, y1 = left')
    if fault == "runtime-call": rows[CRYPTO]["regions"]["_add"] = rows[CRYPTO]["regions"]["_add"].replace('pow(', 'cached(',1)
    if fault == "helper-pin": rows[IMPORTER]["constant"] = '0'*64
    if fault == "skip": rows[SUPERVISOR]["append"] += "\n@unittest.skip('hidden')\ndef test_hidden():\n    pass\n"
    if fault == "xfail": rows[SUPERVISOR]["append"] += "\n@unittest.expectedFailure\ndef test_hidden():\n    pass\n"
    if fault == "collection": rows[SUPERVISOR]["append"] += '\ndef load_tests(a,b,c):\n    return b\n'
    if fault == "shadow": rows[SUPERVISOR]["append"] += '\ndef _credential_inputs():\n    pass\n'
    if fault == "oversize": rows[SUPERVISOR]["append"] = '\n'*131073
    if fault == "missing-id": proof["newTestIds"] = []
    if fault == "extra-id": proof["newTestIds"].append('Extra.test_hidden')
    if fault == "duplicate-id": proof["newTestIds"] *= 2
    reseal(after,proof,before)
    assert all(digest(after[p]) == r["afterSha256"] for p,r in rows.items())
    assert validate_product_delta(after,proof,record,inputs[PRODUCT_PATH])


@pytest.mark.parametrize("fault",["outside-region","doc-prefix","doc-suffix","extra-path","missing-path","wrong-region",
    "before-source","after-hash","authority","packet","schema","self-digest","extra-proof","document-oversize"])
def test_outer_proof_binding_refuses_independent_forgery(authority,fault):
    _,record,inputs = authority
    after,proof,before = sample(authority)
    if fault == "wrong-region": proof["sources"][CRYPTO]["regions"]["verify"] = 'def verify():\n    return True\n'
    if fault == "before-source": proof["beforeSources"][CRYPTO] += '\n'
    if fault == "after-hash": proof["sources"][CRYPTO]["afterSha256"] = '0'*64
    if fault == "authority": proof["authorityDigest"] = '0'*64
    if fault == "packet": proof["packetId"] = 'CONF-PERF-001'
    if fault == "schema": proof["schemaVersion"] = 'planeon.conformance-performance-delta/v1'
    if fault == "self-digest": proof["sources"][DOC] = {}
    if fault == "extra-proof": proof["unknown"] = True
    if fault == "document-oversize": proof["documentSuffix"] = 'x'*65537
    after[DOC] = before[DOC].encode()+proof["documentSuffix"].encode()+b"\n```harness-performance-source-proof\n"+canonical(proof)+b"\n```\n"
    if fault == "outside-region":
        after[CRYPTO] += b'\n# unreviewed\n'
        proof["sources"][CRYPTO]["afterSha256"] = digest(after[CRYPTO])
        after[DOC] = before[DOC].encode()+proof["documentSuffix"].encode()+b"\n```harness-performance-source-proof\n"+canonical(proof)+b"\n```\n"
    if fault == "doc-prefix": after[DOC] = b'!'+after[DOC][1:]
    if fault == "doc-suffix": after[DOC] += b'!'
    if fault == "extra-path": after['Makefile'] = b''
    if fault == "missing-path": after.pop(SCALAR)
    assert validate_product_delta(after,proof,record,inputs[PRODUCT_PATH])


def test_regular_inputs_refuse_links_and_nonregular_sources(tmp_path):
    (tmp_path/'source').write_bytes(b'fixed')
    (tmp_path/'link').symlink_to(tmp_path/'source')
    with pytest.raises(ValueError): regular_bytes(tmp_path,'link')
    os.link(tmp_path/'source',tmp_path/'hard')
    with pytest.raises(ValueError): regular_bytes(tmp_path,'hard')
    (tmp_path/'dir').mkdir()
    with pytest.raises(ValueError): regular_bytes(tmp_path,'dir')
    (tmp_path/'alias').symlink_to(tmp_path/'dir',target_is_directory=True)
    with pytest.raises(ValueError): regular_bytes(tmp_path,'alias/file')


def test_validator_is_data_only_and_product_cannot_execute_in_meta():
    tree = ast.parse((ROOT/'scripts/validate_conformance_performance_followup.py').read_bytes())
    forbidden = {'exec','eval','compile','__import__','Popen','system','CDLL','socket','syscall'}
    for node in ast.walk(tree):
        if isinstance(node,ast.Call):
            name = node.func.id if isinstance(node.func,ast.Name) else getattr(node.func,'attr','')
            assert name not in forbidden
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            names = [n.name for n in node.names] if isinstance(node,ast.Import) else [node.module or '']
            assert not any(n.startswith(('harness_conformance','subprocess','ctypes','socket','cProfile')) for n in names)


def test_roadmap_and_measurement_keep_all_acceptance_boundaries():
    guide = (ROOT/'docs/alpha-2/CONFORMANCE_PERFORMANCE_FOLLOWUP.md').read_text()
    for value in ('NOT_YET_MEASURED','PARTIAL_DIAGNOSTIC_ONLY','SOURCE_DELTA_ONLY','327','750 seconds',
                  '0.85','CONF-LIVE-003','NOT_RUN_ENV_UNAVAILABLE','effort transition NOT_DUE',
                  'subcalls=False, builtins=True','119','119','170','900','create_stats mid-run'):
        assert value in guide
    current = (ROOT/'docs/DEVELOPMENT_STATUS.md').read_text().split('## Historical MET-PERF-003 publication checkpoint\n',1)[1].split('## Historical MET-PERF-002')[0]
    for value in ('MET-PERF-003 | ONGOING','CONF-PERF-002 | WAITING','draft13 | BLOCKED_UNACCEPTED','draft12 | WAITING'):
        assert value in current
