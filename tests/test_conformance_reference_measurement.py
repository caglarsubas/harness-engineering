"""Reference amendment data tests; never execute product snapshots or templates."""
import ast
from copy import deepcopy
import json
import re

import pytest

from scripts.validate_conformance_successor_checkpoint import historical_bytes as checkpoint_history

from scripts.safe_yaml import safe_load
from scripts.validate_conformance_reference_measurement import (
    ROOT, BEFORE_PATH, PRODUCT_PATH, RECORD_SHA256, apply_recipe, canonical,
    current_test_bytes, digest, historical_bytes, load_inputs, region,
    test_ids as ids, validate_additions, validate_authority, validate_product_delta,
    validate_dispatch_ownership, validate_measurement_data, validate_reference_scaffold_data,
)

DOC = "docs/live-backend/linux-boundary.md"
SUP = "tests/live_backend/test_supervisor.py"
CRYPTO = "src/harness_conformance/crypto.py"
HELPER = "tests/platform/linux_baseline/_successor_inventory.py"
IMPORTER = "tests/live_backend/_inventory.py"


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/"task-packets").glob("*.yaml")}
    return packets,*load_inputs(ROOT)


def test_current_authority_preserves_all150_old_yaml_and_records(authority):
    packets, record, inputs = authority
    assert validate_authority(*authority) == []
    assert len(packets) == 194
    old = [p for p in record["protectedFiles"] if p.startswith("task-packets/") and p.endswith(".yaml")]
    assert len(old) == 150
    for path in old:
        assert digest(inputs[path]) == record["protectedFiles"][path]
    assert len(packets["MET-PERF-005"]["offlineAcceptanceCommands"]) == 27
    assert packets["MET-PERF-005"]["offlineAcceptanceCommands"][:-3] == packets["MET-PERF-004"]["offlineAcceptanceCommands"][:-2]
    assert packets["MET-PERF-005"]["offlineAcceptanceCommands"][-2:] == packets["MET-PERF-004"]["offlineAcceptanceCommands"][-2:]
    assert packets["CONF-PERF-004"]["offlineAcceptanceCommands"] == packets["CONF-FIX-005"]["offlineAcceptanceCommands"]
    assert len(packets["CONF-PERF-004"]["offlineAcceptanceCommands"]) == 8
    for path, checksum in record["protectedFiles"].items():
        assert digest(checkpoint_history(path, inputs[path])) == checksum
    assert record["sourceBaseline"]["files"] == 127 and record["sourceBaseline"]["tests"] == 327
    assert record["stages"] == [110,120,127,135,141,146,151]


def test_reversible_current_byte_checks_preserve_historical_tests(authority):
    _, record, inputs = authority
    before = json.loads(inputs[BEFORE_PATH])["files"]
    for path, rule in record["metaRecipes"].items():
        raw = before[path].encode()
        assert apply_recipe(raw, rule) == checkpoint_history(path, inputs[path])
        assert historical_bytes(path, inputs[path]) == raw
        if path.startswith("tests/"):
            assert ids(raw) == ids(inputs[path])
            assert current_test_bytes(raw) == inputs[path]
        with pytest.raises(ValueError):
            historical_bytes(path, inputs[path] + b"\n")


def test_every_record_read_rechecks_bytes_without_cross_call_cache(monkeypatch):
    from scripts import validate_conformance_reference_measurement as module
    raw = module.regular_bytes(ROOT, module.RECORD_PATH)
    reads = []
    def read_again(root,path):
        reads.append(path)
        return raw if len(reads) == 1 else raw + b" "
    monkeypatch.setattr(module,"regular_bytes",read_again)
    assert module._record()["authorityPacket"] == "MET-PERF-005"
    with pytest.raises(ValueError, match="exact fresh authority bytes"):
        module._record()
    assert reads == [module.RECORD_PATH, module.RECORD_PATH]


@pytest.mark.parametrize("fault", ["missing-route","extra-route"])
def test_routing_table_is_exact_and_cannot_suppress_reviewed_changes(authority,monkeypatch,fault):
    from scripts import validate_conformance_reference_measurement as module
    paths = set(module.HISTORY_PATHS)
    if fault == "missing-route": paths.remove("scripts/validate_readiness.py")
    else: paths.add("unreviewed.py")
    monkeypatch.setattr(module,"HISTORY_PATHS",frozenset(paths))
    assert validate_authority(*authority)


def test_unmodified_paths_are_identity_not_an_acceptance_decision(authority,monkeypatch):
    from scripts import validate_conformance_reference_measurement as module
    calls = []
    original = module._record
    def counted():
        calls.append(1)
        return original()
    monkeypatch.setattr(module,"_record",counted)
    assert historical_bytes("unchanged.txt",b"untrusted") == b"untrusted"
    assert calls == []
    raw = authority[2]["scripts/validate_readiness.py"]
    assert historical_bytes("scripts/validate_readiness.py",raw) != raw
    assert calls == [1]


@pytest.mark.parametrize("layer", ["performance","followup","closure"])
def test_each_predecessor_record_is_reread_and_never_cached(monkeypatch,layer):
    from scripts import validate_conformance_performance as performance
    from scripts import validate_conformance_performance_followup as followup
    from scripts import validate_conformance_consumer_closure as closure
    module = {"performance":performance,"followup":followup,"closure":closure}[layer]
    raw = module.regular_bytes(ROOT,module.RECORD_PATH)
    reads = []
    def read_again(root,path):
        reads.append(path)
        return raw if len(reads) == 1 else raw+b" "
    monkeypatch.setattr(module,"regular_bytes",read_again)
    assert module._record() == json.loads(raw)
    with pytest.raises(ValueError,match="exact fresh authority bytes"):
        module._record()
    assert reads == [module.RECORD_PATH,module.RECORD_PATH]


@pytest.mark.parametrize("layer", ["performance","followup","closure"])
@pytest.mark.parametrize("fault", ["missing-route","extra-route"])
def test_each_predecessor_routing_table_is_exact(authority,monkeypatch,layer,fault):
    from scripts import validate_conformance_performance as performance
    from scripts import validate_conformance_performance_followup as followup
    from scripts import validate_conformance_consumer_closure as closure
    module = {"performance":performance,"followup":followup,"closure":closure}[layer]
    record,inputs = module.load_inputs(ROOT)
    paths = set(module.HISTORY_PATHS)
    if fault == "missing-route": paths.remove("scripts/validate_readiness.py")
    else: paths.add("unreviewed.py")
    monkeypatch.setattr(module,"HISTORY_PATHS",frozenset(paths))
    assert module.validate_authority(authority[0],record,inputs)


def test_predecessor_successor_unwinding_still_precedes_identity_routes():
    for name,successor in (("performance","followup_history"),("performance_followup","closure_history"),("consumer_closure","reference_history")):
        source = (ROOT/('scripts/validate_conformance_'+name+'.py')).read_text()
        start = source.index('def historical_bytes(path, raw):')
        end = source.index('\ndef current_test_bytes',start)
        body = source[start:end]
        assert body.index('raw = '+successor+'(path, raw)') < body.index('if path not in HISTORY_PATHS:')


def test_replay_is_read_only_not_source_predecessor_or_candidate_acceptance(authority):
    packets, record, _ = authority
    spec = record["referenceBenchmark"]
    assert spec["executionRole"] == dict(packetId="CONF-BENCH-001", sourceOwner="CONF-PERF-004", sourceEdits=False,
        requiresBranchOrPr=False, acceptedSourcePredecessor=False, **{"class":"READ_ONLY_REFERENCE_REPLAY"})
    assert packets["CONF-BENCH-001"]["predecessors"] == packets["CONF-PERF-004"]["predecessors"] == ["MET-PERF-005","CONF-FIX-003","CONF-FIX-005"]
    assert packets["CONF-BENCH-001"]["prefetchCommands"] == []
    assert packets["CONF-BENCH-001"]["allowedPaths"] == packets["CONF-PERF-004"]["allowedPaths"] == record["productPaths"]
    assert packets["CONF-BENCH-001"]["offlineAcceptanceCommands"] == [["python3","-m","unittest","discover","-s","tests/live_backend","-p","test_supervisor.py","-k","PerformanceArithmeticTests.test_fixed_three_sample_workload"]]
    assert all("-k" not in command for command in packets["CONF-PERF-004"]["offlineAcceptanceCommands"])
    old = json.loads((ROOT/"architecture/conformance-consumer-closure.json").read_bytes())
    assert record["productRegions"] == old["productRegions"] and record["accountingBridges"] == old["accountingBridges"]
    assert old["profiling"]["fullBaselineRequired"] is True
    assert record["profiling"]["fullBaselineRequired"] is False
    assert record["profiling"]["completeReferenceBenchmarkRequired"] is record["profiling"]["fullCandidateRequired"] is True
    assert record["profiling"]["partialMayAuthorizeOptimization"] is False
    assert record["preserved"]["nestedSeconds"] == 420 and record["preserved"]["trustedSeconds"] == 900
    assert record["preserved"]["workflowMinutes"] == 15 and record["profiling"]["candidateTrustedSeconds"] == 750
    assert record["preserved"]["nativeAcceptance"] is record["preserved"]["tenantAcceptance"] is False
    assert len(spec["requiredNewTestIds"]) == 21 and len(spec["requiredProductTestIds"]) == 348


def test_timeout_history_is_never_promoted(authority):
    measurement = authority[1]["measurement"]
    assert measurement["baselineAccepted"] is measurement["algorithmSelected"] is measurement["referenceAccepted"] is False
    last = measurement["attempts"][-1]
    assert last["activation"] == 155 and last["status"] == "TIMEOUT_NOT_PASS"
    assert last["firstFivePassed"] == 170 and last["backend"] == "INCOMPLETE"
    assert last["profile"] == "PARTIAL_DIAGNOSTIC_ONLY" and last["trustedElapsedSeconds"] > 900
    assert measurement["latestCi"]["runnerId"] == measurement["latestCi"]["artifacts"] == 0
    assert measurement["latestCi"]["status"] == "CANCELLED_QUEUED_NO_RUNNER_NOT_PASS"


@pytest.mark.parametrize("fault", ["yaml","recipe","path","predecessor","missing","extra","record","protected","method","before","native","full8","deadline","write-role"])
def test_changed_authority_fails_closed(authority, fault):
    packets, record, inputs = deepcopy(authority)
    if fault == "yaml": inputs["task-packets/CONF-PERF-003.yaml"] += b" "
    if fault == "recipe": packets["CONF-BENCH-001"]["offlineAcceptanceCommands"][0].pop()
    if fault == "path": packets["CONF-PERF-004"]["allowedPaths"].append("Makefile")
    if fault == "predecessor": packets["CONF-PERF-004"]["predecessors"].append("CONF-BENCH-001")
    if fault == "missing": inputs.pop(PRODUCT_PATH)
    if fault == "extra": inputs["extra"] = b""
    if fault == "record": record["approvalDate"] = "old"
    if fault == "protected": inputs["architecture/conformance-consumer-closure.json"] += b"\n"
    if fault == "method": inputs[record["referenceBenchmark"]["templatePath"]] += b" "
    if fault == "before": inputs[BEFORE_PATH] += b" "
    if fault == "native": record["preserved"]["nativeAcceptance"] = True
    if fault == "full8": packets["CONF-PERF-004"]["offlineAcceptanceCommands"].pop()
    if fault == "deadline": record["preserved"]["trustedSeconds"] = 901
    if fault == "write-role": record["referenceBenchmark"]["executionRole"]["sourceEdits"] = True
    assert validate_authority(packets, record, inputs)


def test_exact72_closed_overlaps_preserve_generic_diagnostics(authority):
    from scripts.validate_packet_ownership import validate_packet_ownership
    packets, record, _ = authority
    generic = validate_packet_ownership(packets)
    assert len(generic) == 118 and len(record["overlapPairs"]) == 10
    assert sum(pair[2] for pair in record["overlapPairs"]) == 72
    assert validate_dispatch_ownership(packets) == []


@pytest.mark.parametrize("fault", ["retired-yaml","reference-path","reference-command","reference-owner","candidate-path","candidate-command","missing-replay","unrelated-overlap","unrelated-make"])
def test_dispatch_never_hides_changed_or_unrelated_packets(authority, fault):
    from scripts.validate_packet_ownership import validate_packet_ownership
    packets, record, _ = deepcopy(authority)
    if fault == "retired-yaml": packets["CONF-PERF-003"]["objective"] += "changed"
    if fault == "reference-path": packets["CONF-BENCH-001"]["allowedPaths"].append("extra.py")
    if fault == "reference-command": packets["CONF-BENCH-001"]["offlineAcceptanceCommands"][0].append("extra")
    if fault == "reference-owner": packets["CONF-BENCH-001"]["repository"] = "Harness-Engineering"
    if fault == "candidate-path": packets["CONF-PERF-004"]["allowedPaths"].append("extra.py")
    if fault == "candidate-command": packets["CONF-PERF-004"]["offlineAcceptanceCommands"].pop()
    if fault == "missing-replay": packets.pop("CONF-BENCH-001")
    if fault == "unrelated-overlap": packets["UNRELATED-001"] = dict(repository="mas-harness-conformance-labs",predecessors=[],allowedPaths=[CRYPTO])
    if fault == "unrelated-make": packets["CONF-FIX-005"]["offlineAcceptanceCommands"].append(["make","bad;target"])
    result = validate_dispatch_ownership(packets)
    assert result
    allowed = [left+" and "+right for left,right,_ in record["overlapPairs"]]
    allowed.extend(["CONF-BENCH-001 and CONF-FIX-006","CONF-FIX-006 and CONF-PERF-001","CONF-FIX-006 and CONF-PERF-002","CONF-FIX-006 and CONF-PERF-003", "CONF-DIAG-001 and CONF-LIVE-003", "CONF-DIAG-002 and CONF-LIVE-003", "CONF-BENCH-002 and CONF-FIX-007", "CONF-BENCH-002 and CONF-LIVE-003", "CONF-BENCH-002 and CONF-PERF-006", "CONF-FIX-007 and CONF-PERF-006", "CONF-BENCH-002 and CONF-BENCH-003", "CONF-BENCH-003 and CONF-FIX-007", "CONF-BENCH-003 and CONF-LIVE-003", "CONF-BENCH-003 and CONF-PERF-006", "CONF-BENCH-002 and CONF-FIX-008", "CONF-BENCH-003 and CONF-FIX-008", "CONF-DIAG-003 and CONF-FIX-008", "CONF-FIX-007 and CONF-FIX-008", "CONF-DIAG-003 and CONF-DIAG-004", "CONF-DIAG-004 and CONF-FIX-007", "CONF-BENCH-002 and CONF-FIX-009", "CONF-BENCH-003 and CONF-FIX-009", "CONF-DIAG-003 and CONF-FIX-009", "CONF-FIX-007 and CONF-FIX-009", "CONF-BENCH-002 and CONF-FIX-010", "CONF-BENCH-003 and CONF-FIX-010", "CONF-DIAG-003 and CONF-FIX-010", "CONF-FIX-007 and CONF-FIX-010"])
    unrelated = [e for e in validate_packet_ownership(packets) if not any(pair in e for pair in allowed)]
    assert set(unrelated) <= set(result)


def synthetic_reference(authority):
    # Deliberately synthetic DATA_CHECK_ONLY fixtures, never real-run evidence.
    record = authority[1]
    spec = record["referenceBenchmark"]
    report = {**deepcopy(spec["fixedReport"]),"interpreter":"synthetic-interpreter","platform":"synthetic-platform",
        "sourceSha256":spec["unchangedCryptoSha256"],"samplesSeconds":[10.,11.,12.],"resultDigests":[spec["resultDigest"]]*3,
        "benchmarkWallSeconds":40.,"functions":[dict(function=name,calls=10,primitiveCalls=10,selfSeconds=30. if name=="builtins.pow" else 1.,cumulativeSeconds=35.) for name in spec["requiredFunctions"]]}
    custody = dict(packetId="CONF-BENCH-001",checkoutCommit="1"*40,checkoutTree="2"*40,
        packetSha256=record["inputFiles"]["task-packets/CONF-BENCH-001.yaml"],logSha256="3"*64,sourceInventorySha256="4"*64,
        referenceReportSha256=digest(canonical(report)),activationSequence=156,execution="SIGNED_DENY_ALL_OFFLINE",
        evidenceClass="RETAINED_CUSTODY_DATA_ONLY",status="COMPLETE",exitCode=0,commandsCompleted=1,skipped=0,
        testIds=[spec["testId"]],workingTreeOverlay=False,trackedFilesUnchanged=True,trustedElapsedSeconds=60.)
    return report,custody


def synthetic_candidate(authority):
    report,custody = synthetic_reference(authority)
    reference = dict(report=deepcopy(report),custody=deepcopy(custody))
    report["sourceSha256"] = "a"*64
    report["samplesSeconds"] = [7.,8.,9.]
    report["benchmarkWallSeconds"] = 30.
    for row in report["functions"]:
        row["selfSeconds"] *= 0.7
        row["cumulativeSeconds"] *= 0.7
    custody.update(packetId="CONF-PERF-004",checkoutCommit="5"*40,activationSequence=157,commandsCompleted=8,
        packetSha256=authority[1]["inputFiles"]["task-packets/CONF-PERF-004.yaml"],
        testIds=deepcopy(authority[1]["referenceBenchmark"]["requiredProductTestIds"]),trustedElapsedSeconds=700.)
    return report,custody,reference


def test_consistent_synthetic_data_is_not_a_signature_or_actual_run(authority):
    report,custody = synthetic_reference(authority)
    assert validate_measurement_data(report,custody,authority[1]) == []
    candidate,current,reference = synthetic_candidate(authority)
    assert validate_measurement_data(candidate,current,authority[1],reference=reference) == []
    assert report["evidenceClass"] == "OBSERVATION_DATA_ONLY"
    assert custody["evidenceClass"] == "RETAINED_CUSTODY_DATA_ONLY"
    assert authority[1]["referenceBenchmark"]["dataValidationClass"] == "DATA_CHECK_ONLY_NOT_SIGNATURE_OR_REAL_RUN_VERIFICATION"


@pytest.mark.parametrize("fault", ["partial","timeout","false-pass","skip","skip-bool","sample-missing","sample-extra","sample-nan","sample-inf","sample-negative","sample-bool","wrong-digest","changed-crypto","method","recipe","observer","scope","cache","calls-zero","calls-bool","recursive","function-missing","function-duplicate","self-nan","time-negative","time-over-wall","self-over-cumulative","wall","low-add","low-pow","old-activation","bool-activation","commit","packet","log","inventory","report-digest","overlay","source-write","extra-field","missing-field","commands","one-test","duplicate-test","promoted-custody"])
def test_resealed_reference_data_refuses_incomplete_or_mismatched_evidence(authority,fault):
    report,custody = synthetic_reference(authority)
    if fault == "partial": report["complete"] = False
    if fault == "timeout": custody["status"] = "TIMEOUT_NOT_PASS"
    if fault == "false-pass": custody["exitCode"] = False
    if fault == "skip": custody["skipped"] = 1
    if fault == "skip-bool": custody["skipped"] = False
    if fault == "sample-missing": report["samplesSeconds"].pop()
    if fault == "sample-extra": report["samplesSeconds"].append(1.)
    if fault == "sample-nan": report["samplesSeconds"][0] = float('nan')
    if fault == "sample-inf": report["samplesSeconds"][0] = float('inf')
    if fault == "sample-negative": report["samplesSeconds"][0] = -1.
    if fault == "sample-bool": report["samplesSeconds"][0] = True
    if fault == "wrong-digest": report["resultDigests"][0] = "0"*64
    if fault == "changed-crypto": report["sourceSha256"] = "a"*64
    if fault == "method": report["benchmarkSha256"] = "b"*64
    if fault == "recipe": report["recipeSha256"] = "c"*64
    if fault == "observer": report["subcalls"] = True
    if fault == "scope": report["scope"] = "FULL_SUITE"
    if fault == "cache": report["crossCallCache"] = True
    if fault == "calls-zero": report["functions"][0]["calls"] = 0
    if fault == "calls-bool": report["functions"][0]["calls"] = True
    if fault == "recursive": report["functions"][0]["primitiveCalls"] = 11
    if fault == "function-missing": report["functions"].pop()
    if fault == "function-duplicate": report["functions"].append(deepcopy(report["functions"][0]))
    if fault == "self-nan": report["functions"][0]["selfSeconds"] = float('nan')
    if fault == "time-negative": report["functions"][0]["selfSeconds"] = -1.
    if fault == "time-over-wall": report["functions"][0]["cumulativeSeconds"] = 41.
    if fault == "self-over-cumulative": report["functions"][0]["selfSeconds"] = 36.
    if fault == "wall": report["benchmarkWallSeconds"] = 32.
    if fault == "low-add": next(r for r in report["functions"] if r["function"]=="_add")["cumulativeSeconds"] = 19.
    if fault == "low-pow": next(r for r in report["functions"] if r["function"]=="builtins.pow")["selfSeconds"] = 15.
    if fault == "old-activation": custody["activationSequence"] = 155
    if fault == "bool-activation": custody["activationSequence"] = True
    if fault == "commit": custody["checkoutCommit"] = "../main"
    if fault == "packet": custody["packetSha256"] = "d"*64
    if fault == "log": custody["logSha256"] = "unknown"
    if fault == "inventory": custody["sourceInventorySha256"] = "unknown"
    if fault == "overlay": custody["workingTreeOverlay"] = True
    if fault == "source-write": custody["trackedFilesUnchanged"] = False
    if fault == "extra-field": report["fullProductAccepted"] = True
    if fault == "missing-field": report.pop("interpreter")
    if fault == "commands": custody["commandsCompleted"] = 8
    if fault == "one-test": custody["testIds"] = []
    if fault == "duplicate-test": custody["testIds"] *= 2
    if fault == "promoted-custody": custody["evidenceClass"] = "CRYPTOGRAPHICALLY_VERIFIED"
    # Re-seal deliberately, so most negatives reach the intended semantic guard.
    if fault not in {"sample-nan","sample-inf","self-nan"}:
        custody["referenceReportSha256"] = digest(canonical(report))
    if fault == "report-digest": custody["referenceReportSha256"] = "f"*64
    assert validate_measurement_data(report,custody,authority[1])


@pytest.mark.parametrize("fault", ["slow","deadline","missing-old-id","missing-new-id","selection","reference-partial","reference-host","reference-observer","reference-template","report-binding","same-commit","activation-order","wrong-packet","skip"])
def test_candidate_requires_matched_reference_and_every_full_gate(authority,fault):
    report,custody,reference = synthetic_candidate(authority)
    if fault == "slow": report["samplesSeconds"] = [9.,9.5,10.]
    if fault == "deadline": custody["trustedElapsedSeconds"] = 750.001
    if fault == "missing-old-id": custody["testIds"].pop(0)
    if fault == "missing-new-id": custody["testIds"].remove(SUP+"::PerformanceArithmeticTests.test_fixed_three_sample_workload")
    if fault == "selection": custody["commandsCompleted"] = 1
    if fault == "reference-partial": reference["report"]["complete"] = False
    if fault == "reference-host": report["platform"] += "-other"
    if fault == "reference-observer": report["observerIdentity"] += "-other"
    if fault == "reference-template": report["benchmarkSha256"] = "f"*64
    if fault == "report-binding": custody["referenceReportSha256"] = "a"*64
    if fault == "same-commit": custody["checkoutCommit"] = reference["custody"]["checkoutCommit"]
    if fault == "activation-order": custody["activationSequence"] = reference["custody"]["activationSequence"]
    if fault == "wrong-packet": custody["packetId"] = "CONF-BENCH-001"
    if fault == "skip": custody["skipped"] = 1
    assert validate_measurement_data(report,custody,authority[1],reference=reference)


def scope_sample(authority):
    _,record,inputs = authority
    before = json.loads(inputs[PRODUCT_PATH])["files"]
    method = json.loads(inputs[record["referenceBenchmark"]["templatePath"]])["method"]
    groups = {}
    for name in record["referenceBenchmark"]["requiredNewTestIds"]:
        owner,test = name.split('.')
        groups.setdefault(owner,[]).append((test, method if test=="test_fixed_three_sample_workload" else
            '    def '+test+'(self):\n        self.assertEqual(1, 1)\n'))
    # Scope-only synthetic methods are never executed and prove no behavior.
    addition = '\n'.join('class '+owner+'(unittest.TestCase):\n'+ '\n'.join(src for _,src in tests)
                         for owner,tests in groups.items())
    rows = {}
    for path,spec in record["productRegions"].items():
        if path == DOC: continue
        raw = before[path].encode()
        regions = deepcopy(spec.get("fixedRegions",{name:raw[slice(*region(raw,name)[:2])].decode() for name in spec["regions"]}))
        rows[path] = dict(regions=regions,append='\n'+addition if path==SUP else '',afterSha256='',constant=None)
    rows[IMPORTER]["constant"] = digest(before[HELPER].encode())
    proof = dict(schemaVersion="planeon.conformance-performance-delta/v4",evidenceClass="SOURCE_DELTA_ONLY",packetId="CONF-PERF-004",
        authorityDigest=RECORD_SHA256,baseCommit=record["sourceBaseline"]["commit"],sources=rows,newTestIds=record["referenceBenchmark"]["requiredNewTestIds"],
        beforeSources={p:s for p,s in before.items() if p!=DOC},documentSuffix="\nSynthetic scope only.\n")
    return before,proof


def assemble(before,proof):
    after = {}
    for path,row in proof["sources"].items():
        raw = before[path].encode()
        spans = [(region(raw,name)[:2],value.encode()) for name,value in row["regions"].items()]
        for (start,end),value in sorted(spans,reverse=True): raw = raw[:start]+value+raw[end:]
        if row["constant"] is not None:
            raw = re.sub(rb'^HELPER_SHA256 = "[0-9a-f]{64}"$',('HELPER_SHA256 = "'+row["constant"]+'"').encode(),raw,flags=re.M)
        after[path] = raw+row["append"].encode()
        row["afterSha256"] = digest(after[path])
    after[DOC] = before[DOC].encode()+proof["documentSuffix"].encode()+b"\n```harness-performance-source-proof\n"+canonical(proof)+b"\n```\n"
    return after


def test_v4_source_scope_binds_exact_benchmark_and_unchanged_reference_crypto(authority):
    before,proof = scope_sample(authority)
    after = assemble(before,proof)
    assert validate_product_delta(after,proof,authority[1],authority[2][PRODUCT_PATH]) == []
    assert validate_reference_scaffold_data(after,proof,authority[1],authority[2][PRODUCT_PATH]) == []
    proof["sources"][CRYPTO]["regions"]["_add"] += '    # Different source, even without arithmetic change.\n'
    after = assemble(before,proof)
    assert validate_product_delta(after,proof,authority[1],authority[2][PRODUCT_PATH]) == []
    assert validate_reference_scaffold_data(after,proof,authority[1],authority[2][PRODUCT_PATH])


@pytest.mark.parametrize("fault", ["benchmark","sample-count","template-comment","missing-regression","overlay-observer","skip","bridge","old-checksum","outside-runtime","forged-before","proof-role","extra-path"])
def test_resealed_source_cannot_bypass_benchmark_or_inherited_scope(authority,fault):
    before,proof = scope_sample(authority)
    rows = proof["sources"]
    if fault == "benchmark": rows[SUP]["append"] = rows[SUP]["append"].replace('message = b"a" * length','message = b"b" * length')
    if fault == "sample-count": rows[SUP]["append"] = rows[SUP]["append"].replace('for _ in range(3):','for _ in range(2):')
    if fault == "template-comment": rows[SUP]["append"] = rows[SUP]["append"].replace('        import ast','        # changed observer\n        import ast')
    if fault == "missing-regression": rows[SUP]["append"] = rows[SUP]["append"].replace('test_published_rfc8032_vectors_and_mutations','not_collected_rfc8032_vectors')
    if fault == "overlay-observer": rows[SUP]["append"] += '\ndef setUpModule():\n    pass\n'
    if fault == "skip": rows[SUP]["append"] += "\n@unittest.skip('hide')\ndef test_hidden():\n    pass\n"
    if fault in {"bridge","old-checksum"}:
        b = authority[1]["accountingBridges"][-1]
        rows[b["path"]]["regions"][b["region"]] = b["after"].replace('        _, historical_sources, _ = HELPER.performance_current(ROOT)\n','') if fault=="bridge" else b["after"]+'        self.assertEqual(1, 1)\n'
    if fault == "outside-runtime": rows[CRYPTO]["regions"]["_add"] = rows[CRYPTO]["regions"]["_add"].replace('    x1, y1 = left','    import os\n    x1, y1 = left')
    if fault == "forged-before": proof["beforeSources"][CRYPTO] += '\n'
    if fault == "proof-role": proof["packetId"] = "CONF-BENCH-001"
    after = assemble(before,proof)
    if fault == "extra-path": after['extra.py'] = b''
    assert validate_product_delta(after,proof,authority[1],authority[2][PRODUCT_PATH])


def test_validator_never_imports_or_executes_product_and_template_is_inert(authority):
    tree = ast.parse((ROOT/'scripts/validate_conformance_reference_measurement.py').read_bytes())
    forbidden = {'exec','eval','compile','__import__','Popen','system','CDLL','socket','syscall'}
    for node in ast.walk(tree):
        if isinstance(node,ast.Call):
            name = node.func.id if isinstance(node.func,ast.Name) else getattr(node.func,'attr','')
            assert name not in forbidden
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            names = [n.name for n in node.names] if isinstance(node,ast.Import) else [node.module or '']
            assert not any(n.startswith(('harness_conformance','subprocess','ctypes','socket','cProfile')) for n in names)
    template = json.loads(authority[2][authority[1]['referenceBenchmark']['templatePath']])
    assert template['evidenceClass'] == 'INERT_SOURCE_SPECIFICATION_ONLY'
    assert digest(template['method'].encode()) == template['sha256']
    method = ast.parse('\n'.join(line[4:] if line else line for line in template['method'].splitlines())).body[0]
    assert len([n for n in ast.walk(method) if isinstance(n,ast.Try)]) >= 2
    assert 'sys.setprofile(previous)' in template['method'] and 'finally:' in template['method']


def test_current_roadmap_reports_waiting_and_failed_states_truthfully():
    current = (ROOT/'docs/DEVELOPMENT_STATUS.md').read_text().split('## Historical MET-PERF-004')[0]
    for phrase in ('MET-PERF-005 | ONGOING','CONF-PERF-004 | WAITING','CONF-BENCH-001 | WAITING','draft15 | BLOCKED_TIMEOUT','Native AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE','Effort transition NOT_DUE'):
        assert phrase in current
    guide = (ROOT/'docs/alpha-2/CONFORMANCE_REFERENCE_MEASUREMENT.md').read_text()
    for phrase in ('DATA_CHECK_ONLY','TIMEOUT_NOT_PASS','PARTIAL_DIAGNOSTIC_ONLY','EIGHT commands','750 seconds','Median ratio<=0.85','Nested420 /trusted900 /workflow15','no new META skips','source DAG','independent LOCAL exact-main'):
        assert phrase in guide
