"""Independent source-accounting data tests; no product/native execution."""
import ast
from copy import deepcopy
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_credential_lifecycle import (ADDITIONS, BEFORE_PATH, CHECKPOINT_PATH,
    DOC_PATH, RECORD_SHA256, canonical, definitions, digest, load_credential_inputs,
    region_delta, test_ids as source_ids, validate_additions, validate_delta,
    validate_inventory, validate_credential_lifecycle)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem: safe_yaml_load(p.read_bytes()) for p in (ROOT / "task-packets").glob("*.yaml")}
    return packets, *load_credential_inputs(ROOT)


def seal(after, proof, before):
    after[DOC_PATH] = before[DOC_PATH].encode() + b"\n\nUNIT_ONLY synthetic accounting, not repaired behavior.\n```harness-credential-source-proof\n" + canonical(proof) + b"\n```\n"


def synthetic(authority):
    _, record, inputs = authority
    before = json.loads(inputs[BEFORE_PATH])["files"]
    after = {p: v.encode() for p, v in before.items()}
    proof = dict(schemaVersion=record["change"]["proofSchemaVersion"], evidenceClass="SOURCE_DELTA_ONLY",
        packetId="CONF-FIX-005", packetSha256=record["inputFiles"]["task-packets/CONF-FIX-005.yaml"],
        authorityDigest=RECORD_SHA256, baseCommit=record["sourceBaseline"]["commit"],
        baseTree=record["sourceBaseline"]["tree"], before=inputs[BEFORE_PATH].decode(),
        checkpoint=inputs[CHECKPOINT_PATH].decode(), sources={}, tests={})
    for field, rules in (("sources", "sourceRegions"), ("tests", "testRegions")):
        for path in record["change"][rules]:
            append = ('\n\ndef _unit_credential_source_delta():\n    return None\n' if field == "sources" else
                      '\n\nclass UnitCredentialAccountingTests(unittest.TestCase):\n    def test_inert_accounting(self):\n        self.assertEqual(1, 1)\n')
            after[path] += append.encode()
            proof[field][path] = dict(beforeSha256=digest(before[path].encode()), afterSha256=digest(after[path]),
                                      regions={}, append=append)
    seal(after, proof, before)
    return after, proof


def inventory(authority, stage=2):
    _, record, inputs = authority
    from scripts.validate_credential_ordering import historical_bytes
    inputs = {path: historical_bytes(path, raw) for path, raw in inputs.items()}
    checkpoint = json.loads(inputs[CHECKPOINT_PATH])
    after, proof = synthetic(authority)
    rows = {p: dict(path=p, mode=r["mode"], size=r["size"], sha256=r["sha256"].removeprefix("sha256:"),
                    kind="file", nlink=1, linkedAncestry=False) for p, r in checkpoint["files"].items()}
    tests = {p: after[p] for p in proof["tests"]}
    methods = deepcopy(checkpoint["tests"])
    for path, raw in after.items():
        rows[path].update(size=len(raw), sha256=digest(raw))
    successor = json.loads(inputs["architecture/successor-inventory-amendment.json"])
    for item in successor["stages"][2:stage]:
        for path in item["paths"]:
            if path in rows:
                continue
            raw = b"UNIT_ONLY inert source bytes\n"
            if path.startswith("tests/") and Path(path).name.startswith("test_"):
                raw = b"class NewStageTests(unittest.TestCase):\n    def test_new_stage(self):\n        self.assertEqual(1, 1)\n"
                tests[path] = raw
            rows[path] = dict(path=path, mode="100644", size=len(raw), sha256=digest(raw),
                              kind="file", nlink=1, linkedAncestry=False)
    for path, raw in tests.items():
        methods[path] = source_ids(raw)
    launcher = inputs["architecture/successor-inventory-inputs/live_launcher.before.txt"]
    hook_proof = None
    if stage == 6:
        hook = successor["hook"]
        replacement = '        result = {"status": "NOT_RUN_ENV_UNAVAILABLE"}\n'
        launcher = launcher.replace(hook["beforeBlock"].encode(), replacement.encode(), 1)
        hook_proof = dict(schemaVersion=hook["proofSchemaVersion"], evidenceClass="SOURCE_DELTA_ONLY",
            **{key: hook[key] for key in ("packetId", "packetSha256", "path", "beforeSha256", "prefixSha256", "suffixSha256")},
            replacement=replacement, afterSha256=digest(launcher))
        rows[hook["path"]].update(size=len(launcher), sha256=digest(launcher))
    return [list(rows.values()), tests, methods, after, proof, record, inputs, launcher, hook_proof]


def test_exact_authority_and_all_historical_bytes(authority):
    packets, record, inputs = authority
    assert validate_credential_lifecycle(*authority) == []
    assert len(packets) == 194 and len(record["protectedFiles"]) == 245
    assert len(packets["MET-REPAIR-012"]["offlineAcceptanceCommands"]) == 20
    assert len(packets["CONF-FIX-005"]["allowedPaths"]) == 5
    assert len(packets["CONF-FIX-005"]["offlineAcceptanceCommands"]) == 8
    assert sum(p.startswith("task-packets/") for p in record["protectedFiles"]) == 139
    original = json.loads(inputs[record["sourceBaseline"]["originalPath"]])
    corrected = json.loads(inputs[CHECKPOINT_PATH])
    assert original["testCount"] == 279 and corrected["testCount"] == 305
    assert set(original["files"]) == set(corrected["files"])
    assert corrected["commit"] != original["commit"]
    assert record["evidence"]["nativeAcceptance"] is False
    assert record["diagnosis"]["productTestsRun"] == record["diagnosis"]["liveRequestsRun"] == 0


def test_static_conflict_and_scoped_accounting_are_exact(authority):
    before = json.loads(authority[2][BEFORE_PATH])["files"]
    raw = before["src/harness_conformance/live_linux_boundary.py"].encode()
    _, names = definitions(raw)
    start, end, _ = names["_RetainedCustody.read"]
    assert b"require(not self.sealed" in raw[start:end]
    start, end, _ = names["_RetainedCustody.check_ambient"]
    assert b"len(self.runtime_handles) == 4" in raw[start:end]
    assert b'"AMBIENT_DESCRIPTOR_FORBIDDEN"' in raw[start:end]
    regions = authority[1]["change"]["testRegions"]
    assert len(regions["tests/live_backend/test_supervisor.py"]) == 3
    assert regions["tests/live_backend/test_linux_boundary.py"] == []


def test_synthetic_data_delta_is_not_runtime_approval(authority):
    after, proof = synthetic(authority)
    assert validate_delta(after, proof, authority[1], authority[2][BEFORE_PATH], authority[2][CHECKPOINT_PATH]) == []
    assert proof["evidenceClass"] == "SOURCE_DELTA_ONLY"
    assert authority[1]["evidence"]["product"] == "NOT_RUN"


@pytest.mark.parametrize("field,bad", [("schemaVersion", "other"), ("evidenceClass", "PASS"),
    ("packetId", "CONF-LIVE-003"), ("packetSha256", "0" * 64), ("authorityDigest", "0" * 64),
    ("baseCommit", "0" * 40), ("baseTree", "0" * 40), ("before", "{}"), ("checkpoint", "{}"), ("extra", True)])
def test_each_proof_binding_refuses_even_with_matching_fence(authority, field, bad):
    after, proof = synthetic(authority)
    proof[field] = bad
    seal(after, proof, json.loads(authority[2][BEFORE_PATH])["files"])
    assert validate_delta(after, proof, authority[1], authority[2][BEFORE_PATH], authority[2][CHECKPOINT_PATH])


@pytest.mark.parametrize("kind", ["extra-path", "missing-path", "source-prefix", "behavior-test-body",
    "doc-prefix", "duplicate-fence", "unknown-source-region", "unknown-test-region", "wrong-after-hash", "missing-tests"])
def test_source_delta_never_permits_broad_exemptions(authority, kind):
    after, proof = synthetic(authority)
    source, test = next(iter(proof["sources"])), next(iter(proof["tests"]))
    if kind == "extra-path": after["unowned.py"] = b"x"
    if kind == "missing-path": del after[source]
    if kind == "source-prefix": after[source] = b"# changed\n" + after[source]
    if kind == "behavior-test-body": after[test] = after[test].replace(b"self.assert", b"self.bypass", 1)
    if kind == "doc-prefix": after[DOC_PATH] = b"changed\n" + after[DOC_PATH]
    if kind == "duplicate-fence": after[DOC_PATH] += b"```harness-credential-source-proof\n{}\n```\n"
    if kind == "unknown-source-region": proof["sources"][source]["regions"]["read_owned"] = "def read_owned():\n    pass\n"
    if kind == "unknown-test-region": proof["tests"][test]["regions"]["RetainedSupervisorTests.anything"] = "def anything():\n    pass\n"
    if kind == "wrong-after-hash": proof["sources"][source]["afterSha256"] = "0" * 64
    if kind == "missing-tests": proof["tests"] = {}
    assert validate_delta(after, proof, authority[1], authority[2][BEFORE_PATH], authority[2][CHECKPOINT_PATH])


def test_exact_accounting_region_preserves_interface_and_surrounding_bytes(authority):
    _, record, inputs = authority
    path = "tests/live_backend/test_supervisor.py"
    before = json.loads(inputs[BEFORE_PATH])["files"][path].encode()
    region = "CustodySourceProofTests.inputs"
    _, names = definitions(before)
    start, end, _ = names[region]
    replacement = before[start:end].replace(b"    def inputs(self):\n", b"    def inputs(self):\n        # UNIT_ONLY accounting delta\n")
    base = before[:start] + replacement + before[end:]
    append = '\nclass NewAccountingTests(unittest.TestCase):\n    def test_new(self):\n        self.assertEqual(1, 1)\n'
    row = dict(beforeSha256=digest(before), afterSha256=digest(base + append.encode()),
               regions={region: replacement.decode()}, append=append)
    assert region_delta(before, row, record["change"]["testRegions"][path], record["change"], tests=True) == base + append.encode()
    row["regions"][region] = replacement.decode().replace("inputs(self)", "inputs(self, trusted=True)")
    with pytest.raises(ValueError):
        region_delta(before, row, record["change"]["testRegions"][path], record["change"], tests=True)


@pytest.mark.parametrize("stage,count", [(2,127),(3,135),(4,141),(5,146),(6,151)])
def test_each_approved_successor_stage_keeps_all_old_and_new_methods(authority, stage, count):
    args = inventory(authority, stage)
    assert len(args[0]) == count
    assert validate_inventory(*args) == []
    assert sum(map(len, args[2].values())) >= 307


@pytest.mark.parametrize("kind", ["missing-file", "unknown-file", "duplicate-file", "wrong-hash", "executable-new",
    "linked", "missing-test-file", "missing-old-method", "missing-new-method", "injected-method", "wrong-test-bytes",
    "wrong-checkpoint", "forged-current-proof", "wrong-actual-correction", "premature-launcher", "extra-input"])
def test_current_inventory_and_collection_cannot_be_replaced_by_history(authority, kind):
    args = inventory(authority, 3)
    if kind == "missing-file": args[0].pop()
    if kind == "unknown-file": args[0].append(dict(args[0][0], path="unknown.py"))
    if kind == "duplicate-file": args[0].append(dict(args[0][0]))
    if kind == "wrong-hash": args[0][0]["sha256"] = "0" * 64
    if kind == "executable-new": args[0][-1]["mode"] = "100755"
    if kind == "linked": args[0][0]["linkedAncestry"] = True
    if kind == "missing-test-file": args[1].pop(next(iter(args[1])))
    if kind == "missing-old-method": args[2][next(iter(args[2]))].pop()
    if kind == "missing-new-method": args[2][next(iter(args[1]))].remove("UnitCredentialAccountingTests.test_inert_accounting")
    if kind == "injected-method": args[2][next(iter(args[2]))].append("Injected.test_bypass")
    if kind == "wrong-test-bytes": args[1][next(iter(args[1]))] += b"# changed\n"
    if kind == "wrong-checkpoint": args[6] = {**args[6], CHECKPOINT_PATH: b"{}"}
    if kind == "forged-current-proof": args[4]["authorityDigest"] = "0" * 64
    if kind == "wrong-actual-correction": args[3][next(iter(args[3]))] += b"# changed\n"
    if kind == "premature-launcher": args[7] += b"# changed\n"
    if kind == "extra-input": args[6] = {**args[6], "unowned": b"x"}
    assert validate_inventory(*args)


def test_final_launcher_still_requires_original_exact_hook_proof(authority):
    args = inventory(authority, 6)
    args[-1] = None
    assert validate_inventory(*args)


@pytest.mark.parametrize("packet", ADDITIONS)
@pytest.mark.parametrize("field,bad", [("allowedPaths", ["**"]), ("predecessors", []),
    ("prefetchCommands", [["curl", "external"]]), ("offlineAcceptanceCommands", []), ("sourceReuse", [{}])])
def test_exact_packet_fields_cannot_expand(authority, packet, field, bad):
    packets = deepcopy(authority[0]); packets[packet][field] = bad
    assert validate_additions(packets)


def test_every_input_pin_is_enforced(authority):
    packets, record, inputs = authority
    for path in inputs:
        changed = dict(inputs); changed[path] += b"\n"
        assert validate_credential_lifecycle(packets, record, changed), path
    changed = dict(packets); changed["UNDECLARED"] = {}
    assert validate_credential_lifecycle(changed, record, inputs)


def test_no_snapshot_execution_network_or_native_claim():
    tree = ast.parse((ROOT / "scripts/validate_credential_lifecycle.py").read_bytes())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            assert name not in {"exec", "eval", "compile", "__import__", "run", "Popen", "connect", "sign"}
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = [n.name for n in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            assert not {n.split(".")[0] for n in modules} & {"harness_conformance", "socket", "ctypes", "subprocess", "importlib"}


def test_lifecycle_bounds_dispatch_and_evidence_are_not_flags(authority):
    record = authority[1]
    lifecycle = record["lifecycle"]
    assert lifecycle["initialAuthority"] == "SEALED_IMMUTABLE"
    assert (lifecycle["credentialFiles"], lifecycle["persistentDescriptorLimit"], lifecycle["transientDescriptorLimit"]) == (1,66,2)
    assert not any(lifecycle[k] for k in ("arbitraryDescriptorAdoption", "credentialsBeforeReservationOrIsolation", "policyBypass", "refreshAuthority"))
    assert record["dispatchGate"]["then"] == "CONF-FIX-005"
    assert record["dispatchGate"]["before"] == "CONF-LIVE-003"
    assert record["dispatchGate"]["runtimeUnblocked"] is False
    assert record["previousClosure"]["timingStability"] == "UNRESOLVED"
    assert record["previousClosure"]["timeoutChangeAuthorized"] is False
    current = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text().split("## Historical MET-REPAIR-015 publication checkpoint\n",1)[1].split("## Historical MET-REPAIR-011 publication checkpoint")[0]
    assert "during `MET-REPAIR-015` publication" in current and "305" in current
    assert "CONF-FIX-005" in current and "NOT_DUE" in current


def test_performance_predecessor_and_exact_twenty_commands(authority):
    packets, record, inputs = authority
    from scripts.validate_ci_performance import (
        load_performance_inputs, validate_ci_performance, HISTORICAL_PACKET_COUNT,
    )
    assert HISTORICAL_PACKET_COUNT == 139
    assert "MET-PERF-001" in packets["MET-REPAIR-012"]["predecessors"]
    assert record["metaBaseline"] == "e367e89463b86ebc1b1e20563d677bdfe6694060"
    old = packets["MET-PERF-001"]["offlineAcceptanceCommands"]
    current = packets["MET-REPAIR-012"]["offlineAcceptanceCommands"]
    assert current == [*old[:-2], ["uv", "run", "--offline", "--frozen", "--no-sync", "python",
                                  "scripts/validate_credential_lifecycle.py"], *old[-2:]]
    args = load_performance_inputs(ROOT)
    assert validate_ci_performance(packets, *args) == []
    for name in ADDITIONS:
        changed = deepcopy(packets)
        changed[name]["allowedPaths"] = ["unreviewed/**"]
        assert validate_ci_performance(changed, *args)
    assert record["metaReconciliation"]["limits"] == {"nestedSeconds": 420, "hostSeconds": 900, "workflowMinutes": 15}


def test_all_accepted_meta_test_bytes_and_ids_remain_accounted(authority):
    from scripts.validate_credential_lifecycle import (
        META_BEFORE_PATH, apply_meta_test_recipe, validate_meta_test_preservation, current_test_bytes,
    )
    from scripts.validate_ci_performance import test_definitions, expected_test_source
    _, record, inputs = authority
    recipes = record["metaReconciliation"]["testRecipes"]
    before = json.loads(inputs[META_BEFORE_PATH])["files"]
    current = {p: inputs[p] for p in recipes}
    assert len(recipes) == len(before) == 21
    assert validate_meta_test_preservation(record, inputs[META_BEFORE_PATH], current) == []
    for path, recipe in recipes.items():
        raw = before[path].encode()
        assert current_test_bytes(apply_meta_test_recipe(raw, recipe)) == current[path]
        assert test_definitions(raw) == test_definitions(current[path])
        changed = dict(current)
        changed[path] += b"\n# unreviewed mutation\n"
        assert validate_meta_test_preservation(record, inputs[META_BEFORE_PATH], changed), path
    historical = json.loads(inputs["architecture/ci-performance-inputs/tests.before.json"])["files"]
    performance = json.loads(inputs["architecture/ci-performance-amendment.json"])
    for path, old in historical.items():
        assert expected_test_source(old.encode(), performance["mechanicalTestUpdates"][path]) == before[path].encode()


@pytest.mark.parametrize("kind", ["missing", "extra", "before", "record", "assertion", "skip", "unknown-recipe"])
def test_meta_reconciliation_has_no_broad_test_exemption(authority, kind):
    from scripts.validate_credential_lifecycle import META_BEFORE_PATH, validate_meta_test_preservation
    _, original, inputs = authority
    record = deepcopy(original)
    before = inputs[META_BEFORE_PATH]
    current = {p: inputs[p] for p in record["metaReconciliation"]["testRecipes"]}
    path = "tests/test_ci_performance.py"
    if kind == "missing": del current[path]
    if kind == "extra": current["tests/unowned.py"] = b"pass\n"
    if kind == "before": before += b" "
    if kind == "record": record["metaReconciliation"]["currentPacketCount"] = 142
    if kind == "assertion":
        target = b"assert len(paths) == 210"
        assert current[path].count(target) == 1
        current[path] = current[path].replace(target, b"assert True", 1)
    if kind == "skip": current[path] = b"import pytest\npytest.skip('fast', allow_module_level=True)\n" + current[path]
    if kind == "unknown-recipe": record["metaReconciliation"]["testRecipes"]["unowned"] = {}
    assert validate_meta_test_preservation(record, before, current)


def test_meta_recipe_unknown_bytes_and_ineffective_replacements_refuse(authority):
    from scripts.validate_credential_lifecycle import META_BEFORE_PATH, apply_meta_test_recipe, reconcile_meta_test_bytes
    record, inputs = authority[1:]
    path = "tests/test_ci_performance.py"
    raw = json.loads(inputs[META_BEFORE_PATH])["files"][path].encode()
    rule = deepcopy(record["metaReconciliation"]["testRecipes"][path])
    assert reconcile_meta_test_bytes(raw) == inputs[path]
    with pytest.raises(ValueError):
        reconcile_meta_test_bytes(raw + b"# changed\n")
    rule["replacements"][0]["count"] += 1
    with pytest.raises(ValueError):
        apply_meta_test_recipe(raw, rule)
    rule = deepcopy(record["metaReconciliation"]["testRecipes"][path])
    rule["replacements"][0]["after"] = rule["replacements"][0]["before"]
    with pytest.raises(ValueError):
        apply_meta_test_recipe(raw, rule)
