"""Source-inspection/delta tests only; no product source import or execution."""
import ast
from copy import deepcopy
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_custody_handoff import (ADDITIONS, BEFORE_PATH, DOC_PATH,
    RECORD_SHA256, appended_definitions, canonical, definitions, digest,
    load_custody_inputs, reconstruct_source, validate_additions,
    validate_custody_handoff, validate_delta)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem: safe_yaml_load(p.read_bytes()) for p in (ROOT / "task-packets").glob("*.yaml")}
    return packets, *load_custody_inputs(ROOT)


def synthetic(authority):
    """Inert text append proves only source accounting, NEVER repaired behavior."""
    packets, record, inputs = authority
    raw = inputs[BEFORE_PATH]
    before = json.loads(raw)["files"]
    after = {p: v.encode() for p, v in before.items()}
    proof = dict(schemaVersion=record["change"]["proofSchemaVersion"], evidenceClass="SOURCE_DELTA_ONLY",
        packetId="CONF-FIX-004", packetSha256=record["inputFiles"]["task-packets/CONF-FIX-004.yaml"],
        authorityDigest=RECORD_SHA256, baseCommit=record["sourceBaseline"]["commit"],
        baseTree=record["sourceBaseline"]["tree"], sources={}, tests={},
        baseline=inputs[record["sourceBaseline"]["path"]].decode(), before=raw.decode())
    for path in record["change"]["sourceRegions"]:
        appended = '\n\ndef _unit_only_inert_delta():\n    """Synthetic accounting data; not a runtime implementation."""\n    return None\n'
        after[path] += appended.encode()
        proof["sources"][path] = dict(beforeSha256=digest(before[path].encode()),
            afterSha256=digest(after[path]), regions={}, append=appended)
    for path in set(record["change"]["appendOnlyPaths"]) - {DOC_PATH}:
        appended = '\n\nclass UnitOnlySourceDeltaTests(unittest.TestCase):\n    def test_inert_text_only(self):\n        self.assertTrue(True)\n'
        after[path] += appended.encode()
        proof["tests"][path] = dict(beforeSha256=digest(before[path].encode()), afterSha256=digest(after[path]),
            newTestIds=["UnitOnlySourceDeltaTests.test_inert_text_only"])
    seal(after, proof, before[DOC_PATH].encode())
    return after, proof


def seal(after, proof, before_doc):
    after[DOC_PATH] = before_doc + b"\n\nSynthetic SOURCE_DELTA_ONLY, not a product correction.\n```harness-custody-source-proof\n" + canonical(proof) + b"\n```\n"


def test_exact_publication_correction_and_historical_scope(authority):
    packets, record, inputs = authority
    assert validate_custody_handoff(*authority) == []
    assert len(packets) == 194 and len(record["protectedFiles"]) == 203
    assert "task-packets/MET-REPAIR-010.yaml" in record["protectedFiles"]
    assert {p.name for p in (ROOT / "schemas").glob("*.json")} == {
        Path(p).name for p in record["protectedFiles"] if p.startswith("schemas/")}
    assert len(packets["MET-REPAIR-011"]["offlineAcceptanceCommands"]) == 17
    fix = packets["CONF-FIX-004"]
    baseline = json.loads(inputs[record["sourceBaseline"]["path"]])
    assert len(fix["allowedPaths"]) == 5 and set(fix["allowedPaths"]) <= set(baseline["files"])
    assert len(baseline["files"]) - len(fix["allowedPaths"]) == 122
    assert baseline["testCount"] == sum(map(len, baseline["tests"].values())) == 279
    assert fix["offlineAcceptanceCommands"] == packets["CONF-LIVE-003"]["offlineAcceptanceCommands"]
    assert len(fix["offlineAcceptanceCommands"]) == 8
    assert record["dispatchGate"]["stageCounts"] == [110, 120, 127, 135, 141, 146, 151]
    assert record["diagnosis"]["classification"] == "SOURCE_INSPECTION_ONLY"
    assert record["diagnosis"]["productTestsRun"] == record["diagnosis"]["liveRequestsRun"] == 0


def test_static_baseline_demonstrates_missing_handoff_without_running_product(authority):
    before = json.loads(authority[2][BEFORE_PATH])["files"]
    supervisor = before["src/harness_conformance/live_supervisor.py"].encode()
    _, methods = definitions(supervisor)
    start, end, _ = methods["NativeSupervisor.open_session"]
    method = supervisor[start:end]
    assert b"kit_sources = read_owned_kit(" in method
    assert b"context._source_digest =" in method
    assert b"context._kit_sources =" not in method
    assert b"context._root_fd = open_directory(" in method
    start, end, _ = methods["InstalledContext.__slots__"]
    assert b"_custody" not in supervisor[start:end]
    boundary = before["src/harness_conformance/live_linux_boundary.py"].encode()
    _, locations = definitions(boundary)
    start, end, _ = locations["read_owned"]
    assert b"os.close(fd)" in boundary[start:end]
    start, end, _ = locations["read_owned_kit"]
    assert b"os.close(root_fd)" in boundary[start:end]


def test_synthetic_delta_is_accepted_as_source_data_only(authority):
    after, proof = synthetic(authority)
    assert validate_delta(after, proof, authority[1], authority[2][BEFORE_PATH]) == []
    assert proof["evidenceClass"] == "SOURCE_DELTA_ONLY"
    assert authority[1]["evidence"]["nativeAcceptance"] is False


@pytest.mark.parametrize("field,bad", [("schemaVersion", "other"), ("evidenceClass", "PASS"),
    ("packetId", "CONF-LIVE-003"), ("packetSha256", "0" * 64), ("authorityDigest", "0" * 64),
    ("baseCommit", "0" * 40), ("baseTree", "0" * 40), ("before", "{}"), ("baseline", "{}")])
def test_each_proof_binding_refuses_even_with_matching_document(authority, field, bad):
    after, proof = synthetic(authority)
    proof[field] = bad
    seal(after, proof, json.loads(authority[2][BEFORE_PATH])["files"][DOC_PATH].encode())
    assert validate_delta(after, proof, authority[1], authority[2][BEFORE_PATH])


@pytest.mark.parametrize("kind", ["missing-file", "extra-file", "extra-proof", "missing-proof", "duplicate-fence",
    "changed-doc-prefix", "changed-test-prefix", "changed-source-prefix", "changed-source-hash", "wrong-test-ids",
    "unlisted-region", "missing-source", "bad-snapshot"])
def test_five_path_region_prefix_and_proof_tampering_refuses(authority, kind):
    after, proof = synthetic(authority)
    record, inputs = authority[1:]
    source = next(iter(proof["sources"]))
    test = next(iter(proof["tests"]))
    raw = inputs[BEFORE_PATH]
    if kind == "missing-file": del after[test]
    if kind == "extra-file": after["unknown.py"] = b"x"
    if kind == "extra-proof": proof["verified"] = True
    if kind == "missing-proof": del proof["baseTree"]
    if kind == "changed-doc-prefix": after[DOC_PATH] = b"altered\n" + after[DOC_PATH]
    if kind == "duplicate-fence": after[DOC_PATH] += b"```harness-custody-source-proof\n{}\n```\n"
    if kind == "changed-test-prefix": after[test] = b"# changed\n" + after[test]
    if kind == "changed-source-prefix": after[source] = b"# changed\n" + after[source]
    if kind == "changed-source-hash": proof["sources"][source]["afterSha256"] = "0" * 64
    if kind == "wrong-test-ids": proof["tests"][test]["newTestIds"] = []
    if kind == "unlisted-region": proof["sources"][source]["regions"]["seccomp_program"] = "def seccomp_program(machine):\n    return []\n"
    if kind == "missing-source": del proof["sources"][source]
    if kind == "bad-snapshot": raw += b"\n"
    assert validate_delta(after, proof, record, raw)


def test_named_region_changes_preserve_other_source_bytes_and_function_interface(authority):
    record, inputs = authority[1:]
    before = json.loads(inputs[BEFORE_PATH])["files"]
    path = "src/harness_conformance/live_linux_boundary.py"
    raw = before[path].encode()
    _, methods = definitions(raw)
    start, end, _ = methods["ambient_custody"]
    old = raw[start:end].decode()
    # Inert source transformation, not a behavior change or product test.
    replacement = old.replace("def ambient_custody():\n", "def ambient_custody():\n    # UNIT_ONLY region accounting\n", 1)
    expected = raw[:start] + replacement.encode() + raw[end:]
    row = dict(beforeSha256=digest(raw), afterSha256=digest(expected), regions={"ambient_custody": replacement}, append="")
    assert reconstruct_source(raw, row, record["change"]["sourceRegions"][path], record["change"]) == expected
    row["regions"]["ambient_custody"] = replacement.replace("ambient_custody():", "ambient_custody(verified=False):")
    with pytest.raises(ValueError):
        reconstruct_source(raw, row, record["change"]["sourceRegions"][path], record["change"])


@pytest.mark.parametrize("region,edit", [
    ("_Lifecycle._now", lambda text: text.replace("def _now(self, active):", "def _now(self, active) -> bool:")),
    ("_Lifecycle._now", lambda text: text.replace("def _now(self, active):", "def _now(self, active) -> None:")),
    ("InstalledContext.__slots__", lambda text: text.replace("__slots__ =", "__slots__ = injected =")),
])
def test_region_cannot_change_return_contract_or_bind_another_slot_target(authority, region, edit):
    record, inputs = authority[1:]
    path = "src/harness_conformance/live_supervisor.py"
    raw = json.loads(inputs[BEFORE_PATH])["files"][path].encode()
    _, methods = definitions(raw)
    start, end, _ = methods[region]
    replacement = edit(raw[start:end].decode())
    assert replacement.encode() != raw[start:end]
    expected = raw[:start] + replacement.encode() + raw[end:]
    row = dict(beforeSha256=digest(raw), afterSha256=digest(expected), regions={region: replacement}, append="")
    with pytest.raises(ValueError):
        reconstruct_source(raw, row, record["change"]["sourceRegions"][path], record["change"])


@pytest.mark.parametrize("append", ["\nimport os\n", "\nx = True\n", "\nraise RuntimeError()\n",
    "\ndef read_owned():\n    return None\n", "\ndef os():\n    return None\n",
    "\ndef load_tests(loader, tests, pattern):\n    return []\n", "\n@runner\ndef helper():\n    return None\n",
    "\ndef helper(value=run()):\n    return None\n", "\ndef helper(value: run()):\n    return None\n",
    "\nclass T(meta()):\n    pass\n", "\nclass T(metaclass=type):\n    pass\n",
    "\nclass T:\n    x = run()\n", "\nclass T:\n    @run\n    def helper(self):\n        pass\n"])
def test_appended_code_cannot_execute_or_rebind_existing_names(authority, append):
    raw = json.loads(authority[2][BEFORE_PATH])["files"]["src/harness_conformance/live_linux_boundary.py"].encode()
    with pytest.raises(ValueError):
        appended_definitions(append.encode(), raw)


@pytest.mark.parametrize("packet", ADDITIONS)
@pytest.mark.parametrize("field,bad", [("allowedPaths", ["**"]), ("prefetchCommands", [["curl", "external"]]),
    ("offlineAcceptanceCommands", []), ("sourceReuse", [{"verified": True}]), ("predecessors", [])])
def test_each_new_packet_is_exact_and_cannot_expand_scope(authority, packet, field, bad):
    packets = deepcopy(authority[0]); packets[packet][field] = bad
    assert validate_additions(packets)


def test_all_pinned_inputs_and_catalog_members_are_required(authority):
    packets, record, inputs = authority
    for path in (BEFORE_PATH, "task-packets/CONF-LIVE-003.yaml", "architecture/policy-observation-amendment.json"):
        changed = dict(inputs); changed[path] += b"\n"
        assert validate_custody_handoff(packets, record, changed)
    changed = dict(packets); changed["UNKNOWN"] = {}
    assert validate_custody_handoff(changed, record, inputs)
    changed = deepcopy(record); changed["change"]["sourceRegions"]["other.py"] = ["anything"]
    assert validate_custody_handoff(packets, changed, inputs)


def test_pure_oracle_has_no_snapshot_execution_network_or_credential_primitive():
    tree = ast.parse((ROOT / "scripts/validate_custody_handoff.py").read_bytes())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            assert name not in {"exec", "eval", "compile", "__import__", "run", "Popen", "connect", "sign"}
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            assert not {n.split(".")[0] for n in names} & {"socket", "subprocess", "ctypes", "importlib", "harness_conformance"}


def test_dispatch_preserves_timing_failures_and_separate_evidence(authority):
    record = authority[1]
    gate = record["dispatchGate"]
    assert (gate["requiresCompletedPacket"], gate["then"], gate["before"]) == ("MET-REPAIR-011", "CONF-FIX-004", "CONF-LIVE-003")
    assert gate["runtimeUnblocked"] is False and gate["packetRewrite"] is False
    assert record["previousClosure"]["timingStability"] == "UNRESOLVED"
    assert record["previousClosure"]["timeoutChangeAuthorized"] is False
    assert record["evidence"]["product"] == "NOT_RUN"
    assert record["evidence"]["modelEffortTransition"] == "NOT_DUE"
    text = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text().split("## Historical MET-REPAIR-015 publication checkpoint\n",1)[1]
    current = text.split("## Historical MET-PERF-001 publication checkpoint")[0]
    assert "during `MET-REPAIR-015` publication" in current
    assert "CONF-FIX-004" in current and "CONF-LIVE-003" in current
