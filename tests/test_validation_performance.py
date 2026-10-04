"""VP-01..VP-10: bounded optimization and independent source-accounting checks."""
import ast
from copy import deepcopy
import datetime
import importlib
import json
from pathlib import Path
import re
import shutil

import pytest
from scripts.validate_completion_profiling import historical_bytes as profiling_history
import yaml

from ci.measure_yaml_parsing import shape
import fixture_yaml
from scripts import validate_validation_performance as module
from scripts.safe_yaml import safe_load

NAMES = (
    "credential_lifecycle", "credential_ordering", "broker_handoff",
    "native_qualification", "conformance_performance",
    "conformance_performance_followup", "conformance_consumer_closure",
    "conformance_reference_measurement", "conformance_successor_checkpoint",
    "provider_adoption", "proxy_diagnostics", "canonical_repair_plan",
    "backend_timing", "local_acceptance", "conformance_publication",
    "conformance_completion", "research_adoption",
)
PATH = "tests/test_task_packets.py"


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem: safe_load(p.read_bytes())
               for p in (module.ROOT / "task-packets").glob("*.yaml")}
    return packets, *module.load_inputs(module.ROOT)


def implementation(name):
    target = importlib.import_module("scripts.validate_" + name)
    function = (target.reconcile_meta_test_bytes if name == "credential_lifecycle"
                else target.current_test_bytes)
    return target, function


def predecessor_input(name, target):
    current = (module.ROOT / PATH).read_bytes()
    if name == "credential_lifecycle":
        source = json.loads((module.ROOT / target.META_BEFORE_PATH).read_bytes())
        return source["files"][PATH].encode(), current
    return target.historical_bytes(PATH, current), current


@pytest.mark.parametrize("name", NAMES)
def test_current_recipe_output_and_local_digest_count(name, monkeypatch):
    target, function = implementation(name)
    before, expected = predecessor_input(name, target)
    original = target.digest
    calls = []
    def digest(raw):
        calls.append(raw)
        return original(raw)
    monkeypatch.setattr(target, "digest", digest)
    assert function(before) == expected
    # One recipe search plus the independent apply_recipe before-integrity check.
    assert sum(raw == before for raw in calls) == 2


@pytest.mark.parametrize("name", NAMES)
def test_changed_test_bytes_still_refuse(name):
    target, function = implementation(name)
    before, _ = predecessor_input(name, target)
    with pytest.raises(ValueError):
        function(before + b"\n# unreviewed bytes\n")


@pytest.mark.parametrize("name", NAMES)
def test_authority_is_fresh_and_semantic_tamper_refuses(name, monkeypatch):
    target, function = implementation(name)
    before, expected = predecessor_input(name, target)
    original = target.regular_bytes
    raw = original(target.ROOT, target.RECORD_PATH)
    changed = json.loads(raw)
    changed["unreviewed"] = True
    calls = []
    def read(root, path):
        if path == target.RECORD_PATH:
            calls.append(path)
            return raw if len(calls) == 1 else json.dumps(changed).encode()
        return original(root, path)
    monkeypatch.setattr(target, "regular_bytes", read)
    assert function(before) == expected
    with pytest.raises(ValueError):
        function(before)
    assert calls == [target.RECORD_PATH, target.RECORD_PATH]


@pytest.mark.parametrize("name", NAMES)
def test_complete_recipe_scan_and_uniqueness_guard_preserved(name):
    target, _ = implementation(name)
    text = Path(target.__file__).read_text()
    tree = ast.parse(text)
    function_name = ("reconcile_meta_test_bytes" if name == "credential_lifecycle"
                     else "current_test_bytes")
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                    and n.name == function_name)
    comprehensions = [n for n in ast.walk(function) if isinstance(n, ast.ListComp)]
    assert len(comprehensions) == 1
    assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                   and n.func.id == "digest" for n in ast.walk(comprehensions[0]))
    assert any(isinstance(n, ast.Compare) and isinstance(n.left, ast.Call)
               and isinstance(n.left.func, ast.Name) and n.left.func.id == "len"
               and any(isinstance(v, ast.Constant) and v.value == 1 for v in n.comparators)
               for n in ast.walk(function))


@pytest.mark.parametrize("name", NAMES[1:])
def test_duplicate_recipe_candidate_is_rejected(name, monkeypatch):
    target, function = implementation(name)
    before, _ = predecessor_input(name, target)
    record = deepcopy(target._record())
    matches = [(p, r) for p, r in record["metaRecipes"].items()
               if p.startswith("tests/") and r["beforeSha256"] == module.digest(before)]
    assert len(matches) == 1
    record["metaRecipes"]["tests/duplicate_fixture.py"] = deepcopy(matches[0][1])
    # Inject malformed unit input at the already-read-record boundary only.
    monkeypatch.setattr(target, "_record", lambda: record)
    with pytest.raises(ValueError):
        function(before)


@pytest.mark.parametrize("name", NAMES[2:])
def test_unchanged_fixture_bytes_remain_accepted(name):
    target, function = implementation(name)
    record = target._record()
    path = sorted(record["unchangedTests"])[0]
    raw = (module.ROOT / path).read_bytes()
    assert module.digest(raw) == record["unchangedTests"][path]
    assert function(raw) == raw


def fixture_value():
    shared = ["alias", True, None, b"\x00\xff"]
    cycle = []
    cycle.append(cycle)
    return {"unicode": "Istanbul \u0130 \u4e2d", "ordered": {"z": 2, "a": 1},
            "quoted": ["true", "01", "null", "2026-01-01", "a:b", ""],
            "numbers": [1, -3, 1.25], "date": datetime.date(2026, 1, 1),
            "left": shared, "right": shared, "cycle": cycle}


@pytest.mark.parametrize("native", [False, True])
def test_safe_serializer_structural_parity_and_no_global_change(native, monkeypatch):
    original_dump, original_load = yaml.safe_dump, yaml.safe_load
    if not native:
        monkeypatch.delattr(yaml, "CSafeDumper", raising=False)
    else:
        assert hasattr(yaml, "CSafeDumper"), "installed pinned native dumper required"
    value = fixture_value()
    before = shape(value)
    actual = yaml.safe_load(fixture_yaml.dump_fixture(value))
    expected = yaml.safe_load(original_dump(value, sort_keys=False, width=1000))
    assert shape(actual) == shape(expected) == before
    assert shape(value) == before
    assert yaml.safe_dump is original_dump and yaml.safe_load is original_load
    assert fixture_yaml.selected_safe_dumper() is (
        yaml.CSafeDumper if native else yaml.SafeDumper)


@pytest.mark.parametrize("native", [False, True])
def test_safe_serializer_arbitrary_object_rejection(native, monkeypatch):
    if not native:
        monkeypatch.delattr(yaml, "CSafeDumper", raising=False)
    else:
        assert hasattr(yaml, "CSafeDumper")
    with pytest.raises(yaml.representer.RepresenterError):
        fixture_yaml.dump_fixture({"object": object()})


def test_real_large_fixture_parity_and_metadata_conflict(tmp_path):
    from scripts import validate_reuse
    root = tmp_path / "repository"
    root.mkdir()
    for directory in ("architecture", "schemas", "legal", "task-packets"):
        shutil.copytree(module.ROOT / directory, root / directory)
    (root / "docs").mkdir()
    shutil.copytree(module.ROOT / "docs/phase-0", root / "docs/phase-0")
    path = root / "architecture/reuse-path-index.yaml"
    raw = path.read_bytes()
    assert len(raw) == 3927673
    value = safe_load(raw)
    assert shape(safe_load(fixture_yaml.dump_fixture(value))) == shape(value)
    source = next(s for s in value["sources"] if s["repository"].endswith("agent-hook-v2.git"))
    source["paths"][0]["gitObject"] = "0" * 40
    path.write_text(fixture_yaml.dump_fixture(value), encoding="utf-8")
    with pytest.raises(validate_reuse.ReuseValidationError,
                       match="observed source metadata conflicts"):
        validate_reuse.validate_reuse(root, check_toolchain=False)


def test_complete167_authority_and_old_sources(authority):
    assert module.validate_authority(*authority) == []
    packets, record, inputs = authority
    assert len(packets) == 194
    assert module.NEW_IDS == ("MET-PERF-010",)
    assert len([p for p in record["protectedFiles"]
                if p.startswith("task-packets/") and p.endswith(".yaml")]) == 166
    plan = inputs["docs/repositories/00-harness-engineering.md"].decode()
    section = re.search(r"^## PR packets\s*$([\s\S]*?)(?=^## |\Z)", plan, re.M)
    assert section is not None
    assert re.findall(r"`(MET-PERF-010)`", section.group(1)) == ["MET-PERF-010"]
    indexed = re.findall(r"^\|\s*\d+\s*\|\s*`([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)`\s*\|",
                         inputs["task-packets/README.md"].decode(), re.M)
    assert len(indexed) == len(set(indexed)) == 194
    assert set(indexed) == set(packets)
    vectors = module.parse(inputs[module.SPEC_PATH])["testVectors"]
    assert vectors["expectedAddedCases"] == 130
    assert vectors["inheritedExpandedCases"] == 10
    assert vectors["totalAddedCases"] == 140
    expanded = 0
    for row in vectors["inheritedParameterExpansion"]:
        source_path = "scripts/validate_" + row["module"] + ".py"
        test_path = "tests/test_" + row["module"] + ".py"
        def additions(raw):
            node = next(n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "ADDITIONS" for t in n.targets))
            return ast.literal_eval(node.value)
        current = inputs[source_path]
        before = module.historical_bytes(source_path, current)
        assert additions(profiling_history(source_path, current)) == additions(before) + ("MET-PERF-010",)
        functions = [next(n for n in ast.parse(raw).body
                          if isinstance(n, ast.FunctionDef) and n.name == row["test"])
                     for raw in (module.historical_bytes(test_path, inputs[test_path]), inputs[test_path])]
        assert ast.dump(functions[0]) == ast.dump(functions[1])
        decorators = functions[1].decorator_list
        assert len(decorators) == 2 and decorators[0].args[1].id == "ADDITIONS"
        fields = ast.literal_eval(decorators[1].args[1])
        assert [v[0] for v in fields] == row["fields"]
        assert len(fields) == row["cases"] == 5
        expanded += len(fields)
    assert expanded == vectors["inheritedExpandedCases"]
    assert vectors["expectedAddedCases"] + expanded == vectors["totalAddedCases"]
    assert vectors["expectedPasses"] == {
        name: count + vectors["totalAddedCases"]
        for name, count in vectors["baselineExpectedPasses"].items()}
    assert vectors["expectedPasses"] == {"inner": 3866, "outer": 4115}
    for path, rule in record["metaRecipes"].items():
        before = module.historical_bytes(path, inputs[path])
        assert module.apply_recipe(before, rule) == profiling_history(path, inputs[path])
        if path.startswith("tests/"):
            assert module.test_ids(before) == module.test_ids(inputs[path])


@pytest.mark.parametrize("fault", [
    "record", "missing", "extra", "old-packet", "new-packet", "source",
    "commands", "predecessor", "fixture", "test", "guide",
])
def test_source_authority_substitution_refuses(authority, fault):
    packets, record, inputs = deepcopy(authority)
    if fault == "record": record["metaBaseline"] = "0" * 40
    if fault == "missing": inputs.pop(module.SPEC_PATH)
    if fault == "extra": inputs["unlisted"] = b"x"
    if fault == "old-packet": inputs["task-packets/MET-ADOPT-002.yaml"] += b" "
    if fault == "new-packet": packets["MET-PERF-010"]["allowedPaths"].append("src/")
    if fault == "source": inputs["scripts/validate_credential_lifecycle.py"] += b" "
    if fault == "commands": packets["MET-PERF-010"]["offlineAcceptanceCommands"].pop()
    if fault == "predecessor": packets["MET-PERF-010"]["predecessors"] = ["MET-PERF-009"]
    if fault == "fixture": inputs["tests/fixture_yaml.py"] += b" "
    if fault == "test": inputs["tests/test_validation_performance.py"] += b" "
    if fault == "guide": inputs["docs/alpha-2/VALIDATION_PERFORMANCE_REPAIR.md"] += b" "
    assert module.validate_authority(packets, record, inputs)


@pytest.mark.parametrize("field", [
    "budgets", "limits", "oldBudgets", "policies", "baseline", "draft",
    "logicRegions", "serializer", "testVectors", "evidence",
])
def test_each_repair_boundary_is_exact(authority, field):
    spec = module.parse(authority[2][module.SPEC_PATH])
    spec[field] = {}
    with pytest.raises(ValueError):
        module.validate_spec(spec, bind=False)


@pytest.mark.parametrize("raw", [
    b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}',
])
def test_strict_json_ambiguity_still_refuses(raw):
    with pytest.raises(ValueError):
        module.parse(raw)


def test_fresh_new_authority_cannot_cache_success(monkeypatch):
    original = module.regular_bytes
    raw = original(module.ROOT, module.RECORD_PATH)
    calls = []
    def read(root, path):
        calls.append(path)
        return raw if len(calls) == 1 else raw + b" "
    monkeypatch.setattr(module, "regular_bytes", read)
    assert module._record()["authorityPacket"] == "MET-PERF-010"
    with pytest.raises(ValueError):
        module._record()
    assert len(calls) == 2
