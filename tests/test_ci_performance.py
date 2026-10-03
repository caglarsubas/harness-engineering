"""Parser parity and immutable predecessor tests; never an acceptance cache."""
from copy import deepcopy
import io
import json
from pathlib import Path

import pytest
import yaml

from ci.measure_yaml_parsing import shape
from scripts import safe_yaml
from scripts.validate_ci_performance import (
    BEFORE_PATH, CURRENT_PACKET_COUNT, RECORD_SHA256, canonical, digest,
    expected_current_test_source as expected_test_source, load_performance_inputs, test_definitions as source_test_names,
    validate_additions, validate_ci_performance, validate_test_preservation,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def authority():
    # Shared immutable input bytes; every negative test copies its mutable view.
    packets = {p.stem: safe_yaml.safe_load(p.read_bytes()) for p in (ROOT / "task-packets").glob("*.yaml")}
    return packets, *load_performance_inputs(ROOT)


def test_exact_packet_and_preservation_authority(authority):
    packets, record, inputs, current = authority
    assert len(packets) == CURRENT_PACKET_COUNT == 194
    assert len(record["protectedFiles"]) == 236
    assert len(record["mechanicalTestUpdates"]) == 20
    assert digest(canonical(record)) == RECORD_SHA256
    assert validate_ci_performance(*authority) == []
    assert len(packets["MET-PERF-001"]["offlineAcceptanceCommands"]) == 19
    assert record["limits"] == {"nestedSeconds": 420, "hostSeconds": 900, "workflowMinutes": 15}
    assert record["evidence"]["nativeLinux"] == "NOT_RUN_ENV_UNAVAILABLE"


@pytest.mark.parametrize("field", ["allowedPaths", "offlineAcceptanceCommands", "predecessors", "sourceReuse", "excluded"])
def test_packet_cannot_relax_scope_or_acceptance(authority, field):
    packets = deepcopy(authority[0])
    packets["MET-PERF-001"][field] = [{"unreviewed": True}] if field == "sourceReuse" else []
    assert packets["MET-PERF-001"][field] != authority[0]["MET-PERF-001"][field]
    assert validate_additions(packets)
    assert validate_ci_performance(packets, *authority[1:])


@pytest.mark.parametrize("field", ["protectedFiles", "mechanicalTestUpdates", "inputFiles", "limits", "semantics", "evidence"])
def test_record_cannot_be_widened(authority, field):
    packets, record, inputs, current = authority
    changed = deepcopy(record)
    changed[field] = {}
    assert validate_ci_performance(packets, changed, inputs, current)


def test_each_protected_input_rechecked_not_cached(authority):
    packets, record, inputs, current = authority
    for path in {**record["protectedFiles"], **record["inputFiles"]}:
        changed = dict(inputs)
        changed[path] += b" "
        assert validate_ci_performance(packets, record, changed, current), path
    assert validate_ci_performance(*authority) == []


def test_every_previous_test_body_and_inventory_is_preserved(authority):
    _, record, inputs, current = authority
    before = json.loads(inputs[BEFORE_PATH])["files"]
    assert set(before) == set(current)
    for path, text in before.items():
        assert current[path] == expected_test_source(text.encode(), record["mechanicalTestUpdates"][path])
        assert source_test_names(current[path]) == source_test_names(text.encode())
        changed = dict(current)
        changed[path] += b"\n# unreviewed test change\n"
        assert validate_test_preservation(record, inputs[BEFORE_PATH], changed), path
    assert validate_test_preservation(record, inputs[BEFORE_PATH], {})


@pytest.mark.parametrize("change", [b"assert True", b"pytest.skip('fast')", b"pass"])
def test_assertion_or_skip_substitution_refuses(authority, change):
    _, record, inputs, current = authority
    path = "tests/test_task_packets.py"
    changed = dict(current)
    target = b"assert len(files) == EXPECTED_PACKET_COUNT == 194"
    assert target in changed[path]
    changed[path] = changed[path].replace(target, change, 1)
    assert validate_test_preservation(record, inputs[BEFORE_PATH], changed)


def test_parser_calls_are_fresh_and_global_yaml_is_unchanged():
    original = yaml.safe_load
    first = safe_yaml.safe_load("a: &a [1]\nb: *a\n")
    assert first["a"] is first["b"]
    first["a"].append(2)
    second = safe_yaml.safe_load("a: &a [1]\nb: *a\n")
    assert second == {"a": [1], "b": [1]}
    assert second["a"] is second["b"] and second["a"] is not first["a"]
    assert yaml.safe_load is original
    assert safe_yaml.SafeLoader in (yaml.SafeLoader, getattr(yaml, "CSafeLoader", yaml.SafeLoader))


def test_python_fallback_requires_no_download_or_flag(monkeypatch):
    monkeypatch.delattr(yaml, "CSafeLoader", raising=False)
    selected = safe_yaml._select_safe_loader()
    assert selected is yaml.SafeLoader
    monkeypatch.setattr(safe_yaml, "SafeLoader", selected)
    assert safe_yaml.safe_load("a: [1, true, null]\n") == {"a": [1, True, None]}


@pytest.mark.parametrize("raw", [
    "", "# empty\n", "---\na: true\nb: null\nc: 012\nd: 0x10\ne: 1:20\n",
    "a: [1.5, .inf, -.inf, .nan, -0.0]\n",
    "a: 2026-09-09\nb: 2026-09-09T12:00:00+08:00\n",
    "a: !!binary SGVsbG8=\nb: !!set {x: null, y: null}\n",
    "base: &b {x: 1}\nvalue: {<<: *b, y: 2}\n",
    "a: &a [*a]\n", "a: &a {self: *a}\n",
    "a: [é, 中, '😀']\nb: |\n  line one\n  line two\n",
    "a: 1\na: 2\n", "a: &a [1]\nb: [*a, *a]\n",
    "!!omap [{a: 1}, {b: 2}]\n", "!!pairs [{a: 1}, {b: 2}]\n",
])
def test_safe_scalar_alias_merge_cycle_and_order_parity(raw):
    expected = shape(yaml.load(raw, Loader=yaml.SafeLoader))
    assert shape(safe_yaml.safe_load(raw)) == expected
    if hasattr(yaml, "CSafeLoader"):
        assert shape(yaml.load(raw, Loader=yaml.CSafeLoader)) == expected
    assert shape(safe_yaml.safe_load(io.StringIO(raw))) == expected
    assert shape(safe_yaml.safe_load(io.BytesIO(raw.encode()))) == expected


@pytest.mark.parametrize("raw", [
    b"a: [1", b"a: *missing", b"\0", b"\xff", b"---\na: 1\n---\na: 2\n",
    b"!!python/object/apply:os.system ['should-not-execute']",
    b"!!python/name:builtins.eval", b"!unreviewed {trusted: true}",
])
def test_malformed_and_executable_tags_refuse_without_side_effects(raw):
    for loader in {yaml.SafeLoader, safe_yaml.SafeLoader}:
        with pytest.raises(yaml.YAMLError):
            yaml.load(raw, Loader=loader)


def test_full_current_corpus_matches_the_python_safe_constructor():
    paths = sorted({p for folder in ("architecture", "legal", "policies", "release", "task-packets")
                    for p in (ROOT / folder).rglob("*.yaml")})
    assert len(paths) == 210
    for path in paths:
        raw = path.read_bytes()
        assert shape(safe_yaml.safe_load(raw)) == shape(yaml.load(raw, Loader=yaml.SafeLoader)), path


@pytest.mark.parametrize("module_name", ["validate_architecture", "validate_reuse", "validate_readiness"])
def test_stricter_duplicate_key_constructors_still_refuse(module_name):
    from importlib import import_module
    module = import_module("scripts." + module_name)
    for raw in ("a: 1\na: 2\n", "outer: {x: 1, x: 2}\n", "base: &b {x: 1}\nvalue: {<<: *b, x: 2}\n"):
        with pytest.raises(module.DuplicateYamlKeyError):
            yaml.load(raw, Loader=module.UniqueKeySafeLoader)
    assert yaml.load("a: [1, true]\n", Loader=module.UniqueKeySafeLoader) == {"a": [1, True]}


def test_current_status_does_not_claim_pending_publication_or_native_pass():
    text = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text().split("## Historical MET-REPAIR-015 publication checkpoint\n",1)[1]
    current = text.split("## Historical MET-PERF-001 publication checkpoint")[0]
    assert "during `MET-REPAIR-015` publication" in current
    assert "MET-REPAIR-015 | ONGOING" in current
    assert "NOT_RUN_ENV_UNAVAILABLE" in current and "effort transition NOT_DUE" in current
