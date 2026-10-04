"""Bounded conversion tests, not acceptance caches or performance measurements.

The small loop fixture stops before the catalog gate; it tests the real input
loop, never claims that a synthetic catalog passed the complete validator.
The inherited full-catalog matrices and both complete suites remain mandatory.
"""
import ast
from copy import deepcopy
from hashlib import sha256
import importlib
import json
from pathlib import Path
import sys

import pytest
import yaml

from scripts import validate_ci_performance as ci
from scripts import validate_packet_schema_performance as history
from scripts import validate_successor_inventory as successor


ROOT = Path(__file__).resolve().parents[1]
CI_SOURCE = "scripts/validate_ci_performance.py"
HELPER_SOURCE = "scripts/validate_successor_inventory.py"
RAW = b"id: SEM-FIXTURE-001\nvalue: 1\n"
INPUT_PATH = "task-packets/SEM-FIXTURE-001.yaml"


@pytest.fixture(autouse=True)
def isolated_conversion_cache(monkeypatch):
    # Capture real functions before per-test monkeypatching. Clear before and
    # after so mock output cannot prime a later production-validation lookup.
    helpers = {ci.packet_semantics, successor.packet_semantics}
    for helper in helpers:
        helper.cache_clear()
    yield
    for helper in helpers:
        helper.cache_clear()


def _function(path, name):
    tree = ast.parse((ROOT / path).read_bytes())
    found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(found) == 1
    return found[0]


def _ast_sha(node):
    return sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def test_only_the_owned_semantic_expression_changes_in_the_validator():
    node = deepcopy(_function(CI_SOURCE, "validate_ci_performance"))
    targets = [item for item in ast.walk(node) if isinstance(item, ast.Call)
               and isinstance(item.func, ast.Name) and item.func.id == "packet_semantics"]
    assert len(targets) == 1
    call = targets[0]
    assert not call.keywords and len(call.args) == 1
    assert ast.dump(call.args[0], include_attributes=False) == ast.dump(
        ast.parse("inputs[path]", mode="eval").body, include_attributes=False)
    call.func = ast.Name(id="canonical", ctx=ast.Load())
    call.args = [ast.Call(func=ast.Name(id="safe_load", ctx=ast.Load()), args=call.args, keywords=[])]
    # Only the current catalog member changes mechanically; old body/order is
    # otherwise byte-independent AST-identical to the frozen024 function.
    for item in ast.walk(node):
        if isinstance(item, ast.Constant) and item.value == "MET-PERF-028":
            item.value = "MET-PERF-024"
        if isinstance(item, ast.Set):
            item.elts = [element for element in item.elts
                         if not (isinstance(element, ast.Constant) and element.value in {"MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"})]
    # AST encoding is bound to the declared Python 3.12 toolchain, not the
    # macOS system interpreter used for ordinary source editing.
    assert _ast_sha(node) == "2cba8cc6052f1f11681635e82a0b2f727c0dffde5fc1ffc2c8efd918870cac47"
    tree = ast.parse((ROOT / CI_SOURCE).read_bytes())
    imports = [(item.module, tuple(alias.name for alias in item.names))
               for item in ast.walk(tree) if isinstance(item, ast.ImportFrom)
               and any(alias.name == "packet_semantics" for alias in item.names)]
    assert sorted(imports) == [("scripts.validate_successor_inventory", ("packet_semantics",)),
                               ("validate_successor_inventory", ("packet_semantics",))]


def test_shared_helper_parser_and_canonicalizer_are_not_modified():
    assert _ast_sha(_function(HELPER_SOURCE, "packet_semantics")) == "b8d2d04b957556282f933925568e3822b503530178f80a4e9c0e6f3e314af152"
    assert _ast_sha(_function(HELPER_SOURCE, "canonical")) == "761672ff4f4051fad2a83e50e5378dcb7416ed606cab1ceb938f9f24a1c30b86"
    assert sha256((ROOT / "scripts/safe_yaml.py").read_bytes()).hexdigest() == "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7"


@pytest.mark.parametrize("module_name", ["scripts.validate_successor_inventory", "validate_successor_inventory"])
@pytest.mark.parametrize("raw", [
    b"a: [1, true, null]\n", b"a: 1\na: 2\n",
    b"base: &b {x: 1}\nvalue: {<<: *b, y: 2}\n",
    b"a: &a [1]\nb: *a\n", "a: ['é', '中']\n".encode(),
])
def test_package_and_direct_script_imports_have_canonical_parity(monkeypatch, module_name, raw):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    aliases_before = {name: sys.modules.get(name)
                      for name in ("validate_successor_inventory", "safe_yaml")}
    helper = None
    try:
        module = importlib.import_module(module_name)
        helper = module.packet_semantics
        helper.cache_clear()
        expected = ci.canonical(ci.safe_load(raw))
        assert type(helper(raw)) is bytes
        assert helper(raw) == expected == module.canonical(module.safe_yaml_load(raw))
    finally:
        if helper is not None:
            helper.cache_clear()
        # Leave pre-existing aliases alone; do not make later import behavior
        # depend on which parity parameter happened to run first.
        for name, previous in aliases_before.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                assert sys.modules.get(name) is previous


@pytest.mark.parametrize("loader_choice", ["python", "installed-default"])
def test_fixed_safe_loader_variants_keep_parity_and_leave_no_warm_mock(monkeypatch, loader_choice):
    helper = successor.packet_semantics
    parser_module = sys.modules[successor.safe_yaml_load.__module__]
    loader = yaml.SafeLoader if loader_choice == "python" else getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    with monkeypatch.context() as patch:
        patch.setattr(parser_module, "SafeLoader", loader)
        helper.cache_clear()
        try:
            for raw in (RAW, b"a: 1\na: 2\n", b"a: &a [1]\nb: *a\n"):
                assert helper(raw) == successor.canonical(yaml.load(raw, Loader=loader))
        finally:
            helper.cache_clear()
    assert helper.cache_info().currsize == 0


def test_exact_raw_byte_keys_distinguish_equivalent_whitespace():
    helper = successor.packet_semantics
    first, second = b"value: 1\n", b"value: 1\n\n"
    assert first != second and helper(first) == helper(second)
    assert (helper.cache_info().misses, helper.cache_info().hits) == (2, 0)
    assert helper(first) == b'{"value":1}'
    assert (helper.cache_info().misses, helper.cache_info().hits) == (2, 1)
    assert helper(b"value: 2\n") == b'{"value":2}'


def test_immutable_return_bytes_cannot_be_poisoned_through_decoded_objects():
    helper = successor.packet_semantics
    raw = b"values: [1]\n"
    original = helper(raw)
    assert type(original) is bytes
    decoded = json.loads(original)
    decoded["values"].append(2)
    assert helper(raw) == original == b'{"values":[1]}'


def test_existing_256_entry_bound_and_eviction_are_preserved():
    helper = successor.packet_semantics
    assert helper.cache_parameters() == {"maxsize": 256, "typed": False}
    for number in range(257):
        assert helper(("value: " + str(number) + "\n").encode()) == ("{\"value\":" + str(number) + "}").encode()
    info = helper.cache_info()
    assert (info.currsize, info.misses, info.maxsize) == (256, 257, 256)
    assert helper(b"value: 0\n") == b'{"value":0}'
    assert helper.cache_info().misses == 258 and helper.cache_info().currsize == 256


@pytest.mark.parametrize("raw", [
    b"a: [1", b"a: *missing", b"\xff", b"\0",
    b"!!python/object/apply:os.system ['should-not-execute']",
    b"!!python/name:builtins.eval", b"a: .nan\n", b"a: .inf\n",
    b"a: 2026-10-02\n", b"a: !!binary SGk=\n", b"a: &a [*a]\n",
])
def test_rejected_conversion_does_not_become_cached_success(raw):
    helper = successor.packet_semantics
    with pytest.raises((ValueError, TypeError, yaml.YAMLError)) as expected:
        successor.canonical(successor.safe_yaml_load(raw))
    for _ in range(2):
        with pytest.raises(type(expected.value)):
            helper(raw)
        assert helper.cache_info().currsize == 0
    assert helper.cache_info().misses == 2


class _AfterInputLoop(RuntimeError):
    """Unit-only sentinel, not validation success or an acceptance result."""


@pytest.fixture
def loop_fixture(monkeypatch):
    events = []
    require = ci.require
    real_helper = ci.packet_semantics
    real_history = ci.historical_bytes
    record = {"protectedFiles": {INPUT_PATH: ci.digest(RAW)}, "inputFiles": {}}
    packets = {"SEM-FIXTURE-001": {"id": "SEM-FIXTURE-001", "value": 1}}

    def boundary(condition, message):
        if message == "138 exact predecessors, performance packet and two exact credential packets":
            raise _AfterInputLoop()
        return require(condition, message)

    def projection(path, raw):
        events.append(("history", path))
        return raw

    def semantic(raw):
        events.append(("semantic", raw))
        return real_helper(raw)

    monkeypatch.setattr(ci, "pinned", lambda value: None)
    monkeypatch.setattr(ci, "validate_additions", lambda value: [])
    monkeypatch.setattr(ci, "require", boundary)
    monkeypatch.setattr(ci, "historical_bytes", projection)
    monkeypatch.setattr(ci, "packet_semantics", semantic)
    return packets, record, {INPUT_PATH: RAW}, events, real_history


def _reach_loop_boundary(fixture):
    packets, record, inputs, _, _ = fixture
    with pytest.raises(_AfterInputLoop):
        ci.validate_ci_performance(packets, record, inputs, {})


def test_warm_conversion_still_runs_fresh_interleaved_integrity(loop_fixture):
    events = loop_fixture[3]
    _reach_loop_boundary(loop_fixture)
    _reach_loop_boundary(loop_fixture)
    assert events == [("history", INPUT_PATH), ("semantic", RAW)] * 2


@pytest.mark.parametrize("changed", [RAW + b"\n", b"id: SEM-FIXTURE-001\nvalue: 2\n"])
def test_warm_success_then_byte_drift_refuses_before_semantics(loop_fixture, changed):
    _reach_loop_boundary(loop_fixture)
    packets, record, inputs, events, _ = loop_fixture
    inputs[INPUT_PATH] = changed
    events.clear()
    assert ci.validate_ci_performance(packets, record, inputs, {}) == ["invalid bounded CI-performance authority"]
    assert events == [("history", INPUT_PATH)]


def test_warm_success_then_current_packet_map_drift_still_refuses(loop_fixture):
    _reach_loop_boundary(loop_fixture)
    packets, record, inputs, events, _ = loop_fixture
    packets["SEM-FIXTURE-001"]["value"] = 2
    events.clear()
    assert ci.validate_ci_performance(packets, record, inputs, {}) == ["invalid bounded CI-performance authority"]
    assert events == [("history", INPUT_PATH), ("semantic", RAW)]


@pytest.mark.parametrize("kind", ["missing", "extra", "str", "bytearray", "none"])
def test_bad_inventory_or_nonbytes_never_reaches_semantic_lookup(loop_fixture, kind):
    packets, record, inputs, events, _ = loop_fixture
    if kind == "missing":
        inputs.clear()
    elif kind == "extra":
        inputs["extra"] = b"x"
    else:
        inputs[INPUT_PATH] = {"str": RAW.decode(), "bytearray": bytearray(RAW), "none": None}[kind]
    assert ci.validate_ci_performance(packets, record, inputs, {}) == ["invalid bounded CI-performance authority"]
    assert events == []


@pytest.mark.parametrize("damage", ["changed", "missing", "linked"])
def test_real_projection_refuses_authority_drift_even_with_warm_conversion(monkeypatch, tmp_path, loop_fixture, damage):
    authority = tmp_path / history.AUTHORITY_PATH
    authority.parent.mkdir(parents=True)
    authority.write_bytes((history.ROOT / history.AUTHORITY_PATH).read_bytes())
    owners = [sys.modules[name] for name in
              ("scripts.validate_packet_schema_performance", "validate_packet_schema_performance")
              if name in sys.modules]
    assert history in owners
    authority_reads = []
    for module in owners:
        assert Path(module.__file__).resolve() == ROOT / "scripts/validate_packet_schema_performance.py"
        monkeypatch.setattr(module, "ROOT", tmp_path)

        # Linear rechecks reach this layer's authority through either entry point.
        for entry in ("_checked_authority_raw", "_checked_own_authority_raw"):
            def checked(read=getattr(module, entry), owner=module.__name__):
                authority_reads.append(owner)
                return read()

            monkeypatch.setattr(module, entry, checked)
    packets, record, inputs, events, real_history = loop_fixture

    def projection(path, raw):
        events.append(("history", path))
        return real_history(path, raw)

    monkeypatch.setattr(ci, "historical_bytes", projection)
    _reach_loop_boundary(loop_fixture)
    assert authority_reads  # The real chain, not an unused alias, was observed.
    authority_reads.clear()
    events.clear()
    if damage == "changed":
        authority.write_bytes(authority.read_bytes() + b" ")
    elif damage == "missing":
        authority.unlink()
    else:
        target = tmp_path / "same-authority.json"
        target.write_bytes(authority.read_bytes())
        authority.unlink()
        authority.symlink_to(target)
    if damage == "missing":
        with pytest.raises(OSError):
            ci.validate_ci_performance(packets, record, inputs, {})
    else:
        assert ci.validate_ci_performance(packets, record, inputs, {}) == ["invalid bounded CI-performance authority"]
    assert events == [("history", INPUT_PATH)]
    assert authority_reads  # Refusal still traversed authority custody on a warm hit.


def test_fixed_parser_assumption_is_explicit_not_runtime_drift_detection():
    packet = {}
    for line in (ROOT / "task-packets/MET-PERF-028.yaml").read_text().splitlines():
        key, value = line.split(": ", 1)
        assert key not in packet
        packet[key] = json.loads(value)
    wording = " ".join(packet["contracts"])
    assert "key does not detect arbitrary later parser replacement" in wording
    assert "256" in wording and "Entry count is not a total-memory bound" in wording
    assert "ZERO executions" in wording
    assert len(packet["offlineAcceptanceCommands"]) == 53
    assert packet["offlineAcceptanceCommands"][-2][-4:] == ["pytest", "tests", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]
    assert packet["prefetchCommands"] == []


def test_failed024_evidence_and_seven_consumed_attempts_remain_distinct():
    record = json.loads((ROOT / "architecture/packet-schema-performance-inputs/prior-024-terminal.json").read_bytes())
    assert record["packetId"] == "MET-PERF-024"
    assert record["status"] == "RETAINED_FAILURE_NOT_ACCEPTED_PREDECESSOR"
    attempt = record["separateLocalException"]
    assert (attempt["maximum"], attempt["consumed"], attempt["cumulativeLineageOrdinal"]) == (1, 1, 7)
    assert (attempt["commandsStarted"], attempt["commandsExpected"], attempt["timedOut"]) == (52, 53, True)
    assert attempt["finalScanReached"] is False and attempt["cleanupIndependentlyConfirmed"] is True
    assert record["nestedSuite"]["returncode"] == 0
    assert record["nestedSuite"]["diagnosticsStatus"] == "COMPLETE"
    assert record["outerSuite"]["completeFinalPytestReportAvailable"] is False
    assert record["outerSuite"]["observedPassedCallRecords"] == 4676
    assert record["successorBoundary"]["newExecutionGrants"] == 0
    assert record["successorBoundary"]["newPacketId"] == "MET-PERF-025"
    assert record["successorBoundary"]["budgetReset"] is False
