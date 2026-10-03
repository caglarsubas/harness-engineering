"""Source/data guards for diagnostic repair; no collection, subprocess or sleep."""
from copy import deepcopy
from hashlib import sha256
import ast
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_MODULE = "tests/test_pytest_diagnostics.py"
DRIVER_MODULE = "tests/linux_runner/test_build_and_predecessors.py"
FIXTURE_NAME = "test_invalid_node_latches_incomplete_without_rendering_input"
DRIVER_NAME = "test_full_predecessor_suites_and_validators_remain_green"
IDS = ["none", "bytes", "empty", "oversized"]


def _tree(path):
    return ast.parse((ROOT / path).read_bytes())


def _function(tree, name):
    found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(found) == 1
    return found[0]


def _ast(node):
    return ast.dump(node, include_attributes=False)


def _statements(source):
    return [_ast(node) for node in ast.parse(source).body]


def _fixture_contract(tree):
    function = _function(tree, FIXTURE_NAME)
    assert len(function.decorator_list) == 1
    decorator = function.decorator_list[0]
    assert isinstance(decorator, ast.Call)
    assert _ast(decorator.func) == _ast(ast.parse("pytest.mark.parametrize", mode="eval").body)
    assert len(decorator.args) == 2 and ast.literal_eval(decorator.args[0]) == "node"
    expected_values = ast.parse('[None, b"node", "", "x" * 65_537]', mode="eval").body
    assert _ast(decorator.args[1]) == _ast(expected_values)
    assert len(decorator.keywords) == 1 and decorator.keywords[0].arg == "ids"
    assert ast.literal_eval(decorator.keywords[0].value) == IDS
    assert len(set(IDS)) == 4 and all(len(value) <= 12 for value in IDS)
    assert [_ast(node) for node in function.body] == _statements('''
state, sink, _ = observed
state.start(node, "call")
assert state.finish(0) == 1
assert "INVALID_NODE" in state.reasons
assert all(len(line) <= diagnostics.MAX_RECORD_BYTES for line in sink.lines)
''')
    # This is a static identity bound, not runtime collection or diagnostic PASS.
    prefix = FIXTURE_MODULE + "::" + FIXTURE_NAME
    assert all(len(prefix + "[" + value + "]") < 65_536 for value in IDS)


def _nonzero_contract(tree):
    function = _function(tree, DRIVER_NAME)
    loops = [node for node in function.body if isinstance(node, ast.For)]
    assert len(loops) == 1
    tail = loops[0].body[-3:]
    assert [_ast(node) for node in tail[:2]] == _statements('''
returncode = result.returncode
if returncode != 0:
    raise AssertionError(_predecessor_failure_message(result.stdout, result.stderr))
''')
    assert [_ast(tail[2])] == _statements('''
if ordinal == 1:
    summary = record["pytestDiagnostics"]
    assert (summary["status"] == "COMPLETE"
            and summary["completionSeen"] is True
            and summary["sessionEnd"]["exitCode"] == 0
            and summary["failed"] == 0), "predecessor diagnostics incomplete"
''')


def test_short_fixture_ids_preserve_actual_invalid_values_and_rejection_body():
    _fixture_contract(_tree(FIXTURE_MODULE))


@pytest.mark.parametrize("change", ["missing_ids", "duplicate_ids", "oversized_id",
                                  "removed_input", "reduced_invalid_input", "relaxed_rejection"])
def test_fixture_guard_rejects_identity_or_negative_coverage_drift(change):
    tree = deepcopy(_tree(FIXTURE_MODULE))
    function = _function(tree, FIXTURE_NAME)
    decorator = function.decorator_list[0]
    if change == "missing_ids":
        decorator.keywords = []
    elif change == "duplicate_ids":
        decorator.keywords[0].value = ast.parse('["none", "bytes", "empty", "empty"]', mode="eval").body
    elif change == "oversized_id":
        decorator.keywords[0].value = ast.List(elts=[ast.Constant("x" * 65_537)], ctx=ast.Load())
    elif change == "removed_input":
        decorator.args[1].elts.pop()
    elif change == "reduced_invalid_input":
        decorator.args[1].elts[-1] = ast.parse('"x" * 65_536', mode="eval").body
    else:
        function.body[2] = ast.parse("assert True").body[0]
    with pytest.raises(AssertionError):
        _fixture_contract(tree)


def test_nonzero_driver_raises_exact_payload_and_keeps_completeness_gate():
    _nonzero_contract(_tree(DRIVER_MODULE))


@pytest.mark.parametrize("change", ["rewriteable_assert", "success_condition", "message_changed",
                                  "exception_changed", "missing_completeness"])
def test_driver_guard_rejects_failure_semantic_drift(change):
    tree = deepcopy(_tree(DRIVER_MODULE))
    loop = next(node for node in _function(tree, DRIVER_NAME).body if isinstance(node, ast.For))
    if change == "rewriteable_assert":
        loop.body[-2] = ast.parse("assert returncode == 0, _predecessor_failure_message(result.stdout, result.stderr)").body[0]
    elif change == "success_condition":
        loop.body[-2].test = ast.parse("returncode == 0", mode="eval").body
    elif change == "message_changed":
        loop.body[-2].body[0].exc.args = [ast.Constant("simplified failure")]
    elif change == "exception_changed":
        loop.body[-2].body[0].exc.func = ast.Name(id="RuntimeError", ctx=ast.Load())
    else:
        loop.body.pop()
    with pytest.raises(AssertionError):
        _nonzero_contract(tree)


def test_existing_strict_mock_regressions_and_recorder_are_byte_identical():
    pins = {
        "tests/linux_runner/test_predecessor_diagnostics.py": "58cabbee54b0dbfe3ca3ce28e3b60a844ad77fe410f39404f0321b6be4ab5e28",
        "ci/pytest_diagnostics.py": "67416db359a8d5953b469e33b92f0b29f3377fdd6daff7fe1a2958e8bc503a23",
        "conftest.py": "3d6acbc362d26e23b4ac578d83e8e0205adee5fa914561032a8af298f2751387",
    }
    for path, expected in pins.items():
        assert sha256((ROOT / path).read_bytes()).hexdigest() == expected


def test_failed023_terminal_does_not_turn_passed_assertions_into_acceptance():
    record = json.loads((ROOT / "architecture/packet-schema-performance-inputs/prior-023-terminal.json").read_bytes())
    assert record["status"] == "RETAINED_FAILURE_NOT_ACCEPTED_PREDECESSOR"
    assert record["packetId"] == "MET-PERF-023"
    attempt = record["separateLocalException"]
    assert (attempt["maximum"], attempt["consumed"], attempt["cumulativeLineageOrdinal"]) == (1, 1, 6)
    assert (attempt["commandsStarted"], attempt["commandsExpected"]) == (52, 53)
    assert attempt["timedOut"] is True and attempt["exitCode"] == -15
    assert attempt["finalScanReached"] is False
    assert attempt["cleanupIndependentlyConfirmed"] is True
    nested = record["nestedSuite"]
    assert (nested["stdoutPassed"], nested["stdoutSkipped"], nested["returncode"]) == (5019, 10, 1)
    assert nested["diagnosticsStatus"] == "INCOMPLETE" and nested["acceptancePass"] is False
    assert nested["producerReason"] == "INVALID_NODE" and nested["droppedRecords"] == 4680
    assert record["diagnosis"]["wholeRunTiming"] == "UNRESOLVED"
    assert record["diagnosis"]["completeOuterReportAvailable"] is False
    assert all(item["maximum"] == item["consumed"] for item in record["previousAllowances"].values())
    assert record["successorBoundary"] == {
        "newPacketId": "MET-PERF-024", "newExecutionGrants": 0,
        "budgetReset": False, "automaticCiOrExactMain": False,
        "sourceAccepted": False, "nativeLinux": False, "tenantAcceptance": False,
    }


def test_new_static_guard_module_stays_in_both_unchanged_suite_recipes():
    packet = {}
    for line in (ROOT / "task-packets/MET-PERF-028.yaml").read_text().splitlines():
        key, value = line.split(": ", 1)
        assert key not in packet
        packet[key] = json.loads(value)
    assert packet["offlineAcceptanceCommands"][-2] == [
        "uv", "run", "--offline", "--frozen", "--no-sync", "python", "-m", "pytest",
        "tests", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py",
    ]
    assert "tests/test_diagnostic_repair.py" in packet["allowedPaths"]
    function = _function(_tree(DRIVER_MODULE), DRIVER_NAME)
    commands = next(node for node in function.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "commands" for target in node.targets))
    assert _ast(commands.value) == _ast(ast.parse('''[[sys.executable, "-m", "pytest", "-rs",
        "tests", "--ignore=tests/linux_runner", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]]''', mode="eval").body)
    assert len(packet["offlineAcceptanceCommands"]) == 53 and packet["prefetchCommands"] == []
