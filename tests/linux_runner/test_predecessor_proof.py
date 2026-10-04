"""MET-PERF-030: the in-session predecessor proof never weakens the predecessor guarantee."""
from types import SimpleNamespace
import subprocess

import pytest

import conftest as linux_conftest
from test_build_and_predecessors import _in_session_predecessor_proof, _is_predecessor

PROOF = linux_conftest.PREDECESSOR_PROOF_NODE
TARGETS = ["tests", "--ignore=tests/linux_runner", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]
NODES = ["tests/test_a.py::test_one", "tests/test_b.py::test_two", "ci/test_warm_snapshot.py::Case::test_three"]


def _request(session_nodes, reports):
    items = [SimpleNamespace(nodeid=node) for node in session_nodes]
    config = SimpleNamespace(_planeon_predecessor_outcomes=SimpleNamespace(reports=reports))
    return SimpleNamespace(session=SimpleNamespace(items=items), config=config)


def _collect(monkeypatch, nodes, returncode=0):
    stdout = "\n".join(nodes) + "\n\n%d tests collected in 1.00s\n" % len(nodes)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=returncode, stdout=stdout, stderr=""))


def _passed():
    return [("setup", "passed"), ("call", "passed"), ("teardown", "passed")]


def test_predecessor_membership_matches_the_nested_targets():
    assert _is_predecessor("tests/test_reuse.py::test_x") and _is_predecessor("ci/test_offline_runner.py::T::test_y")
    assert not _is_predecessor("tests/linux_runner/test_isolation.py::test_z")
    assert not _is_predecessor("ci/linux-runner/x.py::test") and not _is_predecessor("conftest.py::x")


def test_proof_runs_last_and_other_order_is_kept():
    items = [SimpleNamespace(nodeid=node) for node in ("a::1", PROOF, "b::2", "c::3")]
    linux_conftest.pytest_collection_modifyitems(None, None, items)
    assert [item.nodeid for item in items] == ["a::1", "b::2", "c::3", PROOF]


def test_recorder_only_observes_reports():
    recorder = linux_conftest.PredecessorOutcomes()
    report = SimpleNamespace(nodeid="tests/test_a.py::test_one", when="call", outcome="passed")
    assert recorder.pytest_runtest_logreport(report) is None
    assert recorder.reports == {"tests/test_a.py::test_one": [("call", "passed")]}
    assert (report.when, report.outcome) == ("call", "passed")


def test_standalone_session_falls_back_to_the_nested_rerun(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("no collection without predecessor items"))
    assert _in_session_predecessor_proof(_request([PROOF], {}), {}, TARGETS) is None


@pytest.mark.parametrize("fault", ["missing", "extra", "collect_failed", "empty"])
def test_partial_or_unverifiable_sessions_fall_back(monkeypatch, fault):
    session = NODES[:-1] if fault == "missing" else NODES + (["tests/test_c.py::test_extra"] if fault == "extra" else [])
    _collect(monkeypatch, [] if fault == "empty" else NODES, returncode=1 if fault == "collect_failed" else 0)
    assert _in_session_predecessor_proof(_request(session, {node: _passed() for node in NODES}), {}, TARGETS) is None


def test_complete_passing_session_is_proven(monkeypatch):
    _collect(monkeypatch, NODES)
    reports = {node: _passed() for node in NODES}
    reports[NODES[1]] = [("setup", "skipped"), ("teardown", "passed")]
    proof = _in_session_predecessor_proof(_request(NODES, reports), {}, TARGETS)
    assert proof["mode"] == "IN_SESSION_PROOF" and proof["predecessorTests"] == 3
    assert proof["failed"] == proof["incomplete"] == 0


@pytest.mark.parametrize("fault", ["failed_call", "failed_setup", "failed_teardown", "never_ran", "no_teardown"])
def test_failed_or_incomplete_predecessors_are_reported(monkeypatch, fault):
    _collect(monkeypatch, NODES)
    reports = {node: _passed() for node in NODES}
    node = NODES[0]
    reports[node] = {"failed_call": [("setup", "passed"), ("call", "failed"), ("teardown", "passed")],
                     "failed_setup": [("setup", "failed"), ("teardown", "passed")],
                     "failed_teardown": [("setup", "passed"), ("call", "passed"), ("teardown", "failed")],
                     "never_ran": [],
                     "no_teardown": [("setup", "passed"), ("call", "passed")]}[fault]
    proof = _in_session_predecessor_proof(_request(NODES, reports), {}, TARGETS)
    assert proof["failed"] + proof["incomplete"] >= 1
    assert node in proof["failedNodes"] + proof["incompleteNodes"]
