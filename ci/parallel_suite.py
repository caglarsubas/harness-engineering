"""Run the outer packet suite on a pinned number of worker processes inside the one pytest command (MET-PERF-035).

The packet's acceptance argv is unchanged; pyproject.toml's pytest addopts load this module (-p ci.parallel_suite). The parent collects as usual and assigns
whole test files to WORKERS worker processes by the pinned per-file weights. Each worker runs `python -m pytest
<its files>` in the same checkout and environment, and streams pytest's own serialized reports to a private file. Worker
output never reaches the parent's output, so the only summary line is the parent's own. The parent replays every report
through its own hooks: terminal reporter, diagnostics and every observing plugin, in arrival order.

Session-wide tests (PARENT_NODES) read the complete session's own results, so they run last, in the parent, with the
standard protocol, after every worker has reported.

Fail closed. The session cannot pass unless all of the following hold:
- each worker collected exactly its assigned node IDs, in order;
- every collected node got exactly one setup and one teardown report, and a call report if and only if its setup
  passed, with no report for an unknown node;
- every worker exited 0, or 1 with at least one failed report from it, before the deadline.
A pytest started by any test always runs serially, and so does every invocation when WORKERS is 1.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

WORKERS = 4
DEADLINE_SECONDS = 840
WEIGHTS_PATH = "ci/parallel_suite_weights.json"
ASSIGNMENT_ENV = "PLANEON_PARALLEL_SUITE_ASSIGNMENT"
SERIAL_ENV = "PLANEON_PARALLEL_SUITE_SERIAL"
PARENT_NODES = frozenset({"tests/linux_runner/test_build_and_predecessors.py"
                          "::test_full_predecessor_suites_and_validators_remain_green"})
DIAGNOSTICS_KEY = "_planeon_met_perf_021_diagnostics"  # conftest.py's diagnostics state
_MAX_PROBLEMS = 50
_LOG_TAIL_LINES = 40

_sink = None      # worker: its report stream
_config = None    # worker: its config, for report serialization
_seen = None      # parent: nodeid -> [(when, outcome)] from every report the parent's hooks receive


def pytest_configure(config):
    """The assignment is popped so that no nested pytest acts as a worker."""
    global _sink, _config
    assignment = os.environ.pop(ASSIGNMENT_ENV, None)
    if assignment:
        _sink, _config = open(assignment + ".reports.jsonl", "x", buffering=1), config
        config._planeon_parallel_assigned = json.loads(Path(assignment).read_text())["nodeids"]


def pytest_unconfigure(config):
    if _sink is not None:
        _sink.close()


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(session, config, items):
    """Worker only: drop the parent-run nodes, then require exactly the assigned node list."""
    assigned = getattr(config, "_planeon_parallel_assigned", None)
    if assigned is None:
        return
    parent_only = [item for item in items if item.nodeid in PARENT_NODES]
    if parent_only:
        items[:] = [item for item in items if item.nodeid not in PARENT_NODES]
        config.hook.pytest_deselected(items=parent_only)
    if [item.nodeid for item in items] != assigned:
        _sink.write(json.dumps({"assignmentMismatch": True}) + "\n")
        pytest.exit("parallel suite: worker collected a different node list", returncode=3)


def pytest_runtest_logreport(report):
    if _sink is not None:
        _sink.write(json.dumps(_config.hook.pytest_report_to_serializable(config=_config, report=report)) + "\n")
    if _seen is not None and report.nodeid in _seen:
        _seen[report.nodeid].append((report.when, report.outcome))


def account(seen):
    """The per-node rule: exactly one setup and one teardown, and a call if and only if setup passed."""
    problems = []
    for nodeid, phases in seen.items():
        whens = [when for when, _ in phases]
        expected = ["setup", "call", "teardown"] if ("setup", "passed") in phases else ["setup", "teardown"]
        if whens != expected:
            problems.append("node %s reported %s" % (nodeid, whens))
    return problems


def worker_exit_problem(name, code, failed):
    """A worker passes only by exiting 0, or 1 with at least one failed report of its own."""
    if code == 0 or (code == 1 and failed > 0):
        return None
    return "%s exited %s with %d failed reports" % (name, code, failed)


def _plan(files, workers, root):
    """Longest first by pinned weight onto the least-loaded worker; unknown files weigh by their node count."""
    # Weights only balance the workers; a project without the table (a test's scratch tree) weighs by node count.
    table = root / WEIGHTS_PATH
    weights = json.loads(table.read_text()) if table.is_file() else {}
    weight = {name: float(weights.get(name, 0.05 * len(nodes))) for name, nodes in files.items()}
    buckets = [[0.0, []] for _ in range(workers)]
    for name in sorted(files, key=lambda name: (-weight[name], name)):
        bucket = min(buckets, key=lambda bucket: bucket[0])
        bucket[0] += weight[name]
        bucket[1].append(name)
    order = list(files)
    return [sorted(bucket[1], key=order.index) for bucket in buckets if bucket[1]]


@pytest.hookimpl(tryfirst=True)
def pytest_runtestloop(session):
    """Returns None to keep pytest's serial loop."""
    global _seen
    config = session.config
    diagnostics = getattr(config, DIAGNOSTICS_KEY, None)
    if (_sink is not None or WORKERS == 1 or os.environ.get(SERIAL_ENV) or config.option.collectonly
            or not session.items):
        return None
    if session.testsfailed and not config.option.continue_on_collection_errors:
        raise session.Interrupted("%d error%s during collection" % (session.testsfailed, "s" if session.testsfailed != 1 else ""))
    items = {item.nodeid: item for item in session.items}
    if len(items) != len(session.items):
        raise session.Failed("parallel suite: duplicate node IDs")
    files, parent_items = {}, [item for item in session.items if item.nodeid in PARENT_NODES]
    for item in session.items:
        if item.nodeid not in PARENT_NODES:
            files.setdefault(item.nodeid.split("::", 1)[0], []).append(item.nodeid)
    # Every pytest started from here on, by a worker's test or by a parent-run test, runs serially.
    os.environ[SERIAL_ENV] = "1"
    work = Path(tempfile.mkdtemp(prefix="planeon-parallel-suite."))
    workers, problems = [], []
    seen = _seen = {nodeid: [] for nodeid in items}

    def drain(worker):
        if not worker["reports"].exists():
            return
        with open(worker["reports"], "rb") as handle:
            handle.seek(worker["offset"])
            chunk = handle.read()
        worker["offset"] += len(chunk)
        *lines, worker["pending"] = (worker["pending"] + chunk).split(b"\n")
        for line in lines:
            record = json.loads(line)
            if not isinstance(record, dict) or record.get("assignmentMismatch"):
                problems.append("%s: assignment mismatch or unserializable report" % worker["name"])
                continue
            report = config.hook.pytest_report_from_serializable(config=config, data=record)
            item = items.get(getattr(report, "nodeid", None))
            if item is None or item.nodeid in PARENT_NODES:
                problems.append("%s: report for an unassigned node" % worker["name"])
                continue
            if report.when == "setup":
                item.ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
            if diagnostics is not None:
                diagnostics.start(report.nodeid, report.when)
                diagnostics.end(report.nodeid, report.when, report.outcome, report.duration,
                                xfail=hasattr(report, "wasxfail"))
            item.ihook.pytest_runtest_logreport(report=report)
            worker["failed"] += int(report.failed)
            if report.when == "teardown":
                item.ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)

    try:
        for index, names in enumerate(_plan(files, WORKERS, config.rootpath)):
            assignment = work / ("worker%d.json" % index)
            assignment.write_text(json.dumps({"nodeids": [node for name in names for node in files[name]]}))
            log = open(work / ("worker%d.log" % index), "wb")
            # Load this plugin explicitly too, so a worker never depends on the project configuration to report.
            process = subprocess.Popen([sys.executable, "-m", "pytest", "-p", __name__, *names], cwd=str(config.rootpath),
                                       env={**os.environ, ASSIGNMENT_ENV: str(assignment)},
                                       stdout=log, stderr=subprocess.STDOUT)
            workers.append({"process": process, "name": assignment.name, "log": log, "offset": 0, "pending": b"",
                            "failed": 0, "reports": Path(str(assignment) + ".reports.jsonl")})

        deadline = time.monotonic() + DEADLINE_SECONDS
        while True:
            for worker in workers:
                drain(worker)
            if all(worker["process"].poll() is not None for worker in workers):
                break
            if time.monotonic() > deadline:
                problems.append("deadline of %d s" % DEADLINE_SECONDS)
                break
            time.sleep(0.05)
    finally:
        for worker in workers:
            if worker["process"].poll() is None:
                worker["process"].kill()
            worker["process"].wait()
            worker["log"].close()
    for worker in workers:
        drain(worker)
        code = worker["process"].returncode
        if worker["pending"]:
            problems.append("%s: partial report line" % worker["name"])
        problem = worker_exit_problem(worker["name"], code, worker["failed"])
        if problem:
            problems.append(problem)
    for index, item in enumerate(parent_items):
        nextitem = parent_items[index + 1] if index + 1 < len(parent_items) else None
        item.config.hook.pytest_runtest_protocol(item=item, nextitem=nextitem)
    problems += account(seen)[:_MAX_PROBLEMS]
    if problems:
        writer = config.get_terminal_writer()
        writer.line("parallel suite INCOMPLETE: %d problem(s); worker logs in %s" % (len(problems), work), red=True)
        for problem in problems[:20]:
            writer.line("  " + problem)
        for worker in workers:
            if worker["process"].returncode not in (0, 1):
                lines = (work / worker["name"].replace(".json", ".log")).read_bytes().splitlines()
                tail = [line for line in lines if not line.startswith(b"PYTEST_DIAGNOSTIC=")][-_LOG_TAIL_LINES:]
                writer.line("  --- %s (last lines) ---" % worker["name"])
                for line in tail:
                    writer.line("  " + line.decode("utf-8", errors="replace"))
        raise session.Failed("parallel suite incomplete")
    return True
