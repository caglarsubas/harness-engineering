"""Run the outer packet suite on a pinned number of worker processes inside the one pytest command (MET-PERF-035).

The packet's acceptance argv is unchanged; pyproject.toml's pytest addopts load this module (-p ci.parallel_suite).
Only an invocation whose own arguments are all file or directory paths runs in parallel. An option, an @argument file
or a node ID on the command line keeps pytest's serial loop, because workers re-read only the ini file and the
environment. Interpreter flags (-W, -X, -B, ...) are passed on to every worker. The parent collects as usual and assigns
whole test files to WORKERS worker processes by the pinned per-file weights. Each worker runs `python -m pytest -p
ci.parallel_suite <its files>` in the same checkout and environment. It streams pytest's own serialized reports, and
the warnings recorded while its tests run, to a private file. Worker output never reaches the parent's output, so the
only summary line is the parent's own. The parent restores each report's tuple fields (JSON has no tuples) and replays
it through its own hooks: terminal reporter, diagnostics and every observing plugin, in arrival order. It re-emits each
forwarded warning through pytest_warning_recorded.

PARENT_NODES run last, in the parent, with the standard protocol, after every worker has reported. These are the
tests that read the complete session's own results, and the tests that write evidence lines past output capture, so
that those lines reach the outer output.

Fail closed. The session cannot pass unless all of the following hold:
- each worker collected exactly its assigned node IDs, in order;
- every report and warning came from the worker that owns its node;
- every collected node got exactly one setup and one teardown report, and a call report if and only if its setup
  passed;
- every stream line decoded;
- every worker exited 0, or 1 with at least one failed report from it, before the deadline.
Otherwise the parent names the problems (worker-supplied text as repr) and the in-flight node of each worker, adds a
"parallel-suite-incomplete" count to the final summary line, and fails the session. The exit code is the authority.
The accounting guards against crashes and partial or cross-worker streams. It does not guard against forgery from
inside a test: test code is trusted here exactly as in a serial run.

Every non-worker session sets PLANEON_PARALLEL_SUITE_SERIAL for its descendants, so a pytest started by any test
runs serially. This needs the environment to be inherited; an in-process pytest.main inside a worker fails closed.
SIGTERM or SIGHUP to the parent kills its workers, unless the parent inherited that signal as ignored, and a worker
whose parent dies exits. Every invocation is serial when WORKERS is 1. Each worker holds different co-resident test
files than a serial run, so warnings that depend on process state (a cached warn, a ResourceWarning's tracemalloc
hint) can differ from a serial run.
"""
import importlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from pathlib import Path

import pytest

WORKERS = 4
DEADLINE_SECONDS = 600
WEIGHTS_PATH = "ci/parallel_suite_weights.json"
ASSIGNMENT_ENV = "PLANEON_PARALLEL_SUITE_ASSIGNMENT"
SERIAL_ENV = "PLANEON_PARALLEL_SUITE_SERIAL"
PARENT_NODES = frozenset({
    # Reads the whole session's own results (MET-PERF-030 in-session predecessor proof).
    "tests/linux_runner/test_build_and_predecessors.py::test_full_predecessor_suites_and_validators_remain_green",
    # Write evidence lines past output capture (capsys.disabled()).
    "tests/linux_runner/test_build_and_predecessors.py::test_byte_identical_package_and_source_inventory",
    "tests/linux_runner/test_isolation.py::test_real_integration_is_not_faked_on_development_host",
})
DIAGNOSTICS_KEY = "_planeon_met_perf_021_diagnostics"  # conftest.py's diagnostics state
INCOMPLETE_STAT = "parallel-suite-incomplete"
INTERRUPTED_STAT = "parallel-suite-interrupted"
_MAX_PROBLEMS = 50

_sink = None      # worker: its record stream
_config = None    # worker: its config, for report serialization
_seen = None      # parent: nodeid -> [(when, outcome)] from every report the parent's hooks receive
_inherited_serial = False  # whether this session itself was started as a serial descendant


def _write(record):
    _sink.write(json.dumps(record) + "\n")


def _watch_parent(parent):
    """Worker only: exit as soon as the parent pytest is gone, so that no worker outlives a killed session."""
    while True:
        time.sleep(1)
        if os.getppid() != parent:
            os._exit(70)


def pytest_configure(config):
    """The assignment is popped so that no nested pytest acts as a worker; descendants of every session run serially."""
    global _sink, _config, _inherited_serial
    assignment = os.environ.pop(ASSIGNMENT_ENV, None)
    _inherited_serial = bool(os.environ.get(SERIAL_ENV))
    os.environ[SERIAL_ENV] = "1"
    if assignment:
        _sink, _config = open(assignment + ".reports.jsonl", "x", buffering=1), config
        record = json.loads(Path(assignment).read_text())
        config._planeon_parallel_assigned = record["nodeids"]
        threading.Thread(target=_watch_parent, args=(record["parent"],), daemon=True).start()


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
        _write({"kind": "mismatch"})
        pytest.exit("parallel suite: worker collected a different node list", returncode=3)


def pytest_runtest_logreport(report):
    if _sink is not None:
        _write({"kind": "report", "data": _config.hook.pytest_report_to_serializable(config=_config, report=report)})
    if _seen is not None and report.nodeid in _seen:
        _seen[report.nodeid].append((report.when, report.outcome))


def pytest_warning_recorded(warning_message, when, nodeid, location):
    """Worker only: forward each warning recorded while a test runs (collection warnings recur in the parent)."""
    if _sink is not None and when == "runtest":
        category = warning_message.category
        _write({"kind": "warning", "nodeid": nodeid, "message": str(warning_message.message),
                "category": [category.__module__, category.__qualname__],
                "filename": str(warning_message.filename), "lineno": warning_message.lineno})


def restore_types(report):
    """JSON turns tuples into lists; give the parent's hooks the types pytest itself produces."""
    if isinstance(report.location, list):
        report.location = tuple(report.location)
    if isinstance(report.longrepr, list):
        report.longrepr = tuple(report.longrepr)
    report.sections = [tuple(section) for section in report.sections]
    report.user_properties = [tuple(prop) for prop in report.user_properties]
    return report


def warning_category(module, qualname):
    """The forwarded warning's own class when importable, else a stand-in with the same module and name."""
    try:
        value = importlib.import_module(module)
        for part in qualname.split("."):
            value = getattr(value, part)
        if isinstance(value, type) and issubclass(value, Warning):
            return value
    except Exception:
        pass
    return type(qualname.rsplit(".", 1)[-1], (Warning,), {"__module__": module, "__qualname__": qualname})


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


def paths_only(config):
    """Workers re-read only the ini file and the environment, so an option, an @file or a node ID keeps the run serial."""
    return all(not str(arg).startswith(("-", "@")) and "::" not in str(arg) for arg in config.invocation_params.args)


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


def _stat(config, name, entry):
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        # Through the reporter's own stats entry point, so that the final summary line counts it (pinned pytest 8.4.2).
        reporter._add_stats(name, [entry])


def _fail(session, problems, work=None, in_flight=()):
    """Name the problems, add the incomplete count to the final summary line, and fail the session."""
    config = session.config
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    lines = ["parallel suite INCOMPLETE: %d problem(s)%s" % (len(problems), "; worker logs in %s" % work if work else "")]
    lines += ["  " + problem for problem in problems[:20]]
    lines += ["  in flight: " + entry for entry in in_flight]
    for line in lines:
        if reporter is not None:
            reporter.write_line(line, red=True)
        else:
            print(line)
    _stat(config, INCOMPLETE_STAT, problems[0])
    raise session.Failed("parallel suite incomplete: " + problems[0])


def _interrupt(signum, frame):
    raise KeyboardInterrupt("parallel suite: signal %d" % signum)


@pytest.hookimpl(tryfirst=True)
def pytest_runtestloop(session):
    """Returns None to keep pytest's serial loop."""
    global _seen
    config = session.config
    diagnostics = getattr(config, DIAGNOSTICS_KEY, None)
    if (_sink is not None or WORKERS == 1 or _inherited_serial or config.option.collectonly
            or not session.items or not paths_only(config)):
        return None
    if session.testsfailed and not config.option.continue_on_collection_errors:
        raise session.Interrupted("%d error%s during collection" % (session.testsfailed, "s" if session.testsfailed != 1 else ""))
    items = {item.nodeid: item for item in session.items}
    if len(items) != len(session.items):
        _fail(session, ["%d duplicate node IDs" % (len(session.items) - len(items))])
    files, parent_items = {}, [item for item in session.items if item.nodeid in PARENT_NODES]
    for item in session.items:
        if item.nodeid not in PARENT_NODES:
            files.setdefault(item.nodeid.split("::", 1)[0], []).append(item.nodeid)
    work = Path(tempfile.mkdtemp(prefix="planeon-parallel-suite."))
    workers, problems, owner = [], [], {}
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
            try:
                record = json.loads(line)
                kind = record["kind"]
                if kind == "report":
                    report = restore_types(config.hook.pytest_report_from_serializable(config=config, data=record["data"]))
                    nodeid = report.nodeid
                elif kind == "warning":
                    nodeid = record["nodeid"]
                else:
                    problems.append("%s: %r record" % (worker["name"], kind))
                    continue
            except Exception as exc:
                problems.append("%s: undecodable record (%s)" % (worker["name"], type(exc).__name__))
                continue
            if owner.get(nodeid) != worker["name"]:
                problems.append("%s: %s for a node it does not own: %r" % (worker["name"], kind, nodeid))
                continue
            item = items[nodeid]
            try:
                if kind == "warning":
                    message = warnings.WarningMessage(record["message"], warning_category(*record["category"]),
                                                      record["filename"], record["lineno"])
                    item.ihook.pytest_warning_recorded.call_historic(
                        kwargs=dict(warning_message=message, when="runtest", nodeid=nodeid, location=None))
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
            except Exception as exc:
                problems.append("%s: replay of %r failed (%s)" % (worker["name"], nodeid, type(exc).__name__))

    # A signal the parent inherited as ignored stays ignored, for the parent and for its workers.
    previous = {number: signal.signal(number, _interrupt) for number in (signal.SIGTERM, signal.SIGHUP)
                if signal.getsignal(number) == signal.SIG_DFL}
    try:
        for index, names in enumerate(_plan(files, WORKERS, config.rootpath)):
            assignment = work / ("worker%d.json" % index)
            nodeids = [node for name in names for node in files[name]]
            owner.update((node, assignment.name) for node in nodeids)
            assignment.write_text(json.dumps({"nodeids": nodeids, "parent": os.getpid()}))
            log = open(work / ("worker%d.log" % index), "wb")
            # Load this plugin explicitly too, so a worker never depends on the project configuration to report.
            # The interpreter's own flags (-W, -X, -B, ...) are passed on, as they are not pytest arguments.
            argv = [sys.executable, *subprocess._args_from_interpreter_flags(), "-m", "pytest", "-p", __name__, *names]
            process = subprocess.Popen(argv, cwd=str(config.rootpath),
                                       env={**os.environ, ASSIGNMENT_ENV: str(assignment)},
                                       stdout=log, stderr=subprocess.STDOUT)
            workers.append({"process": process, "name": assignment.name, "log": log, "offset": 0, "pending": b"",
                            "failed": 0, "reports": Path(str(assignment) + ".reports.jsonl"), "nodeids": nodeids})
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
    except KeyboardInterrupt:
        _stat(config, INTERRUPTED_STAT, "interrupted")
        raise
    finally:
        for worker in workers:
            if worker["process"].poll() is None:
                worker["process"].kill()
            worker["process"].wait()
            worker["log"].close()
        for number, handler in previous.items():
            signal.signal(number, handler)
    for worker in workers:
        drain(worker)
        if worker["pending"]:
            problems.append("%s: partial record line" % worker["name"])
        problem = worker_exit_problem(worker["name"], worker["process"].returncode, worker["failed"])
        if problem:
            problems.append(problem)
    for index, item in enumerate(parent_items):
        nextitem = parent_items[index + 1] if index + 1 < len(parent_items) else None
        item.config.hook.pytest_runtest_protocol(item=item, nextitem=nextitem)
    problems += account(seen)[:_MAX_PROBLEMS]
    if problems:
        in_flight = ["%s: %s" % (worker["name"], next(node for node in worker["nodeids"]
                                                      if not seen[node] or seen[node][-1][0] != "teardown"))
                     for worker in workers
                     if any(not seen[node] or seen[node][-1][0] != "teardown" for node in worker["nodeids"])]
        _fail(session, problems, work, in_flight)
    shutil.rmtree(work, ignore_errors=True)
    return True
