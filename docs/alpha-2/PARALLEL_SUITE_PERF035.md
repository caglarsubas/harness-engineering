# Alpha 2 — parallel suite and suite reuse for verify headroom (PERF-035, MET-PERF-035)

> Current-status page for the verify-time fix. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet
> status.

MET-ENFORCE-016's first verify timed out at 902 s (63/64). Its quiet re-verify took 784 s and merged as main 58e6c25,
past the owner's 750 s PERF floor. The outer pytest (acceptance argv 63) takes about 620 s of a verify. It is spread
evenly over about 100 test files, and every packet adds to it. Owner decisions (via the lane monitor):
- run that suite on worker processes inside the unchanged argv;
- include the reviewed suite-reuse cuts;
- keep every validator, authority, freshness property and refusal unchanged.

- **Parallel suite.** `ci/parallel_suite.py` is loaded by the pytest `addopts` in `pyproject.toml`.
  - Only an invocation whose own arguments are all file or directory paths runs in parallel, as acceptance argv 63 does.
    An option, an `@` argument file or a node ID keeps pytest's serial loop, because workers re-read only the ini file
    and the environment. Interpreter flags (`-W`, `-X`, `-B`, ...) are passed on to every worker.
  - The parent collects as usual and assigns whole test files to 4 worker processes, by the pinned weights in
    `ci/parallel_suite_weights.json`.
  - Each worker runs `python -m pytest -p ci.parallel_suite <its files>` in the same checkout and sandbox. It streams
    pytest's own serialized reports, and the warnings recorded while its tests run, to a private file.
  - The parent restores each report's tuple fields (JSON has none) and replays it through its own hooks: terminal
    reporter, diagnostics and every observing plugin. It re-emits each warning, so the summary line, the diagnostics
    stream and the in-session predecessor recorder see what a serial run shows. One exception: a warning that depends on
    process state, such as a cached warn or a ResourceWarning's tracemalloc hint, can differ.
  - Worker output never reaches the parent's output.
  - `PARENT_NODES` run last, in the parent, after every worker has reported:
    - the in-session predecessor proof
      (`tests/linux_runner/test_build_and_predecessors.py::test_full_predecessor_suites_and_validators_remain_green`),
      which reads the whole session's results;
    - the two tests that print evidence lines past output capture (`LINUX_KIT_SOURCE_PACKAGE=`,
      `LINUX_NATIVE_INTEGRATION=`), so that those lines reach the outer output.
    Two AST guards keep this complete. One lists every test, conftest, helper or hook implementation that touches
    session-level state. The other requires `PARENT_NODES` to be exactly the live-output writers plus the proof.
  - Fail closed. The session fails unless all of the following hold:
    - each worker collected exactly its assigned node list;
    - every report and warning came from the worker that owns its node;
    - every node reported exactly one setup and one teardown, and a call if and only if its setup passed;
    - every record decoded;
    - every worker exited 0, or 1 with a failed report of its own, within 600 s.
  - A failure names the problems (worker-supplied text as repr) and each worker's in-flight node, and adds a
    "parallel-suite-incomplete" count to the final summary line; an interruption adds "parallel-suite-interrupted". The
    exit code is the authority.
  - The accounting guards against crashes and partial or cross-worker streams. It does not guard against forgery from
    inside a test: test code is trusted exactly as in a serial run.
  - SIGTERM or SIGHUP to the parent kills its workers, unless the parent inherited that signal as ignored. A worker
    whose parent dies exits. A passing session removes its work directory.
  - Every non-worker session marks its descendants serial, so a pytest started by any test runs serially, provided it
    inherits the environment. An in-process `pytest.main` inside a worker fails closed.
  - Each worker holds a different set of co-resident test files than a serial run, which matters for process-wide
    caches and `sys.path`. The serial-vs-parallel comparison found identical outcomes.
  - A later packet can return to the serial loop by setting `WORKERS = 1`.
- **Suite reuse.** Two credential tests take the reviewed test-local cuts of the withdrawn MET-PERF-033. Four input
  fixtures read and parse once per module, and give each test its own deep copy.

`scripts/validate_parallel_suite.py` pins the parallel-suite plugin, its weights and its loader as whole files, and
every changed test region by its exact whole lines. Its test checks the following:
- the pins and the constants;
- the accounting against forged and partial phase streams;
- scratch-project runs: pass, fail, a worker that exits early, and nested serial;
- that the predecessor proof is the only test that reads the whole session.

Measured on the author's Mac, not acceptance (prototype on main 58e6c25, argv 63):
- serial: 626.7 s;
- 4 workers: 200.7 s;
- 6 workers: 162.5 s.
Both parallel runs matched the serial run node for node: 23,871 phase records over 7,957 nodes. The predecessor proof
ran in its in-session mode.

A first build also turned sixteen parametrized tamper tests into sharing loops. Measured per test, those loops were
slower: 77.4 s against 68.4 s before. That part was dropped before review.
