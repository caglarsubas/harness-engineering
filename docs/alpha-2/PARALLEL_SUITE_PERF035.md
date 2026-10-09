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
  - The parent collects as usual and assigns whole test files to 4 worker processes, by the pinned weights in
    `ci/parallel_suite_weights.json`.
  - Each worker runs `python -m pytest <its files>` in the same checkout and sandbox, and streams pytest's own
    serialized reports to a private file.
  - The parent replays every report through its own hooks: terminal reporter, diagnostics and every observing plugin.
    So the summary line, the diagnostics stream and the in-session predecessor recorder see every test.
  - The in-session predecessor proof (`tests/linux_runner/test_build_and_predecessors.py::test_full_predecessor_suites_and_validators_remain_green`)
    reads the whole session's results, so it runs last, in the parent, after every worker has reported.
  - Fail closed. Each worker must collect exactly its assigned node list. Every node needs exactly one setup and one
    teardown report, and a call report if and only if its setup passed. Every worker must exit 0, or 1 with a failed
    report of its own. Otherwise the session fails.
  - Every pytest started by a test runs serially.
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
