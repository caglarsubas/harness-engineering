"""Mock-only diagnostic regressions; no pytest invocation, subprocess or sleep."""
from contextlib import contextmanager
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


diagnostics = _load("_met_perf_021_mock_diagnostics", ROOT / "ci/pytest_diagnostics.py")
hooks = _load("_met_perf_021_mock_hooks", ROOT / "conftest.py")
NODE = "tests/test_example.py::test_example[PRIVATE_PARAMETER]"


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        self.value += 0.125
        return self.value


class Sink:
    def __init__(self):
        self.lines = []

    def __call__(self, line):
        self.lines.append(line)
        return len(line)


@pytest.fixture
def observed():
    sink, clock = Sink(), Clock()
    return diagnostics.Diagnostics(sink, clock), sink, clock


def _records(sink):
    return [json.loads(line[len(diagnostics.PREFIX):]) for line in sink.lines]


def _phase(state, phase="call", outcome="passed", *, node=NODE, xfail=False):
    state.start(node, phase)
    state.end(node, phase, outcome, 0.25, xfail=xfail)


def _wire(records):
    return b"".join(diagnostics.PREFIX + json.dumps(record).encode() + b"\n" for record in records)


def test_phase_order_outcomes_and_microseconds_are_recorded(observed):
    state, sink, _ = observed
    for phase in diagnostics.PHASES:
        _phase(state, phase)
    assert state.finish(0) == 0
    records = _records(sink)
    assert [record["event"] for record in records] == ["START", "END"] * 3 + ["SESSION_END"]
    assert [record["phase"] for record in records[:-1]] == ["setup", "setup", "call", "call", "teardown", "teardown"]
    assert [record["seq"] for record in records] == list(range(1, 8))
    assert all(record["durationUs"] == 250_000 for record in records if record["event"] == "END")
    assert records[0]["tUs"] == 0
    assert records[-1]["starts"] == records[-1]["ends"] == 3
    assert not records[-1]["incomplete"]


@pytest.mark.parametrize("node", [
    "tests/test_example.py::test_example[PRIVATE_PARAMETER]",
    "tests/test_example.py::Example::test_example[PRIVATE_PARAMETER::nested]",
    "/PRIVATE_DIRECTORY/test_example.py::test_example",
    "tests/../PRIVATE_DIRECTORY/test_example.py::test_example",
    "tests/test_example.py::test_example[PRIVATE_PARAMETER\nENV=PRIVATE_ENV]",
    "tests/test_example.py::test_example[\ud800]",
])
def test_labels_redact_parameters_absolute_paths_and_controls(node):
    identity = diagnostics.node_identity(node)
    assert identity["node"] == sha256(node.encode("utf-8", errors="surrogatepass")).hexdigest()
    assert "PRIVATE" not in identity["label"]
    assert "[" not in identity["label"] and "\n" not in identity["label"]
    assert len(identity["label"]) <= 70


def test_distinct_parameter_ids_have_distinct_complete_digests():
    first = diagnostics.node_identity("tests/test_x.py::test_x[first]")
    second = diagnostics.node_identity("tests/test_x.py::test_x[second]")
    assert first["label"] == second["label"]
    assert first["node"] != second["node"]


@pytest.mark.parametrize("node", [None, b"node", "", "x" * 65_537],
                         ids=["none", "bytes", "empty", "oversized"])
def test_invalid_node_latches_incomplete_without_rendering_input(observed, node):
    state, sink, _ = observed
    state.start(node, "call")
    assert state.finish(0) == 1
    assert "INVALID_NODE" in state.reasons
    assert all(len(line) <= diagnostics.MAX_RECORD_BYTES for line in sink.lines)


@pytest.mark.parametrize("phase", ["setup", "call", "teardown"])
def test_failed_phase_remains_failed_with_identity(observed, phase):
    state, sink, _ = observed
    _phase(state, phase, "failed")
    assert state.finish(1) == 1
    summary = diagnostics.summarize_nested(b"".join(sink.lines))
    assert summary["status"] == "COMPLETE"  # Complete diagnostics, NOT acceptance.
    assert summary["acceptance"] is False
    assert summary["failed"] == 1
    assert summary["failures"][0]["phase"] == phase
    assert summary["sessionEnd"]["exitCode"] == 1


@pytest.mark.parametrize("outcome,xfail", [("skipped", False), ("skipped", True), ("passed", True)])
def test_skip_xfail_xpass_reports_are_not_reinterpreted(observed, outcome, xfail):
    state, sink, _ = observed
    _phase(state, "call", outcome, xfail=xfail)
    assert state.finish(0) == 0
    end = _records(sink)[1]
    assert end["outcome"] == outcome and end["xfail"] is xfail


def test_unfinished_phase_is_not_synthesized_as_pass(observed):
    state, sink, _ = observed
    state.start(NODE, "call")
    before_finish = diagnostics.summarize_nested(b"".join(sink.lines))
    assert before_finish["latestActive"]["phase"] == "call"
    assert before_finish["ends"] == 0
    assert not before_finish["completionSeen"]
    assert state.finish(0) == 1


@pytest.mark.parametrize("prior_status", [1, 2, 3, 4, 5])
def test_incomplete_diagnostics_preserve_existing_nonzero_status(observed, prior_status):
    state, _, _ = observed
    state.start(NODE, "call")
    assert state.finish(prior_status) == prior_status


@pytest.mark.parametrize("failure", [OSError("PRIVATE_ERROR"), ValueError("PRIVATE_ERROR")])
def test_sink_failure_is_not_retried_or_rendered(failure):
    calls = []

    def sink(line):
        calls.append(line)
        raise failure

    state = diagnostics.Diagnostics(sink, Clock())
    _phase(state)
    assert state.finish(0) == 1
    assert len(calls) == 1
    assert state.reasons == {"SINK"}
    assert "PRIVATE_ERROR" not in repr(calls)


@pytest.mark.parametrize("written", [0, None, True, -1, 1])
def test_short_or_invalid_sink_write_is_incomplete(written):
    state = diagnostics.Diagnostics(lambda _: written, Clock())
    _phase(state)
    assert state.finish(0) == 1
    assert "SINK" in state.reasons


def test_interruption_is_not_swallowed_by_diagnostics():
    interruption = KeyboardInterrupt("PRIVATE_INTERRUPTION")

    def sink(_):
        raise interruption

    state = diagnostics.Diagnostics(sink, Clock())
    with pytest.raises(KeyboardInterrupt) as raised:
        state.start(NODE, "call")
    assert raised.value is interruption


@pytest.mark.parametrize("clock_value", [float("nan"), float("inf"), True, "PRIVATE_CLOCK"])
def test_bad_clock_latches_redacted_failure(clock_value):
    sink = Sink()
    state = diagnostics.Diagnostics(sink, lambda: clock_value)
    _phase(state)
    assert state.finish(0) == 1
    assert "CLOCK" in state.reasons
    assert b"PRIVATE_CLOCK" not in b"".join(sink.lines)


def test_backwards_clock_is_incomplete(observed):
    state, _, clock = observed
    state.start(NODE, "call")
    clock.value = -100
    state.end(NODE, "call", "passed", 0)
    assert state.finish(0) == 1


@pytest.mark.parametrize("duration", [float("nan"), -1, True, "PRIVATE_DURATION"])
def test_invalid_duration_cannot_be_published_as_success(observed, duration):
    state, sink, _ = observed
    state.start(NODE, "call")
    state.end(NODE, "call", "passed", duration)
    assert state.finish(0) == 1
    assert not any(record["event"] == "END" for record in _records(sink))


@pytest.mark.parametrize("kind", ["phase", "outcome", "mismatch", "overlap"])
def test_protocol_errors_latch_incomplete(observed, kind):
    state, _, _ = observed
    if kind == "phase":
        state.start(NODE, "PRIVATE_PHASE")
    elif kind == "outcome":
        state.start(NODE, "call")
        state.end(NODE, "call", "PRIVATE_OUTCOME", 0)
    elif kind == "mismatch":
        state.start(NODE, "call")
        state.end(NODE, "teardown", "passed", 0)
    else:
        state.start(NODE, "setup")
        state.start(NODE, "call")
    assert state.finish(0) == 1


@pytest.mark.parametrize("limit_kind", ["bytes", "events"])
def test_output_limits_reserve_explicit_error_and_terminal_records(limit_kind):
    sink = Sink()
    options = {"byte_limit": 3072} if limit_kind == "bytes" else {"event_limit": 5}
    state = diagnostics.Diagnostics(sink, Clock(), **options)
    for _ in range(30):
        _phase(state)
    assert state.finish(0) == 1
    records = _records(sink)
    assert sum(map(len, sink.lines)) <= state.byte_limit
    assert len(records) <= state.event_limit
    assert len([r for r in records if r["event"] == "ERROR"]) == 1
    assert records[-1]["event"] == "SESSION_END" and records[-1]["incomplete"]
    assert state.dropped > 0


@pytest.mark.parametrize("options", [
    {"byte_limit": 1024}, {"byte_limit": True},
    {"byte_limit": diagnostics.MAX_PROCESS_BYTES + 1},
    {"event_limit": 2}, {"event_limit": diagnostics.MAX_EVENTS + 1},
])
def test_limits_cannot_be_expanded_or_mistyped(options):
    with pytest.raises(ValueError):
        diagnostics.Diagnostics(Sink(), Clock(), **options)


def test_encoding_failure_is_latched_without_recursive_sink_retry(monkeypatch):
    sink = Sink()
    state = diagnostics.Diagnostics(sink, Clock())
    monkeypatch.setattr(diagnostics, "_dumps", lambda *a, **k: (_ for _ in ()).throw(ValueError("PRIVATE_ENCODER")))
    _phase(state)
    assert state.finish(0) == 1
    assert not sink.lines and "ENCODING" in state.reasons


def test_nested_summary_none_or_ordinary_stderr_is_not_success():
    absent = diagnostics.summarize_nested(None)
    assert absent["status"] == "ABSENT" and not absent["available"]
    unknown = diagnostics.summarize_nested(b"PRIVATE_RAW_STDERR\n")
    assert unknown["status"] == "INCOMPLETE" and unknown["records"] == 0
    assert "PRIVATE_RAW_STDERR" not in json.dumps(unknown)


def test_nested_summary_accepts_text_without_claiming_live_delivery(observed):
    state, sink, _ = observed
    _phase(state)
    state.finish(0)
    summary = diagnostics.summarize_nested(b"".join(sink.lines).decode())
    assert summary["status"] == "COMPLETE" and summary["completionSeen"]
    assert summary["buffered"] is True and summary["acceptance"] is False


def test_nested_failure_ledger_keeps_failures_between_head_and_tail(observed):
    state, sink, _ = observed
    for _ in range(200):
        _phase(state)
    _phase(state, outcome="failed")
    for _ in range(200):
        _phase(state)
    state.finish(1)
    raw = b"".join(sink.lines)
    failure_marker = b'"outcome":"failed"'
    failure_offset = raw.index(failure_marker)
    assert 32_768 < failure_offset < len(raw) - 32_768
    assert failure_marker not in raw[:32_768] + raw[-32_768:]
    summary = diagnostics.summarize_nested(raw)
    assert summary["failed"] == 1 and len(summary["failures"]) == 1
    assert summary["latestActive"] is None


def test_nested_failure_detail_limit_has_exact_omitted_count(observed):
    state, sink, _ = observed
    for _ in range(19):
        _phase(state, outcome="failed")
    state.finish(1)
    summary = diagnostics.summarize_nested(b"".join(sink.lines))
    assert summary["failed"] == 19 and len(summary["failures"]) == 16
    assert summary["failuresOmitted"] == 3
    assert summary["status"] == "INCOMPLETE"
    assert len(json.dumps(summary).encode()) < 16 * 1024


@pytest.mark.parametrize("bad", [
    b'{"v":1,"v":1}', b'{"PRIVATE_EXCEPTION":',
    b'{"v":true,"seq":1,"event":"ERROR","reason":"SINK","incomplete":true}',
    b'{"v":1,"seq":1,"event":"ERROR","reason":["PRIVATE_REASON"],"incomplete":true}',
    b"x" * 1200,
])
def test_malformed_nested_records_are_bounded_and_redacted(bad):
    summary = diagnostics.summarize_nested(diagnostics.PREFIX + bad + b"\n")
    assert summary["malformed"] == 1 and summary["status"] == "INCOMPLETE"
    assert "PRIVATE" not in json.dumps(summary)


def test_partial_nested_line_is_explicitly_incomplete(observed):
    state, sink, _ = observed
    state.start(NODE, "call")
    summary = diagnostics.summarize_nested(sink.lines[0][:-1])
    assert "PARTIAL_LINE" in summary["incompleteReasons"]
    assert not summary["completionSeen"]


@pytest.mark.parametrize("tamper", ["sequence", "time", "count", "after", "unknown"])
def test_nested_order_counts_and_closed_schema_are_verified(observed, tamper):
    state, sink, _ = observed
    _phase(state)
    state.finish(0)
    records = _records(sink)
    if tamper == "sequence":
        records[1]["seq"] = 8
    elif tamper == "time":
        records[1]["tUs"] = records[2]["tUs"] + 1
    elif tamper == "count":
        records[2]["ends"] = 100
    elif tamper == "after":
        records.append(records[0])
    else:
        records[0]["PRIVATE_EXTRA"] = "PRIVATE_VALUE"
    summary = diagnostics.summarize_nested(_wire(records))
    assert summary["status"] == "INCOMPLETE"
    assert "PRIVATE" not in json.dumps(summary)


def test_nested_scan_and_line_limits_are_explicit(monkeypatch, observed):
    state, sink, _ = observed
    _phase(state)
    state.finish(0)
    raw = b"".join(sink.lines)
    monkeypatch.setattr(diagnostics, "MAX_SCAN_BYTES", len(raw) - 1)
    summary = diagnostics.summarize_nested(raw)
    assert summary["inputTruncatedBytes"] > 0
    assert "INPUT_LIMIT" in summary["incompleteReasons"]
    monkeypatch.setattr(diagnostics, "MAX_SCAN_BYTES", len(raw) + 1)
    monkeypatch.setattr(diagnostics, "MAX_SCAN_LINES", 1)
    summary = diagnostics.summarize_nested(raw)
    assert "SCAN_LIMIT" in summary["incompleteReasons"]


class CaptureManager:
    def __init__(self):
        self.disabled = False
        self.entries = 0

    @contextmanager
    def global_and_fixture_disabled(self):
        assert not self.disabled
        self.disabled = True
        self.entries += 1
        try:
            yield
        finally:
            self.disabled = False


def _configured(monkeypatch, *, manager=True, writer=None):
    capture = CaptureManager() if manager else None
    lines = []

    def write(fd, value):
        assert fd == 2 and capture.disabled
        if writer is not None:
            return writer(value, lines)
        lines.append(value)
        return len(value)

    monkeypatch.setattr(hooks, "_write", write)
    monkeypatch.setattr(hooks, "_monotonic", Clock())
    config = SimpleNamespace(pluginmanager=SimpleNamespace(getplugin=lambda name: capture))
    hooks.pytest_configure(config)
    return config, capture, lines


def test_root_sink_completes_partial_writes_with_capture_restored(monkeypatch):
    calls = []

    def partial(value, lines):
        chunk = value[:7]
        calls.append(len(value))
        lines.append(chunk)
        return len(chunk)

    config, capture, lines = _configured(monkeypatch, writer=partial)
    state = getattr(config, hooks._STATE_KEY)
    _phase(state)
    assert state.finish(0) == 0
    assert len(calls) > 3 and capture.entries == 3
    assert not capture.disabled
    summary = diagnostics.summarize_nested(b"".join(lines))
    assert summary["status"] == "COMPLETE" and summary["records"] == 3


def test_root_sink_partial_then_error_is_not_retried_and_restores_capture(monkeypatch):
    calls = []

    def partial_then_error(value, lines):
        calls.append(len(value))
        if len(calls) == 1:
            lines.append(value[:7])
            return 7
        raise OSError("PRIVATE_WRITE_ERROR")

    config, capture, lines = _configured(monkeypatch, writer=partial_then_error)
    state = getattr(config, hooks._STATE_KEY)
    _phase(state)
    assert state.finish(0) == 1
    assert len(calls) == 2 and capture.entries == 1
    assert not capture.disabled and state.reasons == {"SINK"}
    assert b"PRIVATE_WRITE_ERROR" not in b"".join(lines)
    summary = diagnostics.summarize_nested(b"".join(lines))
    assert summary["status"] == "INCOMPLETE" and not summary["completionSeen"]


@pytest.mark.parametrize("result", [0, -1, None, True, "oversized"])
def test_root_sink_rejects_invalid_or_oversized_write_returns(monkeypatch, result):
    calls = []

    def invalid(value, lines):
        calls.append(len(value))
        return len(value) + 1 if result == "oversized" else result

    config, capture, lines = _configured(monkeypatch, writer=invalid)
    state = getattr(config, hooks._STATE_KEY)
    _phase(state)
    assert state.finish(0) == 1
    assert len(calls) == 1 and capture.entries == 1
    assert not capture.disabled and not lines
    assert state.reasons == {"SINK"}


def _complete(generator, value=None):
    with pytest.raises(StopIteration) as completed:
        generator.send(value)
    return completed.value.value


@pytest.mark.parametrize("phase", ["setup", "call", "teardown"])
def test_hook_wrappers_preserve_results_and_use_disabled_capture(monkeypatch, phase):
    config, capture, lines = _configured(monkeypatch)
    item = SimpleNamespace(config=config, nodeid=NODE)
    wrapper = getattr(hooks, "pytest_runtest_" + phase)(item)
    next(wrapper)
    assert not capture.disabled and lines
    sentinel = object()
    assert _complete(wrapper, sentinel) is sentinel
    report = SimpleNamespace(when=phase, outcome="passed", duration=0.1)
    observer = hooks.pytest_runtest_makereport(item, None)
    next(observer)
    assert _complete(observer, report) is report
    assert capture.entries == 2 and not capture.disabled


def test_phase_hook_preserves_same_original_interruption(monkeypatch):
    config, capture, _ = _configured(monkeypatch)
    wrapper = hooks.pytest_runtest_call(SimpleNamespace(config=config, nodeid=NODE))
    next(wrapper)
    original = KeyboardInterrupt("PRIVATE_INTERRUPTION")
    with pytest.raises(KeyboardInterrupt) as raised:
        wrapper.throw(original)
    assert raised.value is original and not capture.disabled


def test_report_hook_does_not_read_exception_or_xfail_reason(monkeypatch):
    config, _, lines = _configured(monkeypatch)
    item = SimpleNamespace(config=config, nodeid=NODE)
    wrapper = hooks.pytest_runtest_call(item)
    next(wrapper)
    _complete(wrapper)
    report = SimpleNamespace(when="call", outcome="skipped", duration=0.1,
                             wasxfail="PRIVATE_REASON", longrepr="PRIVATE_EXCEPTION")
    observer = hooks.pytest_runtest_makereport(item, SimpleNamespace(excinfo="PRIVATE_EXCEPTION"))
    next(observer)
    assert _complete(observer, report) is report
    assert b"PRIVATE" not in b"".join(lines)


def test_bound_hook_dependencies_survive_later_module_monkeypatch(monkeypatch):
    config, _, lines = _configured(monkeypatch)
    monkeypatch.setattr(hooks, "_write", lambda *a: pytest.fail("bound sink changed"))
    monkeypatch.setattr(hooks, "_monotonic", lambda: pytest.fail("bound clock changed"))
    state = getattr(config, hooks._STATE_KEY)
    _phase(state)
    assert state.finish(0) == 0 and lines


def test_missing_capture_manager_cannot_allow_success(monkeypatch):
    config, _, _ = _configured(monkeypatch, manager=False)
    state = getattr(config, hooks._STATE_KEY)
    _phase(state)
    session = SimpleNamespace(config=config, exitstatus=0)
    wrapper = hooks.pytest_sessionfinish(session, 0)
    next(wrapper)
    assert _complete(wrapper, "original-result") == "original-result"
    assert session.exitstatus == 1


def test_session_wrapper_preserves_prior_failure_and_return_value(monkeypatch):
    config, _, _ = _configured(monkeypatch)
    state = getattr(config, hooks._STATE_KEY)
    state.start(NODE, "call")
    session = SimpleNamespace(config=config, exitstatus=2)
    wrapper = hooks.pytest_sessionfinish(session, 2)
    next(wrapper)
    sentinel = object()
    assert _complete(wrapper, sentinel) is sentinel
    assert session.exitstatus == 2
