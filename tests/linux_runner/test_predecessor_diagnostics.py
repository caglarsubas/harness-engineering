"""Mock-only observation tests: no subprocess, sleep, native probe or retry."""
from contextlib import contextmanager
import json
import subprocess
from types import SimpleNamespace

import pytest

import test_build_and_predecessors as predecessor


class _Capture:
    def __init__(self):
        self.disabled_now = False

    @contextmanager
    def disabled(self):
        assert not self.disabled_now
        self.disabled_now = True
        try:
            yield
        finally:
            self.disabled_now = False


class _MockReplay:
    def __init__(self, monkeypatch):
        self.capture = _Capture()
        self.calls = []
        self.lines = []
        self.events = []
        self.timeline = []
        self.actions = {}
        self.summary_inputs = []
        self.summary_error = None
        self.summary = {"status": "COMPLETE", "completionSeen": True,
                        "sessionEnd": {"exitCode": 0}, "failed": 0,
                        "acceptance": False, "buffered": True}
        self.fail_print_event = None
        self.output_error = OSError("synthetic diagnostic sink failure")
        self.clock = 100.0
        self.environ = {"LOCAL_FIXTURE": "UNPRINTED_ENVIRONMENT_VALUE", "PYTHONDONTWRITEBYTECODE": "0"}

        def monotonic():
            current = self.clock
            self.clock += 1.0
            return current

        def printed(value, *, flush=False):
            assert self.capture.disabled_now, "diagnostics must bypass delayed pytest capture"
            assert flush is True, "diagnostics must be immediately flushed"
            assert isinstance(value, str)
            if value.startswith("PREDECESSOR_EVENT="):
                record = json.loads(value.removeprefix("PREDECESSOR_EVENT="))
                if record["event"] == self.fail_print_event:
                    raise self.output_error
                self.events.append(record)
                self.timeline.append(("print", record["event"], record["ordinal"]))
            self.lines.append(value)

        def run(argv, **options):
            ordinal = len(self.calls) + 1
            assert self.events[-1]["event"] == "START"
            assert self.events[-1]["ordinal"] == ordinal
            assert self.capture.disabled_now is False
            self.calls.append((list(argv), options))
            self.timeline.append(("run", ordinal))
            action = self.actions.get(ordinal)
            if isinstance(action, BaseException):
                raise action
            if action is not None:
                return action
            return subprocess.CompletedProcess(argv, 0, f"full stdout {ordinal}", "")

        # Replace only references in the observed module. No global subprocess,
        # clock, environment, stdout or pytest capture hook is replaced.
        monkeypatch.setattr(predecessor, "subprocess", SimpleNamespace(
            run=run, TimeoutExpired=subprocess.TimeoutExpired,
        ))
        monkeypatch.setattr(predecessor, "time", SimpleNamespace(monotonic=monotonic))
        monkeypatch.setattr(predecessor, "os", SimpleNamespace(environ=self.environ))
        monkeypatch.setattr(predecessor, "print", printed, raising=False)

        def summarize(value):
            self.summary_inputs.append(value)
            if self.summary_error is not None:
                raise self.summary_error
            return dict(self.summary)

        # Keep observation-unit fixtures subprocess-free. The pure stream
        # parser and root hooks have separate mock-only regression coverage.
        monkeypatch.setattr(predecessor, "summarize_nested", summarize)

    def run(self):
        predecessor.test_full_predecessor_suites_and_validators_remain_green(self.capture)


@pytest.fixture
def replay(monkeypatch):
    return _MockReplay(monkeypatch)


def _expected_argv():
    return [
        [predecessor.sys.executable, "-m", "pytest", "-rs", "tests", "--ignore=tests/linux_runner",
         "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"],
        [predecessor.sys.executable, "scripts/validate_readiness.py"],
        [predecessor.sys.executable, "scripts/validate_reuse.py"],
        [predecessor.sys.executable, "scripts/validate_alpha2_readiness.py"],
        [predecessor.sys.executable, "scripts/validate_readiness_repairs.py"],
        [predecessor.sys.executable, "scripts/validate_linux_readiness.py"],
        [predecessor.sys.executable, "scripts/zero_bill_scan.py", "."],
    ]


def test_diagnostics_preserve_exact_seven_commands_flags_and_start_order(replay):
    replay.run()
    assert [argv for argv, _ in replay.calls] == _expected_argv()
    expected_options = {
        "cwd": predecessor.ROOT,
        "env": {**replay.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        "capture_output": True, "text": True, "timeout": 420, "close_fds": True,
    }
    assert all(options == expected_options for _, options in replay.calls)
    assert replay.timeline == [event for ordinal in range(1, 8) for event in (
        ("print", "START", ordinal), ("run", ordinal), ("print", "END", ordinal),
    )]
    labels = ["full-predecessor-suite", "readiness", "reuse", "alpha2-readiness",
              "readiness-repairs", "linux-readiness", "zero-bill-scan"]
    for ordinal, label in enumerate(labels, start=1):
        start, end = replay.events[(ordinal - 1) * 2:ordinal * 2]
        assert start == {"ordinal": ordinal, "total": 7, "label": label,
                         "event": "START", "timeoutSeconds": 420}
        assert end == {"ordinal": ordinal, "total": 7, "label": label,
                       "event": "END", "returncode": 0, "elapsedSeconds": 1.0,
                       **({"pytestDiagnostics": replay.summary} if ordinal == 1 else {})}
    retained = [line for line in replay.lines if line.startswith("PREDECESSOR_ARGV=")]
    assert [json.loads(line.removeprefix("PREDECESSOR_ARGV=")) for line in retained] == [argv[1:] for argv in _expected_argv()]
    assert "UNPRINTED_ENVIRONMENT_VALUE" not in "\n".join(replay.lines)
    assert replay.summary_inputs == [""]


def test_first_nested_pytest_retains_structured_summary_on_timeout(replay):
    buffered = b"unprinted synthetic stderr input"
    failure = subprocess.TimeoutExpired(["UNPRINTED_EXCEPTION_COMMAND"], 420,
                                         output=b"partial", stderr=buffered)
    replay.actions[1] = failure
    replay.summary = {"status": "INCOMPLETE", "buffered": True,
                      "acceptance": False, "latestActive": {"phase": "call"},
                      "failures": [{"node": "a" * 64, "phase": "setup"}]}
    with pytest.raises(subprocess.TimeoutExpired) as refused:
        replay.run()
    assert refused.value is failure
    assert len(replay.calls) == 1
    assert replay.summary_inputs == [buffered]
    assert replay.events[-1]["pytestDiagnostics"] == replay.summary


@pytest.mark.parametrize("kind", ["incomplete", "absent", "error", "wrong_exit", "failure_count"])
def test_successful_child_cannot_hide_incomplete_required_diagnostics(replay, kind):
    if kind == "error":
        replay.summary_error = ValueError("UNPRINTED_SUMMARY_ERROR")
    elif kind == "wrong_exit":
        replay.summary["sessionEnd"] = {"exitCode": 1}
    elif kind == "failure_count":
        replay.summary["failed"] = 1
    else:
        replay.summary["status"] = kind.upper()
    with pytest.raises(AssertionError, match="predecessor diagnostics incomplete"):
        replay.run()
    assert len(replay.calls) == 1
    assert "UNPRINTED_SUMMARY_ERROR" not in "\n".join(replay.lines)


def test_summary_error_preserves_nonzero_child_assertion(replay):
    replay.actions[1] = subprocess.CompletedProcess(_expected_argv()[0], 3, "out", "err")
    replay.summary_error = ValueError("UNPRINTED_SUMMARY_ERROR")
    with pytest.raises(AssertionError) as refused:
        replay.run()
    assert refused.value.args == ("outerr",)
    assert len(replay.calls) == 1
    assert replay.events[-1]["pytestDiagnostics"]["status"] == "INCOMPLETE"


def test_summary_error_never_replaces_timeout_identity(replay):
    failure = subprocess.TimeoutExpired(["UNPRINTED_EXCEPTION_COMMAND"], 420, stderr=b"partial")
    replay.actions[1] = failure
    replay.summary_error = ValueError("UNPRINTED_SUMMARY_ERROR")
    with pytest.raises(subprocess.TimeoutExpired) as refused:
        replay.run()
    assert refused.value is failure
    assert len(replay.calls) == 1
    record = replay.events[-1]
    assert record["event"] == "EXCEPTION"
    assert record["stderr"]["head"] == "partial"
    assert record["pytestDiagnostics"]["incompleteReasons"] == ["SUMMARY_ERROR"]


def test_structured_stderr_cannot_expand_failed_assertion_to_full_stream(replay):
    # More than head+tail; the unique middle marker must not be replayed by
    # pytest's assertion renderer. No actual pytest/subprocess is invoked.
    stderr = ("PYTEST_DIAGNOSTIC=" + "h" * 65_536
              + "UNREPLAYED_MIDDLE_RECORD" + "t" * 65_536)
    replay.actions[1] = subprocess.CompletedProcess(_expected_argv()[0], 17, "out", stderr)
    with pytest.raises(AssertionError) as refused:
        replay.run()
    message, = refused.value.args
    assert message.startswith("predecessor failed; bounded output=")
    assert "UNREPLAYED_MIDDLE_RECORD" not in message
    assert len(message.encode()) < 2 * predecessor.PREDECESSOR_OUTPUT_LIMIT + 2048
    assert len(replay.calls) == 1
    assert replay.events[-1]["returncode"] == 17


def test_unstructured_stderr_keeps_original_assertion_payload():
    assert predecessor._predecessor_failure_message("stdout", "stderr") == "stdoutstderr"


def test_success_preserves_full_untruncated_stdout(replay):
    stdout = "success output " + "x" * (predecessor.PREDECESSOR_OUTPUT_LIMIT + 17)
    replay.actions[1] = subprocess.CompletedProcess(_expected_argv()[0], 0, stdout, "")
    replay.run()
    assert stdout in replay.lines
    assert len(replay.calls) == 7
    assert "stdout" not in replay.events[1]


def test_nonzero_retains_bounded_failure_output_and_original_assertion(replay):
    stdout = "failed stdout " + "x" * (predecessor.PREDECESSOR_OUTPUT_LIMIT + 17)
    stderr = "failure stderr"
    replay.actions[3] = subprocess.CompletedProcess(_expected_argv()[2], 17, stdout, stderr)
    with pytest.raises(AssertionError) as refused:
        replay.run()
    assert refused.value.args == (stdout + stderr,)
    assert len(replay.calls) == 3
    assert [argv for argv, _ in replay.calls] == _expected_argv()[:3]
    outcome = replay.events[-1]
    assert outcome["event"] == "END" and outcome["returncode"] == 17
    assert outcome["elapsedSeconds"] == 1.0
    assert outcome["stdout"]["retainedBytes"] == predecessor.PREDECESSOR_OUTPUT_LIMIT
    assert outcome["stdout"]["truncatedBytes"] > 0
    assert outcome["stderr"]["head"] == stderr
    assert stdout not in replay.lines


@pytest.mark.parametrize("output_kind", ["bytes", "text", "none", "truncated"])
def test_timeout_retains_bounded_partial_output_and_reraises_same_exception(replay, output_kind):
    if output_kind == "bytes":
        stdout, stderr = b"partial \xff stdout", b"partial stderr"
    elif output_kind == "text":
        stdout, stderr = "partial text stdout", "partial text stderr"
    elif output_kind == "none":
        stdout = stderr = None
    else:
        stdout = b"h" * predecessor.PREDECESSOR_OUTPUT_LIMIT + b"t" * 37
        stderr = b"e" * (predecessor.PREDECESSOR_OUTPUT_LIMIT + 23)
    timeout = subprocess.TimeoutExpired(["UNPRINTED_EXCEPTION_COMMAND"], 420,
                                        output=stdout, stderr=stderr)
    replay.actions[1] = timeout
    with pytest.raises(subprocess.TimeoutExpired) as refused:
        replay.run()
    assert refused.value is timeout
    assert len(replay.calls) == 1
    outcome = replay.events[-1]
    assert outcome["event"] == "EXCEPTION" and outcome["failureType"] == "TimeoutExpired"
    assert outcome["elapsedSeconds"] == 1.0
    for stream, expected in (("stdout", stdout), ("stderr", stderr)):
        retained = outcome[stream]
        assert retained["retainedBytes"] <= predecessor.PREDECESSOR_OUTPUT_LIMIT
        assert retained["capturedBytes"] == retained["retainedBytes"] + retained["truncatedBytes"]
        assert retained["available"] is (expected is not None)
        if expected is None:
            assert retained["head"] == retained["tail"] == ""
            assert retained["capturedBytes"] == 0
        elif output_kind == "truncated":
            assert retained["truncatedBytes"] > 0
            assert retained["tail"]
        else:
            decoded = expected.decode("utf-8", errors="replace") if isinstance(expected, bytes) else expected
            assert retained["head"] == decoded
            assert retained["tail"] == ""
    assert "UNPRINTED_EXCEPTION_COMMAND" not in "\n".join(replay.lines)
    assert "UNPRINTED_ENVIRONMENT_VALUE" not in "\n".join(replay.lines)


@pytest.mark.parametrize("kind", ["oserror", "interruption"])
def test_generic_exception_publishes_only_type_and_preserves_identity(replay, kind):
    failure = (OSError("UNPRINTED_EXCEPTION_DETAIL") if kind == "oserror"
               else KeyboardInterrupt("UNPRINTED_EXCEPTION_DETAIL"))
    replay.actions[1] = failure
    with pytest.raises(type(failure)) as refused:
        replay.run()
    assert refused.value is failure
    assert len(replay.calls) == 1
    assert replay.events[-1] == {
        "ordinal": 1, "total": 7, "label": "full-predecessor-suite", "event": "EXCEPTION",
        "failureType": type(failure).__name__, "elapsedSeconds": 1.0,
    }
    assert "UNPRINTED_EXCEPTION_DETAIL" not in "\n".join(replay.lines)


@pytest.mark.parametrize("kind", ["timeout", "oserror", "interruption"])
def test_diagnostic_sink_failure_cannot_replace_original_exception(replay, kind):
    if kind == "timeout":
        failure = subprocess.TimeoutExpired(["UNPRINTED_EXCEPTION_COMMAND"], 420, output=b"partial")
    elif kind == "oserror":
        failure = OSError("UNPRINTED_EXCEPTION_DETAIL")
    else:
        failure = KeyboardInterrupt("UNPRINTED_EXCEPTION_DETAIL")
    replay.actions[1] = failure
    replay.fail_print_event = "EXCEPTION"
    with pytest.raises(type(failure)) as refused:
        replay.run()
    assert refused.value is failure
    assert len(replay.calls) == 1
    assert [record["event"] for record in replay.events] == ["START"]
    assert replay.capture.disabled_now is False


def test_diagnostic_sink_failure_cannot_replace_nonzero_assertion(replay):
    replay.actions[1] = subprocess.CompletedProcess(_expected_argv()[0], 3, "out", "err")
    replay.fail_print_event = "END"
    with pytest.raises(AssertionError) as refused:
        replay.run()
    assert refused.value.args == ("outerr",)
    assert len(replay.calls) == 1
    assert [record["event"] for record in replay.events] == ["START"]


def test_start_sink_failure_launches_no_command(replay):
    replay.fail_print_event = "START"
    with pytest.raises(OSError) as refused:
        replay.run()
    assert refused.value is replay.output_error
    assert replay.calls == []


@pytest.mark.parametrize("size", [0, 1, 65_536, 65_537])
def test_output_retention_limit_has_exact_byte_accounting(size):
    raw = b"h" * size
    retained = predecessor._bounded_predecessor_output(raw)
    assert retained["available"] is True
    assert retained["capturedBytes"] == size
    assert retained["retainedBytes"] == min(size, predecessor.PREDECESSOR_OUTPUT_LIMIT)
    assert retained["truncatedBytes"] == max(0, size - predecessor.PREDECESSOR_OUTPUT_LIMIT)
    assert retained["head"] + retained["tail"] == "h" * retained["retainedBytes"]
