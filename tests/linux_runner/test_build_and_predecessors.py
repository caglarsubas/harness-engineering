"""Deterministic kit packaging plus the entire unchanged predecessor baseline."""
import ast
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import zipfile

import pytest

from ci.pytest_diagnostics import summarize_nested
from build import SOURCES, build, candidate_bytes
from common import Refused, digest

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "ci/linux-runner"
PREDECESSOR_OUTPUT_LIMIT = 65_536


def _bounded_predecessor_output(value):
    if value is None:
        return {"available": False, "capturedBytes": 0, "retainedBytes": 0,
                "truncatedBytes": 0, "head": "", "tail": ""}
    raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
    if len(raw) <= PREDECESSOR_OUTPUT_LIMIT:
        head, tail = raw, b""
    else:
        half = PREDECESSOR_OUTPUT_LIMIT // 2
        head, tail = raw[:half], raw[-half:]
    retained = len(head) + len(tail)
    return {"available": True, "capturedBytes": len(raw), "retainedBytes": retained,
            "truncatedBytes": len(raw) - retained,
            "head": head.decode("utf-8", errors="replace"),
            "tail": tail.decode("utf-8", errors="replace")}


def _publish_predecessor_record(capsys, record):
    with capsys.disabled():
        print("PREDECESSOR_EVENT=" + json.dumps(record, sort_keys=True), flush=True)


def _predecessor_summary(stderr):
    try:
        return summarize_nested(stderr)
    except Exception:
        # Never discard the existing bounded timeout record or expose a parser
        # exception message. Successful children must still meet completeness.
        return {"status": "INCOMPLETE", "acceptance": False, "buffered": True,
                "incompleteReasons": ["SUMMARY_ERROR"]}


def _predecessor_failure_message(stdout, stderr):
    if "PYTEST_DIAGNOSTIC=" not in stderr:
        # Preserve legacy assertion payloads when no new stream is present.
        return stdout + stderr
    # Pytest would otherwise repeat up to 20MiB of nested structured stderr
    # alongside the outer stream when rendering this failed assertion. Keep
    # the failure and bounded head/tail, never a full diagnostic-stream replay.
    return "predecessor failed; bounded output=" + json.dumps({
        "stdout": _bounded_predecessor_output(stdout),
        "stderr": _bounded_predecessor_output(stderr),
    }, sort_keys=True)


def _publish_predecessor_result(capsys, record, argv, result):
    with capsys.disabled():
        print("PREDECESSOR_EVENT=" + json.dumps(record, sort_keys=True), flush=True)
        if result.returncode == 0:
            # Preserve the existing full successful stdout publication.
            print("PREDECESSOR_ARGV=" + json.dumps(argv[1:]), flush=True)
            print(result.stdout, flush=True)


def test_byte_identical_package_and_source_inventory(tmp_path, capsys):
    root = tmp_path.resolve()
    first = build(KIT, root / "first")
    second = build(KIT, root / "second")
    a = (root / "first/harness-offline-launch.candidate").read_bytes()
    b = (root / "second/harness-offline-launch.candidate").read_bytes()
    assert a == b and first == second
    assert (root / "first/inventory.json").read_bytes() == (root / "second/inventory.json").read_bytes()
    assert first["artifact"]["sha256"] == digest(a)
    assert first["evidence"] == "SOURCE_PACKAGE_ONLY" and first["installed"] is False
    assert first["nativeLinuxAcceptance"] is False
    with capsys.disabled():
        print("LINUX_KIT_SOURCE_PACKAGE=" + json.dumps(first, sort_keys=True), flush=True)
    with zipfile.ZipFile(io.BytesIO(a)) as z:
        assert z.namelist() == sorted([*SOURCES, "__main__.py"])
        for name in z.namelist():
            assert digest(z.read(name)) == first["sourceSha256"][name]
            assert z.getinfo(name).date_time == (1980, 1, 1, 0, 0, 0)
            compile(z.read(name), name, "exec")


def test_packaging_changes_when_candidate_changes(tmp_path):
    for name in SOURCES:
        (tmp_path / name).write_bytes((KIT / name).read_bytes())
    before, _ = candidate_bytes(tmp_path)
    with (tmp_path / "common.py").open("ab") as file:
        file.write(b"\n# synthetic mutation\n")
    assert candidate_bytes(tmp_path)[0] != before


def test_builder_will_not_overwrite_or_install(tmp_path):
    with pytest.raises(Refused):
        build(KIT, tmp_path.resolve())
    with pytest.raises((Refused, OSError)):
        build(KIT, Path("/opt/planeon/bin/new-candidate"))


def test_builder_refuses_root(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(Refused):
        build(KIT, tmp_path / "no-root")


def test_unsigned_prepare_does_not_install_or_mutate(policy, tmp_path):
    from prepare import prepare
    request = {k: v for k, v in policy.items() if k != "profileSha256"}
    before = json.dumps(request, sort_keys=True)
    result = prepare(request, tmp_path.resolve() / "unsigned", 150)
    assert result["status"] == "UNSIGNED_CANDIDATE" and result["installed"] is False
    assert json.dumps(request, sort_keys=True) == before
    assert result["profileSha256"] == policy["profileSha256"]
    with pytest.raises(Refused):
        prepare(policy, tmp_path.resolve() / "bad", 150)


def test_prepare_refuses_profile_injection_before_render(policy, tmp_path):
    from prepare import prepare
    request = {k: v for k, v in policy.items() if k != "profileSha256"}
    request["warmRoots"] = ["/srv/planeon/warm-snapshots/a\nnet eth0"]
    with pytest.raises(Refused):
        prepare(request, tmp_path.resolve() / "bad", 150)


def test_standard_library_only_and_no_shell_evaluation():
    own = {name.removesuffix(".py") for name in SOURCES}
    for file in KIT.glob("*.py"):
        tree = ast.parse(file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [alias.name.split(".")[0] for alias in node.names] if isinstance(node, ast.Import) else [node.module.split(".")[0]]
                assert set(names) <= sys.stdlib_module_names | own
            if isinstance(node, ast.Call):
                assert not any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
                assert not (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                            and node.func.value.id == "os" and node.func.attr in ("system", "popen"))


def _is_predecessor(nodeid):
    return ((nodeid.startswith("tests/") and not nodeid.startswith("tests/linux_runner/"))
            or nodeid.startswith(("ci/test_offline_runner.py::", "ci/test_warm_snapshot.py::")))


def _in_session_predecessor_proof(request, env, targets):
    """Prove the complete predecessor suite passed in this same session, or return None.

    An independent collect-only process lists the exact predecessor tests. Only when
    this session collected that identical set is the proof used; any standalone or
    partial invocation falls back to the original nested re-run.
    """
    session_nodes = {item.nodeid for item in request.session.items if _is_predecessor(item.nodeid)}
    if not session_nodes:
        return None
    started = time.monotonic()
    collect = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", *targets],
                             cwd=ROOT, env=env, capture_output=True, text=True, timeout=420, close_fds=True)
    expected = {line for line in collect.stdout.splitlines() if "::" in line and not line.startswith(" ")}
    if collect.returncode != 0 or not expected or session_nodes != expected:
        return None
    reports = request.config._planeon_predecessor_outcomes.reports
    failed = sorted(node for node in expected if any(outcome == "failed" for _when, outcome in reports.get(node, ())))
    incomplete = sorted(node for node in expected
                        if not any(when == "teardown" for when, _outcome in reports.get(node, ()))
                        or not any(when == "call" or (when == "setup" and outcome == "skipped")
                                   for when, outcome in reports.get(node, ())))
    return {"mode": "IN_SESSION_PROOF", "predecessorTests": len(expected), "failed": len(failed),
            "incomplete": len(incomplete), "failedNodes": failed[:16], "incompleteNodes": incomplete[:16],
            "elapsedSeconds": time.monotonic() - started}


def test_full_predecessor_suites_and_validators_remain_green(capsys):
    # A nested test process stays in this packet's OS-denied tree. Excluding
    # only this new directory prevents recursion, not legacy-test deselection.
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    commands = [[sys.executable, "-m", "pytest", "-rs", "tests", "--ignore=tests/linux_runner", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]]
    commands += [[sys.executable, "scripts/" + name] for name in
                 ("validate_readiness.py", "validate_reuse.py", "validate_alpha2_readiness.py",
                  "validate_readiness_repairs.py", "validate_linux_readiness.py")]
    commands += [[sys.executable, "scripts/zero_bill_scan.py", "."]]
    labels = ("full-predecessor-suite", "readiness", "reuse", "alpha2-readiness",
              "readiness-repairs", "linux-readiness", "zero-bill-scan")
    # The proof lists exactly the nested command's own targets (everything after "-rs").
    # Pinned pytest 8.4.2 keeps the requesting test on its capture fixture; any caller
    # without a real pytest request (such as the strict mock harness) keeps the re-run.
    request = getattr(capsys, "request", None)
    proof = None if request is None else _in_session_predecessor_proof(request, env, commands[0][4:])
    if proof is not None:
        # The outer session already ran every predecessor test; prove it instead of re-running.
        identity = {"ordinal": 1, "total": len(commands), "label": labels[0]}
        _publish_predecessor_record(capsys, {**identity, "event": "START", "timeoutSeconds": 420})
        _publish_predecessor_record(capsys, {**identity, "event": "END",
                                             "returncode": 0 if not (proof["failed"] or proof["incomplete"]) else 1, **proof})
        assert proof["failed"] == 0 and proof["incomplete"] == 0, "predecessor suite failed in this session: " + json.dumps(proof)
    for ordinal, argv in enumerate(commands, start=1):
        if ordinal == 1 and proof is not None:
            continue
        identity = {"ordinal": ordinal, "total": len(commands), "label": labels[ordinal - 1]}
        started = time.monotonic()
        _publish_predecessor_record(capsys, {**identity, "event": "START", "timeoutSeconds": 420})
        try:
            result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=420, close_fds=True)
        except BaseException as exc:
            try:
                record = {**identity, "event": "EXCEPTION", "failureType": type(exc).__name__,
                          "elapsedSeconds": time.monotonic() - started}
                if isinstance(exc, subprocess.TimeoutExpired):
                    record["stdout"] = _bounded_predecessor_output(exc.stdout)
                    record["stderr"] = _bounded_predecessor_output(exc.stderr)
                    if ordinal == 1:
                        # Structured records remain buffered by subprocess.run.
                        # Scan their bounded stream before head/tail retention
                        # loses an earlier failed node. This is not live output.
                        record["pytestDiagnostics"] = _predecessor_summary(exc.stderr)
                _publish_predecessor_record(capsys, record)
            except BaseException:
                # A diagnostic sink failure must never replace the original
                # subprocess exception, including an interruption.
                pass
            raise
        record = {**identity, "event": "END", "returncode": result.returncode,
                  "elapsedSeconds": time.monotonic() - started}
        if ordinal == 1:
            record["pytestDiagnostics"] = _predecessor_summary(result.stderr)
        if result.returncode != 0:
            try:
                record["stdout"] = _bounded_predecessor_output(result.stdout)
                record["stderr"] = _bounded_predecessor_output(result.stderr)
                _publish_predecessor_result(capsys, record, argv, result)
            except BaseException:
                # Preserve the original return-code assertion even if logging
                # fails. The failed command is never retried.
                pass
        else:
            _publish_predecessor_result(capsys, record, argv, result)
        # Explicit raising preserves the exact legacy failure payload under
        # pytest assertion rewriting, without rendering CompletedProcess.
        returncode = result.returncode
        if returncode != 0:
            raise AssertionError(_predecessor_failure_message(result.stdout, result.stderr))
        if ordinal == 1:
            summary = record["pytestDiagnostics"]
            assert (summary["status"] == "COMPLETE"
                    and summary["completionSeen"] is True
                    and summary["sessionEnd"]["exitCode"] == 0
                    and summary["failed"] == 0), "predecessor diagnostics incomplete"
