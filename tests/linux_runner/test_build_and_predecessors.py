"""Deterministic kit packaging plus inherited checks on the current source."""
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

from build import SOURCES, build, candidate_bytes
from common import Refused, digest

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "ci/linux-runner"


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


def _timed_predecessor(argv, env, emit):
    """Observe the existing command; never retry, swallow failure or grant PASS."""
    identity = {"argv": argv[1:], "timeoutSeconds": 420,
                "evidence": "SOURCE_TIMING_ONLY_NOT_ACCEPTANCE"}
    started = time.monotonic_ns()
    emit({**identity, "state": "START"})
    try:
        result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True,
                                text=True, timeout=420, close_fds=True)
    except (subprocess.TimeoutExpired, OSError) as error:
        emit({**identity, "state": "END", "elapsedNs": time.monotonic_ns() - started,
              "outcome": "TIMEOUT" if isinstance(error, subprocess.TimeoutExpired) else "LAUNCH_ERROR",
              "returnCode": None})
        raise
    emit({**identity, "state": "END", "elapsedNs": time.monotonic_ns() - started,
          "outcome": "COMPLETED" if result.returncode == 0 else "NONZERO_EXIT",
          "returnCode": result.returncode})
    return result


@pytest.mark.parametrize("outcome", ["completed", "nonzero", "timeout", "launch_error"])
def test_predecessor_timing_preserves_argv_limits_and_failures(monkeypatch, outcome):
    # Pure observer tests: no subprocess and no real-run marker is emitted.
    argv = [sys.executable, "scripts/zero_bill_scan.py", "."]
    env = {"FIXTURE": "data-only"}
    events, calls = [], []
    ticks = iter([100, 350])
    monkeypatch.setattr(time, "monotonic_ns", lambda: next(ticks))
    error = (subprocess.TimeoutExpired(argv, 420) if outcome == "timeout"
             else OSError("synthetic launch refusal"))
    result = subprocess.CompletedProcess(argv, 1 if outcome == "nonzero" else 0,
                                         stdout="synthetic stdout", stderr="")

    def fake_run(actual_argv, **kwargs):
        calls.append((actual_argv, kwargs))
        assert events == [{"argv": argv[1:], "timeoutSeconds": 420,
                           "evidence": "SOURCE_TIMING_ONLY_NOT_ACCEPTANCE", "state": "START"}]
        if outcome in ("timeout", "launch_error"):
            raise error
        return result

    monkeypatch.setattr(subprocess, "run", fake_run)
    if outcome in ("timeout", "launch_error"):
        with pytest.raises(type(error)) as caught:
            _timed_predecessor(argv, env, events.append)
        assert caught.value is error
    else:
        assert _timed_predecessor(argv, env, events.append) is result
    assert calls == [(argv, {"cwd": ROOT, "env": env, "capture_output": True,
                            "text": True, "timeout": 420, "close_fds": True})]
    assert len(events) == 2 and events[1]["state"] == "END"
    assert events[1]["elapsedNs"] == 250
    assert events[1]["outcome"] == {"completed": "COMPLETED", "nonzero": "NONZERO_EXIT",
                                     "timeout": "TIMEOUT", "launch_error": "LAUNCH_ERROR"}[outcome]
    assert events[1]["returnCode"] == (None if outcome in ("timeout", "launch_error") else result.returncode)


def test_full_predecessor_suites_and_validators_remain_green(capsys):
    # The outer current-source suite includes all inherited Linux test identities
    # with versioned fixtures. This nested process stays in the same OS-denied
    # tree and excludes Linux only to avoid recursively collecting this function.
    # It executes current source; retained historical bytes are never executed.
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    commands = [[sys.executable, "-m", "pytest", "-rs", "tests", "--ignore=tests/linux_runner", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]]
    commands += [[sys.executable, "scripts/" + name] for name in
                 ("validate_readiness.py", "validate_reuse.py", "validate_alpha2_readiness.py",
                  "validate_readiness_repairs.py", "validate_linux_readiness.py")]
    commands += [[sys.executable, "scripts/zero_bill_scan.py", "."]]

    def emit(event):
        prefix = "PREDECESSOR_START=" if event["state"] == "START" else "PREDECESSOR_TIMING="
        with capsys.disabled():
            print(prefix + json.dumps(event, sort_keys=True), flush=True)

    for argv in commands:
        result = _timed_predecessor(argv, env, emit)
        with capsys.disabled():
            print("PREDECESSOR_ARGV=" + json.dumps(argv[1:]), flush=True)
            print(result.stdout, flush=True)
        assert result.returncode == 0, result.stdout + result.stderr
