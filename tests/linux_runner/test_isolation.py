"""Adapter tests are SOURCE_ONLY; the external installed probe owns real Linux results."""
from copy import deepcopy
import errno
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from common import LAUNCHER, PACKET, PROFILE, PYTHON, Refused, Unavailable, canonical
import launcher
import preflight


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EAFNOSUPPORT])
def test_network_requires_os_permission_denial(monkeypatch, code):
    def socket(*args):
        raise OSError(code, "synthetic errno")
    monkeypatch.setattr(preflight.socket, "socket", socket)
    result = preflight.network_negatives()
    assert set(result) == set(preflight.NETWORK_CASES)
    assert all(value is (code in (errno.EPERM, errno.EACCES)) for value in result.values())


def test_successful_socket_is_closed_without_sending(monkeypatch):
    closed = []
    monkeypatch.setattr(preflight.socket, "socket", lambda *args: SimpleNamespace(close=lambda: closed.append(True)))
    assert not any(preflight.network_negatives().values())
    assert len(closed) == 8


@pytest.mark.parametrize("error", [errno.EACCES, errno.EPERM, errno.ENOENT, errno.EIO, errno.EISDIR])
def test_path_errors_not_all_denials(error):
    def operation():
        raise OSError(error, "synthetic")
    assert preflight.denied(operation, preflight.HIDDEN_DENIAL) is (error in preflight.HIDDEN_DENIAL)


def test_failed_path_denial_never_reads_or_writes_contents(tmp_path):
    file = tmp_path / "synthetic-sentinel"
    file.write_bytes(b"untouched")
    assert preflight.hidden(str(file)) == {"read": False, "metadata": False, "write": False}
    assert file.read_bytes() == b"untouched"


@pytest.mark.parametrize("name", ["AWS_ACCESS_KEY_ID", "OPENAI_API_KEY", "SSH_AUTH_SOCK", "KUBECONFIG", "DOCKER_HOST", "LD_PRELOAD", "PYTHONPATH", "HARNESS_WARM_SOURCE_ROOTS", "HARNESS_TASK_PACKET", "UNKNOWN"])
def test_secret_or_unknown_environment_refused(name):
    with pytest.raises(Refused):
        preflight.assert_no_sensitive_environment({name: "synthetic-not-a-credential"}, [])


def test_environment_constructed_not_filtered(policy, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-only")
    monkeypatch.setenv("HARNESS_WARM_SOURCE_ROOTS", policy["warmRoots"][0])
    env = launcher.environment(policy)
    preflight.assert_no_sensitive_environment(env, policy["warmRoots"])
    assert not set(env) & {"AWS_ACCESS_KEY_ID", "HARNESS_WARM_SOURCE_ROOTS", "HARNESS_TASK_PACKET"}
    with pytest.raises(Refused):
        preflight.assert_no_sensitive_environment({"PATH": policy["warmRoots"][0]}, policy["warmRoots"])


def test_profile_preserves_tools_and_hides_authority_parent(policy):
    text = launcher.profile_bytes(policy).decode()
    for line in ("net none", "nonewprivs", "caps.drop all", "restrict-namespaces", "seccomp.block-secondary",
                 "seccomp-error-action EPERM", "blacklist /etc/planeon",
                 "private-srv planeon-runner-placeholder", "read-only " + PACKET,
                 "whitelist " + LAUNCHER, "whitelist " + PACKET, "whitelist " + policy["workspace"],
                 "whitelist /opt/planeon/python/3.12.14"):
        assert line in text.splitlines()
    assert "blacklist /srv" not in text.splitlines()
    assert not any(root in text for root in policy["warmRoots"])
    assert "shell none" not in text and "noroot" not in text
    assert "connect,sendto,sendmsg" in text and "io_uring_setup" in text


def test_non_linux_never_launches_backend(monkeypatch):
    monkeypatch.setattr(launcher.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(launcher.subprocess, "Popen", lambda *a, **k: pytest.fail("no host process authorized"))
    with pytest.raises(Unavailable, match="NON_LINUX_HOST"):
        launcher.load_authority()
    assert preflight.installed_availability() == {"status": "NOT_RUN_ENV_UNAVAILABLE", "reason": "NON_LINUX_HOST", "nativeLinuxAcceptance": False}


def test_uninstalled_candidate_refused_before_root_open(monkeypatch):
    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.sys, "argv", ["/tmp/candidate"])
    monkeypatch.setattr(launcher, "root_read", lambda *a, **k: pytest.fail("must reject candidate path first"))
    with pytest.raises(Refused, match="fixed installed"):
        launcher.load_authority()


def test_internal_payload_without_root_descriptors_cannot_execute(policy):
    with pytest.raises((KeyError, Refused)):
        launcher.internal_authority({"policy": policy, "authorityDescriptors": {}})


def test_deadline_and_success_both_retire_process_group(monkeypatch):
    for timeout in (False, True):
        calls = []
        class Child:
            pid = 77777
            returncode = 0
            def communicate(self, **kwargs):
                calls.append(("communicate", kwargs))
                if timeout:
                    raise subprocess.TimeoutExpired("synthetic", 1)
            def wait(self):
                calls.append(("wait",))
        def popen(argv, **kwargs):
            calls.append(("popen", argv, kwargs))
            return Child()
        monkeypatch.setattr(launcher.subprocess, "Popen", popen)
        monkeypatch.setattr(launcher.os, "killpg", lambda *a: calls.append(("killpg", *a)))
        if timeout:
            with pytest.raises(Refused, match="deadline"):
                launcher.supervise(["fixed"], env={}, cwd="/", payload=b"data", timeout=1, pass_fds=(8,))
        else:
            assert launcher.supervise(["fixed"], env={}, cwd="/", payload=b"data", timeout=1, pass_fds=(8,)) == 0
        assert calls[0][2]["close_fds"] is True and calls[0][2]["start_new_session"] is True
        assert calls[0][2]["pass_fds"] == (8,)
        assert any(call[0] == "killpg" and call[1] == 77777 for call in calls)


@pytest.mark.parametrize("missing", ["NoNewPrivs", "Seccomp", "CapEff"])
def test_kernel_filter_requirements(monkeypatch, missing):
    fields = {"NoNewPrivs": "1", "Seccomp": "2", "CapEff": "0000000000000000"}
    del fields[missing]
    monkeypatch.setattr(Path, "read_text", lambda *a, **k: "\n".join(k + ":\t" + v for k, v in fields.items()))
    with pytest.raises(Refused, match="kernel"):
        preflight.kernel_boundary({})


def test_descendant_uses_fresh_interpreter_and_closed_fds(monkeypatch):
    context = {"roots": [], "hiddenPaths": [], "parentNamespaces": {}, "launcher": LAUNCHER}
    monkeypatch.setattr(preflight, "kernel_boundary", lambda _: None)
    monkeypatch.setattr(preflight, "assert_no_sensitive_environment", lambda *args: None)
    monkeypatch.setattr(preflight, "network_negatives", lambda: {k: True for k in preflight.NETWORK_CASES})
    monkeypatch.setattr(preflight, "denied", lambda *args: True)
    monkeypatch.setattr(Path, "iterdir", lambda _: [])
    seen = []
    def child(argv, **kwargs):
        seen.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"CHILD_NEGATIVES_PASS\n")
    monkeypatch.setattr(preflight.subprocess, "run", child)
    assert preflight.run(context)["descendantsChecked"] is True
    assert seen[0][0] == [PYTHON, "-IB", LAUNCHER, "--probe-child"]
    assert seen[0][1]["close_fds"] is True
    assert seen[0][1]["input"] == canonical(context)
    monkeypatch.setattr(preflight.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=2, stdout=b""))
    with pytest.raises(Refused, match="descendant"):
        preflight.run(context)


def test_real_integration_is_not_faked_on_development_host(capsys):
    disposition = preflight.installed_availability()
    if disposition is not None:
        assert disposition["status"] == "NOT_RUN_ENV_UNAVAILABLE"
        assert disposition["nativeLinuxAcceptance"] is False
        with capsys.disabled():
            print("LINUX_NATIVE_INTEGRATION=" + canonical(disposition).decode(), flush=True)
    else:
        # No nested Firejail or trusted-authority lookup from repository CI.
        # Actual negatives are the external --operator-preflight operation, not
        # a pytest fixture, platform flag, or an installed-file existence check.
        assert os.environ.get("HARNESS_OFFLINE_ENFORCED") == "1"
