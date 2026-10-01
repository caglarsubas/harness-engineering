"""Exact GitHub checkout layout and pre-listener custody, source-only tests."""
from copy import deepcopy
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from common import Refused
import launcher


@pytest.mark.parametrize("workspace", (
    "/opt/planeon/work/harness-onion",
    "/opt/planeon/work/other/other",
    "/opt/planeon/work/harness-onion/other",
    "/opt/planeon/work/harness-onion/harness-onion/extra",
    "/opt/planeon/work/harness-onion/harness-onion/../other",
))
def test_signed_workspace_must_equal_validated_repository_layout(policy, workspace):
    policy["workspace"] = workspace
    with pytest.raises(Refused):
        launcher.validate_policy(policy, 150)


@pytest.mark.parametrize("prior", ("v1", "v2"))
def test_old_policy_and_input_versions_are_not_accepted(policy, prior):
    old = deepcopy(policy)
    old["schemaVersion"] = "planeon.linux-runner-policy/" + prior
    with pytest.raises(Refused, match="policy version"):
        launcher.validate_policy(old, 150)
    old = deepcopy(policy)
    old["inputs"]["schemaVersion"] = "planeon.linux-build-inputs/" + prior
    with pytest.raises(Refused, match="build input version"):
        launcher.validate_policy(old, 150)
    assert launcher.POLICY_DOMAIN == b"planeon.linux-runner-policy/v3\x00"


def synthetic_custody(policy, monkeypatch):
    uid = policy["operatorUid"]
    workspace = Path(policy["workspace"])
    metadata = {}
    for path in (Path("/"), Path("/opt"), Path("/opt/planeon"), Path("/srv"), Path("/srv/planeon"),
                 *(Path(value) for value in launcher.PROTECTED_HOST_ROOTS)):
        metadata[path] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
    metadata[Path("/opt/planeon/work")] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
    for path in (workspace.parent, workspace,
                 workspace / ".git", Path(policy["runnerHome"]),
                 *(Path("/opt/planeon/work") / name for name in launcher.RUNNER_SIBLINGS)):
        metadata[path] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=uid, st_gid=uid)
    metadata[Path("/opt/planeon/work") / launcher.SIBLING_SENTINEL] = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0, st_nlink=1)
    metadata[Path(launcher.SRV_PRIVATE_ANCHOR)] = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0, st_nlink=1, st_size=0)
    monkeypatch.setattr(Path, "lstat", lambda self: metadata[self])
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    return metadata


def test_workspace_and_outside_visible_sibling_custody(policy, monkeypatch):
    synthetic_custody(policy, monkeypatch)
    launcher.check_workspace_custody(policy, host_siblings=True)
    hidden = launcher.hidden_paths(policy)
    assert not set(launcher.PROTECTED_HOST_ROOTS) & set(hidden)
    assert "/srv/planeon" in hidden
    assert "/etc/planeon/linux-runner" in hidden
    assert "private-srv planeon-runner-placeholder" in launcher.profile_bytes(policy).decode()
    assert policy["runnerHome"] in hidden
    assert policy["warmContainer"] in hidden
    for name in (*launcher.RUNNER_SIBLINGS, launcher.SIBLING_SENTINEL):
        path = str(Path("/opt/planeon/work") / name)
        assert path in hidden
        assert "blacklist " + path in launcher.profile_bytes(policy).decode()


def test_inside_checkout_has_private_root_owned_ancestors(policy, monkeypatch):
    metadata = synthetic_custody(policy, monkeypatch)
    workspace = Path(policy["workspace"])
    metadata[workspace.parent].st_uid = metadata[workspace.parent].st_gid = 0
    metadata[workspace.parent].st_mode = stat.S_IFDIR | 0o755
    launcher.check_workspace_custody(policy)
    metadata[workspace.parent].st_uid = policy["operatorUid"]
    with pytest.raises(Refused):
        launcher.check_workspace_custody(policy)


@pytest.mark.parametrize("changed", ("symlink", "writable", "wrong-owner", "absent-sentinel", "runner-owned-parent", "absent-root", "absent-srv-anchor"))
def test_workspace_custody_fails_closed(policy, monkeypatch, changed):
    metadata = synthetic_custody(policy, monkeypatch)
    workspace = Path(policy["workspace"])
    if changed == "symlink":
        metadata[workspace.parent].st_mode = stat.S_IFLNK | 0o777
    elif changed == "writable":
        metadata[Path("/opt/planeon/work")].st_mode = stat.S_IFDIR | 0o777
    elif changed == "wrong-owner":
        metadata[workspace / ".git"].st_uid = 0
    elif changed == "runner-owned-parent":
        metadata[Path("/opt/planeon/work")].st_uid = policy["operatorUid"]
    elif changed == "absent-root":
        metadata.pop(Path("/etc/planeon"))
    elif changed == "absent-srv-anchor":
        metadata.pop(Path(launcher.SRV_PRIVATE_ANCHOR))
    else:
        metadata.pop(Path("/opt/planeon/work") / launcher.SIBLING_SENTINEL)
    with pytest.raises((Refused, KeyError)):
        launcher.check_workspace_custody(policy, host_siblings=True)


@pytest.mark.parametrize("mount", (
    "/opt",
    "/opt/planeon",
    "/opt/planeon/work",
    "/opt/planeon/work/harness-onion/harness-onion",
    "/opt/planeon/work/harness-onion/harness-onion/.git",
))
def test_work_mount_alias_is_refused(mount):
    record = "42 1 8:1 / " + mount + " rw - ext4 /dev/sda1 rw\n"
    assert launcher.work_mount_alias_present(record)
    assert not launcher.work_mount_alias_present("42 1 8:1 / /usr rw - ext4 /dev/sda1 rw\n")
