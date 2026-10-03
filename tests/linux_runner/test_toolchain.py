"""Native bytes and exhaustive system closure admission; no host qualification."""
from copy import deepcopy
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from common import Refused, canonical, digest, validate_inputs
import launcher


def elf(machine):
    return b"\x7fELF\x02\x01" + bytes(12) + machine.to_bytes(2, "little") + bytes(44)


@pytest.mark.parametrize(("arch", "machine"), [("amd64", 62), ("arm64", 183)])
def test_expected_native_elf(arch, machine):
    launcher.validate_elf(elf(machine), arch)


@pytest.mark.parametrize(("raw", "arch"), [(elf(62), "arm64"), (elf(183), "amd64"),
    (b"\xcf\xfa\xed\xfe" + bytes(60), "arm64"), (b"MZ" + bytes(62), "amd64"),
    (b"#!/usr/bin/python\n", "amd64"), (b"\x7fELF", "amd64"), (elf(62)[:4] + b"\x01\x01" + elf(62)[6:], "amd64")])
def test_wrong_native_binary_refused(raw, arch):
    with pytest.raises(Refused):
        launcher.validate_elf(raw, arch)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "writable-place", "unbound-cache", "unknown-field"])
def test_system_helper_and_loader_pins_required(inputs, mutation):
    if mutation == "missing":
        inputs["systemTrees"] = []
    elif mutation == "duplicate":
        inputs["systemTrees"].append(deepcopy(inputs["systemTrees"][0]))
    elif mutation == "writable-place":
        inputs["systemTrees"][0]["root"] = "/tmp/libraries"
    elif mutation == "unbound-cache":
        inputs["systemFiles"] = {}
    else:
        inputs["systemFiles"]["/etc/ld.so.preload"] = "0" * 64
    with pytest.raises(Refused):
        validate_inputs(inputs)


def test_unobservable_libc_cannot_pass_by_label(inputs, monkeypatch):
    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(launcher.platform, "libc_ver", lambda: ("", ""))
    with pytest.raises(Refused, match="libc"):
        launcher.verify_tools(inputs)


def test_global_loader_injection_refused_before_inventory(inputs, monkeypatch):
    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(launcher.platform, "libc_ver", lambda: ("glibc", "2.39"))
    monkeypatch.setattr(launcher.os.path, "lexists", lambda path: path == "/etc/ld.so.preload")
    monkeypatch.setattr(launcher, "inventory", lambda *a, **k: pytest.fail("loader rejection must happen first"))
    with pytest.raises(Refused, match="loader injection"):
        launcher.verify_tools(inputs)


def test_cache_cannot_borrow_alias_permissive_system_inventory(inputs):
    inputs["caches"][0]["root"] = "/usr/bin"
    with pytest.raises(Refused, match="cache overlaps system closure"):
        validate_inputs(inputs)


@pytest.mark.parametrize("root", ("/lib", "/lib64"))
def test_root_alias_contract_is_not_implicitly_admitted(inputs, root):
    inputs["systemTrees"].append({"root": root, "inventorySha256": "0" * 64})
    with pytest.raises(Refused, match="unapproved system root"):
        validate_inputs(inputs)


@pytest.mark.parametrize("kind", ("tool", "cache"))
def test_private_srv_cannot_hide_declared_build_input(inputs, kind):
    if kind == "tool":
        inputs["tools"]["git"]["root"] = "/srv/other/git"
        inputs["tools"]["git"]["path"] = "/srv/other/git/bin/git"
    else:
        inputs["caches"][0]["root"] = "/srv/other/cache"
    with pytest.raises(Refused, match="private profile"):
        validate_inputs(inputs)


@pytest.mark.parametrize("changed", (False, True))
def test_selected_system_tool_uses_verified_cross_root_graph(inputs, monkeypatch, changed):
    executable = elf(62)
    real_git = "/usr/bin/git.real"
    cache_bytes = b"pinned loader cache"
    inputs["systemFiles"]["/etc/ld.so.cache"] = digest(cache_bytes)
    inputs["systemTrees"].append({"root": "/etc/alternatives", "inventorySha256": "0" * 64})
    trees = {
        "/usr/bin": [
            {"kind": "file", "path": "firejail", "sha256": digest(executable)},
            {"kind": "symlink", "path": "git", "target": "/etc/alternatives/git",
             "resolvedPath": real_git},
            {"kind": "file", "path": "git.real", "sha256": digest(executable)},
        ],
        "/usr/lib": [{"kind": "directory", "path": "", "mode": "0755"}],
        "/etc/firejail": [{"kind": "directory", "path": "", "mode": "0755"}],
        "/etc/alternatives": [{"kind": "symlink", "path": "git", "target": real_git,
                                "resolvedPath": real_git}],
    }
    for spec in inputs["systemTrees"]:
        spec["inventorySha256"] = digest(canonical(trees[spec["root"]]))
    for spec in [*inputs["tools"].values(), *inputs["caches"]]:
        spec["inventorySha256"] = (digest(canonical(trees[spec["root"]]))
                                   if spec["root"] in trees else digest(canonical([])))
    calls = []
    graph_calls = []

    def read(path, **kwargs):
        calls.append((path, kwargs))
        if path == "/etc/ld.so.cache":
            return cache_bytes
        if path == real_git and changed:
            return elf(183)
        return executable

    def graph(roots):
        graph_calls.append(roots)
        return trees

    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(launcher.platform, "libc_ver", lambda: ("glibc", "2.39"))
    monkeypatch.setattr(launcher.os.path, "lexists", lambda _: False)
    monkeypatch.setattr(Path, "lstat", lambda self: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755,
                                                                 st_uid=0, st_gid=0))
    monkeypatch.setattr(launcher, "root_read", read)
    monkeypatch.setattr(launcher, "system_inventories", graph)
    monkeypatch.setattr(launcher, "inventory", lambda *args, **kwargs: [])
    if changed:
        with pytest.raises(Refused, match="selected system tool changed"):
            launcher.verify_tools(inputs)
    else:
        launcher.verify_tools(inputs)
    assert graph_calls == [["/etc/alternatives", "/etc/firejail", "/usr/bin", "/usr/lib"]]
    assert (real_git, {"maximum": 256 * 1024 * 1024, "allow_hardlinks": True}) in calls
    assert not any(path == "/usr/bin/git" for path, _ in calls)
