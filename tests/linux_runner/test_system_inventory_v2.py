"""Source-only V3 closure graphs; no Linux host PASS is claimed."""
import os
import stat
from types import SimpleNamespace

import pytest

import common
from common import Refused, canonical, digest, inventory, system_inventories


@pytest.fixture
def synthetic_owner(monkeypatch):
    # tmp_path is user-owned. Production's root-only predicate remains separately
    # asserted below and is never replaced in the installed launcher artifact.
    monkeypatch.setattr(common, "trusted_entry", lambda m: m.st_uid in (0, os.getuid())
                        and (stat.S_ISDIR(m.st_mode) or stat.S_ISLNK(m.st_mode)
                             or not m.st_mode & 0o022))
    # Fixture files must not be group/world writable whatever the host's default
    # umask is (Ubuntu gives ordinary users 002; macOS and root use 022).
    previous = os.umask(0o022)
    yield
    os.umask(previous)


def test_system_tree_binds_file_symlink_and_complete_hardlink_group(tmp_path, synthetic_owner):
    tmp_path = tmp_path.resolve(strict=True)
    first = tmp_path / "libalpha.so.1"
    first.write_bytes(b"pinned")
    second = tmp_path / "libalpha.so.1.0"
    os.link(first, second)
    alias = tmp_path / "libalpha.so"
    alias.symlink_to(first.name)
    entries = inventory(tmp_path, trusted=True, system=True)
    by_path = {entry["path"]: entry for entry in entries}
    assert by_path[alias.name] == {"kind": "symlink", "path": alias.name,
                                    "target": first.name, "resolvedPath": str(first)}
    assert by_path[first.name]["hardlinkGroup"] == sorted((str(first), str(second)))
    assert by_path[second.name]["hardlinkGroup"] == sorted((str(first), str(second)))
    before = digest(canonical(entries))
    alias.unlink()
    alias.symlink_to(second.name)
    assert digest(canonical(inventory(tmp_path, trusted=True, system=True))) != before
    with pytest.raises(Refused, match="symlink"):
        inventory(tmp_path, trusted=True)


def test_system_link_chain_and_parent_directory_are_inventoried(tmp_path, synthetic_owner):
    tmp_path = tmp_path.resolve(strict=True)
    directory = tmp_path / "lib"
    directory.mkdir()
    target = directory / "libalpha.so.1"
    target.write_bytes(b"pinned")
    (directory / "libalpha.so").symlink_to(target.name)
    (tmp_path / "libalpha.so").symlink_to("lib/libalpha.so")
    by_path = {entry["path"]: entry for entry in inventory(tmp_path, trusted=True, system=True)}
    assert by_path["libalpha.so"]["resolvedPath"] == str(target)
    assert by_path["lib/libalpha.so"]["resolvedPath"] == str(target)


def test_signed_cross_root_file_and_directory_aliases(tmp_path, synthetic_owner):
    tmp_path = tmp_path.resolve(strict=True)
    usr_bin = tmp_path / "usr" / "bin"
    usr_lib = tmp_path / "usr" / "lib"
    alternatives = tmp_path / "etc" / "alternatives"
    for root in (usr_bin, usr_lib, alternatives):
        root.mkdir(parents=True)
    editor = usr_bin / "real-editor"
    editor.write_bytes(b"pinned executable")
    library = usr_lib / "libalpha.so"
    library.write_bytes(b"pinned library")
    (usr_bin / "editor").symlink_to(alternatives / "editor")
    (alternatives / "editor").symlink_to("../../usr/bin/real-editor")
    (usr_bin / "lib-alias").symlink_to("../lib", target_is_directory=True)
    (usr_bin / "via-directory").symlink_to("lib-alias/libalpha.so")
    result = system_inventories([str(usr_bin), str(usr_lib), str(alternatives)])
    by_path = {entry["path"]: entry for entry in result[str(usr_bin)]}
    assert by_path["editor"]["resolvedPath"] == str(editor)
    assert by_path["lib-alias"]["resolvedPath"] == str(usr_lib)
    assert by_path["via-directory"]["resolvedPath"] == str(library)
    before = digest(canonical(result[str(alternatives)]))
    (alternatives / "editor").unlink()
    (alternatives / "editor").symlink_to(editor)
    changed = system_inventories([str(usr_bin), str(usr_lib), str(alternatives)])
    assert digest(canonical(changed[str(alternatives)])) != before


def test_signed_cross_root_hardlink_group_must_be_complete(tmp_path, synthetic_owner):
    tmp_path = tmp_path.resolve(strict=True)
    first_root = tmp_path / "usr" / "bin"
    second_root = tmp_path / "usr" / "lib"
    first_root.mkdir(parents=True)
    second_root.mkdir(parents=True)
    first = first_root / "shared"
    second = second_root / "shared"
    first.write_bytes(b"shared")
    os.link(first, second)
    result = system_inventories([str(first_root), str(second_root)])
    expected = sorted((str(first), str(second)))
    assert next(entry for entry in result[str(first_root)] if entry["path"] == "shared")["hardlinkGroup"] == expected
    assert next(entry for entry in result[str(second_root)] if entry["path"] == "shared")["hardlinkGroup"] == expected
    with pytest.raises(Refused, match="incomplete system hardlink"):
        system_inventories([str(first_root)])


def test_cross_root_alias_to_undeclared_tree_is_refused(tmp_path, synthetic_owner):
    tmp_path = tmp_path.resolve(strict=True)
    declared = tmp_path / "usr" / "bin"
    undeclared = tmp_path / "etc" / "alternatives"
    declared.mkdir(parents=True)
    undeclared.mkdir(parents=True)
    target = undeclared / "editor"
    target.write_bytes(b"unreviewed")
    (declared / "editor").symlink_to(target)
    with pytest.raises(Refused, match="uninventoried"):
        system_inventories([str(declared)])


def test_directory_alias_cannot_escape_and_return(tmp_path, synthetic_owner):
    tmp_path = tmp_path.resolve(strict=True)
    declared = tmp_path / "usr" / "bin"
    declared.mkdir(parents=True)
    (declared / "real").write_bytes(b"pinned")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "return").symlink_to("../usr/bin", target_is_directory=True)
    (declared / "alias").symlink_to(str(outside / "return"), target_is_directory=True)
    with pytest.raises(Refused, match="uninventoried"):
        system_inventories([str(declared)])


@pytest.mark.parametrize("kind", ("escape", "outside-return", "dangling", "cycle",
                                  "missing-prefix", "file-prefix"))
def test_system_link_must_end_inside_signed_closure(tmp_path, synthetic_owner, kind):
    tmp_path = tmp_path.resolve(strict=True)
    target = tmp_path / "target"
    target.write_bytes(b"x")
    alias = tmp_path / "alias"
    if kind == "escape":
        alias.symlink_to("../outside")
    elif kind == "outside-return":
        outside = tmp_path.parent / (tmp_path.name + "-outside-return")
        outside.symlink_to(target)
        alias.symlink_to("../" + outside.name)
    elif kind == "dangling":
        alias.symlink_to("missing")
    elif kind == "cycle":
        alias.symlink_to("alias")
    elif kind == "missing-prefix":
        alias.symlink_to("missing/../target")
    elif kind == "file-prefix":
        alias.symlink_to("target/../target")
    with pytest.raises(Refused):
        inventory(tmp_path, trusted=True, system=True)


def test_system_hardlink_outside_declared_root_is_refused(tmp_path, synthetic_owner):
    tmp_path = tmp_path.resolve(strict=True)
    root = tmp_path / "system"
    root.mkdir()
    file = root / "tool"
    file.write_bytes(b"x")
    os.link(file, tmp_path / "outside")
    with pytest.raises(Refused, match="incomplete system hardlink"):
        inventory(root, trusted=True, system=True)


def test_system_inventory_fails_on_traversal_error(tmp_path, synthetic_owner, monkeypatch):
    tmp_path = tmp_path.resolve(strict=True)
    def incomplete_walk(root, *, followlinks, onerror):
        onerror(PermissionError("synthetic unreadable subtree"))
        yield root, [], []
    monkeypatch.setattr(common.os, "walk", incomplete_walk)
    with pytest.raises(Refused, match="traversal incomplete"):
        inventory(tmp_path, trusted=True, system=True)


def test_system_alias_mode_never_applies_to_source_or_untrusted_tree(tmp_path):
    (tmp_path / "file").write_bytes(b"x")
    with pytest.raises(Refused, match="trusted system"):
        inventory(tmp_path, system=True)
    with pytest.raises(Refused, match="trusted system"):
        inventory(tmp_path, trusted=True, source=True, system=True)


def test_production_custody_rejects_nonroot_and_world_writable():
    root_file = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644)
    nonroot_file = SimpleNamespace(st_uid=1001, st_gid=1001, st_mode=stat.S_IFREG | 0o644)
    writable_file = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o666)
    root_link = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFLNK | 0o777)
    assert common.trusted_entry(root_file)
    assert not common.trusted_entry(nonroot_file)
    assert not common.trusted_entry(writable_file)
    assert common.trusted_entry(root_link)
