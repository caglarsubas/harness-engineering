#!/usr/bin/env python3
"""Verify enumerated successor bytes and materialize the immutable predecessor.

This source-only bridge never imports or executes historical source while
validating it. The caller may execute the complete predecessor suite only
after every materialized byte is checked against the accepted-base manifest.
The signed outer runner binds the entire current source tree, including extra
files; this bridge alone does not certify an unenumerated live workspace.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import zlib
from contextlib import ExitStack
from pathlib import Path
from typing import Any

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/current-catalog-successor-authority.json"
BRIDGE_PATH = "scripts/validate_current_catalog_successor.py"
AUTHORITY_SHA256 = "f96516b3e5b53c67eb1816f54492c59cedd46aa1c3d0d75f0300c536094defd9"
BASE_COMMIT = "945de93f89c94f42f1d63bff7997e3d0fa704fc4"
BASE_TREE = "19f27b2b9e499f7437d0ded35c2983209adca4b6"
SUCCESSOR = "MET-LINUX-003"
MAX_FILE = 16_777_216


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result

    def nonfinite(_: str) -> Any:
        raise ValueError("nonfinite JSON number")

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
    require(type(value) is dict, "JSON authority mapping")
    return value


def checked_path(path: str) -> tuple[str, ...]:
    require(type(path) is str and path and not path.startswith("/"), "relative path")
    parts = tuple(path.split("/"))
    require(all(part not in ("", ".", "..") for part in parts), "canonical path")
    return parts


def regular_bytes(root: Path, path: str, *, expected_mode: int | None = None) -> bytes:
    parts = checked_path(path)
    identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink,
                            row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with ExitStack() as opened:
        parent_fd = os.open(root, directory_flags)
        opened.callback(os.close, parent_fd)
        ancestors = []
        for part in parts[:-1]:
            child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            opened.callback(os.close, child_fd)
            ancestors.append((parent_fd, part, identity(os.fstat(child_fd))))
            parent_fd = child_fd
        file_fd = os.open(parts[-1], file_flags, dir_fd=parent_fd)
        opened.callback(os.close, file_fd)
        before = os.fstat(file_fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= MAX_FILE, "bounded unlinked source")
        if expected_mode is not None:
            require(stat.S_IMODE(before.st_mode) == expected_mode,
                    "accepted source mode")
        remaining = before.st_size + 1
        chunks = []
        while remaining:
            chunk = os.read(file_fd, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        require(identity(before) == identity(after) == identity(named)
                and len(raw) == before.st_size,
                "source changed during read")
        for directory_fd, name, initial in ancestors:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            require(identity(named) == initial and stat.S_ISDIR(named.st_mode),
                    "source ancestor changed during read")
        return raw


def sha(value: Any) -> None:
    require(type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value), "SHA-256 value")


def git_tree_oid(source: dict[str, tuple[bytes, int]]) -> str:
    """Recreate the Git SHA-1 tree object for a checked regular-file inventory.

    SHA-1 here identifies Git object format, not an authorization digest; the
    current authority and every source byte remain SHA-256 pinned separately.
    """
    def object_id(kind: bytes, content: bytes) -> bytes:
        header = kind + b" " + str(len(content)).encode("ascii") + b"\0"
        return hashlib.sha1(header + content, usedforsecurity=False).digest()

    tree: dict[str, Any] = {}
    for path, (raw, mode) in source.items():
        parts = checked_path(path)
        require(mode in (0o644, 0o755), "Git regular-file mode")
        node = tree
        for part in parts[:-1]:
            prior = node.setdefault(part, {})
            require(type(prior) is dict, "file/directory collision")
            node = prior
        require(parts[-1] not in node, "duplicate Git path")
        node[parts[-1]] = (raw, mode)

    def hash_tree(node: dict[str, Any]) -> bytes:
        entries = []
        for name, value in node.items():
            encoded = name.encode("utf-8")
            if type(value) is dict:
                mode, oid, order = b"40000", hash_tree(value), encoded + b"/"
            else:
                raw, permissions = value
                mode = b"100755" if permissions == 0o755 else b"100644"
                oid, order = object_id(b"blob", raw), encoded
            entries.append((order, mode + b" " + encoded + b"\0" + oid))
        return object_id(b"tree", b"".join(value for _, value in sorted(entries)))

    return hash_tree(tree).hex()


def predecessor_bytes(encoded: str, expected: str) -> bytes:
    require(type(encoded) is str, "preimage encoding")
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("preimage encoding") from exc
    require(base64.b64encode(compressed).decode("ascii") == encoded,
            "noncanonical preimage encoding")
    try:
        inflater = zlib.decompressobj()
        raw = inflater.decompress(compressed, MAX_FILE + 1)
        require(len(raw) <= MAX_FILE and inflater.eof and not inflater.unused_data
                and not inflater.unconsumed_tail and not inflater.flush(),
                "bounded complete preimage")
    except zlib.error as exc:
        raise ValueError("bounded complete preimage") from exc
    require(digest(raw) == expected, "preimage digest")
    return raw


def authority() -> dict[str, Any]:
    raw = regular_bytes(ROOT, AUTHORITY_PATH)
    require(digest(raw) == AUTHORITY_SHA256, "successor authority digest")
    record = parse(raw)
    require(set(record) == {"schemaVersion", "acceptedBase", "successorPacket",
                           "baselineFiles", "changedFiles", "newFiles",
                           "bridgeNormalizedSha256"}, "closed successor authority")
    require(record["schemaVersion"] == "harness.planeon.ai/current-catalog-successor/v1"
            and record["acceptedBase"] == {"commit": BASE_COMMIT, "tree": BASE_TREE}
            and record["successorPacket"] == SUCCESSOR,
            "accepted successor identity")
    sha(record["bridgeNormalizedSha256"])
    bridge = regular_bytes(ROOT, BRIDGE_PATH)
    literal = ('AUTHORITY_SHA256 = "' + AUTHORITY_SHA256 + '"').encode()
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(bridge.count(literal) == 1
            and digest(bridge.replace(literal, placeholder))
            == record["bridgeNormalizedSha256"], "normalized bridge digest")
    return record


def validated_predecessor() -> dict[str, tuple[bytes, int]]:
    record = authority()
    baseline, changed, added = (record[name] for name in
                                ("baselineFiles", "changedFiles", "newFiles"))
    require(all(type(value) is dict for value in (baseline, changed, added)),
            "closed file mappings")
    require(len(baseline) == 637 and set(changed) <= set(baseline)
            and not set(added) & set(baseline)
            and not {AUTHORITY_PATH, BRIDGE_PATH} & (set(baseline) | set(added)),
            "accepted file membership")
    predecessor: dict[str, tuple[bytes, int]] = {}
    for path, spec in baseline.items():
        checked_path(path)
        require(type(spec) is dict and set(spec) == {"sha256", "mode"}
                and spec["mode"] in ("100644", "100755"),
                "accepted file mode")
        sha(spec["sha256"])
        current = regular_bytes(ROOT, path, expected_mode=(
            0o755 if spec["mode"] == "100755" else 0o644))
        if path in changed:
            rule = changed[path]
            require(type(rule) is dict
                    and set(rule) == {"afterSha256", "beforeZlibBase64"},
                    "closed changed-file rule")
            sha(rule["afterSha256"])
            require(digest(current) == rule["afterSha256"],
                    "changed current source: " + path)
            previous = predecessor_bytes(rule["beforeZlibBase64"], spec["sha256"])
            require(current != previous, "no-op changed source")
        else:
            require(digest(current) == spec["sha256"],
                    "unchanged accepted source: " + path)
            previous = current
        predecessor[path] = (previous, 0o755 if spec["mode"] == "100755" else 0o644)
    for path, expected in added.items():
        checked_path(path)
        require(type(expected) is dict and set(expected) == {"sha256", "mode"}
                and expected["mode"] in ("100644", "100755"),
                "closed new-file mode")
        sha(expected["sha256"])
        mode = 0o755 if expected["mode"] == "100755" else 0o644
        require(digest(regular_bytes(ROOT, path, expected_mode=mode)) == expected["sha256"],
                "new source drift: " + path)
    old_packets = {Path(path).stem for path in baseline
                   if path.startswith("task-packets/") and path.endswith(".yaml")}
    require(len(old_packets) == 189 and SUCCESSOR not in old_packets
            and set((ROOT / "task-packets").glob("*.yaml"))
            == {ROOT / "task-packets" / (name + ".yaml")
                for name in old_packets | {SUCCESSOR}},
            "exact current packet catalog")
    require("task-packets/" + SUCCESSOR + ".yaml" in added,
            "successor packet is new source")
    packet = safe_load(regular_bytes(ROOT, "task-packets/" + SUCCESSOR + ".yaml"))
    require(packet["id"] == SUCCESSOR
            and packet["repository"] == "Harness-Engineering"
            and packet["predecessors"] == ["MET-LINUX-002", "MET-UNIFY-005"],
            "successor packet contract")
    allowed = packet["allowedPaths"]
    require(type(allowed) is list and len(allowed) == len(set(allowed))
            and all(type(scope) is str and scope for scope in allowed),
            "closed packet allowed paths")
    require(all(any(path == scope or (scope.endswith("/") and path.startswith(scope))
                    for scope in allowed)
                for path in set(changed) | set(added) | {AUTHORITY_PATH, BRIDGE_PATH}),
            "unowned successor source")
    require(git_tree_oid(predecessor) == BASE_TREE, "accepted Git tree identity")
    return predecessor


def materialize_predecessor(destination: Path) -> None:
    """Create a checked 189-source tree; do not copy Git or unrelated files."""
    require(destination.is_absolute() and not destination.exists()
            and not destination.is_symlink()
            and destination.parent.resolve(strict=True) == destination.parent
            and destination.parent.lstat().st_uid == os.getuid(),
            "fresh predecessor destination")
    source = validated_predecessor()
    destination.mkdir(mode=0o700)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    root_fd = os.open(destination, directory_flags)
    try:
        root_stat = os.fstat(root_fd)
        for path, (raw, mode) in source.items():
            parts = checked_path(path)
            with ExitStack() as opened:
                parent_fd = root_fd
                for part in parts[:-1]:
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent_fd)
                    except FileExistsError:
                        pass
                    child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
                    opened.callback(os.close, child_fd)
                    parent_fd = child_fd
                file_fd = os.open(parts[-1], file_flags, mode, dir_fd=parent_fd)
                opened.callback(os.close, file_fd)
                view = memoryview(raw)
                while view:
                    written = os.write(file_fd, view)
                    require(written > 0, "projected source write stalled")
                    view = view[written:]
                os.fchmod(file_fd, mode)
        named_root = destination.lstat()
        require((root_stat.st_dev, root_stat.st_ino) == (named_root.st_dev, named_root.st_ino)
                and stat.S_ISDIR(named_root.st_mode), "projected root replaced")
    finally:
        os.close(root_fd)
    # Verify the completed copy, not only the bytes read before creation.
    require(all(digest(regular_bytes(destination, path)) == digest(raw)
                for path, (raw, _) in source.items()), "projected source changed")


if __name__ == "__main__":
    validated_predecessor()
    print("Enumerated successor source valid; 189 exact predecessor packets retained; no CI or native PASS.")
