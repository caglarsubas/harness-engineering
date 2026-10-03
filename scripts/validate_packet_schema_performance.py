#!/usr/bin/env python3
"""Validate the source-only schema lifecycle successor and exact 191-to-190 history.

This module handles only the new current-to-accepted source projection. It never
imports or executes a predecessor validator; the accepted runner bridge composes
the next 190-to-189 step separately.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import stat
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
    import validate_linux_runner_contract as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_linux_runner_contract as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/packet-schema-performance-authority.json"
AUTHORITY_SHA256 = "b22765d800ef757891addcd308570efeefaca1637b806fd28008a800c0cdff4f"
BASE_COMMIT = "0314a684ba637fb205856d5fb5e50206071e647a"
NEW_PACKET = "MET-PERF-028"
MAX_FILE_BYTES = 16_777_216


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate schema performance authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite schema performance authority number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def regular_bytes(path: str) -> bytes:
    require(type(path) is str and bool(path) and not path.startswith("/")
            and all(part not in ("", ".", "..") for part in path.split("/")),
            "relative source path")
    parent = ROOT
    for part in path.split("/")[:-1]:
        parent /= part
        require(stat.S_ISDIR(parent.lstat().st_mode), "linked source ancestor")
    target = parent / path.split("/")[-1]
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= MAX_FILE_BYTES, "bounded regular source file")
    raw = target.read_bytes()
    after = target.lstat()
    identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink,
                            row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
            "source changed during read")
    return raw


# Exact bytes most recently proven to hash to the pin. Every call still reads
# the complete file; byte-identical input implies the identical digest, while
# any other bytes or pin are hashed in full before they are accepted.
_VERIFIED_AUTHORITY: tuple[str, bytes] | None = None


def _checked_authority_raw() -> bytes:
    """Newest first: every newer authority, then this one, each read exactly once."""
    successor._checked_authority_raw()
    return _checked_own_authority_raw()


def _checked_own_authority_raw() -> bytes:
    """Fresh complete read of this layer's authority only; callers reach newer
    authorities through exactly one successor route per public call."""
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256,
                "schema performance history authority digest")
        if type(raw) is bytes:
            _VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw)
    return raw


def fresh_authority() -> None:
    """Re-read and hash the complete pinned authority without reparsing its JSON."""
    _checked_authority_raw()


def _sha(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def authority() -> dict[str, Any]:
    value = parse(_checked_authority_raw())
    require(type(value) is dict and set(value) == {
        "schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets",
        "packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256",
    }, "closed schema performance history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/packet-schema-performance-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 190
            and all(type(name) is str and _sha(expected)
                    for name, expected in value["baselinePackets"].items())
            and _sha(value["packetSha256"])
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and all(type(path) is str and _sha(expected)
                    for path, expected in value["newFiles"].items())
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 190-packet base")
    return value


def _base64(value: Any) -> bytes:
    require(type(value) is str, "inverse hunk encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError("inverse hunk encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value,
            "noncanonical inverse hunk")
    return raw


def _rules() -> MappingProxyType:
    record = authority()
    changed = record["changedFiles"]
    require(set(changed).isdisjoint(record["newFiles"]),
            "overlapping new and changed source")
    frozen = {}
    for path, rule in changed.items():
        require(type(path) is str and type(rule) is dict
                and set(rule) == {"beforeSha256", "afterSha256", "reverseHunks"}
                and _sha(rule["beforeSha256"]) and _sha(rule["afterSha256"])
                and rule["beforeSha256"] != rule["afterSha256"]
                and type(rule["reverseHunks"]) is list
                and 0 < len(rule["reverseHunks"]) <= 4096,
                "closed schema performance inverse route")
        hunks = []
        prior_at, prior_end, total = -1, 0, 0
        for hunk in rule["reverseHunks"]:
            require(type(hunk) is dict
                    and set(hunk) == {"at", "removeBase64", "insertBase64"}
                    and type(hunk["at"]) is int
                    and prior_at < hunk["at"] <= MAX_FILE_BYTES
                    and hunk["at"] >= prior_end, "ordered schema performance inverse hunk")
            removed = _base64(hunk["removeBase64"])
            inserted = _base64(hunk["insertBase64"])
            require(removed != inserted, "effective schema performance inverse hunk")
            total += len(removed) + len(inserted)
            require(total <= MAX_FILE_BYTES, "bounded schema performance inverse payload")
            hunks.append((hunk["at"], removed, inserted))
            prior_at, prior_end = hunk["at"], hunk["at"] + len(removed)
        frozen[path] = MappingProxyType({"beforeSha256": rule["beforeSha256"],
                                         "afterSha256": rule["afterSha256"],
                                         "reverseHunks": tuple(hunks)})
    return MappingProxyType(frozen)


_PROJECTION_RULES = _rules()


def _inverse(raw: bytes, hunks: tuple[tuple[int, bytes, bytes], ...]) -> bytes:
    cursor, chunks = 0, []
    for at, removed, inserted in hunks:
        require(cursor <= at and at + len(removed) <= len(raw), "inverse hunk bounds")
        require(raw[at:at + len(removed)] == removed, "inverse hunk current bytes")
        chunks.extend((raw[cursor:at], inserted))
        cursor = at + len(removed)
    chunks.append(raw[cursor:])
    before = b"".join(chunks)
    require(len(before) <= MAX_FILE_BYTES, "bounded predecessor bytes")
    return before


def historical_bytes(path: str, raw: bytes) -> bytes:
    """Undo the newer successors, then this step; every authority is read once."""
    require(type(raw) is bytes, "source bytes required")
    rule = _PROJECTION_RULES.get(path)
    # An exact 190-era byte string is already older than the successor layer.
    # Every newer authority and this one are still rechecked before this fast return.
    if rule is not None and digest(raw) == rule["beforeSha256"]:
        _checked_authority_raw()
        return raw
    # The successor route freshly rechecks every newer authority exactly once.
    raw = successor.historical_bytes(path, raw)
    _checked_own_authority_raw()
    return _undo_this_layer(path, raw)


def _undo_this_layer(path: str, raw: bytes) -> bytes:
    """Apply only this layer's reviewed inverse; callers have already rechecked authorities."""
    rule = _PROJECTION_RULES.get(path)
    if rule is None:
        return raw
    current_sha = digest(raw)
    require(current_sha in (rule["beforeSha256"], rule["afterSha256"]),
            "unreviewed current source: " + path)
    if current_sha == rule["beforeSha256"]:
        return raw
    before = _inverse(raw, rule["reverseHunks"])
    require(digest(before) == rule["beforeSha256"], "predecessor bytes: " + path)
    return before


def historical_test_bytes(raw: bytes) -> bytes:
    require(type(raw) is bytes, "test bytes required")
    raw = successor.historical_test_bytes(raw)
    _checked_own_authority_raw()
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith("tests/") and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    require(type(before) is bytes, "test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith("tests/") and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        current = successor.current_test_bytes(before)
        _checked_own_authority_raw()
        return current
    current = successor.historical_bytes(matches[0], regular_bytes(matches[0]))
    _checked_own_authority_raw()
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return successor.current_test_bytes(current)


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Require this exact added packet without pre-validating old fixture payloads."""
    record = authority()
    packets = successor.historical_catalog(packets)
    require(type(packets) is dict, "packet mapping")
    old = set(record["baselinePackets"])
    require(set(packets) == old | {NEW_PACKET}, "unexpected packet addition or loss")
    packet_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(packet_raw) == record["packetSha256"]
            and digest(canonical(packets[NEW_PACKET]))
            == digest(canonical(safe_load(packet_raw))),
            "changed schema performance packet")
    return {name: packets[name] for name in old}


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(
        "scripts/validate_packet_schema_performance.py",
        regular_bytes("scripts/validate_packet_schema_performance.py"))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "' + b"TO_BE_PINNED_AFTER_SOURCE_FREEZE" + b'"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"],
            "schema performance validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 194
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET,
                                                         successor.successor.successor.NEW_PACKET},
            "closed 194-packet catalog retaining the 191-packet checkpoint")
    for name, expected in record["baselinePackets"].items():
        require(digest(regular_bytes("task-packets/" + name + ".yaml")) == expected,
                "changed predecessor YAML: " + name)
    packet_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(packet_raw) == record["packetSha256"],
            "schema performance packet YAML drift")
    packet = safe_load(packet_raw)
    previous = safe_load(regular_bytes("task-packets/MET-RUNNER-001.yaml"))
    commands = packet["offlineAcceptanceCommands"]
    require(packet["id"] == NEW_PACKET
            and packet["repository"] == "Harness-Engineering"
            and packet["predecessors"] == ["MET-PERF-018", "MET-RUNNER-001", "MET-LINUX-002"]
            and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
            and packet["sourceReuse"] == packet["prefetchCommands"] == []
            and packet["offlineExecution"] == previous["offlineExecution"]
            and "liveCampaignExecution" not in packet
            and len(commands) == 53
            and commands[:-3] + commands[-2:] == previous["offlineAcceptanceCommands"]
            and commands[-3] == ["uv", "run", "--offline", "--frozen", "--no-sync",
                                 "python", "scripts/validate_packet_schema_performance.py"],
            "closed source-only schema performance packet and inherited commands")
    require(len(packet["allowedPaths"]) == 113
            and len(set(packet["allowedPaths"])) == 113
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"])
            | {AUTHORITY_PATH, "scripts/validate_packet_schema_performance.py",
               "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted schema performance packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)


if __name__ == "__main__":
    try:
        validate()
    except (ValueError, TypeError, KeyError, OSError, UnicodeError) as exc:
        print("Schema performance source invalid: " + str(exc))
        raise SystemExit(1)
    print("Schema performance source valid: 194 current packets; 191-packet checkpoint and 190 immutable predecessors; no runtime acceptance.")
