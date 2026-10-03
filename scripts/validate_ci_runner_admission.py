#!/usr/bin/env python3
"""Validate the CI exception after the exact 194-to-193-to-192-to-191-to-190-to-189 source chain."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import stat
import zlib
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

if __package__:
    from scripts import validate_packet_schema_performance as successor
else:
    import validate_packet_schema_performance as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/ci-runner-admission-authority.json"
AUTHORITY_SHA256 = "48d6c9bf14fc575399a34457217fcdc84890a089ecc3acccd7943208649afb30"
BASE_COMMIT = "945de93f89c94f42f1d63bff7997e3d0fa704fc4"
NEW_PACKET = "MET-RUNNER-001"
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
            require(key not in result, "duplicate authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite authority number")

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
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "CI runner history authority digest")
        if type(raw) is bytes:
            _VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw)
    return raw


def authority() -> dict[str, Any]:
    value = parse(_checked_authority_raw())
    require(type(value) is dict and set(value) == {
        "schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets",
        "packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256",
    }, "closed CI runner history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/ci-runner-admission-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 189
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict,
            "accepted 189-packet base")
    # Older idempotent routes call this public authority directly rather than
    # passing through historical_bytes; they must recheck the newest pin too.
    # Keep the existing local-authority refusal precedence before that check.
    successor.fresh_authority()
    return value


def _sha(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _base64(value: Any) -> bytes:
    require(type(value) is str, "inverse hunk encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError("inverse hunk encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical inverse hunk")
    return raw


def _rules() -> MappingProxyType:
    changed = authority()["changedFiles"]
    frozen = {}
    for path, rule in changed.items():
        require(type(path) is str and type(rule) is dict
                and set(rule) == {"beforeSha256", "afterSha256", "reverseHunks"}
                and _sha(rule["beforeSha256"]) and _sha(rule["afterSha256"])
                and rule["beforeSha256"] != rule["afterSha256"]
                and type(rule["reverseHunks"]) is list
                and 0 < len(rule["reverseHunks"]) <= 4096,
                "closed inverse route")
        hunks = []
        prior_at, prior_end, total = -1, 0, 0
        for hunk in rule["reverseHunks"]:
            require(type(hunk) is dict
                    and set(hunk) == {"at", "removeBase64", "insertBase64"}
                    and type(hunk["at"]) is int
                    and prior_at < hunk["at"] <= MAX_FILE_BYTES
                    and hunk["at"] >= prior_end, "ordered inverse hunk")
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            require(removed != inserted, "effective inverse hunk")
            total += len(removed) + len(inserted)
            require(total <= MAX_FILE_BYTES, "bounded inverse payload")
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
    """Undo the current successor first, then this accepted predecessor step."""
    # The accepted projection is idempotent for its exact 189-era bytes. Keep
    # that inherited behavior without teaching the new 191-to-190 validator
    # anything about the older 190-to-189 inverse.
    rule = _PROJECTION_RULES.get(path)
    if type(raw) is bytes and rule is not None and digest(raw) == rule["beforeSha256"]:
        successor.fresh_authority()
        _checked_authority_raw()
        return raw
    previous = successor.historical_bytes(path, raw)
    _checked_authority_raw()
    return _historical_bytes_this_layer(path, previous)


def _historical_bytes_this_layer(path: str, raw: bytes) -> bytes:
    require(type(raw) is bytes, "source bytes required")
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
    previous = successor.historical_test_bytes(raw)
    _checked_authority_raw()
    require(type(previous) is bytes, "test bytes required")
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith("tests/") and digest(previous) == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _historical_bytes_this_layer(matches[0], previous) if matches else previous


def current_test_bytes(before: bytes) -> bytes:
    _checked_authority_raw()
    require(type(before) is bytes, "test bytes required")
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith("tests/") and digest(before) == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        return successor.current_test_bytes(before)
    current = successor.historical_bytes(matches[0], regular_bytes(matches[0]))
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return successor.current_test_bytes(current)


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    previous = successor.historical_catalog(packets)
    record = authority()
    require(type(previous) is dict, "packet mapping")
    old = set(record["baselinePackets"])
    require(set(previous) == old | {NEW_PACKET}, "unexpected packet addition or loss")
    packet_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(packet_raw) == record["packetSha256"]
            and digest(canonical(previous[NEW_PACKET]))
            == digest(canonical(safe_load(packet_raw))), "changed runner packet")
    return {name: previous[name] for name in old}


def validate() -> None:
    successor.validate()
    record = authority()
    validator_raw = successor.historical_bytes(
        "scripts/validate_ci_runner_admission.py",
        regular_bytes("scripts/validate_ci_runner_admission.py"))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "runner validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 194
            and {path.stem for path in paths}
            == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET,
                      successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET},
            "closed 194-to-193-to-192-to-191-to-190-to-189 packet catalog")
    for name, expected in record["baselinePackets"].items():
        require(digest(regular_bytes("task-packets/" + name + ".yaml")) == expected,
                "changed predecessor YAML: " + name)
    packet_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(packet_raw) == record["packetSha256"], "runner packet YAML drift")
    packet = safe_load(packet_raw)
    previous = safe_load(regular_bytes("task-packets/MET-UNIFY-005.yaml"))
    commands = packet["offlineAcceptanceCommands"]
    require(packet["id"] == NEW_PACKET and packet["repository"] == "Harness-Engineering"
            and packet["predecessors"] == ["MET-LINUX-002", "MET-UNIFY-005"]
            and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
            and packet["sourceReuse"] == packet["prefetchCommands"] == []
            and packet["offlineExecution"] == previous["offlineExecution"]
            and "liveCampaignExecution" not in packet
            and len(commands) == 52
            and commands[:-3] + commands[-2:] == previous["offlineAcceptanceCommands"]
            and commands[-3] == ["uv", "run", "--offline", "--frozen", "--no-sync",
                                 "python", "scripts/validate_ci_runner_admission.py"],
            "closed source-only runner packet and inherited commands")
    require(set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, "scripts/validate_ci_runner_admission.py",
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted runner packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(_historical_bytes_this_layer(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == expected, "new source drift: " + path)
    for phrase in (b"MET-RUNNER-001", b"pre-checkout", b"single job", b"billing"):
        require(phrase in regular_bytes("docs/alpha-2/CI_CAPACITY_EXCEPTION.md"),
                "missing CI exception term")


if __name__ == "__main__":
    try:
        validate()
    except (ValueError, TypeError, KeyError, OSError, UnicodeError) as exc:
        print("CI runner admission source invalid: " + str(exc))
        raise SystemExit(1)
    print("CI runner admission source valid: 194 current packets; exact 190-to-189 predecessor history; no host or product acceptance.")
