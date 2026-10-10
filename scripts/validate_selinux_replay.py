#!/usr/bin/env python3
"""Validate the MET-PERF-036 SELinux replay changes and the exact 217-to-216 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import copy
import hashlib
import json
import stat
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
    import validate_sector_catalog as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_sector_catalog as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/selinux-replay-authority.json"
AUTHORITY_SHA256 = "cdc4535db69bb9b784980ef1e1c2ed8dac2d6a80a12408ddf0bc8177001e2edf"
VALIDATOR_PATH = "scripts/validate_selinux_replay.py"
BASE_COMMIT = "1d107e4ac906fcd93c617d26d523c01b0e72bce1"
NEW_PACKET = "MET-PERF-036"
PREVIOUS_PACKET = "MET-PERF-035"
MAX_FILE_BYTES = 16_777_216
# Test routes cover the top-level ci/test_ files as well as tests/.
TEST_PREFIXES = ("tests/", "ci/test_")


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
            require(key not in result, "duplicate selinux-replay authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite selinux-replay authority number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _path(path: Any) -> None:
    require(type(path) is str and bool(path) and not path.startswith("/")
            and "\\" not in path and not any(ord(char) < 32 for char in path)
            and all(part not in ("", ".", "..") for part in path.split("/")),
            "relative source path")


def regular_bytes(path: str) -> bytes:
    _path(path)
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
        require(digest(raw) == AUTHORITY_SHA256, "SELinux replay history authority digest")
        if type(raw) is bytes:
            _VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw)
    return raw


def fresh_authority() -> None:
    """Re-read the complete pinned authority without reparsing its JSON."""
    _checked_authority_raw()


def _sha(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def authority() -> dict[str, Any]:
    value = parse(_checked_authority_raw())
    require(type(value) is dict and set(value) == {
        "schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets",
        "packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256",
    }, "closed SELinux replay history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/selinux-replay-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 216
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 216-packet base")
    for name, expected in value["baselinePackets"].items():
        require(type(name) is str and name and "/" not in name
                and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for char in name)
                and _sha(expected), "predecessor packet identity")
    for path, expected in value["newFiles"].items():
        _path(path)
        require(_sha(expected), "new source digest")
    for path in value["changedFiles"]:
        _path(path)
    special = {AUTHORITY_PATH, VALIDATOR_PATH, "task-packets/" + NEW_PACKET + ".yaml"}
    require(not (set(value["changedFiles"]) & set(value["newFiles"]))
            and not (special & (set(value["changedFiles"]) | set(value["newFiles"])))
            and all(not path.startswith("task-packets/") or path == "task-packets/README.md"
                    for path in set(value["changedFiles"]) | set(value["newFiles"])),
            "disjoint source routes and immutable predecessor packets")
    return value


def _base64(value: Any) -> bytes:
    require(type(value) is str, "inverse hunk encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("inverse hunk encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical inverse hunk")
    return raw


def _rules() -> MappingProxyType:
    changed = authority()["changedFiles"]
    frozen = {}
    for path, rule in changed.items():
        require(type(rule) is dict
                and set(rule) == {"beforeSha256", "afterSha256", "reverseHunks"}
                and _sha(rule["beforeSha256"]) and _sha(rule["afterSha256"])
                and rule["beforeSha256"] != rule["afterSha256"]
                and type(rule["reverseHunks"]) is list
                and 0 < len(rule["reverseHunks"]) <= 4096, "closed inverse route")
        hunks = []
        prior_at, prior_end, total = -1, 0, 0
        for hunk in rule["reverseHunks"]:
            require(type(hunk) is dict
                    and set(hunk) == {"at", "removeBase64", "insertBase64"}
                    and type(hunk["at"]) is int
                    and 0 <= hunk["at"] <= MAX_FILE_BYTES
                    and prior_at < hunk["at"] and hunk["at"] >= prior_end,
                    "ordered inverse hunk")
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            require(removed != inserted, "effective inverse hunk")
            total += len(removed) + len(inserted)
            require(total <= MAX_FILE_BYTES and hunk["at"] + len(removed) <= MAX_FILE_BYTES,
                    "bounded inverse payload")
            hunks.append((hunk["at"], removed, inserted))
            prior_at, prior_end = hunk["at"], hunk["at"] + len(removed)
        frozen[path] = MappingProxyType({"beforeSha256": rule["beforeSha256"],
                                         "afterSha256": rule["afterSha256"],
                                         "reverseHunks": tuple(hunks)})
    return MappingProxyType(frozen)


_PROJECTION_RULES = _rules()


def _packet_byte_rules() -> MappingProxyType:
    record = authority()
    return MappingProxyType(dict(record["baselinePackets"],
                                 **{NEW_PACKET: record["packetSha256"]}))


_PACKET_BYTE_RULES = _packet_byte_rules()


def _new_packet_rule() -> tuple[str, str]:
    checksum = _PACKET_BYTE_RULES[NEW_PACKET]
    raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(raw) == checksum, "packet YAML drift: " + NEW_PACKET)
    return checksum, digest(canonical(safe_load(raw)))


_NEW_PACKET_RULE = _new_packet_rule()


@lru_cache(maxsize=1)
def _packet_rules_for(source_root: Path, authority_sha: str) -> MappingProxyType:
    """Freeze expected payload digests once per exact source-root/authority pin."""
    require(source_root == ROOT and authority_sha == AUTHORITY_SHA256,
            "packet source identity changed")
    _checked_authority_raw()
    own_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(own_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    rules = {NEW_PACKET: _NEW_PACKET_RULE}
    for name, checksum in _PACKET_BYTE_RULES.items():
        if name == NEW_PACKET:
            continue
        raw = regular_bytes("task-packets/" + name + ".yaml")
        require(digest(raw) == checksum, "packet YAML drift: " + name)
        rules[name] = (checksum, digest(canonical(safe_load(raw))))
    return MappingProxyType(rules)


def _packet_rules() -> MappingProxyType:
    return _packet_rules_for(ROOT, AUTHORITY_SHA256)


# Only expected parsed-data digests are cached, never a validation verdict.
# Historical traversal checks just this layer's packet. Full payload validation
# hashes every supplied packet anew, and validate() rereads every on-disk YAML.


def _inverse(raw: bytes, hunks: tuple[tuple[int, bytes, bytes], ...]) -> bytes:
    cursor, chunks = 0, []
    for at, removed, inserted in hunks:
        require(type(at) is int and cursor <= at and at + len(removed) <= len(raw),
                "inverse hunk bounds")
        require(raw[at:at + len(removed)] == removed, "inverse hunk current bytes")
        chunks.extend((raw[cursor:at], inserted))
        cursor = at + len(removed)
    chunks.append(raw[cursor:])
    before = b"".join(chunks)
    require(len(before) <= MAX_FILE_BYTES, "bounded predecessor bytes")
    return before


def historical_bytes(path: str, raw: bytes) -> bytes:
    """Undo the newer successor, then this step; every authority is read once."""
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
    rule = _PROJECTION_RULES.get(path)
    # An exact 216-era byte string is already older than the successor layer.
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
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    raw = successor.historical_test_bytes(raw)
    _checked_own_authority_raw()
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
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
    """Remove only this layer, leaving predecessor checks to their owners."""
    packets = successor.historical_catalog(packets)
    _checked_own_authority_raw()
    require(type(packets) is dict, "packet mapping")
    current_ids = set(_PACKET_BYTE_RULES)
    require(NEW_PACKET in current_ids and set(packets) == current_ids,
            "unexpected packet addition or loss")
    packet_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(packet_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    try:
        supplied_sha = digest(canonical(packets[NEW_PACKET]))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("changed packet payload: " + NEW_PACKET) from exc
    require(supplied_sha == _NEW_PACKET_RULE[1],
            "changed packet payload: " + NEW_PACKET)
    return {name: packets[name] for name in current_ids - {NEW_PACKET}}


def validate_packet_payloads(packets: dict[str, Any]) -> None:
    """Check all current payloads separately from the inherited traversal."""
    record = authority()
    rules = _packet_rules()
    require(type(packets) is dict, "packet mapping")
    old = set(record["baselinePackets"])
    require(set(packets) == old | {NEW_PACKET}, "unexpected packet addition or loss")
    require(set(rules) == old | {NEW_PACKET}
            and all(rules[name][0] == expected
                    for name, expected in record["baselinePackets"].items())
            and rules[NEW_PACKET][0] == record["packetSha256"],
            "pinned packet data inventory")
    for name, (_byte_sha, payload_sha) in rules.items():
        try:
            supplied_sha = digest(canonical(packets[name]))
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("changed packet payload: " + name) from exc
        require(supplied_sha == payload_sha, "changed packet payload: " + name)


# MET-PERF-036 (roadmap PERF-SEL) cuts the SELinux layer tests' cost without changing any validator refusal: each layer's
# vector replay is split into per-row helpers whose conjunction, in the old order and with the old messages, is the old
# replay; the weakening tests call the conjunct that checks the changed row; the full replay runs inside validate() and
# no longer again in a second test, which pins that route and drives one refusal through it. Nothing is cached.
# Repository bytes are read only through reviewed_bytes. Every changed function, test and test table is pinned by its
# exact whole lines, and each route from validate() to the vector replay is an unconditional top-level call.
SOURCE_PINS = {'scripts/validate_selinux_matrix.py': {'check_vector_keys': '24865e12681a71660064cb1947c2c2cba5bb808ed742d3382886cefb2672771d', 'check_access_row': '7d2f9a5e1cb16c167514c448f9aa0d8bfbd32aba6ee0c8d3873e263a20813cea', 'check_mutation_row': '4aff663580cd57a5699bbe316ad20c7ae1fb5ce4e7e252064f77ff65c8920455', 'check_vector_inventory': '8cd496549ab67d45c4c23ee63d98b95375a6423471a69def8e109e1b1c1081d6', 'replay_vectors': '7f79baef2b87a122927bfdb9e6c966ccd30ec7c5a81971618ad3b7adbe810b6f', 'validate_vectors': '055b7dd6258156e8a4199122cecc8261376f9ae603af5aebc0f22befbdcfb121'}, 'scripts/validate_selinux_matrix_v2.py': {'check_v4_vector_keys': '44bddfd2070c06a9e9e53f188d04367428f863f5140e33eaf8c369a0133ba199', 'check_access_row': '7d2f9a5e1cb16c167514c448f9aa0d8bfbd32aba6ee0c8d3873e263a20813cea', 'check_mutation_row': '477b76b42710c294383d9daad834a8ac45a3203c0a89a80a544e5d74538c45aa', 'check_v4_vector_inventory': '979a4598b1318c6637498ca116706d633954bee9ebb7a91393cc378d7cce2c57', 'replay_v4_vectors': 'f30aa782298093f6aa0aa3d392ef2e92bc10f366af806229233b27d4cf0c4182', 'validate_v4_vectors': '2f99a923d56637b8f87410e4ecced8b41820e71d8313ae45ee20be2eb3f9d697'}, 'tests/test_selinux_matrix.py': {'test_every_vector_replays_and_every_assertion_holds': 'fe7d424462b3d9b41552f1b0a2dc6cbaf27921e8e9a2077338649e5cbed2c6c8', '<assign WEAKENINGS>': '04b6e42bb50c120f6d5d99021e11bc136a1c0c1b8b0cda429c2d22d321e1126e', 'test_vectors_cannot_be_weakened': '691c804962e76d9cab3bd68b466b09cca309e3f300afecd93f900301959298ef', 'test_full_replay_is_exactly_the_conjunction_of_the_helpers': 'a05e2463e86fcdf2c16c5ceb6a1e987bc3bfa8cb6060ae814eecb97035359230', 'test_full_replay_refuses_with_the_first_weakened_rows_message': 'b42d67a56f56af955beee4c58c5b54b810768a46972cae30f53f5a533c88f007', 'test_vector_refusal_reaches_the_contract_route': '6ebed3b08d338d03c06cebfa9e2decad2850785814fa6dbc43f3c7162329abc6'}, 'tests/test_selinux_matrix_v2.py': {'test_matrix_v4_replays_and_adoption_follows_the_review': 'e7984cfc6b4bb6065323c914ec099bdf565002a0de631884de75787bd1a7330b', '<assign WEAKENINGS>': '3a9af4be0aef19e99de93920088e38e9a1e8b61b3973444e1ff8bf99f20e847d', 'test_v4_vectors_cannot_be_weakened': 'c6bad31f0061cdfb2361515ac202643f190c057f3998d3e105ff3c135e38d7fb', 'test_full_replay_is_exactly_the_conjunction_of_the_helpers': '2258be820d9a7cb70c183622e31ddd4105328e3260dec8d6876a4ba79fc43e0b', 'test_full_replay_refuses_with_the_first_weakened_rows_message': '655c94be9fe71f0ea481347ee635b0dc28e256a28850c5cdf97b882470a85e98', 'test_vector_refusal_reaches_the_contract_route': 'c4c754ab812388e634326adecd19510e265b088af0be4f1b917fdbe8b93f4dc0', 'test_reviewed_bytes_is_the_only_semantic_read': '3b1d6d090b314b951f1d8dfc326ffb2e7419e47fc48d637a3793eb2fd8d0336c'}}
# (file, function, the call that must be an unconditional top-level statement of its body)
ROUTE_CALLS = (("scripts/validate_selinux_matrix.py", "validate", "validate_selinux_contract"),
               ("scripts/validate_selinux_matrix.py", "validate_selinux_contract", "validate_vectors"),
               ("scripts/validate_selinux_matrix_v2.py", "validate", "validate_selinux_matrix_v2"),
               ("scripts/validate_selinux_matrix_v2.py", "validate_selinux_matrix_v2", "validate_v4_vectors"))


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _whole(raw: str, node: ast.stmt) -> bytes:
    """The exact whole lines of a definition or assignment, decorators included."""
    lines = raw.splitlines(keepends=True)
    first = min([node.lineno] + [decorator.lineno for decorator in getattr(node, "decorator_list", [])])
    return "".join(lines[first - 1:node.end_lineno]).encode("utf-8")


def _definitions(tree: ast.Module, path: str) -> dict:
    named = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            name = node.name
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = "<assign %s>" % node.targets[0].id
        else:
            continue
        require(name not in named, "one definition per pinned name: %s %s" % (path, name))
        named[name] = node
    return named


def validate_selinux_replay_sources() -> None:
    """Every pinned helper, test and test table is exactly its reviewed text."""
    for path, pins in SOURCE_PINS.items():
        raw = reviewed_bytes(path).decode("utf-8")
        named = _definitions(ast.parse(raw), path)
        for name, expected in pins.items():
            node = named.get(name)
            require(node is not None, "pinned replay source present: %s %s" % (path, name))
            require(digest(_whole(raw, node)) == expected, "unreviewed replay source: %s %s" % (path, name))


def validate_selinux_replay_routes() -> None:
    """validate() reaches each layer's vector replay through unconditional top-level calls (review R3-F1)."""
    for path, function, call in ROUTE_CALLS:
        named = _definitions(ast.parse(reviewed_bytes(path).decode("utf-8")), path)
        node = named.get(function)
        require(isinstance(node, ast.FunctionDef), "route function present: %s %s" % (path, function))
        top = [statement for statement in node.body if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
               and isinstance(statement.value.func, ast.Name) and statement.value.func.id == call]
        require(len(top) == 1 and not any(isinstance(inner, (ast.Return, ast.Yield, ast.YieldFrom)) for inner in ast.walk(node)),
                "unconditional top-level route call: %s %s -> %s" % (path, function, call))


def validate_selinux_replay() -> None:
    validate_selinux_replay_sources()
    validate_selinux_replay_routes()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "SELinux replay validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 225
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 225-packet catalog retaining the 217-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
            continue
        raw = regular_bytes("task-packets/" + path.name)
        expected = record["packetSha256"] if path.stem == NEW_PACKET else record["baselinePackets"][path.stem]
        require(digest(raw) == expected, "packet YAML drift: " + path.stem)
        packets[path.stem] = safe_load(raw)
    validate_packet_payloads(packets)
    packet = packets[NEW_PACKET]
    previous = packets[PREVIOUS_PACKET]
    commands = packet["offlineAcceptanceCommands"]
    require(packet["id"] == NEW_PACKET and packet["repository"] == "Harness-Engineering"
            and packet["predecessors"] == [PREVIOUS_PACKET]
            and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
            and packet["sourceReuse"] == packet["prefetchCommands"] == []
            and packet["offlineExecution"] == previous["offlineExecution"]
            and "liveCampaignExecution" not in packet
            and len(commands) == 64
            and commands == previous["offlineAcceptanceCommands"]
            and not any(VALIDATOR_PATH in argv for argv in commands),
            "closed source-only selinux-replay packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted selinux-replay packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_selinux_replay()


if __name__ == "__main__":
    validate()
    print("SELinux replay valid: 225 current specifications; 217-packet checkpoint and exact 216-packet predecessor; validator refusals and freshness unchanged.")
