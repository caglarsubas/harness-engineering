#!/usr/bin/env python3
"""Validate the MET-ENFORCE-019 W03-0 backend distribution selection and plan, and the exact 221-to-220 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import builtins
import copy
import hashlib
import json
import stat
import types
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
    import validate_seccomp_v3 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_seccomp_v3 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/backend-distribution-authority.json"
AUTHORITY_SHA256 = "8300bd32f701040cdce3c3f403df05d1870114d9823e6d7149b51502ce63d6e4"
VALIDATOR_PATH = "scripts/validate_backend_distribution.py"
BASE_COMMIT = "195c4c98e7142a08ab34a62ceaf7c07a2f2da687"
NEW_PACKET = "MET-ENFORCE-019"
PREVIOUS_PACKET = "MET-ENFORCE-018"
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
            require(key not in result, "duplicate backend-distribution authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite backend-distribution authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "backend distribution history authority digest")
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
    }, "closed backend distribution history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/backend-distribution-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 220
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 220-packet base")
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
    # An exact 220-era byte string is already older than the successor layer.
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


# MET-ENFORCE-019 (roadmap W03-0) publishes the W03 backend distribution selection and the W03 plan (owner decisions Q1,
# Q2, Q3, Q4, Q5, Q-L, Q-L2, Q-L3, Q-E, Q-N and Q-S, via the lane monitor). Repository bytes are read only through
# reviewed_bytes, so a later bridged successor projects its own edits away first. Every reviewed file of this era is bound
# by digest before anything is parsed, and both reference modules are executed from this era's reviewed bytes, not
# imported, together with this era's safe_yaml, so a later revision of any of them cannot change how this layer judges
# its era.
CONTRACT_DIR = "architecture/backend-distribution/"
PLAN_DIR = "architecture/w03-plan/"
SELECTION_MODEL = "scripts/backend_distribution.py"
PLAN_MODEL = "scripts/w03_plan.py"
SAFE_YAML = "scripts/safe_yaml.py"
STATUS_PATH = CONTRACT_DIR + "status.json"
REVIEWED_SUBJECT = {"commit": "104b11529b6448a2c208450e5fbbd677e5dd8069", "tree": "a73a213b495910117d58cdf600a107c9e53a1b8f"}
ROUNDS = ((1, "CHANGES_REQUIRED"), (2, "CHANGES_REQUIRED"), (3, "CHANGES_REQUIRED"), (4, "CHANGES_REQUIRED"),
          (5, "PASS_FOR_SOURCE_PUBLICATION"))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "harness.planeon.ai/w03-selection-review/v1"
STATUS_KEYS = ("schemaVersion", "workItem", "status", "reviewedSubject", "rebase", "rounds", "carried", "nonClaims")
ROW_KEYS = ("round", "subject", "subjectTree", "verdict", "record", "snapshot", "severities")
SEVERITIES = ("MAJOR", "MINOR", "NOTE")
NON_CLAIMS = ["No artifact is installed or executed.", "No I06 evidence record exists.", "E01-E12 stay OPEN_UNPROVEN.",
              "Not native or tenant acceptance."]
SELECTION_DECISIONS = {"Q4": "a", "Q-L": "L-a", "Q-L2": "L2-a", "Q-L3": "L3-a", "Q-E": "E-a", "Q-N": "N-a"}
PLAN_DECISIONS = {"Q1": "a", "Q2": "a", "Q3": "a", "Q5": "a", "Q-L3": "L3-a", "Q-S": "S-b"}
# The adopted bytes (f38487e) of every reviewed file, round copy and review record, the status record, both reference
# modules, and the safe_yaml the selection module imports.
ERA_SHA256 = MappingProxyType({
    "architecture/backend-distribution/README.md": "86a44a8d56bfa93098e233f90516c180966314eecbe0906dbffb9bf9fe2b7a81",
    "architecture/backend-distribution/REVIEW_BRIEF.md": "07392779790aa3657acc17770ba75662bf10dde54cf9b5b57297d19fdf7c9bf6",
    "architecture/backend-distribution/review-round1.json": "7121854c36005edaf3120de42e2ec6c51acfdc2ed314d7d471e6ea61d99df547",
    "architecture/backend-distribution/review-round2.json": "2d58ad8885952adbf816bbffb4adfcdce9ffee84f11129b7ac1bb209feb5e1f7",
    "architecture/backend-distribution/review-round3.json": "9a4c6a78ccc206b27e2d18fdcd5d5ebec785bee7011f2c7ad711a2cfdae38bf8",
    "architecture/backend-distribution/review-round4.json": "77e40813c9914c45ceaf397d0fef6ba890732faf2d9c5e5adb90987e5bdfe403",
    "architecture/backend-distribution/review-round5.json": "277c45930217b8d870393dcbc84e0be4e41809275dff769e8292327ab8842cc8",
    "architecture/backend-distribution/round1/README.md": "ef9f72e73f7c75dd00704d533c6255b7d01373def1ebb72cb1be1fc91b91a74c",
    "architecture/backend-distribution/round1/REVIEW_BRIEF.md": "349ae57cc05fa7c965a2776bdee4a781d3b3906790a42cfc750c081194538509",
    "architecture/backend-distribution/round1/scripts/backend_distribution.py": "510b003fbfe822f5e161ba83255653083a024a466e681a2c8744def44b1ee171",
    "architecture/backend-distribution/round1/selection.json": "69d2d563b29fe03565f0d005396a1fedce2ea52fb925bc5d9fd15711e510e06a",
    "architecture/backend-distribution/round2/README.md": "c9f9c34905b60f1853b617d9249f2ae0ae56cb775891bec849d959f32dfbd8fd",
    "architecture/backend-distribution/round2/REVIEW_BRIEF.md": "ef9c8160432f57882c2e57655f2f3f05c868fbc99f597ba759ccad32faafdca7",
    "architecture/backend-distribution/round2/scripts/backend_distribution.py": "90cf6a7f2227a45c15f02a51c7412df9e4a2b5cef1aff3f413fcf2e8b4dbcc7b",
    "architecture/backend-distribution/round2/scripts/w03_plan.py": "89bc276bcb74f481a697e513dcda66e9b5584e03d2d16ffde785ee01464c33c7",
    "architecture/backend-distribution/round2/selection.json": "45e8e092e09c04c93517b54ce6f37102e8ca84511011f81f08132b950cc8a5cc",
    "architecture/backend-distribution/round2/w03-plan/README.md": "835fe2b5d1a3fde71da02c3ddaf05a333733c483d378c5acdd5ce67d7f0c5039",
    "architecture/backend-distribution/round2/w03-plan/plan.json": "e5e180ef580b2ebc62bf83f542fd98a6726363b5098df4494f5c39e0a16bc3b7",
    "architecture/backend-distribution/round3/README.md": "64c41a3f7e3ac12b4ec6db115ae755e5407c724f2a37a26c9efec20e358c48d3",
    "architecture/backend-distribution/round3/REVIEW_BRIEF.md": "f66bab18e5c2af7a6eeb4842d5ab112571a71fa6b8b5b1b8698aa443f043417e",
    "architecture/backend-distribution/round3/scripts/backend_distribution.py": "fb7ee7268e471f3687e03196760f41e61204390995a72cf3730b04075d1226ae",
    "architecture/backend-distribution/round3/scripts/w03_plan.py": "7e1b7fd39b9767ee6dd13a4bdeb47284aa73941e743a6c52b5896a171b7a3636",
    "architecture/backend-distribution/round3/selection.json": "c08ba6a6123f552d1dd98a5269e0e0fed4bd8bbcb9166c3145dccf73c020bf05",
    "architecture/backend-distribution/round3/w03-plan/README.md": "b4eb2bf9ed84e41e619d12821b081328c75b0632f23d0ab58eca2b8127c3f999",
    "architecture/backend-distribution/round3/w03-plan/plan.json": "a1512984adb6f93e2636359e68098ca7e6988725540bf1ff7b62df6522f24a34",
    "architecture/backend-distribution/round4/README.md": "4dae0d3af3ec023c9d42b5cdacf8aef54ee7332c66d3171caeba582b93404eb9",
    "architecture/backend-distribution/round4/REVIEW_BRIEF.md": "0aedcc276cf151a95dc535c9c4b8308d7561033cebfc0ca23c5980c5a3c5ebdb",
    "architecture/backend-distribution/round4/scripts/backend_distribution.py": "a2aa0580ba93d5fa836cf715a0da16f4642cd65236aae07f6fb436490fa037fa",
    "architecture/backend-distribution/round4/scripts/w03_plan.py": "23b91b2743ae0a0efb70d84d4a06b8ca4117dadb63e1f9ca94c118a8336911bf",
    "architecture/backend-distribution/round4/selection.json": "e5c550cf15621d079d93fe85ec306f7e00bf0128aaff055d9e00b66fa5ac9891",
    "architecture/backend-distribution/round4/w03-plan/README.md": "92825e183ade9a7ee772f6223cc359a42f73b63e6567471c5577e44242029f66",
    "architecture/backend-distribution/round4/w03-plan/plan.json": "5043ba7e5c84b6ee4ebc368e44e419bbb772600b911ef07abda8cb7b743d1948",
    "architecture/backend-distribution/selection.json": "e6750f20a56f76486c24e35114b9e0b204357e51e3f97e560a34c544bf238952",
    "architecture/backend-distribution/status.json": "e46244543ec10024ccf2cc59f31e512e417d632b1d1cbad8011cd3538680e395",
    "architecture/w03-plan/README.md": "bfc7d685de013f7f65d83009b3ef8e8fcd589289dde3fb207870db220d919915",
    "architecture/w03-plan/plan.json": "40b501f48fe0eb13d64d2e0cf7fa542817f0fa3034d86058c233d1a3accaff9a",
    "scripts/backend_distribution.py": "bcdceb73de739a34462a1dcfa6fa3ac2799d8aaaafe69d255739d39d20dc0b47",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7",
    "scripts/w03_plan.py": "357b8e568bfe7e0821a4875a1e4c5f6b50a744a3898a3b6cfac4a8dc7ec71c29"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _json(path: str) -> Any:
    return parse(reviewed_bytes(path))


def _bound(check: Any, message: str) -> None:
    """A structural check over a module's result; a malformed result is refused, not raised."""
    try:
        holds = check()
    except (KeyError, TypeError, AttributeError, IndexError):
        holds = False
    require(holds is True, message)


def _era_import(era: dict) -> Any:
    """An import function that resolves the named modules to this era's executed copies and everything else normally."""
    def era_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in era:
            return era[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    return era_import


def _era_model(path: str, name: str, imports: dict | None = None) -> types.ModuleType:
    """A reference module of this era, executed from its reviewed bytes; named imports resolve to this era's copies."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    if imports:
        namespace = dict(vars(builtins))
        namespace["__import__"] = _era_import(imports)
        module.__dict__["__builtins__"] = namespace
    exec(compile(reviewed_bytes(path), path, "exec"), module.__dict__)
    return module


def validate_era_bytes() -> None:
    """Every reviewed file of this era is bound by digest before anything is parsed or executed."""
    for path, expected in ERA_SHA256.items():
        require(digest(reviewed_bytes(path)) == expected, "W03-0 reviewed bytes are bound: " + path)


def validate_backend_distribution_status() -> None:
    """Adopted after five independent review rounds, each bound to its record, the last a pass on the reviewed subject."""
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == set(STATUS_KEYS)
            and status["schemaVersion"] == "planeon.internal.backend-distribution-status/v1"
            and status["workItem"] == "W03-0" and status["status"] == "ADOPTED_FOR_SOURCE_PUBLICATION"
            and status["reviewedSubject"] == REVIEWED_SUBJECT and status["nonClaims"] == NON_CLAIMS
            and type(status["carried"]) is list and len(status["carried"]) > 0
            and all(type(row) is dict and set(row) == {"item", "to", "action"} for row in status["carried"]),
            "adopted W03-0 status")
    rounds = status["rounds"]
    require(type(rounds) is list and all(type(row) is dict for row in rounds)
            and [(row.get("round"), row.get("verdict")) for row in rounds] == list(ROUNDS), "five review rounds in order")
    for row in rounds:
        number = row["round"]
        require(set(row) == set(ROW_KEYS) and row["record"] == CONTRACT_DIR + "review-round%d.json" % number
                and row["snapshot"] == (CONTRACT_DIR + "round%d/" % number if number < LAST_ROUND else None),
                "review round %d row" % number)
        record = _json(row["record"])
        require(type(record) is dict and record.get("schemaVersion") == REVIEW_SCHEMA and record.get("round") == number
                and record.get("subjectCommit") == row["subject"] and record.get("subjectTree") == row["subjectTree"]
                and record.get("verdict") == row["verdict"], "review round %d identity" % number)
        actions = record.get("actions")
        require(type(actions) is dict and actions.get("filesEdited") is False and actions.get("largeDownloads") == [],
                "review round %d edited nothing" % number)
        findings = record.get("findings")
        require(type(findings) is list and all(type(item) is dict and item.get("severity") in SEVERITIES for item in findings)
                and row["severities"] == sorted({item["severity"] for item in findings}),
                "review round %d severities" % number)
    final = rounds[-1]
    require(final["subject"] == REVIEWED_SUBJECT["commit"] and final["subjectTree"] == REVIEWED_SUBJECT["tree"]
            and final["severities"] == ["NOTE"], "the passing round reviewed this subject and left notes only")


def validate_backend_distribution() -> None:
    """Every reviewed byte and the adoption record first; then both reference modules from this era's reviewed bytes,
    whose results must carry the owner's decisions."""
    validate_era_bytes()
    validate_backend_distribution_status()
    safe_yaml = _era_model(SAFE_YAML, "_met_enforce_019_safe_yaml")
    selection = _era_model(SELECTION_MODEL, "_met_enforce_019_backend_distribution",
                           {"safe_yaml": safe_yaml, "scripts.safe_yaml": safe_yaml}).check(reviewed_bytes)

    def agents() -> list:
        return [part for component in selection["components"] if component["role"] == "NETWORK_POLICY_AGENT"
                for part in component["parts"]]

    _bound(lambda: [(row["id"], row["selected"]) for row in selection["ownerDecisions"]] == list(SELECTION_DECISIONS.items())
           and len(selection["licenseReviews"]) > 0
           and all(row["status"] == "OWNER_APPROVED" for row in selection["licenseReviews"])
           and len(agents()) > 0 and all(len(part["artifacts"]) > 0 for part in agents())
           and all(artifact["kind"] == "SOURCE_BUILD" for part in agents() for artifact in part["artifacts"]),
           "the selection carries the owner's decisions")
    plan = _era_model(PLAN_MODEL, "_met_enforce_019_w03_plan").check(reviewed_bytes)
    _bound(lambda: [(row["id"], row["selected"]) for row in plan["ownerDecisions"]] == list(PLAN_DECISIONS.items()),
           "the plan carries the owner's decisions")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "backend distribution validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 225
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET},
            "closed 225-packet catalog retaining the 221-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only backend-distribution packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted backend-distribution packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_backend_distribution()


if __name__ == "__main__":
    validate()
    print("W03-0 backend distribution valid: 225 current specifications; 221-packet checkpoint and exact 220-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
