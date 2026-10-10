#!/usr/bin/env python3
"""Validate the MET-ENFORCE-021 license-policy amendment LIC-HOST-A1 and the exact 223-to-222 projection."""
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
    import validate_enforcement_test_plan as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_enforcement_test_plan as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/license-amendment-authority.json"
AUTHORITY_SHA256 = "1e56c285b0e4598a86ace4d85fb262688a921783e5ebd51840ca7e610e203613"
VALIDATOR_PATH = "scripts/validate_license_amendment.py"
BASE_COMMIT = "5fab673e250e7dd0f2ce9c19f6ce9da8cce9321c"
NEW_PACKET = "MET-ENFORCE-021"
PREVIOUS_PACKET = "MET-ENFORCE-020"
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
            require(key not in result, "duplicate license-amendment authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite license-amendment authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "license amendment history authority digest")
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
    }, "closed license amendment history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/license-amendment-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 222
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 222-packet base")
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
    # An exact 222-era byte string is already older than the successor layer.
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


# MET-ENFORCE-021 (roadmap LIC-HOST) publishes license-policy amendment LIC-HOST-A1 as a reviewed overlay on the
# byte-identical base policy (owner decisions Q-L, Q-L2 and Q-L3, via the lane monitor). Repository bytes are read only
# through reviewed_bytes, so a later bridged successor projects its own edits away first. Every reviewed file of this era
# is bound by digest before anything is parsed, and the reference module is executed from this era's reviewed bytes,
# together with this era's safe_yaml, so a later revision of either cannot change how this layer judges its era.
AMEND_DIR = "legal/license-policy-amendment/"
MODEL = "scripts/license_amendment.py"
SAFE_YAML = "scripts/safe_yaml.py"
BASE_POLICY = "legal/third-party-license-policy.yaml"
STATUS_PATH = AMEND_DIR + "status.json"
REVIEWED_SUBJECT = {"commit": "c12fa44ccdc07b3ed1df5f0611359d49f2fa2f9f", "tree": "f2f4b2d1d0ea9f7c4e7296595be66a66ff315a75"}
ROUNDS = ((1, "CHANGES_REQUIRED"), (2, "CHANGES_REQUIRED"), (3, "CHANGES_REQUIRED"), (4, "PASS_FOR_SOURCE_PUBLICATION"))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "harness.planeon.ai/license-amendment-review/v1"
STATUS_KEYS = ("schemaVersion", "workItem", "amendmentId", "status", "reviewedSubject", "rounds", "carried", "nonClaims")
ROW_KEYS = ("round", "subject", "subjectTree", "verdict", "record", "snapshot", "severities")
SEVERITIES = ("MAJOR", "MINOR", "NOTE")
NON_CLAIMS = ["The base policy is byte-identical and keeps its outcomes.", "No artifact is released.",
              "Not legal advice; the owner's decisions are the approving authority."]
DECISIONS = (("Q-L", "L-a"), ("Q-L2", "L2-a"), ("Q-L3", "L3-a"))
CLASS_COMPONENTS = ("glibc", "libseccomp", "libgcc", "libgcc_eh", "libnftnl", "libmnl")
ELECTIONS = (("libpathrs", "MPL-2.0"), ("gmp", "LGPL-3.0-or-later"))
VECTORS = 88
# Owner-decided uses the classifier must decide this way (packet review P1-F3): (expression, component, kind, binary it
# is linked into, outcome, elections).
DECIDED_CASES = (
    ("LGPL-2.1-or-later", "glibc", "STATIC_SYSTEM_LIBRARY", "runc", "HOST_OS_SYSTEM_LIBRARY", ()),
    ("LGPL-2.1-or-later", "glibc", "HOST_OS_LIBRARY", None, "HOST_OS_SYSTEM_LIBRARY", ()),
    ("GPL-2.0-or-later", "glibc", "STATIC_SYSTEM_LIBRARY", "runc", "OUT_OF_SCOPE", ()),
    ("LGPL-2.1-only", "libseccomp", "STATIC_SYSTEM_LIBRARY", "runc", "HOST_OS_SYSTEM_LIBRARY", ()),
    ("LGPL-2.1-only", "libseccomp", "STATIC_SYSTEM_LIBRARY", "containerd", "OUT_OF_SCOPE", ()),
    ("GPL-3.0-or-later WITH GCC-exception-3.1", "libgcc", "STATIC_SYSTEM_LIBRARY", "pause", "HOST_OS_SYSTEM_LIBRARY", ()),
    ("GPL-2.0-or-later", "libnftnl", "HOST_OS_LIBRARY", None, "HOST_OS_SYSTEM_LIBRARY", ()),
    ("LGPL-2.1-or-later", "libnftnl", "HOST_OS_LIBRARY", None, "OUT_OF_SCOPE", ()),
    ("GPL-2.0-only", "nft", "HOST_OS_PROGRAM", None, "OPTIONAL_EXPLICIT_REVIEW_APPROVED", ()),
    ("LGPL-3.0-or-later", "gmp", "HOST_OS_LIBRARY", None, "OPTIONAL_EXPLICIT_REVIEW_APPROVED", ()),
    ("MPL-2.0 OR LGPL-3.0-or-later", "libpathrs", "STATIC_SYSTEM_LIBRARY", "runc", "ACCEPTED_OR",
     (("LGPL-3.0-or-later OR MPL-2.0", "MPL-2.0"),)),
    ("LGPL-3.0-or-later OR GPL-2.0-or-later", "gmp", "HOST_OS_LIBRARY", None, "ACCEPTED_OR",
     (("GPL-2.0-or-later OR LGPL-3.0-or-later", "LGPL-3.0-or-later"),)),
    ("MIT AND GPL-2.0-or-later", "glibc", "STATIC_SYSTEM_LIBRARY", "runc", "OUT_OF_SCOPE", ()),
)
# The base policy stays byte-identical: the amendment is an overlay, never an edit.
FROZEN_PATHS = (BASE_POLICY,)
# The adopted bytes (fab6aea) of every reviewed file, round copy and review record, the status record and the reference
# module; the safe_yaml it imports and the base policy it reads (the accepted base).
ERA_SHA256 = MappingProxyType({
    "legal/license-policy-amendment/README.md": "ba204cc0bd86444028355725546d2b0971dfe5d6bef8b06f9f7156dd93380646",
    "legal/license-policy-amendment/REVIEW_BRIEF.md": "6c70d5672446ae5a0739fff0be8cfcd9fe1683f1dc37194653b295ad39fe4251",
    "legal/license-policy-amendment/amendment.json": "f6a8c0796857cf40906df3e6bc483122988b91271cc77b3aaed4d4e213d864c2",
    "legal/license-policy-amendment/review-round1.json": "01c48cf4d3fe5ed2fc4f3695dab9ebe5a98222c8e1973177893cb4c3773a4a2d",
    "legal/license-policy-amendment/review-round2.json": "10133203680941956eaee43dde7628c417834c2148c344ffb4d1bff30558f93c",
    "legal/license-policy-amendment/review-round3.json": "e073b9d6385fa571ff80a4bae7ba9980855c890375a53220469a72241b17fd8c",
    "legal/license-policy-amendment/review-round4.json": "46189374349481dadceed5c631be43ee6ead055dccb23bb17f357be4b48df6a9",
    "legal/license-policy-amendment/round1/README.md": "057078e15b0f694efbe008f69b4a206e717481332129846c1d14e1c9020ea573",
    "legal/license-policy-amendment/round1/REVIEW_BRIEF.md": "12da796fb7c6ff152e0f56be45c43a4c5bfeea8527d342e811899a092749130b",
    "legal/license-policy-amendment/round1/amendment.json": "b99a38851035f6944f1bee6548f5a59625c683594ce1739b9b5d7a77b1bc244e",
    "legal/license-policy-amendment/round1/scripts/license_amendment.py": "34f51249de4270caa64cfbfb84136aa315f28a6a91ae063158151644e64f9cbd",
    "legal/license-policy-amendment/round1/vectors.json": "d53e4bfec04df55014ef6171f5d140eb3b3cee5eac252c4bb8d209365bb58a46",
    "legal/license-policy-amendment/round2/README.md": "ceb46141a8677255067557e1e55d0a3b5b803a422b3ab914585f167a8d6020c0",
    "legal/license-policy-amendment/round2/REVIEW_BRIEF.md": "7bfe81322949c5319fdc3063b88d2fac52c8a5e9e49572312a4dd07b471f011b",
    "legal/license-policy-amendment/round2/amendment.json": "b95016325e35470bd654d6353697ae7aa5625458d3ce2110dee85e921f15f95f",
    "legal/license-policy-amendment/round2/scripts/license_amendment.py": "b944b02edc9bcacc226d16d32850b0f258938ad4549129ba207f4c9fc845e99c",
    "legal/license-policy-amendment/round2/vectors.json": "bf4aa6d0200f5ed443666348f851fa9b74b462e2fdb4247a5dbcd10651190f69",
    "legal/license-policy-amendment/round3/README.md": "86bc4c7bb6eba3dbfac186df7ed0cdd8538ecaae9e966d3edad9943eb024ce54",
    "legal/license-policy-amendment/round3/REVIEW_BRIEF.md": "d4475c1b2f74df031cd444edd771cf4f7f80fc37202e6da748aa4f38ef0b8cd2",
    "legal/license-policy-amendment/round3/amendment.json": "7c956dabbf0c24a00080dfd80483b917ba3d0c588f355a96580867c589a10827",
    "legal/license-policy-amendment/round3/scripts/license_amendment.py": "9f4a1c3766488010964d9f622c2580fb636ade015fe7695964fb51ecbdce9f66",
    "legal/license-policy-amendment/round3/vectors.json": "b4eaaed5852665fd6f2f69808ec4e89bc784b076ccdfac3486f7de5fc38fda99",
    "legal/license-policy-amendment/status.json": "38706b716665b9073ee07e7c77fcdce08f7d39fb2fb03c97a530e40011cad2fc",
    "legal/license-policy-amendment/vectors.json": "fd2af21605c04420f76d148b71cf39e026251931df215e77eafce8c925549b24",
    "legal/third-party-license-policy.yaml": "fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0",
    "scripts/license_amendment.py": "58758a4a7bb6bbcf49daf1880cc423566da306cfd90dceadfa1b4b7c53ec28cd",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read, so every byte parsed or executed is a hashed byte
    (packet review P1-F4); a path outside the era is refused."""
    raw = reviewed_bytes(path)
    expected = ERA_SHA256.get(path)
    require(expected is not None and digest(raw) == expected, "LIC-HOST reviewed bytes are bound: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


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
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_era_bytes() -> None:
    """Every reviewed file of this era is bound by digest before anything is parsed or executed."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the base license policy must stay byte-identical")
    for path, expected in ERA_SHA256.items():
        require(digest(reviewed_bytes(path)) == expected, "LIC-HOST reviewed bytes are bound: " + path)


def validate_license_amendment_status() -> None:
    """Adopted after four independent review rounds, each bound to its record, the last a pass on the reviewed subject."""
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == set(STATUS_KEYS)
            and status["schemaVersion"] == "planeon.internal.license-policy-amendment-status/v1"
            and status["workItem"] == "LIC-HOST" and status["amendmentId"] == "LIC-HOST-A1"
            and status["status"] == "ADOPTED_FOR_SOURCE_PUBLICATION"
            and status["reviewedSubject"] == REVIEWED_SUBJECT and status["nonClaims"] == NON_CLAIMS
            and type(status["carried"]) is list and len(status["carried"]) > 0
            and all(type(row) is dict and set(row) == {"item", "to", "action"} for row in status["carried"]),
            "adopted LIC-HOST status")
    rounds = status["rounds"]
    require(type(rounds) is list and all(type(row) is dict for row in rounds)
            and [(row.get("round"), row.get("verdict")) for row in rounds] == list(ROUNDS), "four review rounds in order")
    for row in rounds:
        number = row["round"]
        require(set(row) == set(ROW_KEYS) and row["record"] == AMEND_DIR + "review-round%d.json" % number
                and row["snapshot"] == (AMEND_DIR + "round%d/" % number if number < LAST_ROUND else None),
                "review round %d row" % number)
        record = _json(row["record"])
        require(type(record) is dict and record.get("schemaVersion") == REVIEW_SCHEMA and record.get("round") == number
                and record.get("subjectCommit") == row["subject"] and record.get("subjectTree") == row["subjectTree"]
                and record.get("verdict") == row["verdict"], "review round %d identity" % number)
        actions = record.get("actions")
        require(type(actions) is dict and actions.get("filesEdited") is False and actions.get("personalDataSent") is False,
                "review round %d edited nothing and sent no personal data" % number)
        findings = record.get("findings")
        require(type(findings) is list and all(type(item) is dict and item.get("severity") in SEVERITIES for item in findings)
                and row["severities"] == sorted({item["severity"] for item in findings}),
                "review round %d severities" % number)
    final = rounds[-1]
    require(final["subject"] == REVIEWED_SUBJECT["commit"] and final["subjectTree"] == REVIEWED_SUBJECT["tree"]
            and final["severities"] == ["NOTE"], "the passing round reviewed this subject and left notes only")


def validate_license_amendment() -> None:
    """Every reviewed byte and the adoption record first; then the reference module from this era's reviewed bytes,
    whose result must carry the owner's decisions."""
    validate_era_bytes()
    validate_license_amendment_status()
    safe_yaml = _era_model(SAFE_YAML, "_met_enforce_021_safe_yaml")
    module = _era_model(MODEL, "_met_enforce_021_license_amendment", {"safe_yaml": safe_yaml, "scripts.safe_yaml": safe_yaml})
    amendment = module.check(_verified)

    def decided() -> bool:
        policy = module.effective_policy(_verified)
        for expression, name, kind, linked, outcome, elections in DECIDED_CASES:
            component = {"name": name, "kind": kind, "custody": "UPSTREAM_PINNED", "crateField": False,
                         "linkedInto": None if linked is None else {"name": linked, "custody": "UPSTREAM_PINNED"}}
            result = module.classify(policy, expression, component)
            if (result["outcome"], tuple((row["group"], row["elected"]) for row in result["elections"])) != (outcome, elections):
                return False
        return True

    _bound(lambda: [(row["id"], row["selected"]) for row in amendment["ownerDecisions"]] == list(DECISIONS)
           and tuple(amendment["hostOsSystemLibraryClass"]["components"]) == CLASS_COMPONENTS
           and [(row["component"], row["elects"]) for row in amendment["ownerElections"]] == list(ELECTIONS)
           and amendment["base"] == {"path": BASE_POLICY, "sha256": ERA_SHA256[BASE_POLICY], "policyVersion": "0.3.0"}
           and len(_json(AMEND_DIR + "vectors.json")["cases"]) == VECTORS
           and decided(),
           "the amendment carries the owner's decisions")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "license amendment validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 225
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET},
            "closed 225-packet catalog retaining the 223-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET):
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
            "closed source-only license-amendment packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted license-amendment packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_license_amendment()


if __name__ == "__main__":
    validate()
    print("License-policy amendment LIC-HOST-A1 valid: 225 current specifications; 223-packet checkpoint and exact 222-packet predecessor; DATA_CHECK_ONLY, the base policy byte-identical.")
