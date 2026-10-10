#!/usr/bin/env python3
"""Validate the MET-ENFORCE-023 W02 notes errata and the exact 225-to-224 projection."""
from __future__ import annotations

import ast
import base64
import binascii
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
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/w02-notes-errata-authority.json"
AUTHORITY_SHA256 = "b934c22caa35780ec40bd3d14fbf173bc21c22ca40112896f813847dc499313b"
VALIDATOR_PATH = "scripts/validate_w02_notes_errata.py"
BASE_COMMIT = "4cb451018989885f2a014718854a2f5b4db5955f"
NEW_PACKET = "MET-ENFORCE-023"
PREVIOUS_PACKET = "MET-ENFORCE-022"
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
            require(key not in result, "duplicate w02-notes-errata authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite w02-notes-errata authority number")

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
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "W02 notes errata history authority digest")
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
    }, "closed W02 notes errata history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/w02-notes-errata-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 224
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 224-packet base")
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
    """Recheck the pinned authority and undo only this reviewed successor."""
    _checked_authority_raw()
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
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
    _checked_authority_raw()
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    _checked_authority_raw()
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        return before
    current = regular_bytes(matches[0])
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return current


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Remove only this layer, leaving predecessor checks to their owners."""
    _checked_authority_raw()
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


# MET-ENFORCE-023 (roadmap W02-CLEANUP) publishes the W02 notes errata: errata records for the adopted native-profile-v3
# (W02a-F2: R6-1, R6-2 and the R6-3 vectors) and I06 backend profile v2 (W02g-F2: R2-4, R3-1, R3-2) contracts, with no
# version, rule, vector or model change, and the PERF-032-F follow-up checks F12, F14 and F15 with the F13 wording (owner
# decisions Q-S = A, Q-F = A and ROUND-6-FINAL, via the lane monitor). Repository bytes are read only through
# reviewed_bytes, so a later bridged successor projects its own edits away first. Every reviewed file of this era and
# every input the checks read is bound by digest before anything is parsed, the review binding is checked before any
# module runs, and both modules are executed from this era's reviewed bytes.
ERRATA_DIR = "architecture/w02-notes-errata/"
ERRATA_MODEL = "scripts/contract_errata.py"
FOLLOWUP_MODEL = "scripts/perf032_followup.py"
STATUS_PATH = ERRATA_DIR + "status.json"
RECORDS = (ERRATA_DIR + "native-profile-v3-errata.json", ERRATA_DIR + "i06-backend-profile-v2-errata.json")
VECTORS_PATH = ERRATA_DIR + "native-profile-v3-r6-3-vectors.json"
VERDICTS = ("CHANGES_REQUIRED",) * 5 + ("PASS_FOR_SOURCE_PUBLICATION",)
ROUNDS = tuple(enumerate(VERDICTS, 1))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "planeon.internal.w02-notes-errata-review/v1"
STATUS_KEYS = ("schemaVersion", "workItem", "answers", "ownerDecisions", "reviewRounds", "closedFindings",
               "carriedFindings", "carriedTo", "contractState", "independentReviewer", "versionRipple", "ruleChanged",
               "modelChanged", "nativeAcceptance", "tenantAcceptance")
DECISIONS = (("Q-S", "A"), ("Q-F", "A"), ("ROUND-6-FINAL", "A"))
ANSWERS = {"W02a-F2": ["R6-1", "R6-2", "R6-3"], "W02g-F2": ["R2-4", "R3-1", "R3-2"],
           "PERF-032-F": ["F12", "F13", "F14", "F15"]}
VECTOR_CASES = 39
UNIQUE_CORPUS = 773
ROUTE_CALLS = 935
# Each review round's exact subject paths (round 1 predates the catalogue edit, C1-11).
SUBJECTS = MappingProxyType({
    1: (
        "architecture/w02-notes-errata/README.md",
        "architecture/w02-notes-errata/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json",
        "architecture/w02-notes-errata/effective/native-profile-v3/README.md",
        "architecture/w02-notes-errata/i06-backend-profile-v2-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json",
        "docs/MASTER_DEVELOPMENT_PLAN.md",
        "scripts/contract_errata.py",
        "scripts/perf032_followup.py",
        "scripts/schema_unique.py",
        "scripts/validate_verify_headroom.py",
        "tests/test_verify_headroom.py",
    ),
    2: (
        "architecture/w02-notes-errata/README.md",
        "architecture/w02-notes-errata/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json",
        "architecture/w02-notes-errata/effective/native-profile-v3/README.md",
        "architecture/w02-notes-errata/i06-backend-profile-v2-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json",
        "docs/MASTER_DEVELOPMENT_PLAN.md",
        "docs/repositories/00-harness-engineering.md",
        "scripts/contract_errata.py",
        "scripts/perf032_followup.py",
        "scripts/schema_unique.py",
        "scripts/validate_verify_headroom.py",
        "tests/test_verify_headroom.py",
    ),
    3: (
        "architecture/w02-notes-errata/README.md",
        "architecture/w02-notes-errata/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json",
        "architecture/w02-notes-errata/effective/native-profile-v3/README.md",
        "architecture/w02-notes-errata/i06-backend-profile-v2-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json",
        "docs/MASTER_DEVELOPMENT_PLAN.md",
        "docs/repositories/00-harness-engineering.md",
        "scripts/contract_errata.py",
        "scripts/perf032_followup.py",
        "scripts/schema_unique.py",
        "scripts/validate_verify_headroom.py",
        "tests/test_verify_headroom.py",
    ),
    4: (
        "architecture/w02-notes-errata/README.md",
        "architecture/w02-notes-errata/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json",
        "architecture/w02-notes-errata/effective/native-profile-v3/README.md",
        "architecture/w02-notes-errata/i06-backend-profile-v2-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json",
        "docs/MASTER_DEVELOPMENT_PLAN.md",
        "docs/repositories/00-harness-engineering.md",
        "scripts/contract_errata.py",
        "scripts/perf032_followup.py",
        "scripts/schema_unique.py",
        "scripts/validate_verify_headroom.py",
        "tests/test_verify_headroom.py",
    ),
    5: (
        "architecture/w02-notes-errata/README.md",
        "architecture/w02-notes-errata/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json",
        "architecture/w02-notes-errata/effective/native-profile-v3/README.md",
        "architecture/w02-notes-errata/i06-backend-profile-v2-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json",
        "docs/MASTER_DEVELOPMENT_PLAN.md",
        "docs/repositories/00-harness-engineering.md",
        "scripts/contract_errata.py",
        "scripts/perf032_followup.py",
        "scripts/schema_unique.py",
        "scripts/validate_verify_headroom.py",
        "tests/test_verify_headroom.py",
    ),
    6: (
        "architecture/w02-notes-errata/README.md",
        "architecture/w02-notes-errata/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md",
        "architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json",
        "architecture/w02-notes-errata/effective/native-profile-v3/README.md",
        "architecture/w02-notes-errata/i06-backend-profile-v2-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-errata.json",
        "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json",
        "docs/MASTER_DEVELOPMENT_PLAN.md",
        "docs/repositories/00-harness-engineering.md",
        "scripts/contract_errata.py",
        "scripts/perf032_followup.py",
        "scripts/schema_unique.py",
        "scripts/validate_verify_headroom.py",
        "tests/test_verify_headroom.py",
    )
})
# The reviewed subject outside the errata directory that chain mechanics keep changing (the PERF-032 validator and test,
# the master plan and the repository catalogue). Rounds 1 to 5 bind them to their kept round copies. Round 6 reviewed them
# on base 5fab673; on this packet's base they also carry the mechanical edits of MET-ENFORCE-021 and MET-ENFORCE-022 and
# this packet's own, so their round-6 digests cannot be re-checked here (the F13 hunks were transplanted byte-identically,
# confirmed by the packet review). Instead each F13 wording edit must be present as often as it was written, and each
# replaced wording must be gone (count 0); the authority's after-digests pin their exact current bytes.
SHARED_SUBJECT = MappingProxyType({
    "scripts/validate_verify_headroom.py": (("corpus array, reaching the sorted, grouped and kept paths; the RecursionError fallback is pinned by bytes only.", 1), ("\"the corpus reaches the sorted, grouped and kept paths\")", 1), ("every comparison path", 0),),
    "tests/test_verify_headroom.py": (("verify-time changes with unchanged refusals (apart from inputs within one\nstack frame of the recursion limit)", 1), ("\"reaches the sorted, grouped and kept paths\"", 2), ("every comparison path", 0), ("verify-time changes with unchanged refusals and freshness", 0),),
    "docs/MASTER_DEVELOPMENT_PLAN.md": (("with unchanged refusals (apart from inputs within one stack frame of the recursion limit);", 1), ("computations with unchanged refusals;", 0),),
    "docs/repositories/00-harness-engineering.md": (("with unchanged refusals (apart from inputs within one stack frame of the recursion limit); source only.", 1), ("computations with unchanged refusals; source only.", 0),)
})
# The route tests F12 covers, as at this era (a later layer's new route test is that layer's own concern).
ROUTE_TESTS = (
    "tests/test_admission_channel_v3.py",
    "tests/test_admission_semantics_v2.py",
    "tests/test_backend_distribution.py",
    "tests/test_dedicated_verifier_account.py",
    "tests/test_enforcement_test_plan.py",
    "tests/test_host_interface_resolution.py",
    "tests/test_i05_gate_channel.py",
    "tests/test_i05_gate_channel_v2.py",
    "tests/test_i06_backend_profile.py",
    "tests/test_i06_backend_profile_v2.py",
    "tests/test_i07_policy_write.py",
    "tests/test_i07_policy_write_v2.py",
    "tests/test_in_session_predecessor_proof.py",
    "tests/test_isolated_network_canary.py",
    "tests/test_isolated_offline_runner.py",
    "tests/test_license_amendment.py",
    "tests/test_linear_history_rechecks.py",
    "tests/test_linux_runner_contract.py",
    "tests/test_native_profile_v2.py",
    "tests/test_native_profile_v3.py",
    "tests/test_owner_verifier.py",
    "tests/test_parallel_suite.py",
    "tests/test_portable_warm_snapshot_temp.py",
    "tests/test_projection_reuse.py",
    "tests/test_seccomp_allowlists.py",
    "tests/test_seccomp_v3.py",
    "tests/test_sector_catalog.py",
    "tests/test_sector_direction.py",
    "tests/test_selinux_matrix.py",
    "tests/test_selinux_matrix_v2.py",
    "tests/test_selinux_replay.py",
    "tests/test_verify_headroom.py",
    "tests/test_w01_amendment.py",
    "tests/test_w02_notes_errata.py",
)
# The adopted bytes of every reviewed file, round copy, review and status record and both modules, and of every input
# the checks read (the adopted contracts the errata name, the PERF-032 model, schema_unique and the route tests, one of
# which is also a shared file above).
ERA_SHA256 = MappingProxyType({
    "architecture/i06-backend-profile-v2/README.md": "553880b957586dbfa50eabc4a99d51735eef2a1b0a82641ea51d8e3ea8cf72eb",
    "architecture/i06-backend-profile-v2/REVIEW_BRIEF.md": "f65c1ef1fbe43013c06f962a2ffde8d231a70392603ecc44850481c5ae8ec739",
    "architecture/i06-backend-profile-v2/criteria.json": "026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda",
    "architecture/i06-backend-profile-v2/review-round2.json": "a5eefd7c6fb0f53f2a14880a079a69bd786c95be1ca8b3a3c5ab7c6de04cc0df",
    "architecture/i06-backend-profile-v2/review-round3.json": "1a04fb792d080ee70f24fc93da68df8238a1593e91c9072c2e6dd3f75bf48bd2",
    "architecture/i06-backend-profile-v2/status.json": "44217baf7857b86abfa9c8ccadb953e2678592e437c9caf049096c402abb9c20",
    "architecture/native-profile-v3/README.md": "93b6f3897f4011ab85832b4319db44e4e1e94566adf61062a6170d1437dfcf50",
    "architecture/native-profile-v3/qualification.schema.json": "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
    "architecture/native-profile-v3/review-round6.json": "dce53008c9b21f670935a6fb0c434678dec2538599fc757c46ac5a54a718c929",
    "architecture/native-profile-v3/status.json": "f242944dd7a03eb64fd4f14d811711f7ed4ccf9bdb00bca82ea8abbaa5cb0538",
    "architecture/native-profile-v3/vectors.json": "14af47a69c972039294be8659c31332acd5326bfb0a3a38384a2c6bf9d11fe6d",
    "architecture/w02-notes-errata/README.md": "744da8b31616ec352b604912a03d29d19e082718e5cb522e7c31da2dde83b535",
    "architecture/w02-notes-errata/REVIEW_BRIEF.md": "3713c9958fb0076f8ea6ffc90f0e51ad7a59a007f199564e980338f24f27311a",
    "architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md": "562b00852cb84dc44f4118f8449e19819b2b1dae4d683102b5a1b53890abdd9c",
    "architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md": "1634d77c9ebd8fea1a1021a22143dadeb702e66f0b81f592f3319c877abd7a99",
    "architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json": "8d4f5d7837b0f68859f222dec8766d57c2b6cc5fe49f95fddd830836569940b4",
    "architecture/w02-notes-errata/effective/native-profile-v3/README.md": "fd12a0ded9b7de557cb75a8bdeb01c2c3fa85c24035b174282d2274dc6000bd0",
    "architecture/w02-notes-errata/i06-backend-profile-v2-errata.json": "ae59ac046609184015790f9e43ed8d99aece31575011f667f6b28ec30dba5b96",
    "architecture/w02-notes-errata/native-profile-v3-errata.json": "e22e968d931d477d6cd70648d52eea52e5bcda6a76e07b17bd658d004e063961",
    "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json": "3b9b6b32b8da1b53cf2b597b8ac9e1f230889364424b14b667e7f985b03fb7a7",
    "architecture/w02-notes-errata/review-round1.json": "35b046c1b31dd062c91856b21869aad97f777e7298a0c3d6c28cc09ff21a4d8f",
    "architecture/w02-notes-errata/review-round2.json": "14cebfdf3b596b186360cf6897dd96a5f2b23a0d910b8bf7728067b82d3835fb",
    "architecture/w02-notes-errata/review-round3.json": "8de69961b8699064bc2729381591acbb05636e0301b494b12bea42e43e14738d",
    "architecture/w02-notes-errata/review-round4.json": "4177faaf9e33f8c06cf758ef514dfbc4e409b2ed6554db0ec022015e2eaed7b6",
    "architecture/w02-notes-errata/review-round5.json": "56e7ac7e08ec23712d20549feffe192b1c3de84ca12e74a3cff2b97a8ec5830f",
    "architecture/w02-notes-errata/review-round6.json": "8925fba2fba2547d5b67b7e40b411ad3208d29f61f4d8bd2900a45022045ecea",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/README.md": "51fd9d095aad71996f8fda2c2f7cabb7dee517806901445c121e725a73bc4e68",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/REVIEW_BRIEF.md": "52bda55c76659ec644975ceb1c8373a5f632b56bf4d77b619d6e8f6b27153912",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md": "562b00852cb84dc44f4118f8449e19819b2b1dae4d683102b5a1b53890abdd9c",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md": "1634d77c9ebd8fea1a1021a22143dadeb702e66f0b81f592f3319c877abd7a99",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json": "8d4f5d7837b0f68859f222dec8766d57c2b6cc5fe49f95fddd830836569940b4",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/effective/native-profile-v3/README.md": "c102cdde499552a1f945b90b242e88321cae5e454d0ff06985bb0fc701127bb9",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/i06-backend-profile-v2-errata.json": "ae59ac046609184015790f9e43ed8d99aece31575011f667f6b28ec30dba5b96",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/native-profile-v3-errata.json": "b497992a6b91431b882959bc65d338f30ed8d57353b706948be235394e7b8453",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json": "bb6964e6b8118180b81751837c83ddeca32df68b8b05fe4d2ff23166730402cf",
    "architecture/w02-notes-errata/round1/architecture/w02-notes-errata/source-index.json": "6d4b6b8cd2ecec4dcc706e0ab2acb7fa3948d6662b4166a8011b3be63401a00c",
    "architecture/w02-notes-errata/round1/docs/MASTER_DEVELOPMENT_PLAN.md": "bcaadfbefc3d4abd9af88658f2c34da00bf0621393ba546e38986a0e026a4f87",
    "architecture/w02-notes-errata/round1/scripts/contract_errata.py": "9d01fcf5b654780cb20c1a1be1f4eb04d290ba4825f931b8bbbcc6b250eedfa1",
    "architecture/w02-notes-errata/round1/scripts/perf032_followup.py": "951b72bbfbe5e26c5f9e01c09c75b3562b745846d447b64395c1479b52993ead",
    "architecture/w02-notes-errata/round1/scripts/schema_unique.py": "a89588bd3f0f63a528c07d1962e2c320c25120409e8d0b20a1c78ca52c1b2354",
    "architecture/w02-notes-errata/round1/scripts/validate_verify_headroom.py": "58bc01760a0cf6f57f8de6f048b08d9af5b39f76485042970acea52a5951d634",
    "architecture/w02-notes-errata/round1/tests/test_verify_headroom.py": "25a7419dcd9c6d8d264ada1bb97e045bb5af6f661021d21daf780d9d23246d6e",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/README.md": "0515e1c4081c4ddbd471370efff3af640bc179d646b72024f30c2f5bf7ac83b8",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/REVIEW_BRIEF.md": "7b15d5db1703fd99bc60ff3f23bcb87b316863f7645a12e7b5a4553e2dda9573",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md": "562b00852cb84dc44f4118f8449e19819b2b1dae4d683102b5a1b53890abdd9c",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md": "1634d77c9ebd8fea1a1021a22143dadeb702e66f0b81f592f3319c877abd7a99",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json": "8d4f5d7837b0f68859f222dec8766d57c2b6cc5fe49f95fddd830836569940b4",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/effective/native-profile-v3/README.md": "ccec7e2e9d46df373313b2d9effee5230bcd9cf9040f8c6b891ee64a959e9fa8",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/i06-backend-profile-v2-errata.json": "ae59ac046609184015790f9e43ed8d99aece31575011f667f6b28ec30dba5b96",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/native-profile-v3-errata.json": "e1b75c4a312b1cf7d46e1fff594ec403711cd4c441936c4d42f15700f7dc4387",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json": "bb6964e6b8118180b81751837c83ddeca32df68b8b05fe4d2ff23166730402cf",
    "architecture/w02-notes-errata/round2/architecture/w02-notes-errata/source-index.json": "9c50bfe3a522fb7dda0af4f84552cce893b7a06f0ffb67fcc6ddfce9873f164b",
    "architecture/w02-notes-errata/round2/docs/MASTER_DEVELOPMENT_PLAN.md": "bcaadfbefc3d4abd9af88658f2c34da00bf0621393ba546e38986a0e026a4f87",
    "architecture/w02-notes-errata/round2/docs/repositories/00-harness-engineering.md": "4cdb6997029923c14cfcebc0f987d5b896ccd12da1a4132ee826a8f4e055fafa",
    "architecture/w02-notes-errata/round2/scripts/contract_errata.py": "205e049174446e5ce8aaa3c336933709baa56ff40bf35963f8fb6c9c23fd0baa",
    "architecture/w02-notes-errata/round2/scripts/perf032_followup.py": "edecf241978d84fce5ee5496d462f768e41d8f9648b6e03417127c3e05e40c9d",
    "architecture/w02-notes-errata/round2/scripts/schema_unique.py": "a89588bd3f0f63a528c07d1962e2c320c25120409e8d0b20a1c78ca52c1b2354",
    "architecture/w02-notes-errata/round2/scripts/validate_verify_headroom.py": "58bc01760a0cf6f57f8de6f048b08d9af5b39f76485042970acea52a5951d634",
    "architecture/w02-notes-errata/round2/tests/test_verify_headroom.py": "41706e1fd841542fb3ac47cf9fe7addb407c793b0c8c4a1007c2992fd4839ae0",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/README.md": "56f72d964ee3ecab4db548ccf618143b1668d2d7b84805298db0fc63fa69373b",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/REVIEW_BRIEF.md": "78416aa8e1f12a931a4c1b68ab96ca113a1677efe2de6281cd8a9884a54942d3",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md": "562b00852cb84dc44f4118f8449e19819b2b1dae4d683102b5a1b53890abdd9c",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md": "1634d77c9ebd8fea1a1021a22143dadeb702e66f0b81f592f3319c877abd7a99",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json": "8d4f5d7837b0f68859f222dec8766d57c2b6cc5fe49f95fddd830836569940b4",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/effective/native-profile-v3/README.md": "fd12a0ded9b7de557cb75a8bdeb01c2c3fa85c24035b174282d2274dc6000bd0",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/i06-backend-profile-v2-errata.json": "ae59ac046609184015790f9e43ed8d99aece31575011f667f6b28ec30dba5b96",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/native-profile-v3-errata.json": "b88ec96c34476bc3dd0bc6f62a0fd3edc46bcedbc02fe05d112d2cc1442dac1d",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json": "83698328ec9ac8bd6b5289a69bcd6715705c7380e5c4c5b9bca20b03723527d6",
    "architecture/w02-notes-errata/round3/architecture/w02-notes-errata/source-index.json": "4ce4a1ab4871d5eb869e5b28ef176cfcfbfa2af9b3795d1981fea4de5a9f643f",
    "architecture/w02-notes-errata/round3/docs/MASTER_DEVELOPMENT_PLAN.md": "bcaadfbefc3d4abd9af88658f2c34da00bf0621393ba546e38986a0e026a4f87",
    "architecture/w02-notes-errata/round3/docs/repositories/00-harness-engineering.md": "4cdb6997029923c14cfcebc0f987d5b896ccd12da1a4132ee826a8f4e055fafa",
    "architecture/w02-notes-errata/round3/scripts/contract_errata.py": "ceb3c6088a25eed9ef9c8ab9d471984e426487612a35b4b932207012fdb50e05",
    "architecture/w02-notes-errata/round3/scripts/perf032_followup.py": "eddeec5e21c7930c979a2039f2963c6c6da0f15473321eef59e64f9280c08aa9",
    "architecture/w02-notes-errata/round3/scripts/schema_unique.py": "a89588bd3f0f63a528c07d1962e2c320c25120409e8d0b20a1c78ca52c1b2354",
    "architecture/w02-notes-errata/round3/scripts/validate_verify_headroom.py": "58bc01760a0cf6f57f8de6f048b08d9af5b39f76485042970acea52a5951d634",
    "architecture/w02-notes-errata/round3/tests/test_verify_headroom.py": "41706e1fd841542fb3ac47cf9fe7addb407c793b0c8c4a1007c2992fd4839ae0",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/README.md": "27bc803487451887d7806bfe95bd3cb383046ee6ed4f3467bb8692d977c7dda2",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/REVIEW_BRIEF.md": "f02bb3aebe1adec5aaf67a2e012cf5035fd13c9a486619b1faa27045fe826a16",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md": "562b00852cb84dc44f4118f8449e19819b2b1dae4d683102b5a1b53890abdd9c",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md": "1634d77c9ebd8fea1a1021a22143dadeb702e66f0b81f592f3319c877abd7a99",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json": "8d4f5d7837b0f68859f222dec8766d57c2b6cc5fe49f95fddd830836569940b4",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/effective/native-profile-v3/README.md": "fd12a0ded9b7de557cb75a8bdeb01c2c3fa85c24035b174282d2274dc6000bd0",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/i06-backend-profile-v2-errata.json": "ae59ac046609184015790f9e43ed8d99aece31575011f667f6b28ec30dba5b96",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/native-profile-v3-errata.json": "e22e968d931d477d6cd70648d52eea52e5bcda6a76e07b17bd658d004e063961",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json": "3b9b6b32b8da1b53cf2b597b8ac9e1f230889364424b14b667e7f985b03fb7a7",
    "architecture/w02-notes-errata/round4/architecture/w02-notes-errata/source-index.json": "1e0b0b7196ecb50224dd386f95ed1e8e2eeea9c545b68bafadc5aa3889abaed5",
    "architecture/w02-notes-errata/round4/docs/MASTER_DEVELOPMENT_PLAN.md": "bcaadfbefc3d4abd9af88658f2c34da00bf0621393ba546e38986a0e026a4f87",
    "architecture/w02-notes-errata/round4/docs/repositories/00-harness-engineering.md": "4cdb6997029923c14cfcebc0f987d5b896ccd12da1a4132ee826a8f4e055fafa",
    "architecture/w02-notes-errata/round4/scripts/contract_errata.py": "15bef4f7e34302a3a1bc7d21fc5d17a806fe23753d27578075799e94508db449",
    "architecture/w02-notes-errata/round4/scripts/perf032_followup.py": "5217528c83c7ec445903295b2456a849ccdd54952e96d78c1588fc621734bc96",
    "architecture/w02-notes-errata/round4/scripts/schema_unique.py": "a89588bd3f0f63a528c07d1962e2c320c25120409e8d0b20a1c78ca52c1b2354",
    "architecture/w02-notes-errata/round4/scripts/validate_verify_headroom.py": "58bc01760a0cf6f57f8de6f048b08d9af5b39f76485042970acea52a5951d634",
    "architecture/w02-notes-errata/round4/tests/test_verify_headroom.py": "41706e1fd841542fb3ac47cf9fe7addb407c793b0c8c4a1007c2992fd4839ae0",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/README.md": "7a7dd42224b59b535b87a45b622d4115bcf3f3834af2bb740a1fec652f1371ec",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/REVIEW_BRIEF.md": "79c94fce1c62967209ce75127a9746570a72f10dd92c79e160e52515eb1d8192",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md": "562b00852cb84dc44f4118f8449e19819b2b1dae4d683102b5a1b53890abdd9c",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md": "1634d77c9ebd8fea1a1021a22143dadeb702e66f0b81f592f3319c877abd7a99",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json": "8d4f5d7837b0f68859f222dec8766d57c2b6cc5fe49f95fddd830836569940b4",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/effective/native-profile-v3/README.md": "fd12a0ded9b7de557cb75a8bdeb01c2c3fa85c24035b174282d2274dc6000bd0",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/i06-backend-profile-v2-errata.json": "ae59ac046609184015790f9e43ed8d99aece31575011f667f6b28ec30dba5b96",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/native-profile-v3-errata.json": "e22e968d931d477d6cd70648d52eea52e5bcda6a76e07b17bd658d004e063961",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json": "3b9b6b32b8da1b53cf2b597b8ac9e1f230889364424b14b667e7f985b03fb7a7",
    "architecture/w02-notes-errata/round5/architecture/w02-notes-errata/source-index.json": "222254d92d5073e62e263416bfd02b2b029158fef508a242e0b742a84aaefe1d",
    "architecture/w02-notes-errata/round5/docs/MASTER_DEVELOPMENT_PLAN.md": "bcaadfbefc3d4abd9af88658f2c34da00bf0621393ba546e38986a0e026a4f87",
    "architecture/w02-notes-errata/round5/docs/repositories/00-harness-engineering.md": "4cdb6997029923c14cfcebc0f987d5b896ccd12da1a4132ee826a8f4e055fafa",
    "architecture/w02-notes-errata/round5/scripts/contract_errata.py": "15bef4f7e34302a3a1bc7d21fc5d17a806fe23753d27578075799e94508db449",
    "architecture/w02-notes-errata/round5/scripts/perf032_followup.py": "a41f8123ba446ed6c25de120de33fe2e802334c6c0c93df273d87ef56afc3645",
    "architecture/w02-notes-errata/round5/scripts/schema_unique.py": "a89588bd3f0f63a528c07d1962e2c320c25120409e8d0b20a1c78ca52c1b2354",
    "architecture/w02-notes-errata/round5/scripts/validate_verify_headroom.py": "58bc01760a0cf6f57f8de6f048b08d9af5b39f76485042970acea52a5951d634",
    "architecture/w02-notes-errata/round5/tests/test_verify_headroom.py": "41706e1fd841542fb3ac47cf9fe7addb407c793b0c8c4a1007c2992fd4839ae0",
    "architecture/w02-notes-errata/source-index.json": "2a952827a5b4446ef4c5d4ffef5c3c0fc3eb6881d63a328ebc2d42d8f4849c4c",
    "architecture/w02-notes-errata/status.json": "8f9c8bbb4d6d582a1c597c56dbd94c791c738202331e259895a3c000d58dd03f",
    "scripts/contract_errata.py": "15bef4f7e34302a3a1bc7d21fc5d17a806fe23753d27578075799e94508db449",
    "scripts/native_qualification_v2.py": "c72b6e18044f685c646756a1574bd81cd24f1475d7eda326778d70d1314ef68b",
    "scripts/native_qualification_v3.py": "2ef5c14ad5d8c962cf3703ccd076059685ed8dcc852059e4f863e8d9dc8965ad",
    "scripts/perf032_followup.py": "4c764c6451d8273f18c544aac3c3e72b6fe3992b72f34af6c1a1f87da8a1a2cf",
    "scripts/schema_unique.py": "a89588bd3f0f63a528c07d1962e2c320c25120409e8d0b20a1c78ca52c1b2354",
    "tests/test_admission_channel_v3.py": "9769990729649056b02acd8fb030235ad0a6bd31f9c4edb209aedaffe1c62269",
    "tests/test_admission_semantics_v2.py": "269657f418feff4d0aff1732c50424a6cdf1f2f1232bc9f7525a9222a11881b8",
    "tests/test_backend_distribution.py": "d8c10ea1313b61db0b58dcde67998dfe535c5c8a6d20d468c057474922d877e5",
    "tests/test_dedicated_verifier_account.py": "d44d7699e084b60f2261893f3421eac4ecd0a7265aac90068971491ca46992d4",
    "tests/test_enforcement_test_plan.py": "afbfbcddfd6b3319e9a1958cad9975c4ce3ba9ac2c94f1787fb7471c73edcd4f",
    "tests/test_host_interface_resolution.py": "5698e3f92292851c588b8bd93b0a35b6b0dd1346b6bc2b8f592a64e9f9820c97",
    "tests/test_i05_gate_channel.py": "47548ac4ada72eb5387b8504ea9221c25a48a176e96ade4b58c917a243b992c5",
    "tests/test_i05_gate_channel_v2.py": "6eb34a86b8d2e943c11612cca9ef2a8279ace03a793058ac1713b8573600b94f",
    "tests/test_i06_backend_profile.py": "f7bf1978e92424ce0e6754dd21361dbf53ef43ad4a40d5e3ffc33fd8126ece70",
    "tests/test_i06_backend_profile_v2.py": "b2db03b5a57ca5802187e635b6bd567b2808f327a30ba402ddbf4509d495031e",
    "tests/test_i07_policy_write.py": "b6d17167af6913cda65857e4d523d0837bb610a49c03d747c6aed4855256fb68",
    "tests/test_i07_policy_write_v2.py": "f670a6e78e5006e49fb91bb6ef7cb8b26c0551248072af67a3e23829140da026",
    "tests/test_in_session_predecessor_proof.py": "d385db48e5c0449e52e06be82f4c069a962bfdefbceab50ea3f9b3cb0f49f399",
    "tests/test_isolated_network_canary.py": "86e7be4c6cb15a9d0b8a8c3a4e8dbdf6e0c85f5e02fad4c2951e84c185fcb1e9",
    "tests/test_isolated_offline_runner.py": "aaab03ad11f1f0186361cedd02ced1ca6edd6a4431dad527bdc775ed6b9de623",
    "tests/test_license_amendment.py": "dd88c2d42a987c7e821e22159f682cf82eb713b2e18cf8f9626b4278bffb166a",
    "tests/test_linear_history_rechecks.py": "367362265a5fc97d5a51666534b290a0c4e95274260635ec87c7005ad1878fcb",
    "tests/test_linux_runner_contract.py": "0ba51e9c5c92eede5f9ea21e65111f5b5437f72fe0e3efbddd4ac95d41e0bc6f",
    "tests/test_native_profile_v2.py": "713d072feb7ce81d433d9a5220d875d86f39a38f0f0d15d68f1f197fac101692",
    "tests/test_native_profile_v3.py": "b7729629130e46c8bb9bc0eed0f7c0a970fb8c52e509aa9a260e1bc20fb255ca",
    "tests/test_owner_verifier.py": "87b0730df50dfe4fd5ab5aca873fc2331b675b22bad45620994a6279f022cefa",
    "tests/test_parallel_suite.py": "3e11d759c89a3dac15dfc584ac5a636404a43050790f658cb4bfa83ad9f4cb6d",
    "tests/test_portable_warm_snapshot_temp.py": "190ec0b8b86e6f8ad4878106a1d8f29e5d9e3e10ed12d1131fe8853598d6e3a2",
    "tests/test_projection_reuse.py": "0384f121a52a900136d41ee1146d49b30db5e50b66011847b5d24e335aea75c1",
    "tests/test_seccomp_allowlists.py": "5c4bf2f65a79bc466356c531fddeee2f224158571d39d96bb01cf5bdad09001c",
    "tests/test_seccomp_v3.py": "50382355b67f4c4dba7685b2862e58a740ba0e8e105132745df14a12ac04f404",
    "tests/test_sector_catalog.py": "9782f3dd08cd60d12244b44e02b977c35cd263a03e4a400f5bd9fc1711f3fbfc",
    "tests/test_sector_direction.py": "9d631918c0673632442aea39fcac18c6df17a055a140e98eee18dfd36c878ec5",
    "tests/test_selinux_matrix.py": "50a8d9541273611afed932c3e0a398e9d8a993e2e6b38c519e1908234e48c7cd",
    "tests/test_selinux_matrix_v2.py": "982029bf1a31590cc68a92921302789b2c3cb567eb3b3773c577e2aafda360a3",
    "tests/test_selinux_replay.py": "ba234d32ea80cbc9b35d8d4af84190a793cc28a83d5cd448b490fb8980fd2941",
    "tests/test_verify_headroom.py": "c264d816010e76d6d4e36154bcf6813761531d67060fb1256e4456500a77109f",
    "tests/test_w01_amendment.py": "25f431dbe9473e1f813c6467e5c49bbfead5baca18d7cb308a5f596d23e6cca2",
    "tests/test_w02_notes_errata.py": "c005da839f3b513cc32b5b18bfeb20ee7caa36b3595fe6db4902f53bb63e81ce"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    raw = reviewed_bytes(path)
    expected = ERA_SHA256.get(path)
    require(expected is not None and digest(raw) == expected, "W02 notes errata reviewed bytes are bound: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _era_model(path: str, name: str) -> types.ModuleType:
    """A module of this era, executed from its reviewed bytes."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def _subject_path(number: int, path: str) -> str:
    return ERRATA_DIR + "round%d/" % number + path if number < LAST_ROUND else path


def validate_era_bytes() -> None:
    """Every reviewed file of this era and every checked input is bound by digest before anything is parsed or run."""
    for path, expected in ERA_SHA256.items():
        require(digest(reviewed_bytes(path)) == expected, "W02 notes errata reviewed bytes are bound: " + path)
    for path, edits in SHARED_SUBJECT.items():
        raw = reviewed_bytes(path)
        require(all(raw.count(edit.encode("utf-8")) == count for edit, count in edits), "F13 wording present: " + path)


def validate_errata_status() -> dict:
    """Adopted after six independent review rounds, each bound to its record and, for the errata's own files, to its
    exact subject bytes; the final round passes with notes only, all carried."""
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == set(STATUS_KEYS)
            and status["schemaVersion"] == "planeon.internal.w02-notes-errata-status/v1"
            and status["workItem"] == "W02-CLEANUP" and status["answers"] == ANSWERS
            and status["contractState"] == "ADOPTED_ERRATA"
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in ("versionRipple", "ruleChanged", "modelChanged",
                                                        "nativeAcceptance", "tenantAcceptance"))
            and [(row.get("id"), row.get("selected")) for row in status["ownerDecisions"]] == list(DECISIONS)
            and set(status["carriedTo"]) == {"W02-PROD"}, "adopted W02 notes errata status")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and [(row.get("round"), row.get("verdict")) for row in rounds if type(row) is dict]
            == list(ROUNDS), "six review rounds in order")
    for row in rounds:
        number = row["round"]
        require(set(row) == {"round", "record", "recordSha256", "verdict", "subjectCommit", "subjectDirectory"}
                and row["record"] == ERRATA_DIR + "review-round%d.json" % number
                and row["subjectDirectory"] == (ERRATA_DIR + "round%d/" % number if number < LAST_ROUND else "CURRENT")
                and row["recordSha256"] == digest(_verified(row["record"])), "review round identity %d" % number)
        review = _json(row["record"])
        require(type(review) is dict and review.get("schemaVersion") == REVIEW_SCHEMA and review.get("round") == number
                and review.get("verdict") == row["verdict"] and review.get("subjectCommit") == row["subjectCommit"]
                and type(review.get("subjectSha256")) is dict and type(review.get("findings")) is list,
                "review record %d" % number)
        subject = review["subjectSha256"]
        bound = {path: sha for path, sha in subject.items() if number < LAST_ROUND or path not in SHARED_SUBJECT}
        require(tuple(sorted(subject)) == SUBJECTS[number]
                and all(_subject_path(number, path) in ERA_SHA256 for path in bound)
                and all(digest(_verified(_subject_path(number, path))) == sha for path, sha in bound.items()),
                "review round %d is bound to its exact subject bytes" % number)
    final = _json(rounds[-1]["record"])
    require(all(type(row) is dict and row.get("severity") == "NOTE" for row in final["findings"])
            and {row["id"] for row in final["findings"]} == set(status["carriedFindings"]),
            "the final round passes with notes only, all carried")
    return status


def validate_w02_notes_errata() -> None:
    """Every reviewed byte and the adoption record first; then both modules from this era's reviewed bytes: both errata
    records against the adopted contracts, the R6-3 vectors through the unchanged v3 model, and the PERF-032-F checks."""
    validate_era_bytes()
    validate_errata_status()
    errata = _era_model(ERRATA_MODEL, "_met_enforce_023_contract_errata")
    followup = _era_model(FOLLOWUP_MODEL, "_met_enforce_023_perf032_followup")
    effective = {}
    for path in RECORDS:
        effective.update(errata.check_errata(_json(path), _verified))
    require(len(effective) == 5, "both errata records replace exactly their five files")
    require(errata.replay_vectors(_json(VECTORS_PATH), _verified) == VECTOR_CASES, "every R6-3 vector replays")
    require(followup.check_unique_oracle(_verified(followup.UNIQUE_PATH)) == UNIQUE_CORPUS
            and followup.validate_perf032_followup(_verified, list(ROUTE_TESTS)) == ROUTE_CALLS, "the PERF-032-F checks hold")


def validate() -> None:
    record = authority()
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "W02 notes errata validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 225 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 225-packet catalog")
    packets = {}
    for path in paths:
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
            "closed source-only w02-notes-errata packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted w02-notes-errata packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_w02_notes_errata()


if __name__ == "__main__":
    validate()
    print("W02 notes errata valid: 225 current specifications; exact 224-packet predecessor; DATA_CHECK_ONLY, no contract version, rule or model changed.")
