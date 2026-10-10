#!/usr/bin/env python3
"""Validate the MET-ENFORCE-017 W02d seccomp allowlists and the exact 219-to-218 projection."""
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
    import validate_w01_amendment as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_w01_amendment as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/seccomp-allowlists-authority.json"
AUTHORITY_SHA256 = "f9094ceb10148cc8e03d06b257dda99e5ea6fcd0eeef2b601817345a0df0eb93"
VALIDATOR_PATH = "scripts/validate_seccomp_allowlists.py"
BASE_COMMIT = "984c953ad034dee9d0f8028e1ecfff4fefea98c3"
NEW_PACKET = "MET-ENFORCE-017"
PREVIOUS_PACKET = "MET-SECTOR-002"
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
            require(key not in result, "duplicate seccomp-allowlists authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite seccomp-allowlists authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "seccomp allowlists history authority digest")
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
    }, "closed seccomp allowlists history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/seccomp-allowlists-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 218
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 218-packet base")
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
    # An exact 218-era byte string is already older than the successor layer.
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


# MET-ENFORCE-017 publishes the W02d per-role, per-architecture seccomp allowlists (planeon.internal.seccomp-allowlists/v1)
# for the seven roles on x86_64 and aarch64 at Linux v6.12, under owner decisions W02d-Q1..Q3 and QA..QD (README and duty sources). Repository
# bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away first. The
# reference model is executed from this era's reviewed bytes, not imported, and those bytes are bound by the review
# rounds below, so a later revision of the model cannot change how this layer judges its own era.
CONTRACT_DIR = "architecture/seccomp-allowlists/"
MODEL_PATH = "scripts/seccomp_allowlists.py"
STATUS_PATH = CONTRACT_DIR + "status.json"
SUBJECT = (CONTRACT_DIR + "README.md", CONTRACT_DIR + "REVIEW_BRIEF.md", CONTRACT_DIR + "syscalls.json",
           CONTRACT_DIR + "allowlists.json", CONTRACT_DIR + "vectors.json", MODEL_PATH)
ROUNDS = ((1, "CHANGES_REQUIRED"), (2, "CHANGES_REQUIRED"), (3, "PASS_FOR_SOURCE_PUBLICATION"))
# The reviewed W01 design and the native-profile record whose digest slot W02d fills stay byte-identical.
FROZEN_PATHS = ("architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md",
                "architecture/native-profile-v3/qualification.schema.json", "architecture/native-profile-v3/README.md",
                "docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md")
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
FALSE_FLAGS = ("nativeAcceptance", "tenantAcceptance", "filtersInstalled", "roleCodeExists", "traceValidated",
               "distributionSelected", "productExecution", "runnerActivated", "phaseComplete")
DECISIONS = ("W02d-Q1", "W02d-Q2", "W02d-Q3")
# A reviewer reads (round 1 also the pinned upstream kernel sources) and executes the reference model; it never edits,
# runs repository validators or tests, mutates GitHub, activates a runner or takes a native action.
REVIEW_ACTIONS = ("filesEdited", "githubMutated", "nativeActions", "repositoryValidatorsRun", "runnerActivated", "testsRun")
FLOORS = {"decisionChecks": 2789, "workerStackChecks": 351, "policyMutations": 13}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _json(path: str) -> Any:
    return parse(reviewed_bytes(path))


def _era_model() -> types.ModuleType:
    """The reference model of this era, executed from its reviewed bytes."""
    module = types.ModuleType("_met_enforce_017_seccomp_allowlists")
    module.__file__ = str(ROOT / MODEL_PATH)
    exec(compile(reviewed_bytes(MODEL_PATH), MODEL_PATH, "exec"), module.__dict__)
    return module


def _round_path(number: int, path: str) -> str:
    """Rounds 1 and 2 keep every subject file they reviewed under roundN/; round 3 reviewed the current bytes."""
    return path if number == 3 else CONTRACT_DIR + "round%d/" % number + path


def validate_seccomp_policy(model: types.ModuleType, table: dict, policy: dict) -> None:
    """The table is the pinned v6.12 one, the policy is closed and refuses what W01 denies, and the owner decisions are
    recorded."""
    require(table.get("schemaVersion") == "planeon.internal.seccomp-syscall-table/v1"
            and table.get("kernel") == {"tag": "v6.12", "commit": "adc218676eef25575469234709c2d87185ca223a"}
            and table["arches"] == {"x86_64": {"auditArch": 0xC000003E, "x32Bit": 0x40000000},
                                    "aarch64": {"auditArch": 0xC00000B7, "x32Bit": None}}, "the pinned v6.12 syscall table")
    require(policy.get("schemaVersion") == "planeon.internal.seccomp-allowlists/v1" and policy.get("mode") == 2
            and policy.get("defaultAction") == "KILL_PROCESS"
            and [row.get("id") for row in policy["ownerDecisions"]] == list(DECISIONS), "closed policy and owner decisions")
    model.check_policy(policy, table)


def validate_seccomp_vectors(model: types.ModuleType, table: dict, policy: dict, vectors: dict) -> int:
    """Every decision replays through both the reference decision and the compiled program; the worker's stacked
    filters decide as its own; every mutation is refused with its stated message; the digests are the compiled ones."""
    require(type(vectors) is dict and set(vectors) == {"evidenceClass", "filterDigests", "programLengths", "decisionChecks",
                                                       "workerStackChecks", "policyMutations"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY"
            and all(len(vectors[key]) >= floor for key, floor in FLOORS.items()), "closed seccomp vectors")
    programs = {(role, arch): model.compile_filter(policy, table, role, arch) for role in model.ROLES for arch in model.ARCHES}
    require(vectors["filterDigests"] == {role: {arch: "sha256:" + digest(model.program_bytes(programs[role, arch]))
                                                for arch in model.ARCHES} for role in model.ROLES}
            and vectors["programLengths"] == {role: {arch: len(programs[role, arch]) for arch in model.ARCHES}
                                              for role in model.ROLES}, "the published digests are the compiled programs'")
    checks, by_id = 0, {}
    for row in vectors["decisionChecks"]:
        data = model.seccomp_data(row["nr"], row["auditArch"], row["args"])
        expect = model.action_name(model.decide(policy, table, row["role"], row["arch"], row["auditArch"], row["nr"], row["args"]))
        require(expect == row["expect"] == model.action_name(model.run_filter(programs[row["role"], row["arch"]], data)),
                "decision check " + row["id"])
        by_id[row["id"]] = row
        checks += 1
    for row in vectors["workerStackChecks"]:
        base = by_id[row["decision"]]
        require(base["role"] == "WORKER" and row["expect"] == "SAME_AS_WORKER"
                and model.decide_stack(policy, table, ["BROKER", "WORKER"], base["arch"], base["auditArch"], base["nr"], base["args"])
                == model.decide(policy, table, "WORKER", base["arch"], base["auditArch"], base["nr"], base["args"]),
                "worker stack check " + row["id"])
        checks += 1
    for row in vectors["policyMutations"]:
        changed = copy.deepcopy(policy)
        changed["roles"][row["role"]]["duties"].append(row["addDuty"])
        try:
            model.check_policy(changed, table)
            refused = None
        except ValueError as exc:
            refused = str(exc)
        require(refused is not None and refused == row["expect"], "policy mutation " + row["id"])
        checks += 1
    return checks


def reviewer_actions_allowed(actions: Any) -> bool:
    """Exactly the eight reviewer action booleans; reading and model execution may be true, every other action false."""
    return (type(actions) is dict and set(actions) == set(REVIEW_ACTIONS) | {"referenceModelExecuted", "warmSourcesAccessed"}
            and all(type(value) is bool for value in actions.values())
            and all(actions[key] is False for key in REVIEW_ACTIONS))


def validate_seccomp_status() -> None:
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == {
        "schemaVersion", "contract", "kernel", "reviewRounds", "closedFindings", "carriedFindings", "ownerDecisions",
        "carriedToW01", "carriedToW03", "openObligations", "contractState", "obligations", "independentReviewer", *FALSE_FLAGS}
            and status["schemaVersion"] == "planeon.internal.seccomp-allowlists-status/v1"
            and status["contract"] == "planeon.internal.seccomp-allowlists/v1"
            and status["contractState"] == "ADOPTED_DATA_CONTRACT"
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in FALSE_FLAGS)
            and [row.get("id") for row in status["ownerDecisions"]] == list(DECISIONS)
            and status["ownerDecisions"] == _json(CONTRACT_DIR + "allowlists.json")["ownerDecisions"], "closed seccomp status")
    rounds = status["reviewRounds"]
    require([(row.get("round"), row.get("verdict")) for row in rounds] == list(ROUNDS), "three review rounds")
    for row in rounds:
        number = row["round"]
        require(row["record"] == CONTRACT_DIR + "review-round%d.json" % number
                and row["subjectDirectory"] == (CONTRACT_DIR + "round%d/" % number if number < 3 else "CURRENT")
                and row["recordSha256"] == digest(reviewed_bytes(row["record"])), "review round identity %d" % number)
        review = _json(row["record"])
        require(review.get("schemaVersion") == "planeon.internal.seccomp-allowlists-review/v1" and review.get("round") == number
                and review.get("verdict") == row["verdict"]
                and reviewer_actions_allowed(review.get("actions")),
                "review record %d" % number)
        require(review.get("subjectSha256") == {path: digest(reviewed_bytes(_round_path(number, path))) for path in SUBJECT},
                "review round %d is bound to its exact subject bytes" % number)
    final = _json(rounds[-1]["record"])
    require(all(row["severity"] in ("MINOR", "NOTE") for row in final["findings"])
            and {row["id"] for row in final["findings"]} <= set(status["carriedFindings"]),
            "the final round passes; every final finding is carried")


def validate_seccomp_allowlists() -> None:
    """The allowlists replay exactly, the published digests are the compiled programs, and adoption follows the review."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "predecessor contract bytes must stay unchanged: " + path)
    # The review binding is checked before the model is executed or any contract data is used.
    validate_seccomp_status()
    model = _era_model()
    table, policy = _json(CONTRACT_DIR + "syscalls.json"), _json(CONTRACT_DIR + "allowlists.json")
    validate_seccomp_policy(model, table, policy)
    checks = validate_seccomp_vectors(model, table, policy, _json(CONTRACT_DIR + "vectors.json"))
    require(checks >= sum(FLOORS.values()), "every seccomp vector replays")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "seccomp allowlists validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 225
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 225-packet catalog retaining the 219-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only seccomp-allowlists packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted seccomp-allowlists packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_seccomp_allowlists()


if __name__ == "__main__":
    validate()
    print("Seccomp allowlists valid: 225 current specifications; 219-packet checkpoint and exact 218-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
