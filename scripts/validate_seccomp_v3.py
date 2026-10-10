#!/usr/bin/env python3
"""Validate the MET-ENFORCE-020 seccomp allowlists v3 and the exact 222-to-221 projection."""
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
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/seccomp-v3-authority.json"
AUTHORITY_SHA256 = "14ff4d7d5f0af242265fa17ed8940b46bf1ca34e8c9891885b0670b285ceb528"
VALIDATOR_PATH = "scripts/validate_seccomp_v3.py"
BASE_COMMIT = "0e747049cba3eca9ec5b0334e0314525d053a83c"
NEW_PACKET = "MET-ENFORCE-020"
PREVIOUS_PACKET = "MET-ENFORCE-019"
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
            require(key not in result, "duplicate seccomp-v3 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite seccomp-v3 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "seccomp v3 history authority digest")
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
    }, "closed seccomp v3 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/seccomp-v3-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 221
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 221-packet base")
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


# MET-ENFORCE-020 (roadmap W02d-V3) publishes the W02d successor planeon.internal.seccomp-allowlists/v3: owner decision
# W02d-V3 adds three narrow NATIVE_STATIC rules for the Rust+musl native roles (mremap only with MREMAP_MAYMOVE, prctl only
# with PR_SET_NAME, tkill). Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its
# own edits away first. The reference model is executed from this era's reviewed bytes, not imported, after the review
# binding has been checked.
V3_DIR = "architecture/seccomp-allowlists-v3/"
V3_MODEL = "scripts/seccomp_allowlists_v3.py"
SUBJECT = (V3_DIR + "README.md", V3_DIR + "REVIEW_BRIEF.md", V3_DIR + "syscalls.json", V3_DIR + "allowlists.json",
           V3_DIR + "vectors.json", V3_MODEL)
ROUNDS = ((1, "PASS_FOR_SOURCE_PUBLICATION"), (2, "PASS_FOR_SOURCE_PUBLICATION"))
LAST_ROUND = len(ROUNDS)
# Round 1 passed with two MINOR README findings; the README and brief it reviewed are kept under round1/.
ROUND_COPIES = {1: (V3_DIR + "README.md", V3_DIR + "REVIEW_BRIEF.md")}
# The adopted v2 contract stays byte-identical: v3 succeeds it.
FROZEN_PATHS = ("architecture/seccomp-allowlists-v2/README.md", "architecture/seccomp-allowlists-v2/syscalls.json",
                "architecture/seccomp-allowlists-v2/allowlists.json", "architecture/seccomp-allowlists-v2/vectors.json",
                "architecture/seccomp-allowlists-v2/status.json", "scripts/seccomp_allowlists_v2.py")
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
REVIEW_ACTIONS = ("filesEdited", "githubMutated", "nativeActions", "repositoryValidatorsRun", "runnerActivated", "testsRun")
V3_DECISIONS = ("W02d-Q1", "W02d-Q2", "W02d-Q3", "W01-AMEND-QW1", "W01-AMEND-QW2", "W01-AMEND-QW3", "W02d-V3", "W01-AMEND-QW4")
FLOORS = {"decisionChecks": 2953, "workerStackChecks": 355, "policyMutations": 18}
V3_FALSE = ("nativeAcceptance", "tenantAcceptance", "filtersInstalled", "roleCodeExists", "traceValidated",
            "distributionSelected", "productExecution", "runnerActivated", "phaseComplete")


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _json(path: str) -> Any:
    return parse(reviewed_bytes(path))


def _era_model() -> types.ModuleType:
    """The v3 reference model of this era, executed from its reviewed bytes."""
    module = types.ModuleType("_met_enforce_020_seccomp_allowlists_v3")
    module.__file__ = str(ROOT / V3_MODEL)
    exec(compile(reviewed_bytes(V3_MODEL), V3_MODEL, "exec"), module.__dict__)
    return module


def reviewer_actions_allowed(actions: Any) -> bool:
    """Exactly the eight reviewer action booleans; reading and model execution may be true, every other action false."""
    return (type(actions) is dict and set(actions) == set(REVIEW_ACTIONS) | {"referenceModelExecuted", "warmSourcesAccessed"}
            and all(type(value) is bool for value in actions.values())
            and all(actions[key] is False for key in REVIEW_ACTIONS))


def _round_path(number: int, path: str) -> str:
    """A round's reviewed bytes of path: its kept copy if a later round changed the file, else the current file."""
    return V3_DIR + "round%d/" % number + path if path in ROUND_COPIES.get(number, ()) else path


def validate_v3_status() -> dict:
    """The status is closed, its rounds are bound to their exact subject bytes, and the last round passes with notes."""
    status = _json(V3_DIR + "status.json")
    require(type(status) is dict and set(status) == {
        "schemaVersion", "contract", "kernel", "supersedes", "ownerDecisions", "reviewRounds", "closedFindings",
        "carriedFindings", "carriedToW03", "openObligations", "contractState", "obligations", "independentReviewer", *V3_FALSE}
            and status["schemaVersion"] == "planeon.internal.seccomp-allowlists-status/v3"
            and status["contract"] == "planeon.internal.seccomp-allowlists/v3"
            and status["supersedes"] == {"directory": "architecture/seccomp-allowlists-v2/",
                                         "contract": "planeon.internal.seccomp-allowlists/v2",
                                         "status": "architecture/seccomp-allowlists-v2/status.json"}
            and status["contractState"] == "ADOPTED_DATA_CONTRACT"
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in V3_FALSE)
            and status["ownerDecisions"] == _json(V3_DIR + "allowlists.json")["ownerDecisions"], "closed seccomp v3 status")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and [(row.get("round"), row.get("verdict")) for row in rounds if type(row) is dict]
            == list(ROUNDS), "two review rounds")
    for row in rounds:
        number = row["round"]
        require(set(row) == {"round", "record", "recordSha256", "verdict", "subjectDirectory"}
                and row["record"] == V3_DIR + "review-round%d.json" % number
                and row["subjectDirectory"] == (V3_DIR + "round%d/" % number if number < LAST_ROUND else "CURRENT")
                and row["recordSha256"] == digest(reviewed_bytes(row["record"])), "review round identity %d" % number)
        review = _json(row["record"])
        require(type(review) is dict and review.get("schemaVersion") == "planeon.internal.seccomp-allowlists-v3-review/v1"
                and review.get("round") == number and review.get("verdict") == row["verdict"]
                and reviewer_actions_allowed(review.get("actions")), "review record %d" % number)
        require(review.get("subjectSha256") == {path: digest(reviewed_bytes(_round_path(number, path))) for path in SUBJECT},
                "review round %d is bound to its exact subject bytes" % number)
    final = _json(rounds[-1]["record"])
    require(all(type(row) is dict and row.get("severity") == "NOTE" for row in final["findings"])
            and {row["id"] for row in final["findings"]} <= set(status["carriedFindings"]),
            "the final round passes with notes only, all carried")
    return status


def validate_v3_vectors(model: types.ModuleType, table: dict, policy: dict, vectors: dict) -> int:
    """Every decision replays through both the reference decision and the compiled program; the worker's stacked filters
    decide as its own; every mutation is refused with its stated message; the digests are the compiled programs'."""
    require(table.get("schemaVersion") == "planeon.internal.seccomp-syscall-table/v3"
            and table.get("kernel") == {"tag": "v6.12", "commit": "adc218676eef25575469234709c2d87185ca223a"}
            and policy.get("schemaVersion") == "planeon.internal.seccomp-allowlists/v3" and policy.get("mode") == 2
            and policy.get("defaultAction") == "KILL_PROCESS"
            and [row.get("id") for row in policy["ownerDecisions"]] == list(V3_DECISIONS), "closed v3 table and policy")
    model.check_policy(policy, table)
    require(type(vectors) is dict and set(vectors) == {"evidenceClass", "filterDigests", "programLengths", "decisionChecks",
                                                       "workerStackChecks", "policyMutations"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY"
            and all(len(vectors[key]) >= floor for key, floor in FLOORS.items()), "closed v3 vectors")
    programs = {(role, arch): model.compile_filter(policy, table, role, arch) for role in model.ROLES for arch in model.ARCHES}
    require(vectors["filterDigests"] == {role: {arch: "sha256:" + digest(model.program_bytes(programs[role, arch]))
                                                for arch in model.ARCHES} for role in model.ROLES}
            and vectors["programLengths"] == {role: {arch: len(programs[role, arch]) for arch in model.ARCHES}
                                              for role in model.ROLES}, "the published v3 digests are the compiled programs'")
    checks, by_id = 0, {}
    for row in vectors["decisionChecks"]:
        data = model.seccomp_data(row["nr"], row["auditArch"], row["args"])
        expect = model.action_name(model.decide(policy, table, row["role"], row["arch"], row["auditArch"], row["nr"], row["args"]))
        require(expect == row["expect"] == model.action_name(model.run_filter(programs[row["role"], row["arch"]], data)),
                "v3 decision check " + row["id"])
        by_id[row["id"]] = row
        checks += 1
    for row in vectors["workerStackChecks"]:
        base = by_id[row["decision"]]
        require(base["role"] == "WORKER" and row["expect"] == "SAME_AS_WORKER"
                and model.decide_stack(policy, table, ["BROKER", "WORKER"], base["arch"], base["auditArch"], base["nr"], base["args"])
                == model.decide(policy, table, "WORKER", base["arch"], base["auditArch"], base["nr"], base["args"]),
                "v3 worker stack check " + row["id"])
        checks += 1
    for row in vectors["policyMutations"]:
        changed = copy.deepcopy(policy)
        changed["roles"][row["role"]]["duties"].append(row["addDuty"])
        try:
            model.check_policy(changed, table)
            refused = None
        except ValueError as exc:
            refused = str(exc)
        require(refused is not None and refused == row["expect"], "v3 policy mutation " + row["id"])
        checks += 1
    return checks


def validate_seccomp_v3() -> None:
    """The review binding first; then the full v3 replay, from this era's reviewed bytes."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "predecessor contract bytes must stay unchanged: " + path)
    validate_v3_status()
    checks = validate_v3_vectors(_era_model(), _json(V3_DIR + "syscalls.json"), _json(V3_DIR + "allowlists.json"),
                                 _json(V3_DIR + "vectors.json"))
    require(checks >= sum(FLOORS.values()), "every v3 vector replays")


def validate() -> None:
    record = authority()
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "seccomp v3 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 222 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 222-packet catalog")
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
            "closed source-only seccomp-v3 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted seccomp-v3 packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_seccomp_v3()


if __name__ == "__main__":
    validate()
    print("Seccomp allowlists v3 valid: 222 current specifications; exact 221-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
