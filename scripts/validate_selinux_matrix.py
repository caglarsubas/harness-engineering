#!/usr/bin/env python3
"""Validate the SELinux domain, type, boolean and permission matrix (W02e) and the exact 206-to-205 projection."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import stat
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
    import selinux_matrix as model
    import validate_sector_direction as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import selinux_matrix as model
    from scripts import validate_sector_direction as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/selinux-matrix-authority.json"
AUTHORITY_SHA256 = "383db4407986408c8d27dcfc6673d7b456df6715c2ffbf02518da1ee866e4c7e"
VALIDATOR_PATH = "scripts/validate_selinux_matrix.py"
BASE_COMMIT = "f4edb9afee08e52435f470cf32d2ebc4bbca384e"
NEW_PACKET = "MET-ENFORCE-009"
PREVIOUS_PACKET = "MET-ENFORCE-008"
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
            require(key not in result, "duplicate selinux-matrix authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite selinux-matrix authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "selinux matrix history authority digest")
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
    }, "closed selinux matrix history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/selinux-matrix-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 205
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 205-packet base")
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
    # An exact 205-era byte string is already older than the successor layer.
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


CONTRACT_DIR = "architecture/selinux-matrix/"
STATUS_PATH = CONTRACT_DIR + "status.json"
SUBJECT_PATHS = {"README.md": CONTRACT_DIR + "README.md", "REVIEW_BRIEF.md": CONTRACT_DIR + "REVIEW_BRIEF.md",
                 "matrix.json": CONTRACT_DIR + "matrix.json", "vectors.json": CONTRACT_DIR + "vectors.json",
                 "selinux_matrix.py": "scripts/selinux_matrix.py"}
# The reviewed W01 design and the adopted W02a, W02g, W02b and W02c contracts stay byte-identical; the matrix fills
# W02a's open label slots and must agree with its fixed process labels.
W02A_SCHEMA = "architecture/native-profile-v2/qualification.schema.json"
FROZEN_PATHS = ("architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md",
                "architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md",
                "architecture/host-interface-inputs/resolution-review-round1.json", W02A_SCHEMA,
                "architecture/native-profile-v2/README.md", "architecture/native-profile-v2/status.json",
                "architecture/i06-backend-profile/identity-closure.json", "architecture/i05-gate-channel/README.md",
                "architecture/i07-policy-write/README.md", "scripts/i05_gate_channel.py", "scripts/i07_policy_write.py")
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
FALSE_FLAGS = ("nativeAcceptance", "tenantAcceptance", "policyModuleWritten", "policyLoaded", "distributionSelected",
               "seccompFiltersDefined", "w02aSchemaConstantsFixed", "productExecution", "runnerActivated", "phaseComplete")


def _round_subject(directory: str) -> dict[str, str]:
    """Earlier rounds keep the files they reviewed under roundN/ when those files changed later;
    an unchanged file is reviewed in place and must still hash to the recorded subject."""
    if directory == "CURRENT":
        return SUBJECT_PATHS
    require(directory in (CONTRACT_DIR + "round1/", CONTRACT_DIR + "round2/", CONTRACT_DIR + "round3/"),
            "closed review subject directory")
    return {name: directory + name if (ROOT / (directory + name)).is_file() else path for name, path in SUBJECT_PATHS.items()}


def _json_file(path: str) -> Any:
    return parse(regular_bytes(path))


def validate_w02a_agreement(matrix: dict) -> None:
    """Process labels equal W02a's constants; slot values fit W02a's label patterns; W02a's domain census is covered."""
    import re
    defs = _json_file(W02A_SCHEMA)["$defs"]
    labels = {d["label"] for d in matrix["domains"]}
    fixed = [v["properties"]["processLabel"]["const"] for v in defs["roles"]["properties"].values()]
    fixed += [v["properties"]["processLabel"]["const"] for v in defs["lifecycleSubjects"]["properties"].values()]
    fixed += [v["allOf"][1]["properties"]["processLabel"]["const"] for v in defs["backendComponents"]["properties"].values()]
    require(set(fixed) <= labels and len(fixed) == 15, "every W02a process label is a matrix domain")
    require(set(defs["lifecycleCapture"]["properties"]["domainProcessCounts"]["required"]) <= {d["name"] for d in matrix["domains"]},
            "W02a's domain census names matrix domains")
    slots = model.w02a_slots(matrix)
    patterns = [defs["roleCgroup"]["properties"]["selinuxLabel"]["pattern"], defs["program"]["properties"]["pinLabel"]["pattern"],
                defs["hardening"]["properties"]["sealMarker"]["properties"]["selinuxLabel"]["pattern"]]
    values = [list(slots["roleCgroupLabels"].values()), [slots["bpfPinLabel"]], [slots["sealMarkerLabel"]]]
    require(all(re.fullmatch(pattern, value) for pattern, group in zip(patterns, values) for value in group),
            "slot values fit the W02a label patterns")


def validate_vectors(matrix: dict, vectors: dict) -> int:
    """Replay every vector through the reference evaluator; returns the number of checks."""
    require(type(vectors) is dict and set(vectors) == {"evidenceClass", "accessChecks", "mutationChecks", "w02aSlots"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY", "closed selinux matrix vectors")
    checks = 0
    for row in vectors["accessChecks"]:
        require(model.allowed(matrix, row["state"], row["source"], row["target"], row["class"], row["perm"]) is row["expect"],
                "access check " + row["id"])
        checks += 1
    for row in vectors["mutationChecks"]:
        mutated = model.apply_ops(matrix, row["ops"])
        expect = row["expect"]
        try:
            model.check_matrix(mutated)
            ok = expect == {"failedAssertions": model.failed_assertions(mutated)} and expect["failedAssertions"] != []
        except ValueError as exc:
            # The pinned refusal is the full message or the part naming the refused object.
            ok = set(expect) == {"matrixError"} and expect["matrixError"] in (str(exc), str(exc).split(":", 1)[0])
        require(ok, "mutation check " + row["id"])
        checks += 1
    require(vectors["w02aSlots"] == model.w02a_slots(matrix), "W02a slot values")
    ids = [row["id"] for key in ("accessChecks", "mutationChecks") for row in vectors[key]]
    require(len(ids) == len(set(ids)) and len(vectors["accessChecks"]) >= 1716 and len(vectors["mutationChecks"]) >= 50,
            "closed vector inventory with unique identifiers")
    return checks + 1


def validate_selinux_contract() -> None:
    """The matrix is closed, every assertion holds, the vectors replay, W02a agrees; adoption follows the review."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "predecessor contract bytes must stay unchanged: " + path)
    matrix = _json_file(SUBJECT_PATHS["matrix.json"])
    model.check_matrix(matrix)
    require(model.failed_assertions(matrix) == [] and len(matrix["assertions"]) >= 100, "every deny assertion holds")
    validate_w02a_agreement(matrix)
    validate_vectors(matrix, _json_file(SUBJECT_PATHS["vectors.json"]))
    validate_selinux_status()


def validate_selinux_status() -> None:
    status = _json_file(STATUS_PATH)
    require(type(status) is dict and set(status) == {
        "schemaVersion", "contract", "reviewRounds", "carriedFindings", "ownerDecisions", "contractState", "obligations",
        "independentReviewer", "f2", *FALSE_FLAGS,
    } and status["schemaVersion"] == "planeon.internal.selinux-matrix-status/v1"
            and status["contract"] == model.MATRIX_VERSION
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and status["f2"] in ("CLOSED_DESIGN", "OPEN")
            and all(status[flag] is False for flag in FALSE_FLAGS), "closed selinux matrix status")
    decisions = status["ownerDecisions"]
    require(type(decisions) is list and all(type(row) is dict and set(row) == {"id", "date", "finding", "decision", "amends",
                                                                               "carriedTo"} for row in decisions)
            and [row["id"] for row in decisions][:1] == ["E1"],
            "owner decisions, E1 first, are recorded where downstream parts read them")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and 1 <= len(rounds) <= 4, "review rounds")
    for number, row in enumerate(rounds, 1):
        require(type(row) is dict and set(row) == {"round", "record", "recordSha256", "verdict", "subjectDirectory"}
                and row["round"] == number
                and (row["subjectDirectory"] == "CURRENT") == (number == len(rounds)), "review round identity")
        raw = regular_bytes(row["record"])
        require(digest(raw) == row["recordSha256"], "review record drift: " + row["record"])
        review = parse(raw)
        require(type(review) is dict and review.get("schemaVersion") == "planeon.internal.selinux-matrix-review/v1"
                and review.get("round") == number and review.get("verdict") == row["verdict"]
                and row["verdict"] in ("PASS_FOR_SOURCE_PUBLICATION", "CHANGES_REQUIRED", "BLOCKED")
                and type(review.get("actions")) is dict
                and all(review["actions"][key] is False for key in review["actions"] if key != "referenceModelExecuted"),
                "review record " + str(number))
        require(number == len(rounds) or row["verdict"] != "PASS_FOR_SOURCE_PUBLICATION",
                "a passed round has no successor round")
        subject = _round_subject(row["subjectDirectory"])
        # A reviewer may key the digests by file name or by repository path.
        by_name = {next((n for n, p in SUBJECT_PATHS.items() if key in (n, p)), key): value
                   for key, value in review.get("subjectSha256", {}).items()}
        require(set(by_name) == set(subject) and len(by_name) == len(review.get("subjectSha256", {}))
                and all(digest(regular_bytes(path)) == by_name[name] for name, path in subject.items()),
                "review round " + str(number) + " is bound to its exact subject bytes")
    final = parse(regular_bytes(rounds[-1]["record"]))
    findings = final.get("findings")
    passed = final["verdict"] == "PASS_FOR_SOURCE_PUBLICATION"
    require(type(findings) is list and type(status["carriedFindings"]) is dict
            and set(status["carriedFindings"]) == {row.get("id") for row in findings}
            and (not passed or all(row.get("severity") in ("MINOR", "NOTE") for row in findings)),
            "every final finding is carried; a pass has no blocking or major finding")
    require(status["contractState"] == ("ADOPTED_DATA_CONTRACT" if passed else "CONTRACT_CANDIDATE")
            and (status["f2"] == "CLOSED_DESIGN") == passed, "contract state and F2 follow the final independent review")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "selinux matrix validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 212
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 212-packet catalog retaining the 206-packet checkpoint")
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
            "closed source-only selinux-matrix packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted selinux-matrix packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_selinux_contract()


if __name__ == "__main__":
    validate()
    print("SELinux matrix contract valid: 212 current specifications; 206-packet checkpoint and exact 205-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
