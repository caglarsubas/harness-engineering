#!/usr/bin/env python3
"""Validate the I05 broker-gate channel v2 contract (W02b-F) and the exact 210-to-209 projection."""
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
    import i05_gate_channel_v2 as model
    import validate_i06_backend_profile_v2 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import i05_gate_channel_v2 as model
    from scripts import validate_i06_backend_profile_v2 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/i05-gate-channel-v2-authority.json"
AUTHORITY_SHA256 = "62da18524bfa5e6102ec1b3e0912f3c2c94122ad87b57247dbe5c55aa326c7dd"
VALIDATOR_PATH = "scripts/validate_i05_gate_channel_v2.py"
BASE_COMMIT = "a29c93c7813ff71eb8179c4e8611032d972e3a36"
NEW_PACKET = "MET-ENFORCE-011"
PREVIOUS_PACKET = "MET-ENFORCE-010"
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
            require(key not in result, "duplicate i05-gate-channel-v2 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite i05-gate-channel-v2 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "I05 channel v2 history authority digest")
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
    }, "closed I05 channel v2 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/i05-gate-channel-v2-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 209
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 209-packet base")
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
    # An exact 209-era byte string is already older than the successor layer.
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


# MET-ENFORCE-011 publishes the W02b-F successor contract planeon.internal.effect-gate-frame/v2. Repository bytes are
# read only through reviewed_bytes, so a later bridged successor projects its own edits away first; the reference model
# is imported and executed, and its exact bytes are bound by the review round below.
CONTRACT_DIR = "architecture/i05-gate-channel-v2/"
STATUS_PATH = CONTRACT_DIR + "status.json"
MODEL_PATH = "scripts/i05_gate_channel_v2.py"
SUBJECT_PATHS = {"README.md": CONTRACT_DIR + "README.md", "REVIEW_BRIEF.md": CONTRACT_DIR + "REVIEW_BRIEF.md",
                 "channel.schema.json": CONTRACT_DIR + "channel.schema.json",
                 "outcome-mapping.json": CONTRACT_DIR + "outcome-mapping.json",
                 "vectors.json": CONTRACT_DIR + "vectors.json", "i05_gate_channel_v2.py": MODEL_PATH}
V1_DIR = "architecture/i05-gate-channel/"
# The adopted v1 contract and model, the I07 contract that extends the v1 model and the W01 resolution stay
# byte-identical.
FROZEN_PATHS = (V1_DIR + "README.md", V1_DIR + "channel.schema.json", V1_DIR + "outcome-mapping.json",
                V1_DIR + "vectors.json", V1_DIR + "status.json", "scripts/i05_gate_channel.py",
                "architecture/i07-policy-write/README.md", "architecture/i07-policy-write/status.json",
                "scripts/i07_policy_write.py", "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md")
KUBERNETES_COMMIT = "f78e722310e50bcaca9276be22276d9e91d91308"
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
FALSE_FLAGS = ("nativeAcceptance", "tenantAcceptance", "gateInstalled", "journalImplemented", "failureMarkerImplemented",
               "substrateSelected", "distributionSelected", "i07MovedToV2", "productExecution", "runnerActivated",
               "phaseComplete")
CARRIED = ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8")
VECTOR_FLOORS = {"transcripts": 106, "agreement": 42, "frames": 33, "byteFrames": 14, "configRefusals": 3}
INPUT_TYPES = {"bytes": bytes, "bytearray": bytearray, "str": lambda raw: raw.decode("ascii")}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _json(path: str) -> Any:
    return parse(reviewed_bytes(path))


def validate_v2_schema(schema: dict, mapping: dict) -> None:
    """The frame schema is the v2 version; the mapping excludes 408 from the mutation 4xx rows and pins its sources."""
    import jsonschema
    jsonschema.Draft202012Validator.check_schema(schema)
    require(schema.get("$id") == "urn:planeon:internal:effect-gate-frame:v2"
            and all(variant["properties"]["schemaVersion"] == {"const": model.FRAME_VERSION} for variant in schema["oneOf"])
            and len(schema["oneOf"]) == 2 * len(model.OPERATIONS), "v2 frame schema version")
    require(mapping.get("schemaVersion") == "planeon.internal.effect-gate-outcome-mapping/v2"
            and all(type(row.get("excludeStatus")) is list for row in mapping["rows"])
            and {(row["verb"], row["httpStatus"]): row["excludeStatus"] for row in mapping["rows"]
                 if row["httpStatus"] == "4xx"} == {("CREATE", "4xx"): [408], ("GET", "4xx"): [], ("DELETE", "4xx"): [408]},
            "the mutation 4xx agreement rows exclude 408")
    source = mapping.get("upstreamSource", {})
    require(source.get("tag") == "v1.37.1" and source.get("commit") == KUBERNETES_COMMIT
            and len(source.get("files", [])) == 5 and all(_sha(row.get("sha256")) for row in source["files"]),
            "pinned upstream Kubernetes sources")


def validate_v2_vectors(schema: dict, mapping: dict, vectors: dict) -> int:
    """Every case replays to its pinned result through the reference model."""
    require(vectors["evidenceClass"] == "DATA_CHECK_ONLY" and set(vectors["configs"]) == {"ACTIVE", "INSPECTING", "LATER"}
            and all(len(vectors[key]) >= floor for key, floor in VECTOR_FLOORS.items()), "v2 vectors are closed")
    checks = 0
    for row in vectors["transcripts"]:
        outputs, final = model.replay(vectors["configs"][row["config"]], row["events"], schema)
        require(outputs == row["outputs"] and final == row["final"], "transcript " + row["id"])
        checks += 1
    for row in vectors["agreement"]:
        got = model.check_agreement(mapping, row["verb"], row["identity"], row["outcome"], row["resourceResult"])
        require(got == row["expect"], "agreement " + row["id"])
        checks += 1
    for row in vectors["frames"]:
        try:
            model.check_frame(row["frame"], schema)
            got = None
        except ValueError as exc:
            got = str(exc)
        require(got == row["expect"], "frame " + row["id"])
        checks += 1
    for row in vectors["byteFrames"]:
        try:
            model.decode_frame(INPUT_TYPES[row["inputType"]](_base64(row["base64"])), schema)
            got = None
        except ValueError as exc:
            got = str(exc)
        require(got == row["expect"], "byte frame " + row["id"])
        checks += 1
    for row in vectors["configRefusals"]:
        try:
            model.Gate(dict(vectors["configs"]["ACTIVE"], **row["override"]))
            got = None
        except ValueError as exc:
            got = str(exc)
        require(got is not None and got == row["expect"], "configuration refusal " + row["id"])
        checks += 1
    return checks


def validate_v2_status() -> None:
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == {
        "schemaVersion", "contract", "predecessorContract", "reviewRounds", "closedFindings", "carriedFindings",
        "ownerDecisions", "contractState", "obligations", "independentReviewer", *FALSE_FLAGS,
    } and status["schemaVersion"] == "planeon.internal.i05-gate-channel-v2-status/v1"
            and status["contract"] == model.FRAME_VERSION
            and status["predecessorContract"] == "planeon.internal.effect-gate-frame/v1"
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR" and status["ownerDecisions"] == []
            and all(status[flag] is False for flag in FALSE_FLAGS), "closed I05 v2 status")
    require(type(status["closedFindings"]) is dict and set(status["closedFindings"]) == set(CARRIED),
            "the carried v1 round-3 findings are dispositioned")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and len(rounds) == 1, "review rounds")
    row = rounds[0]
    require(type(row) is dict and set(row) == {"round", "record", "recordSha256", "verdict", "subjectDirectory"}
            and row["round"] == 1 and row["subjectDirectory"] == "CURRENT"
            and row["record"] == CONTRACT_DIR + "review-round1.json", "review round identity")
    raw = reviewed_bytes(row["record"])
    require(digest(raw) == row["recordSha256"], "review record drift: " + row["record"])
    review = parse(raw)
    require(type(review) is dict and review.get("schemaVersion") == "planeon.internal.i05-gate-channel-v2-review/v1"
            and review.get("round") == 1 and review.get("verdict") == row["verdict"]
            and row["verdict"] in ("PASS_FOR_SOURCE_PUBLICATION", "CHANGES_REQUIRED", "BLOCKED")
            and type(review.get("actions")) is dict
            and all(review["actions"][key] is False for key in review["actions"] if key != "referenceModelExecuted"),
            "review record 1")
    subject = review.get("subjectSha256", {})
    require(set(subject) == set(SUBJECT_PATHS)
            and all(digest(reviewed_bytes(path)) == subject[name] for name, path in SUBJECT_PATHS.items()),
            "review round 1 is bound to its exact subject bytes")
    require(type(review.get("openItemStatus")) is dict
            and all(review["openItemStatus"].get(name, {}).get("status") == "CLOSED" for name in CARRIED),
            "the review closes every carried finding")
    findings = review.get("findings")
    passed = review["verdict"] == "PASS_FOR_SOURCE_PUBLICATION"
    require(type(findings) is list and type(status["carriedFindings"]) is dict
            and set(status["carriedFindings"]) == {finding.get("id") for finding in findings}
            and (not passed or all(finding.get("severity") in ("MINOR", "NOTE") for finding in findings)),
            "every final finding is carried; a pass has no blocking or major finding")
    require(status["contractState"] == ("ADOPTED_DATA_CONTRACT" if passed else "CONTRACT_CANDIDATE"),
            "contract state follows the final independent review")


def validate_i05_gate_channel_v2() -> None:
    """The v2 contract is closed and replays exactly; predecessors are untouched; adoption follows the review."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "predecessor contract bytes must stay unchanged: " + path)
    schema = _json(SUBJECT_PATHS["channel.schema.json"])
    mapping = _json(SUBJECT_PATHS["outcome-mapping.json"])
    validate_v2_schema(schema, mapping)
    checks = validate_v2_vectors(schema, mapping, _json(SUBJECT_PATHS["vectors.json"]))
    require(checks >= sum(VECTOR_FLOORS.values()), "every v2 vector replays")
    validate_v2_status()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "I05 channel v2 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 215
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 215-packet catalog retaining the 210-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only i05-gate-channel-v2 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted i05-gate-channel-v2 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_i05_gate_channel_v2()


if __name__ == "__main__":
    validate()
    print("I05 channel v2 contract valid: 215 current specifications; 210-packet checkpoint and exact 209-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
