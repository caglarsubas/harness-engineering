#!/usr/bin/env python3
"""Validate the I06 backend profile v2 contract (W02g-F) and the exact 211-to-210 projection."""
from __future__ import annotations

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
    import i06_backend_profile_v2 as model
    import validate_admission_semantics_v2 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import i06_backend_profile_v2 as model
    from scripts import validate_admission_semantics_v2 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/i06-backend-profile-v2-authority.json"
AUTHORITY_SHA256 = "c5a1616b478e50d57937d979fd29463d6c3fe4e7e82e1bc77be237cdaf973576"
VALIDATOR_PATH = "scripts/validate_i06_backend_profile_v2.py"
BASE_COMMIT = "487eca6809eca9fd5b2647f79522d107dee8d814"
NEW_PACKET = "MET-ENFORCE-012"
PREVIOUS_PACKET = "MET-ENFORCE-011"
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
            require(key not in result, "duplicate i06-backend-profile-v2 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite i06-backend-profile-v2 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "I06 profile v2 history authority digest")
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
    }, "closed I06 profile v2 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/i06-backend-profile-v2-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 210
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 210-packet base")
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
    # An exact 210-era byte string is already older than the successor layer.
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


# MET-ENFORCE-012 publishes the W02g-F successor contract, I06 backend profile v2. Repository bytes are read only
# through reviewed_bytes, so a later bridged successor projects its own edits away first; the reference model is
# imported and executed, and its exact bytes are bound by the review rounds below.
CONTRACT_DIR = "architecture/i06-backend-profile-v2/"
STATUS_PATH = CONTRACT_DIR + "status.json"
MODEL_PATH = "scripts/i06_backend_profile_v2.py"
SUBJECT_PATHS = {"README.md": CONTRACT_DIR + "README.md", "REVIEW_BRIEF.md": CONTRACT_DIR + "REVIEW_BRIEF.md",
                 "criteria.json": CONTRACT_DIR + "criteria.json", "vectors.json": CONTRACT_DIR + "vectors.json",
                 "i06_backend_profile_v2.py": MODEL_PATH}
V1_DIR = "architecture/i06-backend-profile/"
W02A_DIR = "architecture/native-profile-v3/"
W02A_V2_VECTORS = "architecture/native-profile-v2/vectors.json"
# The adopted I06 v1 profile and its inputs, the W02a v2 and v3 contracts and models stay byte-identical.
FROZEN_PATHS = tuple(V1_DIR + name for name in (
    "README.md", "criteria.json", "vectors.json", "status.json", "identity-closure.json", "writer-inventory.json",
    "upstream-facts-v1.37.1.json", "upstream-bootstrap-rbac-v1.37.1.json")) + (
    "scripts/i06_backend_profile.py", W02A_DIR + "README.md", W02A_DIR + "qualification.schema.json",
    W02A_DIR + "vectors.json", W02A_DIR + "status.json", "scripts/native_qualification_v3.py", W02A_V2_VECTORS,
    "architecture/native-profile-v2/status.json")
CHANGED_CRITERIA = ("SC00", "SC08", "IC03")
# v1 evidence negatives that now stop at an earlier rule (README "Replayed v1 cases").
CHANGED_REPLAYS = ("E06", "E35", "E36", "E38", "E55", "E56", "E60", "E61", "E70", "E71")
# v1 accepted variants whose backends W02a v3 refuses: moved to the cross-version cases.
MOVED_ACCEPTED = {"A02": "X03", "A05": "X04"}
DISTINCTNESS = "SC08 components must use distinct executables with distinct content (one entry type per confined domain)"
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
FALSE_FLAGS = ("nativeAcceptance", "tenantAcceptance", "installedProfile", "distributionSelected", "clusterObserved",
               "productionBackendProfile", "productExecution", "runnerActivated", "phaseComplete")
VECTOR_FLOORS = {"evidenceAccepted": 7, "snapshotAccepted": 5, "evidenceNegative": 91, "snapshotNegative": 38,
                 "crossVersion": 6}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _json(path: str) -> Any:
    return parse(reviewed_bytes(path))


def _locate(node: Any, key: Any) -> Any:
    if type(key) is dict:
        found = [index for index, item in enumerate(node) if all(item.get(k) == v for k, v in key.items())]
        require(len(found) == 1, "vector selector must match exactly one element")
        return found[0]
    return key


def _apply(value: Any, ops: list) -> Any:
    value = copy.deepcopy(value)
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete", "append") and type(op.get("path")) is list
                and op["path"], "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[_locate(node, key)]
        if op["op"] == "set":
            node[_locate(node, last)] = copy.deepcopy(op["value"])
        elif op["op"] == "delete":
            del node[_locate(node, last)]
        else:
            node[_locate(node, last)].append(copy.deepcopy(op["value"]))
    return value


def validate_i06_v2_criteria(criteria: dict, v1_criteria: dict) -> None:
    """v2 restates exactly SC00, SC08 and IC03 and keeps every other v1 criterion."""
    require(type(criteria) is dict and set(criteria) == set(v1_criteria)
            and criteria["schemaVersion"] == "planeon.internal.i06-selection-criteria/v2"
            and criteria["kubernetesBaseline"] == v1_criteria["kubernetesBaseline"], "closed v2 criteria")
    new, old = criteria["criteria"], v1_criteria["criteria"]
    require([row["id"] for row in new] == [row["id"] for row in old], "v2 keeps every v1 criterion in order")
    for row, before in zip(new, old):
        changed = row["id"] in CHANGED_CRITERIA
        require(set(row) == set(before) and row["checkedBy"] == before["checkedBy"]
                and (row["requirement"] != before["requirement"]) == changed
                and (row["source"] != before["source"]) == changed, "criterion " + row["id"])


def validate_i06_v2_vectors(vectors: dict, v1_vectors_raw: bytes, inventory: dict, closure: dict, bootstrap: dict,
                            w02a_vectors: dict, w02a_schema: dict, w02a_v2_vectors: dict) -> int:
    """Every case replays to its pinned result; every v1 case is replayed or moved, with the changed set pinned."""
    require(type(vectors) is dict and set(vectors) == {
        "evidenceClass", "kubernetesBaseline", "qualificationNamespace", "v1Vectors", "w02aBackend", "evidencePositive",
        "snapshotPositive", "evidenceAccepted", "snapshotAccepted", "evidenceNegative", "snapshotNegative", "crossVersion"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["kubernetesBaseline"] == "v1.37.1"
            and vectors["v1Vectors"] == {"path": V1_DIR + "vectors.json", "sha256": digest(v1_vectors_raw)}
            and vectors["w02aBackend"] == {"vectors": W02A_DIR + "vectors.json", "schema": W02A_DIR + "qualification.schema.json",
                                           "positive": 0}
            and all(len(vectors[key]) >= floor for key, floor in VECTOR_FLOORS.items()), "closed i06 v2 vectors")
    v1_vectors = parse(v1_vectors_raw)
    namespace = vectors["qualificationNamespace"]
    require(namespace == v1_vectors["qualificationNamespace"], "same qualification namespace")
    evidence, snapshot = vectors["evidencePositive"], vectors["snapshotPositive"]
    positives = w02a_vectors["positive"]
    require(snapshot == v1_vectors["snapshotPositive"]
            and {key: value for key, value in evidence.items() if key not in ("schemaVersion", "w02aRecord")}
            == {key: value for key, value in v1_vectors["evidencePositive"].items() if key != "schemaVersion"}
            and evidence["schemaVersion"] == model.EVIDENCE_VERSION
            and evidence["w02aRecord"] == {"schemaVersion": model.W02A_VERSION,
                                           "qualificationDigest": model.record_digest(positives[0]["record"])},
            "v2 positives are the v1 positives bound to W02a v3 positive 0")

    def w02a(row: dict) -> tuple:
        p = positives[row.get("w02aPositive", 0)]
        return _apply(p["record"], row["backendOps"]), p["profile"], p["endpoints"]

    def evidence_result(row: dict) -> Any:
        record, profile, endpoints = w02a(row)
        base = copy.deepcopy(evidence)
        base["w02aRecord"]["qualificationDigest"] = model.record_digest(record)
        return model.explain(model.check_evidence, _apply(base, row["ops"]), inventory, record, profile, endpoints,
                             w02a_schema, row["testFixture"])

    def snapshot_result(row: dict) -> Any:
        return model.explain(model.check_rbac_snapshot, _apply(snapshot, row["ops"]), closure, inventory, bootstrap,
                             row.get("namespace", namespace))

    record, profile, endpoints = positives[0]["record"], positives[0]["profile"], positives[0]["endpoints"]
    require(model.explain(model.check_evidence, evidence, inventory, record, profile, endpoints, w02a_schema, True) is None
            and model.explain(model.check_evidence, evidence, inventory, record, profile, endpoints, w02a_schema, False)
            == "SC00 a test-only W02a backend qualifies only in an explicit fixture call"
            and model.explain(model.check_rbac_snapshot, snapshot, closure, inventory, bootstrap, namespace) is None,
            "v2 positives: accepted as a fixture, refused in production")
    checks = 3
    for row in vectors["evidenceAccepted"]:
        require(row["testFixture"] is True and evidence_result(row) is None, "accepted evidence variant " + row["id"])
        checks += 1
    for row in vectors["snapshotAccepted"]:
        require(snapshot_result(row) is None, "accepted snapshot variant " + row["id"])
        checks += 1
    for key, replay in (("evidenceNegative", evidence_result), ("snapshotNegative", snapshot_result)):
        for row in vectors[key]:
            result = replay(row)
            require(result is not None and result == row["refusal"], key + " " + row["id"] + " refusal")
            checks += 1
    # Replay parity with v1: same operations and flags; only the pinned set changes its refusal.
    old_evidence = {row["id"]: row for row in v1_vectors["evidenceNegative"]}
    new_evidence = {row["id"]: row for row in vectors["evidenceNegative"]}
    for name, old in old_evidence.items():
        row = new_evidence.get(name)
        require(row is not None and row["ops"] == old["ops"] and row["backendOps"] == old["backendOps"]
                and row["testFixture"] is (not old["production"]), "v1 evidence negative replayed: " + name)
        if name in CHANGED_REPLAYS:
            require(row.get("v1Refusal") == old["refusal"] != row["refusal"], "changed replay pinned: " + name)
        else:
            require("v1Refusal" not in row and row["refusal"] == old["refusal"], "unchanged replay: " + name)
    old_snapshots = {row["id"]: row for row in v1_vectors["snapshotNegative"]}
    new_snapshots = {row["id"]: row for row in vectors["snapshotNegative"]}
    for name, old in old_snapshots.items():
        row = new_snapshots.get(name)
        require(row is not None and row["ops"] == old["ops"] and row["namespace"] == old["namespace"]
                and "v1Refusal" not in row and row["refusal"] == old["refusal"], "v1 snapshot negative replayed: " + name)
    accepted = {row["id"]: row for row in vectors["evidenceAccepted"]}
    for old in v1_vectors["evidenceAccepted"]:
        if old["id"] in MOVED_ACCEPTED:
            require(old["id"] not in accepted, "moved v1 accepted variant: " + old["id"])
        else:
            require(accepted.get(old["id"], {}).get("ops") == old["ops"], "v1 accepted variant replayed: " + old["id"])
    require([row["ops"] for row in vectors["snapshotAccepted"][:len(v1_vectors["snapshotAccepted"])]]
            == [row["ops"] for row in v1_vectors["snapshotAccepted"]], "v1 snapshot variants replayed")
    # R1-1: I06 code distinctness is pinned with backends W02a v3 accepts.
    for name in ("G19", "G20"):
        row = new_evidence.get(name)
        require(row is not None and model.w02a.explain(model.w02a.check_record, *w02a(row), w02a_schema) is None
                and row["refusal"] == DISTINCTNESS, "distinctness pinned with a W02a-accepted backend: " + name)
    # Cross-version: the v1 model with the W02a v2 backend against the v2 model with the W02a v3 record.
    old_record = w02a_v2_vectors["positive"][0]["record"]
    old_backend = {"backendProfile": old_record["backendProfile"], "backendComponents": old_record["backendComponents"]}
    moved = {MOVED_ACCEPTED[row["id"]]: row for row in v1_vectors["evidenceAccepted"] if row["id"] in MOVED_ACCEPTED}
    ids = []
    for row in vectors["crossVersion"]:
        ids.append(row["id"])
        if row["subject"] == "snapshot":
            value = _apply(snapshot, row["ops"])
            require(row["v1Result"] == model.v1.explain(model.v1.check_rbac_snapshot, value, closure, inventory, bootstrap,
                                                        row["namespace"]) is None
                    and row["v2Result"] == snapshot_result({"ops": row["ops"], "namespace": row["namespace"]}) is not None,
                    "cross-version " + row["id"])
        else:
            require(row["subject"] == "evidence" and row["v1Subject"] in ("v1", "v2") and row["v2Subject"] in ("v1", "v2"),
                    "closed cross-version case")
            if row["id"] in moved:
                old = moved[row["id"]]
                require(row["ops"] == old["ops"] and row["backendOps"] == old["backendOps"]
                        and row["production"] is old["production"], "moved v1 variant: " + row["id"])
            current, current_profile, current_endpoints = w02a(row)
            bound = copy.deepcopy(evidence)
            bound["w02aRecord"]["qualificationDigest"] = model.record_digest(current)
            bases = {"v1": v1_vectors["evidencePositive"], "v2": bound}
            require(row["v1Result"] == model.v1.explain(model.v1.check_evidence, _apply(bases[row["v1Subject"]], row["ops"]),
                                                        inventory, _apply(old_backend, row["backendOps"]), row["production"])
                    and row["v2Result"] == model.explain(model.check_evidence, _apply(bases[row["v2Subject"]], row["ops"]),
                                                         inventory, current, current_profile, current_endpoints,
                                                         w02a_schema, not row["production"]),
                    "cross-version " + row["id"])
        checks += 1
    all_ids = ids + [row["id"] for key in ("evidenceAccepted", "snapshotAccepted", "evidenceNegative", "snapshotNegative")
                     for row in vectors[key]]
    require(len(all_ids) == len(set(all_ids)), "unique vector identifiers")
    return checks


def _round_subject(directory: str) -> dict[str, str]:
    """Every earlier round keeps the files it reviewed under roundN/."""
    if directory == "CURRENT":
        return SUBJECT_PATHS
    require(directory in (CONTRACT_DIR + "round1/", CONTRACT_DIR + "round2/"), "closed review subject directory")
    return {name: directory + name for name in SUBJECT_PATHS}


def validate_i06_v2_status() -> None:
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == {
        "schemaVersion", "contract", "supersedes", "reviewRounds", "closedFindings", "carriedFindings", "ownerDecisions",
        "contractState", "obligations", "independentReviewer", *FALSE_FLAGS,
    } and status["schemaVersion"] == "planeon.internal.i06-backend-profile-v2-status/v1"
            and status["contract"] == "SEALED_SINGLE_NODE_CONTROL_PLANE_V1/i06-backend-profile/v2"
            and status["supersedes"] == "SEALED_SINGLE_NODE_CONTROL_PLANE_V1/i06-backend-profile"
            and status["ownerDecisions"] == []
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in FALSE_FLAGS), "closed I06 v2 status")
    require(type(status["closedFindings"]) is dict and {"N1", "N2", "N3", "W02A_P7"} <= set(status["closedFindings"])
            and type(status["carriedFindings"]) is dict and {"N4", "N5", "N6"} <= set(status["carriedFindings"]),
            "the W02g round-2 findings are dispositioned")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and 1 <= len(rounds) <= 3, "review rounds")
    for number, row in enumerate(rounds, 1):
        require(type(row) is dict and set(row) == {"round", "record", "recordSha256", "verdict", "subjectDirectory"}
                and row["round"] == number and row["record"] == CONTRACT_DIR + "review-round%d.json" % number
                and row["subjectDirectory"] == ("CURRENT" if number == len(rounds) else CONTRACT_DIR + "round%d/" % number),
                "review round identity")
        raw = reviewed_bytes(row["record"])
        require(digest(raw) == row["recordSha256"], "review record drift: " + row["record"])
        review = parse(raw)
        require(type(review) is dict and review.get("schemaVersion") == "planeon.internal.i06-backend-profile-v2-review/v1"
                and review.get("round") == number and review.get("verdict") == row["verdict"]
                and row["verdict"] in ("PASS_FOR_SOURCE_PUBLICATION", "CHANGES_REQUIRED", "BLOCKED")
                and type(review.get("actions")) is dict
                and all(review["actions"][key] is False for key in review["actions"] if key != "referenceModelExecuted"),
                "review record " + str(number))
        subject = _round_subject(row["subjectDirectory"])
        require(review.get("subjectSha256") == {name: digest(reviewed_bytes(path)) for name, path in subject.items()},
                "review round " + str(number) + " is bound to its exact subject bytes")
    final = parse(reviewed_bytes(rounds[-1]["record"]))
    findings = final.get("findings")
    passed = final["verdict"] == "PASS_FOR_SOURCE_PUBLICATION"
    require(type(findings) is list and {row.get("id") for row in findings} <= set(status["carriedFindings"])
            and (not passed or all(row.get("severity") == "NOTE" for row in findings)),
            "every final finding is carried; a pass leaves only notes")
    require(status["contractState"] == ("ADOPTED_DATA_CONTRACT" if passed else "CONTRACT_CANDIDATE"),
            "contract state follows the final independent review")


def validate_i06_backend_profile_v2() -> None:
    """The v2 contract is closed and replays exactly; predecessors are untouched; adoption follows the review."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "predecessor contract bytes must stay unchanged: " + path)
    validate_i06_v2_criteria(_json(SUBJECT_PATHS["criteria.json"]), _json(V1_DIR + "criteria.json"))
    checks = validate_i06_v2_vectors(
        _json(SUBJECT_PATHS["vectors.json"]), reviewed_bytes(V1_DIR + "vectors.json"),
        _json(V1_DIR + "writer-inventory.json"), _json(V1_DIR + "identity-closure.json"),
        _json(V1_DIR + "upstream-bootstrap-rbac-v1.37.1.json"), _json(W02A_DIR + "vectors.json"),
        _json(W02A_DIR + "qualification.schema.json"), _json(W02A_V2_VECTORS))
    require(checks >= sum(VECTOR_FLOORS.values()) + 3, "every v2 vector replays")
    validate_i06_v2_status()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "I06 profile v2 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 219
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 219-packet catalog retaining the 211-packet checkpoint")
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
            "closed source-only i06-backend-profile-v2 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted i06-backend-profile-v2 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_i06_backend_profile_v2()


if __name__ == "__main__":
    validate()
    print("I06 profile v2 contract valid: 219 current specifications; 211-packet checkpoint and exact 210-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
