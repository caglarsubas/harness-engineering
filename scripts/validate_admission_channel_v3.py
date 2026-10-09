#!/usr/bin/env python3
"""Validate the W02-ADM-F successor contracts (I05 v3, admission semantics v3, I07 v3) and the exact 214-to-213 projection."""
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
    import i05_gate_channel_v3 as model5
    import admission_semantics_v3 as modela
    import i07_policy_write_v3 as model7
    import validate_selinux_matrix_v2 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import i05_gate_channel_v3 as model5
    from scripts import admission_semantics_v3 as modela
    from scripts import i07_policy_write_v3 as model7
    from scripts import validate_selinux_matrix_v2 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/admission-channel-v3-authority.json"
AUTHORITY_SHA256 = "e6af6ae19a07090bd3b3f9a6c5735e6ca35ebd59aa4447866a08f49af51076df"
VALIDATOR_PATH = "scripts/validate_admission_channel_v3.py"
BASE_COMMIT = "f88e7f7884de9c96a09ed8aa65d468966038bffd"
NEW_PACKET = "MET-ENFORCE-015"
PREVIOUS_PACKET = "MET-ENFORCE-014"
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
            require(key not in result, "duplicate admission-channel-v3 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite admission-channel-v3 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "admission channel v3 history authority digest")
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
    }, "closed admission channel v3 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/admission-channel-v3-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 213
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 213-packet base")
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
    # An exact 213-era byte string is already older than the successor layer.
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


# MET-ENFORCE-015 publishes the W02-ADM-F successor contracts: planeon.internal.effect-gate-frame/v3 (I05 v3),
# POLICY-ADMISSION-SEMANTICS/v3 and planeon.internal.policy-write-frame/v3 (I07 v3), under one combined review.
# Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away first;
# the three reference models are imported and executed, and their exact bytes are bound by the review rounds below.
REVIEW_DIR = "architecture/w02-adm-f/"
I05_DIR, ADM_DIR, I07_DIR = "architecture/i05-gate-channel-v3/", "architecture/admission-semantics-v3/", "architecture/i07-policy-write-v3/"
SUBJECT = (REVIEW_DIR + "REVIEW_BRIEF.md",
           I05_DIR + "README.md", I05_DIR + "channel.schema.json", I05_DIR + "outcome-mapping.json", I05_DIR + "vectors.json",
           "scripts/i05_gate_channel_v3.py",
           ADM_DIR + "README.md", ADM_DIR + "allowlists.json", ADM_DIR + "admission-manifests/planeon-a2.json",
           ADM_DIR + "vectors.json", "scripts/admission_semantics_v3.py",
           I07_DIR + "README.md", I07_DIR + "channel.schema.json", I07_DIR + "policy-kinds.json", I07_DIR + "vectors.json",
           "scripts/i07_policy_write_v3.py")
# Round 1 reviewed these files at other bytes; round1/ keeps them under the same relative paths. The other subject files
# are byte-identical in both rounds.
ROUND1_COPIES = (REVIEW_DIR + "REVIEW_BRIEF.md", I05_DIR + "README.md", I05_DIR + "vectors.json", "scripts/i05_gate_channel_v3.py",
                 ADM_DIR + "README.md", ADM_DIR + "allowlists.json", ADM_DIR + "vectors.json", "scripts/admission_semantics_v3.py",
                 I07_DIR + "README.md")
V2_MANIFEST = "architecture/admission-semantics-v2/admission-manifests/planeon-a2.json"
CLOSURE_PATH = "architecture/i06-backend-profile/identity-closure.json"
# The three adopted v2 contracts and models, the I05 v1 README, the W02g README and closure and the W01 resolution stay
# byte-identical.
FROZEN_PATHS = tuple(d + f for d in ("architecture/i05-gate-channel-v2/",)
                     for f in ("README.md", "channel.schema.json", "outcome-mapping.json", "vectors.json", "status.json")) + tuple(
    d + f for d in ("architecture/admission-semantics-v2/",)
    for f in ("README.md", "allowlists.json", "admission-manifests/planeon-a2.json", "vectors.json", "status.json")) + tuple(
    d + f for d in ("architecture/i07-policy-write-v2/",)
    for f in ("README.md", "channel.schema.json", "policy-kinds.json", "vectors.json", "status.json")) + (
    "scripts/i05_gate_channel_v2.py", "scripts/admission_semantics_v2.py", "scripts/i07_policy_write_v2.py",
    "architecture/i05-gate-channel/README.md", "architecture/i06-backend-profile/README.md", CLOSURE_PATH,
    "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md")
KUBERNETES_COMMIT = "f78e722310e50bcaca9276be22276d9e91d91308"
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
STATUS = {
    I05_DIR: ("planeon.internal.i05-gate-channel-v3-status/v1", ("V1", "V2", "V3", "V4", "V5", "V6", "AF-I05-1", "AF-I05-2", "AF-I05-3"),
              ("gateInstalled", "journalImplemented", "failureMarkerImplemented", "substrateSelected", "distributionSelected",
               "productExecution", "runnerActivated", "phaseComplete")),
    ADM_DIR: ("planeon.internal.admission-semantics-v3-status/v1", ("R2-F1", "R2-F2", "R2-F3", "R2-F4", "R2-F5", "AF-ADM-1", "AF-ADM-2"),
              ("admissionConfigurationInstalled", "signerImplemented", "distributionSelected", "productExecution",
               "runnerActivated", "phaseComplete")),
    I07_DIR: ("planeon.internal.i07-policy-write-v3-status/v1", ("W1", "W2", "W3", "W4", "AF-I07-1"),
              ("gateInstalled", "writerInstalled", "substrateSelected", "enrollmentRulesDefined", "staticGuardInstalled",
               "productExecution", "runnerActivated", "phaseComplete")),
}
CONTRACT_OF = {I05_DIR: "I05", ADM_DIR: "ADMISSION", I07_DIR: "I07"}
I05_FLOORS = {"transcripts": 120, "agreement": 42, "frames": 34, "byteFrames": 14, "configRefusals": 5}
ADM_FLOORS = {"manifest": 36, "endToEnd": 19, "finalObject": 24, "objects": 9, "directoryHash": 4, "claims": 22}
I07_FLOORS = {"kindChecks": 79, "renderChecks": 7, "outcomeChecks": 22, "frames": 48, "byteFrames": 9, "transcripts": 62}
INPUT_TYPES = {"bytes": bytes, "bytearray": bytearray, "str": lambda raw: raw.decode("ascii")}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _json(path: str) -> Any:
    return parse(reviewed_bytes(path))


def _refusal(call) -> str | None:
    try:
        call()
    except ValueError as exc:
        return str(exc)
    return None


def validate_i05_v3(schema: dict, mapping: dict, vectors: dict) -> int:
    """The I05 v3 frame schema and the unchanged v2 mapping; every I05 v3 vector replays exactly."""
    import jsonschema
    jsonschema.Draft202012Validator.check_schema(schema)
    require(schema.get("$id") == "urn:planeon:internal:effect-gate-frame:v3"
            and model5.FRAME_VERSION == "planeon.internal.effect-gate-frame/v3"
            and all(variant["properties"]["schemaVersion"] == {"const": model5.FRAME_VERSION} for variant in schema["oneOf"])
            and len(schema["oneOf"]) == 2 * len(model5.OPERATIONS), "v3 effect-gate frame schema")
    require(mapping == _json("architecture/i05-gate-channel-v2/outcome-mapping.json"), "the I05 outcome mapping is v2's")
    require(type(vectors) is dict and set(vectors) == {"evidenceClass", "configs", "configRefusals", "frames", "byteFrames",
                                                        "transcripts", "agreement"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and set(vectors["configs"]) == {"ACTIVE", "INSPECTING", "LATER"}
            and all(len(vectors[key]) >= floor for key, floor in I05_FLOORS.items()), "closed I05 v3 vectors")
    checks = 0
    for row in vectors["transcripts"]:
        outputs, final = model5.replay(vectors["configs"][row["config"]], row["events"], schema)
        require(outputs == row["outputs"] and final == row["final"], "I05 transcript " + row["id"])
        checks += 1
    for row in vectors["agreement"]:
        require(model5.check_agreement(mapping, row["verb"], row["identity"], row["outcome"], row["resourceResult"]) == row["expect"],
                "I05 agreement " + row["id"])
        checks += 1
    for row in vectors["frames"]:
        require(_refusal(lambda: model5.check_frame(row["frame"], schema)) == row["expect"], "I05 frame " + row["id"])
        checks += 1
    for row in vectors["byteFrames"]:
        raw = INPUT_TYPES[row["inputType"]](_base64(row["base64"]))
        require(_refusal(lambda: model5.decode_frame(raw, schema)) == row["expect"], "I05 byte frame " + row["id"])
        checks += 1
    for row in vectors["configRefusals"]:
        got = _refusal(lambda: model5.Gate(dict(vectors["configs"]["ACTIVE"], **row["override"])))
        require(got is not None and got == row["expect"], "I05 configuration refusal " + row["id"])
        checks += 1
    require([row["id"] for row in vectors["byteFrames"]] == ["B%02d" % n for n in range(1, 15)], "byte checks in order")
    return checks


def _apply_ops(value: Any, ops: list) -> Any:
    value = modela.copy.deepcopy(value)
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete") and type(op.get("path")) is list and op["path"],
                "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = modela.copy.deepcopy(op["value"])
        else:
            del node[last]
    return value


def validate_admission_v3(manifest_raw: bytes, allowlists: dict, vectors: dict) -> int:
    """The sealed file is v2's byte for byte and the model's rendering; every admission v3 vector replays exactly."""
    require(manifest_raw == reviewed_bytes(V2_MANIFEST), "the sealed A2 manifest file is unchanged from v2")
    sealed = vectors["sealed"]
    require(manifest_raw == modela.manifest_file_bytes(sealed)
            and modela.check_a2_objects(parse(manifest_raw)["items"], sealed) is None
            and modela.manifest_directory_hash({"planeon-a2.json": manifest_raw}) == vectors["pinned"]["manifestDirectoryHash"],
            "the sealed file is the contract's rendering with the pinned directory hash")
    require(allowlists.get("schemaVersion") == "planeon.internal.admission-allowlists/v2"
            and allowlists.get("semantics") == modela.SEMANTICS_V3 == "POLICY-ADMISSION-SEMANTICS/v3"
            and allowlists.get("kubernetes", {}).get("commit") == KUBERNETES_COMMIT
            and allowlists.get("publisherIdentity") == modela.PUBLISHER_USER
            and set(allowlists.get("kinds", {})) == set(modela.KINDS)
            and {"MC%02d" % n for n in (0, 1, 2, 3, 4, 5, 10, 11, 20, 21, 22, *range(30, 42))} <= set(allowlists["constraintCoverage"])
            and all(allowlists["constraintCoverage"][code].startswith("SIGNER_GUARANTEED")
                    for code in ("MC00", "MC02", "MC03", "MC39", "MC40", "MC41")), "closed v3 allowlists")
    require(vectors.get("evidenceClass") == "DATA_CHECK_ONLY"
            and all(len(vectors[key]) >= floor for key, floor in ADM_FLOORS.items()), "closed admission v3 vectors")
    ns, server, positives = sealed["namespace"], vectors["server"], vectors["positives"]
    kind_of = lambda name: "Pod" if name.startswith("Pod") else name
    checks = 0
    for name, manifest in positives.items():
        require(modela.check_manifest(kind_of(name), manifest, ns) is None, "positive manifest " + name)
        checks += 1
    for row in vectors["manifest"]:
        require(modela.check_manifest(row["kind"], _apply_ops(positives[row["positive"]], row["ops"]), ns) == row["expect"],
                "manifest vector " + row["id"])
        checks += 1
    for row in vectors["endToEnd"]:
        final = modela.final_object(row["kind"], _apply_ops(positives[row["positive"]], row.get("manifestOps", [])),
                                    dict(server, **row["serverFacts"]))
        require(final == row["finalObject"]
                and modela.check_final(row["kind"], final, sealed, row["username"]) == row["expect"], "end-to-end vector " + row["id"])
        checks += 1
    for row in vectors["finalObject"]:
        require(modela.check_final(row["kind"], row["object"], sealed, row["username"]) == row["expect"], "final-object vector " + row["id"])
        checks += 1
    for row in vectors["objects"]:
        require(modela.check_a2_objects(row["objects"], sealed) == row["expect"], "policy-object vector " + row["id"])
        checks += 1
    for row in vectors["directoryHash"]:
        files = {name: text.encode("utf-8") for name, text in row["files"].items()}
        require(modela.manifest_directory_hash(files) == row["expect"], "directory-hash vector " + row["id"])
        checks += 1
    for row in vectors["claims"]:
        require(modela.check_claim(row["claim"], vectors["pinned"]) == row["expect"], "claim vector " + row["id"])
        checks += 1
    return checks


def validate_i07_v3(i05_schema: dict, schema: dict, kinds: dict, vectors: dict) -> int:
    """The I07 v3 schema on the I05 v3 gate, the unchanged v2 kind table; every I07 v3 vector replays exactly."""
    import jsonschema
    jsonschema.Draft202012Validator.check_schema(schema)
    require(schema.get("$id") == "urn:planeon:internal:policy-write-frame:v3"
            and model7.FRAME_VERSION == "planeon.internal.policy-write-frame/v3" and model7.i05 is model5
            and model7.SCOPES == ("QUALIFICATION_NAMESPACE", "QUALIFICATION_NAMESPACE_OBJECT"), "v3 writer frame schema on the I05 v3 gate")
    require(kinds == _json("architecture/i07-policy-write-v2/policy-kinds.json")
            and all(row["scope"] in model7.SCOPES for row in kinds["writable"]), "the I07 kind table is v2's, with no cluster scope")
    require(type(vectors) is dict and set(vectors) == {"evidenceClass", "configs", "kindChecks", "renderChecks", "outcomeChecks",
                                                        "frames", "byteFrames", "transcripts"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and set(vectors["configs"]) == {"ACTIVE", "INSPECTING"}
            and all(len(vectors[key]) >= floor for key, floor in I07_FLOORS.items()), "closed I07 v3 vectors")
    namespace, authority = "planeon-qual", "127.0.0.1:6443"
    schemas = {"i05": i05_schema, "i07": schema}
    checks = 0
    for row in vectors["kindChecks"]:
        require(model7.check_write(kinds, namespace, row["payload"]) == row["expect"], "I07 kind check " + row["id"])
        checks += 1
    for row in vectors["renderChecks"]:
        entry, _ = model7.classify_resource(kinds, row["payload"]["resource"])
        require(model7.render_write(entry, row["payload"], namespace, authority) == {"head": row["head"], "bodyDigest": row["bodyDigest"]},
                "I07 render check " + row["id"])
        checks += 1
    for row in vectors["outcomeChecks"]:
        require(model7.write_outcome_is_final(row["operation"], row["httpStatus"]) is row["final"], "I07 outcome check")
        checks += 1
    for row in vectors["transcripts"]:
        outputs, final = model7.replay(vectors["configs"][row["config"]], row["events"], schemas, kinds)
        require(outputs == row["outputs"] and final == row["final"], "I07 transcript " + row["id"])
        checks += 1
    for key, check in (("frames", lambda row: model7.check_frame(row["frame"], schema)),
                       ("byteFrames", lambda row: model7.decode_frame(_base64(row["base64"]), schema))):
        for row in vectors[key]:
            got = _refusal(lambda: check(row))
            require((got.split(" ", 1)[0] if got else None) == row["expect"], "I07 " + key + " check " + row["id"])
            checks += 1
    return checks


def _round_path(number: int, path: str) -> str:
    return REVIEW_DIR + "round1/" + path if number == 1 and path in ROUND1_COPIES else path


def validate_adm_f_reviews() -> dict:
    """Both combined review rounds are bound to their exact subject bytes; the final round passes with only minor
    findings or notes. Returns the final review."""
    reviews = []
    for number in (1, 2):
        review = _json(REVIEW_DIR + "review-round%d.json" % number)
        require(type(review) is dict and review.get("schemaVersion") == "planeon.internal.w02-adm-f-review/v1"
                and review.get("round") == number and review.get("verdict") == "PASS_FOR_SOURCE_PUBLICATION"
                and type(review.get("actions")) is dict
                and all(review["actions"][key] is False for key in review["actions"] if key != "referenceModelExecuted"),
                "combined review record %d" % number)
        require(review.get("subjectSha256") == {path: digest(reviewed_bytes(_round_path(number, path))) for path in SUBJECT},
                "combined review round %d is bound to its exact subject bytes" % number)
        reviews.append(review)
    require(all(reviewed_bytes(REVIEW_DIR + "round1/" + path) != reviewed_bytes(path) for path in ROUND1_COPIES),
            "round1/ keeps only the files round 2 changed")
    final = reviews[-1]
    require(all(row.get("severity") in ("MINOR", "NOTE") and row.get("contract") in CONTRACT_OF.values() for row in final["findings"])
            and all(str(final["openItemStatus"].get(name, "")).startswith("CLOSED")
                    for _, closed, _ in STATUS.values() for name in closed), "the final round passes and closes every answered finding")
    return final


def validate_adm_f_status(directory: str, final: dict) -> None:
    schema_version, closed, flags = STATUS[directory]
    status = _json(directory + "status.json")
    head = {I05_DIR: {"contract", "supersedes"}, ADM_DIR: {"semantics", "supersedes"}, I07_DIR: {"contract", "supersedes", "baseGate"}}[directory]
    require(type(status) is dict and set(status) == head | {
        "schemaVersion", "reviewRounds", "closedFindings", "carriedFindings", "ownerDecisions", "contractState", "obligations",
        "independentReviewer", "nativeAcceptance", "tenantAcceptance", *flags}
            and status["schemaVersion"] == schema_version and status["contractState"] == "ADOPTED_DATA_CONTRACT"
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in ("nativeAcceptance", "tenantAcceptance", *flags))
            and "W02-ADM-F" in [row.get("id") for row in status["ownerDecisions"]], "closed %s status" % directory)
    require({I05_DIR: status.get("contract") == model5.FRAME_VERSION and status["supersedes"] == "planeon.internal.effect-gate-frame/v2",
             ADM_DIR: status.get("semantics") == modela.SEMANTICS_V3 and status["supersedes"] == modela.SEMANTICS_V2,
             I07_DIR: status.get("contract") == model7.FRAME_VERSION and status["baseGate"] == model5.FRAME_VERSION
             and status["supersedes"] == "planeon.internal.policy-write-frame/v2"}[directory], "successor identity " + directory)
    rounds = status["reviewRounds"]
    require([row.get("round") for row in rounds] == [1, 2]
            and all(row["record"] == REVIEW_DIR + "review-round%d.json" % row["round"]
                    and row["recordSha256"] == digest(reviewed_bytes(row["record"])) and row["verdict"] == "PASS_FOR_SOURCE_PUBLICATION"
                    and row["subjectDirectory"] == (REVIEW_DIR + "round1/" if row["round"] == 1 else "CURRENT") for row in rounds),
            "review rounds of " + directory)
    require(set(status["closedFindings"]) == set(closed)
            and set(status["carriedFindings"]) == {row["id"] for row in final["findings"] if row["contract"] == CONTRACT_OF[directory]},
            "every answered finding is closed and every final finding of this contract is carried: " + directory)


def validate_admission_channel_v3() -> None:
    """The three successor contracts replay exactly, their predecessors are untouched, and adoption follows the review."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "predecessor contract bytes must stay unchanged: " + path)
    i05_schema = _json(I05_DIR + "channel.schema.json")
    checks = validate_i05_v3(i05_schema, _json(I05_DIR + "outcome-mapping.json"), _json(I05_DIR + "vectors.json"))
    checks += validate_admission_v3(reviewed_bytes(ADM_DIR + "admission-manifests/planeon-a2.json"), _json(ADM_DIR + "allowlists.json"),
                                    _json(ADM_DIR + "vectors.json"))
    checks += validate_i07_v3(i05_schema, _json(I07_DIR + "channel.schema.json"), _json(I07_DIR + "policy-kinds.json"),
                              _json(I07_DIR + "vectors.json"))
    require(checks >= sum(I05_FLOORS.values()) + sum(ADM_FLOORS.values()) + sum(I07_FLOORS.values()), "every v3 vector replays")
    final = validate_adm_f_reviews()
    for directory in STATUS:
        validate_adm_f_status(directory, final)


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "admission channel v3 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 216
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET},
            "closed 216-packet catalog retaining the 214-packet checkpoint")
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
            "closed source-only admission-channel-v3 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted admission-channel-v3 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_admission_channel_v3()


if __name__ == "__main__":
    validate()
    print("Admission channel v3 contracts valid: 216 current specifications; 214-packet checkpoint and exact 213-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
