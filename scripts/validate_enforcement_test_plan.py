#!/usr/bin/env python3
"""Validate the MET-ENFORCE-022 W04-0 enforcement test plan and the exact 224-to-223 projection."""
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
AUTHORITY_PATH = "architecture/enforcement-test-plan-authority.json"
AUTHORITY_SHA256 = "39330f4b634b3aa1d188b90786c04efc7bc3e5164689e895bc62bdff71ada437"
VALIDATOR_PATH = "scripts/validate_enforcement_test_plan.py"
BASE_COMMIT = "a5a0625e68c39ee5c80cd17841ccf3cecd2a6cda"
NEW_PACKET = "MET-ENFORCE-022"
PREVIOUS_PACKET = "MET-ENFORCE-021"
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
            require(key not in result, "duplicate enforcement-test-plan authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite enforcement-test-plan authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "enforcement test plan history authority digest")
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
    }, "closed enforcement test plan history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/enforcement-test-plan-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 223
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 223-packet base")
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


# MET-ENFORCE-022 (roadmap W04, packet W04-0) publishes the independent enforcement test plan
# planeon.internal.enforcement-test-plan/v1: the TG-01..TG-08 traceability record against E01-E12 and the observation-window
# register schema (owner decisions D-R12, D-TOOL, D-MAP, D-OW, D-ID and D-OW-1 = A, via the lane monitor). Repository
# bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away first. Every
# reviewed file of this era and every input the plan model reads is bound by digest before anything is parsed, the
# review binding is checked before the model runs, and the model is executed from this era's reviewed bytes. Both of its
# checks run: check() and check_publishable(), which check() alone does not call (review round 4, R4-1).
PLAN_DIR = "architecture/enforcement-test-plan/"
PLAN_MODEL = "scripts/enforcement_test_plan.py"
STATUS_PATH = PLAN_DIR + "status.json"
SUBJECT = (PLAN_DIR + "README.md", PLAN_DIR + "REVIEW_BRIEF.md", PLAN_DIR + "observation-windows.schema.json",
           PLAN_DIR + "traceability.json", PLAN_MODEL)
ROUNDS = ((1, "CHANGES_REQUIRED"), (2, "CHANGES_REQUIRED"), (3, "CHANGES_REQUIRED"), (4, "PASS_FOR_SOURCE_PUBLICATION"))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "planeon.internal.enforcement-test-plan-review/v1"
REVIEW_ACTIONS = ("filesEdited", "githubMutated", "nativeActions", "repositoryValidatorsRun", "runnerActivated", "testsRun")
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
PLAN_FALSE = ("testsWritten", "testsRun", "nativeEvidence", "registerFilled", "phaseComplete")
STATUS_KEYS = ("schemaVersion", "plan", "planLabel", "reviewRounds", "closedFindings", "carriedFindings",
               "roadmapAmendment", "contractState", "independentReviewer", "obligations", *PLAN_FALSE)
DECISIONS = (("D-R12", "a"), ("D-TOOL", "a"), ("D-MAP", "accepted"), ("D-OW", "accepted"), ("D-ID", "accepted"),
             ("D-OW-1", "A"))
TEST_GROUPS = tuple("TG-%02d" % number for number in range(1, 9))
PLAN_PACKETS = tuple("W04-%d" % number for number in range(8))
# The adopted bytes of every reviewed file, round copy, review record, the status and index records and the plan model;
# and of every input the plan model reads (the W02 contracts, the W01 amendment, the W03-0 selection and the design
# documents), as on the accepted base.
ERA_SHA256 = MappingProxyType({
    "architecture/admission-semantics-v3/admission-manifests/planeon-a2.json": "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741",
    "architecture/admission-semantics-v3/allowlists.json": "9314cd0732880a8e6af91df562af0a392183f6ef078c12fa9b479f6953fad5d4",
    "architecture/admission-semantics-v3/status.json": "65fedb6284ae7ee70686166db0bcf0f2fdf37756b59ee3f3f8267b25b0ccfda7",
    "architecture/admission-semantics-v3/vectors.json": "a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1",
    "architecture/backend-distribution/selection.json": "e6750f20a56f76486c24e35114b9e0b204357e51e3f97e560a34c544bf238952",
    "architecture/enforcement-test-plan/README.md": "f2a312eaa81df74146d3f68f07785b7513d5212e1ef8657186367117d18a2d5c",
    "architecture/enforcement-test-plan/REVIEW_BRIEF.md": "fbe5560293a6dff671957a1e712aa60763ba8c39d7c76ed206baed71b00eb1a6",
    "architecture/enforcement-test-plan/observation-windows.schema.json": "98cae664073e8fa26a8e686d8bcf743f734ac4fb843f6583e3c47bcac8b14f2d",
    "architecture/enforcement-test-plan/review-round1.json": "bd4c45e1c514dac45e1f32029462ac1bb8b984e57a3a3c2fdc5184cd5de1c0d4",
    "architecture/enforcement-test-plan/review-round2.json": "8d1eb0ce4734f8b2e5692aad9ba95622d7a2007dcd4d5af4f5667e3fe1b8efac",
    "architecture/enforcement-test-plan/review-round3.json": "a93e318279792543722238bc7395a2e0f35d9169b81346b34194fc66e9367f4e",
    "architecture/enforcement-test-plan/review-round4.json": "06b595e86862f76bc635334137c83798125ec9b5f5892522175abccf86bffda8",
    "architecture/enforcement-test-plan/round1/architecture/enforcement-test-plan/README.md": "a80ca1f3d20a7d94c1fb97271380ec0f6dbd7ae672482108b476c92195c4d3aa",
    "architecture/enforcement-test-plan/round1/architecture/enforcement-test-plan/REVIEW_BRIEF.md": "bc15d9c5b40144de529e26409ab88151fc336659f2d7396e74523eb5fc4a71a1",
    "architecture/enforcement-test-plan/round1/architecture/enforcement-test-plan/observation-windows.schema.json": "93d8aba182c3822954ff2242313b8a3fdde9d936889a0c3a49f4deb9435f148a",
    "architecture/enforcement-test-plan/round1/architecture/enforcement-test-plan/traceability.json": "901e3aa2e279518d21e6e8705806779a6244bacd1ef2dfce26322b0feb5dc4ac",
    "architecture/enforcement-test-plan/round1/scripts/enforcement_test_plan.py": "82c8f46d2ef377a2c9fab212991279bb01f5dec63adfa3110ad585cbf7e9d10b",
    "architecture/enforcement-test-plan/round2/architecture/enforcement-test-plan/README.md": "8270f8035eeac459f2b165560824f0592f9a15c7e1e685d7fdfa0b0f0ca3260a",
    "architecture/enforcement-test-plan/round2/architecture/enforcement-test-plan/REVIEW_BRIEF.md": "d2a1021240d4cb732330626f4ddf57d7edecf01a9fa7716c986725c0770099ee",
    "architecture/enforcement-test-plan/round2/architecture/enforcement-test-plan/observation-windows.schema.json": "1a996db4633d1a5dc13982fedfe45d8300d508fdd5ee86d89a4ee2c04a283ca8",
    "architecture/enforcement-test-plan/round2/architecture/enforcement-test-plan/traceability.json": "5c38956ae4ba1fbba62d73993e015a8039322467ee9f24cf003880d12278e945",
    "architecture/enforcement-test-plan/round2/scripts/enforcement_test_plan.py": "3e03b37b90bda242378e3d3e474f23da7ff60221692818662086a1a92e2ba343",
    "architecture/enforcement-test-plan/round3/architecture/enforcement-test-plan/README.md": "863666a247f7b9c7829f38315a650e4baa65bbd22266e2cff726851bcd28ba71",
    "architecture/enforcement-test-plan/round3/architecture/enforcement-test-plan/REVIEW_BRIEF.md": "3ed1bbc3c13ca52a82cfe7a30c0b5135d4ed1fc4a750a3937b24b245b31a46e5",
    "architecture/enforcement-test-plan/round3/architecture/enforcement-test-plan/observation-windows.schema.json": "98cae664073e8fa26a8e686d8bcf743f734ac4fb843f6583e3c47bcac8b14f2d",
    "architecture/enforcement-test-plan/round3/architecture/enforcement-test-plan/traceability.json": "5471ca04b3de8b8215911118bd782432c49d05571c61f4a8fdf790ed78327c28",
    "architecture/enforcement-test-plan/round3/scripts/enforcement_test_plan.py": "569b59ffac793e05b89ef040e760dc081cf96465093a49a0568cfcc1f60dbd23",
    "architecture/enforcement-test-plan/source-index.json": "a0324aa745eeaf02362546d8c6d93063d17d82948c255d6da6a100d930b6fa67",
    "architecture/enforcement-test-plan/status.json": "3cc32fcccf5657e2e96fd71bcb5bfde1567b7fe4f619b218b1170046b6b94f42",
    "architecture/enforcement-test-plan/traceability.json": "762c2dfa4356b5ac59491fc51359dc4e6ef26f6a22f08c7cca6982c0b2979f72",
    "architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md": "2ac2751cbddd7fae20ee92a93a8fc18c7988dd0c96853d1ccb2d08cb3753f83b",
    "architecture/host-interface-amendment-w02d/amendment.json": "8c20ccc25ae504073d89d052b1618c21ab53108dcc44af26f747024709e8f6f9",
    "architecture/host-interface-amendment-w02d/status.json": "5a3479778f70c73cf956886712bbe5cff691f741dcd73240a9465ec03360866f",
    "architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md": "8e627ee92919d6228ce63caadb32b4e2cb3948f4e805131ad4b4bfc9055c0338",
    "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md": "8a3a09bb5dbc08804dbea06dd0700a14648a9cdbc8efd62112dc64ba0b6ba1b4",
    "architecture/i05-gate-channel-v3/channel.schema.json": "3bfee13c9d32e82fe5ab908eb6f716bc11881f9d57b324f8ea4a21a3ad35356f",
    "architecture/i05-gate-channel-v3/outcome-mapping.json": "4466f379f1cc669e047cffd8afa5fa88b2cc7648a51e2d38b17f0bd5e2252a3a",
    "architecture/i05-gate-channel-v3/status.json": "7cd5302ba7fe8bbb47b2859c4311e247ae6d730cf37d31d8c7140a61e3e8c5c4",
    "architecture/i05-gate-channel-v3/vectors.json": "ab75d86fe54ade7ee2695ef84b200d0473e14e4112e64e7702032593658763ed",
    "architecture/i06-backend-profile-v2/criteria.json": "026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda",
    "architecture/i06-backend-profile-v2/status.json": "44217baf7857b86abfa9c8ccadb953e2678592e437c9caf049096c402abb9c20",
    "architecture/i06-backend-profile-v2/vectors.json": "1a5e168f0d8fff233f5072b1440e75a633b38e428f87b2893a96e579122a430e",
    "architecture/i07-policy-write-v3/channel.schema.json": "c68721a1002fccc7d6e59eeee9016a0a0f4a7428fad714e5a3d90a362d30ce09",
    "architecture/i07-policy-write-v3/policy-kinds.json": "4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0",
    "architecture/i07-policy-write-v3/status.json": "b95b720e1741bc8db86cce3259ae3c6c4eda4b4b6970def95a06e47f0544e983",
    "architecture/i07-policy-write-v3/vectors.json": "c4c24c5ff15618aa2f0fe0f016011359bc4316220c6e40d5168f9ee24b6f736d",
    "architecture/native-profile-v3/qualification.schema.json": "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
    "architecture/native-profile-v3/status.json": "f242944dd7a03eb64fd4f14d811711f7ed4ccf9bdb00bca82ea8abbaa5cb0538",
    "architecture/native-profile-v3/vectors.json": "14af47a69c972039294be8659c31332acd5326bfb0a3a38384a2c6bf9d11fe6d",
    "architecture/seccomp-allowlists-v2/allowlists.json": "c041263a9526a3526e1fa10bf7e73d1d26cba70931c9329f31cfce2d9ce74344",
    "architecture/seccomp-allowlists-v2/status.json": "9695c5e4a19fbaec760c0745485c5cd3237951e3c316092bef8f00ba0007a419",
    "architecture/seccomp-allowlists-v2/syscalls.json": "343176d6518530ba9a4d71c36eec7f6e5a98a87198e5e08d53ac0d68d746ad67",
    "architecture/seccomp-allowlists-v2/vectors.json": "7aec409b0b6520d11beec0a89a8600ab87c3a5083cfd3860e2b1550c0f25eb47",
    "architecture/selinux-matrix-v2/matrix.json": "1d2f27e53d7b1a77d1c80b5e167fd477bc5c25dd78250399edc33de8397eebff",
    "architecture/selinux-matrix-v2/status.json": "0a9edabf6c2136bf0f5acc2055e7757af0704fb69b2538c56180bf9f2d600aa8",
    "architecture/selinux-matrix-v2/vectors.json": "e6a0afb937443d6f6cb941ba06e9bd46d9bda5b8f1bcdf97d6dba0b634f25961",
    "docs/alpha-2/ENFORCEMENT_FEASIBILITY.md": "9fac4492e1b5f6255993374a6642072855a5855a40bcc68706a25b78fd822965",
    "docs/alpha-2/ENFORCEMENT_INTEGRATION.md": "abbf35454a80b6e5b847f86e944819910320e274dc78a31d817bbbbf155ecc55",
    "docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md": "44ceb7ef3a8e2c71b93cbaee695ee486c65b1be9d4e9fdd564473ec65681b1e6",
    "scripts/admission_semantics_v3.py": "3db8f51ab55f49dc33cf6f028306bfb6d7aa1c5d7d96f264cfe709dae925ad22",
    "scripts/enforcement_test_plan.py": "cb036384953325d721c7a7a0e787679261c9d0e01be2f6d742d8d7a126ae4fb1",
    "scripts/host_interface_amendment.py": "cc7e3fd22aaf5dff057184c9aff47ee358b27b2c65afbfc527c8f3d19d78262b",
    "scripts/i05_gate_channel_v3.py": "2c7985b539c0ce8eb79eaabfa1f1ab7d43bdca7515defc590a76ecb1697ca959",
    "scripts/i06_backend_profile_v2.py": "58ceb7a6817aab512a56f9f2a614868ce27660d174be353c5629cc8de335e426",
    "scripts/i07_policy_write_v3.py": "6cc7ea0d3df0c7f2966184bb6d322189de3b49b5b02dfe2429911121973afe08",
    "scripts/native_qualification_v3.py": "2ef5c14ad5d8c962cf3703ccd076059685ed8dcc852059e4f863e8d9dc8965ad",
    "scripts/seccomp_allowlists_v2.py": "12845115589add9e1b0562c6f764decda7685b32a63c9f11872f847af2a54caf",
    "scripts/selinux_matrix_v2.py": "09fe67b911e66adfc4eb6ba26b5cb75a16a90748157f628c9ca2d9066412ddd8"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    raw = reviewed_bytes(path)
    expected = ERA_SHA256.get(path)
    require(expected is not None and digest(raw) == expected, "W04-0 reviewed bytes are bound: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _bound(check: Any, message: str) -> None:
    """A structural check over the model's result; a malformed result is refused, not raised."""
    try:
        holds = check()
    except (KeyError, TypeError, AttributeError, IndexError):
        holds = False
    require(holds is True, message)


def _era_model() -> types.ModuleType:
    """The plan model of this era, executed from its reviewed bytes."""
    module = types.ModuleType("_met_enforce_022_enforcement_test_plan")
    module.__file__ = str(ROOT / PLAN_MODEL)
    exec(compile(_verified(PLAN_MODEL), PLAN_MODEL, "exec", dont_inherit=True), module.__dict__)
    return module


def reviewer_actions_allowed(actions: Any) -> bool:
    """Exactly the eight reviewer action booleans; reading and model execution may be true, every other action false."""
    return (type(actions) is dict and set(actions) == set(REVIEW_ACTIONS) | {"referenceModelExecuted", "warmSourcesAccessed"}
            and all(type(value) is bool for value in actions.values())
            and all(actions[key] is False for key in REVIEW_ACTIONS))


def _round_path(number: int, path: str) -> str:
    """A round's reviewed bytes of path: its kept copy for every round before the last."""
    return PLAN_DIR + "round%d/" % number + path if number < LAST_ROUND else path


def validate_era_bytes() -> None:
    """Every reviewed file of this era and every plan input is bound by digest before anything is parsed or executed."""
    for path, expected in ERA_SHA256.items():
        require(digest(reviewed_bytes(path)) == expected, "W04-0 reviewed bytes are bound: " + path)


def validate_plan_status() -> dict:
    """Adopted after four independent review rounds, each bound to its record and its exact subject bytes, the last a pass
    with notes only, all carried."""
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == set(STATUS_KEYS)
            and status["schemaVersion"] == "planeon.internal.enforcement-test-plan-status/v1"
            and status["plan"] == "planeon.internal.enforcement-test-plan/v1" and status["planLabel"] == "W04-0"
            and status["contractState"] == "ADOPTED_PLAN"
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and all(status[flag] is False for flag in PLAN_FALSE)
            and type(status["roadmapAmendment"]) is dict and status["roadmapAmendment"].get("item") == "W04"
            and status["roadmapAmendment"].get("answers") == "R4-2", "adopted W04-0 status")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and [(row.get("round"), row.get("verdict")) for row in rounds if type(row) is dict]
            == list(ROUNDS), "four review rounds in order")
    for row in rounds:
        number = row["round"]
        require(set(row) == {"round", "record", "recordSha256", "verdict", "subjectDirectory"}
                and row["record"] == PLAN_DIR + "review-round%d.json" % number
                and row["subjectDirectory"] == (PLAN_DIR + "round%d/" % number if number < LAST_ROUND else "CURRENT")
                and row["recordSha256"] == digest(_verified(row["record"])), "review round identity %d" % number)
        review = _json(row["record"])
        require(type(review) is dict and review.get("schemaVersion") == REVIEW_SCHEMA and review.get("round") == number
                and review.get("verdict") == row["verdict"] and reviewer_actions_allowed(review.get("actions")),
                "review record %d" % number)
        require(review.get("subjectSha256") == {path: digest(_verified(_round_path(number, path))) for path in SUBJECT},
                "review round %d is bound to its exact subject bytes" % number)
    final = _json(rounds[-1]["record"])
    require(type(final.get("findings")) is list
            and all(type(row) is dict and row.get("severity") == "NOTE" for row in final["findings"])
            and {row["id"] for row in final["findings"]} == set(status["carriedFindings"]),
            "the final round passes with notes only, all carried")
    return status


def validate_enforcement_test_plan() -> None:
    """Every reviewed byte and the adoption record first; then the plan model from this era's reviewed bytes, both of its
    checks, and the owner's decisions in its result."""
    validate_era_bytes()
    validate_plan_status()
    module = _era_model()
    plan = module.check(_verified)
    require(type(plan) is dict, "the plan carries the owner's decisions")
    module.check_publishable(plan)
    _bound(lambda: [(row["id"], row["selected"]) for row in plan["ownerDecisions"]] == list(DECISIONS)
           and all(row["state"] == "ACCEPTED" for row in plan["ownerDecisions"])
           and tuple(row["id"] for row in plan["testGroups"]) == TEST_GROUPS
           and tuple(row["id"] for row in plan["packets"]) == PLAN_PACKETS
           and plan["repository"] == _json(PLAN_DIR + "traceability.json")["repository"],
           "the plan carries the owner's decisions")


def validate() -> None:
    record = authority()
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "enforcement test plan validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 224 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 224-packet catalog")
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
            "closed source-only enforcement-test-plan packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted enforcement-test-plan packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_enforcement_test_plan()


if __name__ == "__main__":
    validate()
    print("W04-0 enforcement test plan valid: 224 current specifications; exact 223-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
