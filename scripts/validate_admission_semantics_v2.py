#!/usr/bin/env python3
"""Validate the POLICY-ADMISSION-SEMANTICS/v2 contract (W02f) and the exact 212-to-211 projection."""
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
    import admission_semantics_v2 as model
    import validate_i07_policy_write_v2 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import admission_semantics_v2 as model
    from scripts import validate_i07_policy_write_v2 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/admission-semantics-v2-authority.json"
AUTHORITY_SHA256 = "41468cf5ed268f573666a7fe5a18b64f5c5cfbd5bcd4168710516a5b5a624cfd"
VALIDATOR_PATH = "scripts/validate_admission_semantics_v2.py"
BASE_COMMIT = "4f75dedd20f1ebbe262799651abed8f5ee2fe502"
NEW_PACKET = "MET-ENFORCE-013"
PREVIOUS_PACKET = "MET-ENFORCE-012"
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
            require(key not in result, "duplicate admission-semantics-v2 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite admission-semantics-v2 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "admission semantics v2 history authority digest")
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
    }, "closed admission semantics v2 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/admission-semantics-v2-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 211
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 211-packet base")
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
    # An exact 211-era byte string is already older than the successor layer.
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


# MET-ENFORCE-013 publishes the W02f contract POLICY-ADMISSION-SEMANTICS/v2 with the A2 admission field allowlists and
# the sealed static admission manifest directory. Repository bytes are read only through reviewed_bytes, so a later
# bridged successor projects its own edits away first; the reference model is imported and executed, and its exact
# bytes are bound by the review rounds below.
CONTRACT_DIR = "architecture/admission-semantics-v2/"
STATUS_PATH = CONTRACT_DIR + "status.json"
MODEL_PATH = "scripts/admission_semantics_v2.py"
MANIFEST_PATH = "admission-manifests/planeon-a2.json"
SUBJECT_FILES = {"README.md": "README.md", "REVIEW_BRIEF.md": "REVIEW_BRIEF.md", "allowlists.json": "allowlists.json",
                 "planeon-a2.json": MANIFEST_PATH, "vectors.json": "vectors.json"}
SUBJECT_PATHS = dict({name: CONTRACT_DIR + relative for name, relative in SUBJECT_FILES.items()},
                     **{"admission_semantics_v2.py": MODEL_PATH})
V1_DOC = "docs/alpha-2/POLICY_OBSERVATION_READINESS.md"
V1_DOC_SHA256 = "65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c"
V1_SENTENCE = (b"Before committing a mutation, its immutable admission guard rechecks current\n"
               b"namespace/UID, effective RBAC, quotas, network policy and actual post-mutation\n"
               b"manifest under the broker's serialized admission transaction.\n")
# The accepted policy-observation document, the W01 resolution, the W02g profile and the I05 v2 and I07 contracts stay
# byte-identical.
FROZEN_PATHS = (V1_DOC, "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md",
                "architecture/i06-backend-profile/README.md", "architecture/i06-backend-profile/criteria.json",
                "architecture/i06-backend-profile/upstream-facts-v1.37.1.json", "scripts/i06_backend_profile.py",
                "architecture/i05-gate-channel-v2/README.md", "architecture/i05-gate-channel-v2/status.json",
                "architecture/i07-policy-write/README.md", "architecture/i07-policy-write/status.json")
KUBERNETES_COMMIT = "f78e722310e50bcaca9276be22276d9e91d91308"
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
FALSE_FLAGS = ("nativeAcceptance", "tenantAcceptance", "admissionConfigurationInstalled", "celCompiled",
               "distributionSelected", "signerImplemented", "i07AdmissionWritesRemoved", "productExecution",
               "runnerActivated", "phaseComplete")
ROUND1_FINDINGS = ("F1", "F2", "F3", "F4", "F5", "F6", "F7")
VECTOR_FLOORS = {"manifest": 30, "endToEnd": 17, "finalObject": 24, "objects": 9, "directoryHash": 4, "claims": 18}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _json(path: str) -> Any:
    return parse(reviewed_bytes(path))


def _apply_ops(value: Any, ops: list) -> Any:
    value = model.copy.deepcopy(value)
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete") and type(op.get("path")) is list and op["path"],
                "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = model.copy.deepcopy(op["value"])
        else:
            del node[last]
    return value


def _expect(got: str | None, expected: Any, label: str) -> None:
    require(got == expected, label)


def validate_admission_v2_pins(manifest_raw: bytes, allowlists: dict, vectors: dict) -> None:
    """The v1 sentence is pinned, the sealed file is the model's rendering, and its loader hash is the pinned one."""
    v1 = reviewed_bytes(V1_DOC)
    require(digest(v1) == V1_DOC_SHA256 and v1.count(V1_SENTENCE) == 1, "the pinned POLICY-ADMISSION-SEMANTICS/v1 sentence")
    sealed = vectors["sealed"]
    require(manifest_raw == model.manifest_file_bytes(sealed)
            and model.check_a2_objects(parse(manifest_raw)["items"], sealed) is None, "the sealed file is the contract's rendering")
    require(model.manifest_directory_hash({"planeon-a2.json": manifest_raw}) == vectors["pinned"]["manifestDirectoryHash"],
            "the pinned static manifest directory hash")
    require(allowlists.get("schemaVersion") == "planeon.internal.admission-allowlists/v1"
            and allowlists.get("semantics") == model.SEMANTICS_V2
            and allowlists.get("kubernetes", {}).get("commit") == KUBERNETES_COMMIT
            and allowlists.get("publisherIdentity") == model.PUBLISHER_USER
            and set(allowlists.get("kinds", {})) == set(model.KINDS), "closed allowlists")


def validate_admission_v2_vectors(vectors: dict) -> int:
    """Every case replays to its pinned result through the reference model."""
    require(vectors.get("evidenceClass") == "DATA_CHECK_ONLY"
            and all(len(vectors[key]) >= floor for key, floor in VECTOR_FLOORS.items()), "admission v2 vectors are closed")
    ns, sealed, server, positives = vectors["sealed"]["namespace"], vectors["sealed"], vectors["server"], vectors["positives"]
    kind_of = lambda name: "Pod" if name.startswith("Pod") else name
    checks = 0
    for name, manifest in positives.items():
        require(model.check_manifest(kind_of(name), manifest, ns) is None, "positive manifest " + name)
        checks += 1
    for row in vectors["manifest"]:
        _expect(model.check_manifest(row["kind"], _apply_ops(positives[row["positive"]], row["ops"]), ns), row["expect"],
                "manifest vector " + row["id"])
        checks += 1
    for row in vectors["endToEnd"]:
        manifest = _apply_ops(positives[row["positive"]], row.get("manifestOps", []))
        final = model.final_object(row["kind"], manifest, dict(server, **row["serverFacts"]))
        require(final == row["finalObject"], "end-to-end final object " + row["id"])
        _expect(model.check_final(row["kind"], final, sealed, row["username"]), row["expect"], "end-to-end vector " + row["id"])
        checks += 1
    for row in vectors["finalObject"]:
        _expect(model.check_final(row["kind"], row["object"], sealed, row["username"]), row["expect"], "final-object vector " + row["id"])
        checks += 1
    for row in vectors["objects"]:
        _expect(model.check_a2_objects(row["objects"], sealed), row["expect"], "policy-object vector " + row["id"])
        checks += 1
    for row in vectors["directoryHash"]:
        files = {name: text.encode("utf-8") for name, text in row["files"].items()}
        _expect(model.manifest_directory_hash(files), row["expect"], "directory-hash vector " + row["id"])
        checks += 1
    for row in vectors["claims"]:
        _expect(model.check_claim(row["claim"], vectors["pinned"]), row["expect"], "claim vector " + row["id"])
        checks += 1
    return checks


def _round_subject(directory: str) -> dict[str, str]:
    """Earlier rounds keep the files they reviewed under roundN/ (same relative layout)."""
    if directory == "CURRENT":
        return SUBJECT_PATHS
    require(directory == CONTRACT_DIR + "round1/", "closed review subject directory")
    return dict({name: directory + relative for name, relative in SUBJECT_FILES.items()},
                **{"admission_semantics_v2.py": directory + "admission_semantics_v2.py"})


def validate_admission_v2_status() -> None:
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == {
        "schemaVersion", "semantics", "supersedes", "ownerDecisions", "reviewRounds", "closedFindings", "carriedFindings",
        "contractState", "obligations", "independentReviewer", *FALSE_FLAGS,
    } and status["schemaVersion"] == "planeon.internal.admission-semantics-v2-status/v1"
            and status["semantics"] == model.SEMANTICS_V2 and status["supersedes"] == model.SEMANTICS_V1
            and [row.get("id") for row in status["ownerDecisions"]] == ["A2-PLACEMENT"]
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in FALSE_FLAGS), "closed admission semantics v2 status")
    require(type(status["closedFindings"]) is dict and set(status["closedFindings"]) == set(ROUND1_FINDINGS),
            "the round-1 findings are dispositioned")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and len(rounds) == 2, "review rounds")
    for number, row in enumerate(rounds, 1):
        require(type(row) is dict and set(row) == {"round", "record", "recordSha256", "verdict", "subjectDirectory"}
                and row["round"] == number and row["record"] == CONTRACT_DIR + "review-round%d.json" % number
                and row["subjectDirectory"] == ("CURRENT" if number == len(rounds) else CONTRACT_DIR + "round%d/" % number),
                "review round identity")
        raw = reviewed_bytes(row["record"])
        require(digest(raw) == row["recordSha256"], "review record drift: " + row["record"])
        review = parse(raw)
        require(type(review) is dict and review.get("schemaVersion") == "planeon.internal.admission-semantics-v2-review/v1"
                and review.get("round") == number and review.get("verdict") == row["verdict"]
                and row["verdict"] in ("PASS_FOR_SOURCE_PUBLICATION", "CHANGES_REQUIRED", "BLOCKED")
                and type(review.get("actions")) is dict
                and all(review["actions"][key] is False for key in review["actions"] if key != "referenceModelExecuted"),
                "review record " + str(number))
        require(number == len(rounds) or row["verdict"] != "PASS_FOR_SOURCE_PUBLICATION", "a passed round has no successor round")
        subject = _round_subject(row["subjectDirectory"])
        require(review.get("subjectSha256") == {name: digest(reviewed_bytes(path)) for name, path in subject.items()},
                "review round " + str(number) + " is bound to its exact subject bytes")
    final = parse(reviewed_bytes(rounds[-1]["record"]))
    findings = final.get("findings")
    passed = final["verdict"] == "PASS_FOR_SOURCE_PUBLICATION"
    require(type(findings) is list and set(status["carriedFindings"]) == {row.get("id") for row in findings}
            and (not passed or all(row.get("severity") in ("MINOR", "NOTE") for row in findings)),
            "every final finding is carried; a pass has no blocking or major finding")
    require(status["contractState"] == ("ADOPTED_DATA_CONTRACT" if passed else "CONTRACT_CANDIDATE"),
            "contract state follows the final independent review")


def validate_admission_semantics_v2() -> None:
    """The contract is closed and replays exactly; predecessors are untouched; adoption follows the review."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "predecessor contract bytes must stay unchanged: " + path)
    vectors = _json(SUBJECT_PATHS["vectors.json"])
    validate_admission_v2_pins(reviewed_bytes(SUBJECT_PATHS["planeon-a2.json"]), _json(SUBJECT_PATHS["allowlists.json"]), vectors)
    checks = validate_admission_v2_vectors(vectors)
    require(checks >= sum(VECTOR_FLOORS.values()), "every admission v2 vector replays")
    validate_admission_v2_status()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "admission semantics v2 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 214
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET},
            "closed 214-packet catalog retaining the 212-packet checkpoint")
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
            "closed source-only admission-semantics-v2 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted admission-semantics-v2 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_admission_semantics_v2()


if __name__ == "__main__":
    validate()
    print("Admission semantics v2 contract valid: 214 current specifications; 212-packet checkpoint and exact 211-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
