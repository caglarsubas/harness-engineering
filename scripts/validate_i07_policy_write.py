#!/usr/bin/env python3
"""Validate the I07 policy writer channel contract (W02c) and the exact 205-to-204 projection."""
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
    import i07_policy_write as model
    import validate_selinux_matrix as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import i07_policy_write as model
    from scripts import validate_selinux_matrix as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/i07-policy-write-authority.json"
AUTHORITY_SHA256 = "c15c1021ea549dfc62a6884bbe97d012c469c54da5c0716316f96d6eb57ae6ba"
VALIDATOR_PATH = "scripts/validate_i07_policy_write.py"
BASE_COMMIT = "f94229a7c81c39016d83213bb17cce8c6f862c65"
NEW_PACKET = "MET-ENFORCE-008"
PREVIOUS_PACKET = "MET-PERF-031"
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
            require(key not in result, "duplicate i07-policy-write authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite i07-policy-write authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "i07 policy write history authority digest")
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
    }, "closed i07 policy write history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/i07-policy-write-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 204
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 204-packet base")
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
    # An exact 204-era byte string is already older than the successor layer.
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


CONTRACT_DIR = "architecture/i07-policy-write/"
STATUS_PATH = CONTRACT_DIR + "status.json"
SUBJECT_PATHS = {"README.md": CONTRACT_DIR + "README.md", "REVIEW_BRIEF.md": CONTRACT_DIR + "REVIEW_BRIEF.md",
                 "channel.schema.json": CONTRACT_DIR + "channel.schema.json",
                 "policy-kinds.json": CONTRACT_DIR + "policy-kinds.json",
                 "vectors.json": CONTRACT_DIR + "vectors.json",
                 "i07_policy_write.py": "scripts/i07_policy_write.py"}
# The W02b I05 contract and model, the W02g identity closure and the reviewed W01 design stay byte-identical;
# I07 extends the W02b gate model without changing it and derives its writable table from W02g.
I05_SCHEMA = "architecture/i05-gate-channel/channel.schema.json"
CLOSURE_PATH = "architecture/i06-backend-profile/identity-closure.json"
FROZEN_PATHS = ("scripts/i05_gate_channel.py", I05_SCHEMA, "architecture/i05-gate-channel/README.md",
                "architecture/i05-gate-channel/vectors.json", "architecture/i05-gate-channel/status.json", CLOSURE_PATH,
                "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md",
                "architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md")
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
FALSE_FLAGS = ("nativeAcceptance", "tenantAcceptance", "gateInstalled", "writerInstalled", "substrateSelected",
               "a2PoliciesPinned", "w02bI05BookkeepingFixed", "productExecution", "runnerActivated", "phaseComplete")
VERB_OF = {"CREATE": "create", "UPDATE": "update", "DELETE": "delete"}
NOT_WRITABLE = {("rbac.authorization.k8s.io", "clusterroles"): "REBOOT_MAINTENANCE_ONLY",
                ("rbac.authorization.k8s.io", "clusterrolebindings"): "REBOOT_MAINTENANCE_ONLY",
                ("admissionregistration.k8s.io", "validatingwebhookconfigurations"): "MUST_STAY_ABSENT",
                ("admissionregistration.k8s.io", "mutatingwebhookconfigurations"): "MUST_STAY_ABSENT",
                ("admissionregistration.k8s.io", "mutatingadmissionpolicies"): "MUST_STAY_ABSENT",
                ("admissionregistration.k8s.io", "mutatingadmissionpolicybindings"): "MUST_STAY_ABSENT",
                ("apiregistration.k8s.io", "apiservices"): "MUST_STAY_ABSENT",
                ("apiextensions.k8s.io", "customresourcedefinitions"): "MUST_STAY_ABSENT",
                ("certificates.k8s.io", "certificatesigningrequests"): "REBOOT_MAINTENANCE_ONLY"}


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


def validate_kinds(kinds: dict) -> None:
    """The writable table is exactly the POLICY_WRITE grants of planeon:policy-writer in the W02g closure, minus patch."""
    closure_raw = regular_bytes(CLOSURE_PATH)
    closure = parse(closure_raw)
    writer = [row for row in closure["identities"] if row.get("name") == "planeon:policy-writer"]
    require(len(writer) == 1, "one W02g policy-writer identity")
    grants: dict[tuple, set] = {}
    for grant in writer[0]["allowedGrants"]:
        if grant["category"] == "POLICY_WRITE":
            grants.setdefault((grant["resource"], grant["scope"]), set()).add(grant["verb"])
    require(type(kinds) is dict and set(kinds) == {"schemaVersion", "kubernetesVersion", "source", "operationVerbs", "writable",
                                                  "rbacSideGrants", "effectKinds", "notWritable"}
            and kinds["schemaVersion"] == "planeon.internal.i07-policy-kinds/v1"
            and kinds["kubernetesVersion"] == closure["kubernetesVersion"]
            and kinds["source"] == {"identityClosure": CLOSURE_PATH, "identityClosureSha256": "sha256:" + digest(closure_raw),
                                    "identity": "planeon:policy-writer"}
            and kinds["operationVerbs"] == VERB_OF, "closed policy-kind table bound to the W02g closure")
    rows = {}
    for row in kinds["writable"]:
        require(set(row) == {"group", "version", "resource", "kind", "scope", "operations", "topLevelKeys", "closureResource",
                             "closureScope", "unusedVerbs"}
                and row["closureResource"] == row["group"] + "/" + row["resource"]
                and row["scope"] == ("CLUSTER" if row["closureScope"] == "CLUSTER" else "QUALIFICATION_NAMESPACE_OBJECT"
                                     if row["resource"] == "namespaces" else "QUALIFICATION_NAMESPACE")
                and row["operations"] == [op for op in model.WRITE_OPERATIONS
                                          if VERB_OF[op] in grants.get((row["closureResource"], row["closureScope"]), set())]
                and row["unusedVerbs"] == sorted(grants[(row["closureResource"], row["closureScope"])]
                                                 - {VERB_OF[op] for op in row["operations"]}) == ["patch"],
                "writable row derived from the W02g grant: " + row["closureResource"])
        rows[(row["closureResource"], row["closureScope"])] = row
    require(set(rows) == set(grants), "every W02g policy-write grant has exactly one writable row")
    require(kinds["effectKinds"] == [{"group": "", "resource": plural, "kind": kind}
                                     for kind, plural in sorted(model.i05.PLURALS.items())]
            and {(row["group"], row["resource"]): row["disposition"] for row in kinds["notWritable"]} == NOT_WRITABLE
            and len(kinds["notWritable"]) == len(NOT_WRITABLE), "closed effect and non-writable policy kinds")
    special = sorted({(row["resource"], row["verb"]) for row in writer[0]["allowedGrants"] if row["category"] == "SPECIAL"})
    require(kinds["rbacSideGrants"]["grants"] == [{"resource": res, "verb": verb} for res, verb in special]
            and kinds["rbacSideGrants"]["resourceNames"] == writer[0]["resourceNames"], "bind and escalate recorded, not used")


def validate_vectors(schemas: dict, kinds: dict, vectors: dict) -> int:
    """Replay every vector through the reference model; returns the number of checks."""
    require(type(vectors) is dict and set(vectors) == {"evidenceClass", "configs", "kindChecks", "renderChecks", "outcomeChecks",
                                                        "frames", "byteFrames", "transcripts"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and set(vectors["configs"]) == {"ACTIVE", "INSPECTING"},
            "closed i07 vectors")
    namespace, authority = "planeon-qual", "127.0.0.1:6443"
    require(all(cfg["policyWriter"] == {"qualificationNamespace": namespace, "apiserverAuthority": authority}
                for cfg in vectors["configs"].values()), "one qualification namespace and apiserver authority")
    checks = 0
    for row in vectors["kindChecks"]:
        require(model.check_write(kinds, namespace, row["payload"]) == row["expect"], "kind check " + row["id"])
        checks += 1
    for row in vectors["renderChecks"]:
        entry, _ = model.classify_resource(kinds, row["payload"]["resource"])
        body = row["body"].encode("ascii")
        require(model.render_write(entry, row["payload"], namespace, authority) == {"head": row["head"], "bodyDigest": row["bodyDigest"]}
                and digest(body) == row["bodyDigest"].removeprefix("sha256:") and ("Content-Length: %d\r\n" % len(body)) in row["head"],
                "render check " + row["id"])
        checks += 1
    for row in vectors["outcomeChecks"]:
        require(model.write_outcome_is_final(row["operation"], row["httpStatus"]) is row["final"],
                "outcome check %s %d" % (row["operation"], row["httpStatus"]))
        checks += 1
    for row in vectors["transcripts"]:
        require(set(row) == {"id", "intent", "config", "events", "outputs", "final"}, "closed transcript vector")
        outputs, final = model.replay(vectors["configs"][row["config"]], row["events"], schemas, kinds)
        require(outputs == row["outputs"] and final == row["final"], "transcript " + row["id"] + " replay")
        checks += 1
    for key, check in (("frames", lambda row: model.check_frame(row["frame"], schemas["i07"])),
                       ("byteFrames", lambda row: model.decode_frame(base64.b64decode(row["base64"], validate=True), schemas["i07"]))):
        for row in vectors[key]:
            try:
                check(row)
                result = None
            except ValueError as exc:
                result = str(exc).split(" ", 1)[0]
            require(result == row["expect"], key + " check " + row["id"])
            checks += 1
    ids = [row["id"] for key in ("kindChecks", "renderChecks", "frames", "byteFrames", "transcripts") for row in vectors[key]]
    require(len(ids) == len(set(ids)) and len(vectors["kindChecks"]) >= 77 and len(vectors["renderChecks"]) >= 7
            and len(vectors["outcomeChecks"]) >= 22 and len(vectors["frames"]) >= 20 and len(vectors["byteFrames"]) >= 9
            and len(vectors["transcripts"]) >= 45, "closed vector inventory with unique identifiers")
    return checks


def validate_i07_channel() -> None:
    """The contract replays exactly, its table derives from W02g, and adoption follows only the verbatim review."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "predecessor contract bytes must stay unchanged: " + path)
    schema = _json_file(SUBJECT_PATHS["channel.schema.json"])
    import jsonschema
    jsonschema.Draft202012Validator.check_schema(schema)
    kinds = _json_file(SUBJECT_PATHS["policy-kinds.json"])
    validate_kinds(kinds)
    validate_vectors({"i05": _json_file(I05_SCHEMA), "i07": schema}, kinds, _json_file(SUBJECT_PATHS["vectors.json"]))
    validate_i07_status()


def validate_i07_status() -> None:
    status = _json_file(STATUS_PATH)
    require(type(status) is dict and set(status) == {
        "schemaVersion", "contract", "reviewRounds", "carriedFindings", "ownerDecisions", "contractState", "obligations",
        "independentReviewer", "w02bP1", *FALSE_FLAGS,
    } and status["schemaVersion"] == "planeon.internal.i07-policy-write-status/v1"
            and status["contract"] == model.FRAME_VERSION
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and status["w02bP1"] == "WRITE_SIDE_RESOLVED_I05_SIDE_CARRIED"
            and all(status[flag] is False for flag in FALSE_FLAGS), "closed i07 policy write status")
    decisions = status["ownerDecisions"]
    require(type(decisions) is list and all(type(row) is dict and set(row) == {"id", "date", "finding", "decision", "amends",
                                                                               "carriedTo"} for row in decisions),
            "owner decisions are recorded where downstream parts read them")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and 1 <= len(rounds) <= 4, "review rounds")
    for number, row in enumerate(rounds, 1):
        require(type(row) is dict and set(row) == {"round", "record", "recordSha256", "verdict", "subjectDirectory"}
                and row["round"] == number
                and (row["subjectDirectory"] == "CURRENT") == (number == len(rounds)), "review round identity")
        raw = regular_bytes(row["record"])
        require(digest(raw) == row["recordSha256"], "review record drift: " + row["record"])
        review = parse(raw)
        require(type(review) is dict and review.get("schemaVersion") == "planeon.internal.i07-policy-write-review/v1"
                and review.get("round") == number and review.get("verdict") == row["verdict"]
                and row["verdict"] in ("PASS_FOR_SOURCE_PUBLICATION", "CHANGES_REQUIRED", "BLOCKED")
                and type(review.get("actions")) is dict
                and all(review["actions"][key] is False for key in review["actions"] if key != "referenceModelExecuted"),
                "review record " + str(number))
        require(number == len(rounds) or row["verdict"] != "PASS_FOR_SOURCE_PUBLICATION",
                "a passed round has no successor round")
        subject = _round_subject(row["subjectDirectory"])
        require(set(review.get("subjectSha256", {})) == set(subject)
                and all(digest(regular_bytes(path)) == review["subjectSha256"][name] for name, path in subject.items()),
                "review round " + str(number) + " is bound to its exact subject bytes")
    final = parse(regular_bytes(rounds[-1]["record"]))
    findings = final.get("findings")
    passed = final["verdict"] == "PASS_FOR_SOURCE_PUBLICATION"
    require(type(findings) is list and type(status["carriedFindings"]) is dict
            and set(status["carriedFindings"]) == {row.get("id") for row in findings}
            and (not passed or all(row.get("severity") in ("MINOR", "NOTE") for row in findings)),
            "every final finding is carried; a pass has no blocking or major finding")
    require(status["contractState"] == ("ADOPTED_DATA_CONTRACT" if passed else "CONTRACT_CANDIDATE"),
            "contract state must follow the final independent review")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "i07 policy write validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 217
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 217-packet catalog retaining the 205-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only i07-policy-write packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted i07-policy-write packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_i07_channel()


if __name__ == "__main__":
    validate()
    print("I07 policy writer contract valid: 217 current specifications; 205-packet checkpoint and exact 204-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
