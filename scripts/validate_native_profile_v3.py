#!/usr/bin/env python3
"""Validate the native qualification record v3 contract (W02a-F) and the exact 209-to-208 projection."""
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
    import native_qualification_v3 as model
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import native_qualification_v3 as model


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/native-profile-v3-authority.json"
AUTHORITY_SHA256 = "ec5221bed0734ed9800829714353ba88f349e6e154107993ed243a43a1cbfbb9"
VALIDATOR_PATH = "scripts/validate_native_profile_v3.py"
BASE_COMMIT = "51440c8de083b09e9d74fbaef3365b86d9fe89da"
NEW_PACKET = "MET-ENFORCE-010"
PREVIOUS_PACKET = "MET-PERF-032"
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
            require(key not in result, "duplicate native-profile-v3 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite native-profile-v3 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "native profile v3 history authority digest")
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
    }, "closed native profile v3 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/native-profile-v3-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 208
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 208-packet base")
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


# MET-ENFORCE-010 publishes the W02a-F successor contract planeon.internal.native-qualification/v3. Repository bytes
# are read only through reviewed_bytes, so a later bridged successor projects its own edits away first; the reference
# model is imported and executed, and its exact bytes are bound by the review rounds below.
CONTRACT_DIR = "architecture/native-profile-v3/"
STATUS_PATH = CONTRACT_DIR + "status.json"
MODEL_PATH = "scripts/native_qualification_v3.py"
SUBJECT_PATHS = {"README.md": CONTRACT_DIR + "README.md", "REVIEW_BRIEF.md": CONTRACT_DIR + "REVIEW_BRIEF.md",
                 "qualification.schema.json": CONTRACT_DIR + "qualification.schema.json",
                 "vectors.json": CONTRACT_DIR + "vectors.json", "native_qualification_v3.py": MODEL_PATH}
V1_DIR = "architecture/native-qualification-inputs/"
V2_DIR = "architecture/native-profile-v2/"
CLOSURE_PATH = "architecture/i06-backend-profile/identity-closure.json"
# The adopted v2 contract, the W02g closure, the W02e matrix and the W01 resolution stay byte-identical.
FROZEN_PATHS = (V1_DIR + "qualification.schema.json", V1_DIR + "vectors.json", V2_DIR + "README.md", V2_DIR + "qualification.schema.json", V2_DIR + "vectors.json", V2_DIR + "status.json",
                "scripts/native_qualification_v2.py", CLOSURE_PATH, "architecture/selinux-matrix/README.md",
                "architecture/selinux-matrix/status.json",
                "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md")
# Linux v6.12 cgroup attach types: to_cgroup_bpf_attach_type (include/linux/bpf-cgroup.h) plus BPF_LSM_CGROUP.
CGROUP_ATTACH_TYPES = frozenset("BPF_CGROUP_" + name for name in (
    "INET_INGRESS", "INET_EGRESS", "INET_SOCK_CREATE", "SOCK_OPS", "DEVICE", "INET4_BIND", "INET6_BIND",
    "INET4_CONNECT", "INET6_CONNECT", "UNIX_CONNECT", "INET4_POST_BIND", "INET6_POST_BIND", "UDP4_SENDMSG",
    "UDP6_SENDMSG", "UNIX_SENDMSG", "SYSCTL", "UDP4_RECVMSG", "UDP6_RECVMSG", "UNIX_RECVMSG", "GETSOCKOPT",
    "SETSOCKOPT", "INET4_GETPEERNAME", "INET6_GETPEERNAME", "UNIX_GETPEERNAME", "INET4_GETSOCKNAME",
    "INET6_GETSOCKNAME", "UNIX_GETSOCKNAME", "INET_SOCK_RELEASE")) | {"BPF_LSM_CGROUP"}
# W02e "W02a slot values".
LABEL_SLOTS = {"SERVER": "planeon_cgroup_server_t", "OBSERVER": "planeon_cgroup_observer_t",
               "BROKER": "planeon_cgroup_broker_t", "WORKER": "planeon_cgroup_worker_t",
               "EFFECT_GATE": "planeon_cgroup_gate_t"}
OBLIGATIONS = tuple("E%02d" % number for number in range(1, 13))
FALSE_FLAGS = ("nativeAcceptance", "tenantAcceptance", "productionProfileSelected", "bootEntryMeasured",
               "seccompFiltersDefined", "productExecution", "runnerActivated", "phaseComplete")
VECTOR_FLOORS = {"positive": 4, "negative": 207, "accepted": 9, "crossVersion": 14, "migration": 14}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _json(path: str) -> Any:
    return parse(reviewed_bytes(path))


def validate_v3_schema(schema: dict, closure: dict) -> None:
    """Label slots are W02e's values, backend identities are the W02g closure's, and the census is the v6.12 set."""
    defs = schema["$defs"]
    for role, label in LABEL_SLOTS.items():
        require(defs["roles"]["properties"][role]["properties"]["cgroup"]["properties"]["selinuxLabel"]
                == {"const": "system_u:object_r:%s:s0" % label}, "W02e cgroup label slot: " + role)
    require(defs["program"]["properties"]["pinLabel"] == {"const": "system_u:object_r:planeon_bpf_pin_t:s0"}
            and defs["hardening"]["properties"]["sealMarker"]["properties"]["selinuxLabel"]
            == {"const": "system_u:object_r:planeon_seal_t:s0"}, "W02e pin and seal label slots")
    holders: dict[str, set] = {}
    for row in closure["identities"]:
        holders.setdefault(row["holder"], set()).add(row["name"])
    for component, rule in defs["backendComponents"]["properties"].items():
        identities = rule["allOf"][1]["properties"]["apiIdentities"]
        if component in ("DATASTORE", "CONTAINER_RUNTIME"):
            require(identities == {"maxItems": 0}, "backend identity binding: " + component)
        elif component == "KUBELET":
            require(identities["items"]["anyOf"][0] == {"enum": sorted(holders["KUBELET"])}, "backend identity binding: KUBELET")
        else:
            require(identities == {"items": {"enum": sorted(holders[component])}}, "backend identity binding: " + component)
    hooks = {"BPF_CGROUP_" + hook for hook in model.HOOKS}
    require(set(defs["effectiveCensus"]["required"]) == set(model.CENSUS_ATTACH_TYPES) == CGROUP_ATTACH_TYPES - hooks
            and set(model.HOOK_ATTACH_TYPES) == hooks <= CGROUP_ATTACH_TYPES, "census covers every other v6.12 cgroup attach type")
    require(all(row["properties"]["testOnly"]["const"] is True
                for row in defs["backendProfile"]["oneOf"]), "every defined implementation profile is test-only")


def _apply(value: Any, ops: list) -> Any:
    value = copy.deepcopy(value)
    for op in ops:
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        elif op["op"] == "delete":
            del node[last]
        else:
            require(op["op"] == "append", "closed vector operation")
            node[last].append(copy.deepcopy(op["value"]))
    return value


def validate_v3_vectors(schema: dict, vectors: dict, v1_schema: dict, v1_vectors: dict, v2_schema: dict,
                        v2_vectors: dict) -> int:
    """Every case replays to its pinned result through the reference model."""
    require(vectors["schemaSha256"] == model.SCHEMA_SHA256 == digest(canonical(schema))
            and vectors["v1SchemaSha256"] == model.V1_SCHEMA_SHA256 == digest(canonical(v1_schema))
            and vectors["v2SchemaSha256"] == model.V2_SCHEMA_SHA256 == digest(canonical(v2_schema))
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["nativeAcceptance"] is False
            and vectors["tenantAcceptance"] is False
            and all(len(vectors[key]) >= floor for key, floor in VECTOR_FLOORS.items()), "v3 vectors bound to the pinned schema")
    history1 = [row["record"] for row in v1_vectors["positive"]]
    history = [row["record"] for row in v2_vectors["positive"]]
    positives = vectors["positive"]

    def qualify(p: dict, bundle: dict, test_fixture: bool = True) -> Any:
        return model.explain(model.check_qualification, p["record"], p["profile"], p["endpoints"], bundle["captures"],
                             bundle["lifecycle"], bundle["backendCaptures"], history1, history, v1_schema, v2_schema,
                             schema, False, test_fixture)

    for p in positives:
        require(qualify(p, p) is None, "v3 positive refused")
    checks = len(positives)
    for kind in ("negative", "accepted"):
        for row in vectors[kind]:
            p = positives[row["positive"]]
            profile = _apply(p["profile"], row.get("profileOps", []))
            endpoints = _apply(p["endpoints"], row.get("endpointOps", []))
            target = row["target"]
            if target == "record":
                record = _apply(p["record"], row["ops"])
                if row.get("rebindProfile"):
                    record["profileDigest"] = "sha256:" + digest(canonical(profile))
                result = model.explain(model.check_record, record, profile, endpoints, schema)
            elif target == "capture":
                capture = _apply(next(c for c in p["captures"] if c["role"] == row["role"]), row["ops"])
                result = model.explain(model.check_capture, p["record"], capture, row["role"], schema)
            elif target == "lifecycle":
                result = model.explain(model.check_lifecycle_capture, p["record"], _apply(p["lifecycle"], row["ops"]), schema)
            elif target == "backend":
                capture = _apply(next(c for c in p["backendCaptures"] if c["component"] == row["component"]), row["ops"])
                result = model.explain(model.check_backend_capture, p["record"], capture, schema)
            else:
                require(target == "qualification", "closed vector target")
                bundle = _apply({key: p[key] for key in ("captures", "lifecycle", "backendCaptures")}, row["ops"])
                result = qualify(p, bundle, row.get("testFixture", True))
            require(result == (row["refusal"] if kind == "negative" else None), "%s vector %s" % (kind, row["id"]))
            checks += 1
    for row in vectors["crossVersion"]:
        p = positives[row["index"]]
        if row["kind"] == "V2_RECORD_UNDER_V3":
            result = model.explain(model.check_record, history[row["index"]], p["profile"], p["endpoints"], schema)
            require(result == row["expect"] == "not a v3 record", "cross-version " + row["id"])
        elif row["kind"].endswith("_UNDER_V3"):
            old = v2_vectors["positive"][row["index"]]
            value, check, args = {"V2_CAPTURE_UNDER_V3": (old["captures"][0], model.check_capture, ("SERVER",)),
                                  "V2_LIFECYCLE_UNDER_V3": (old["lifecycle"], model.check_lifecycle_capture, ()),
                                  "V2_BACKEND_CAPTURE_UNDER_V3": (old["backendCaptures"][0], model.check_backend_capture, ())}[row["kind"]]
            require(model.explain(check, p["record"], value, *args, schema) == row["expect"], "cross-version " + row["id"])
        else:
            value, variant = {"V3_RECORD_UNDER_V2": (p["record"], "record"),
                              "V3_CAPTURE_UNDER_V2": (p["captures"][0], "capture"),
                              "V3_LIFECYCLE_UNDER_V2": (p["lifecycle"], "lifecycleCapture"),
                              "V3_BACKEND_CAPTURE_UNDER_V2": (p["backendCaptures"][0], "backendCapture")}[row["kind"]]
            errors = {(error.json_path, error.validator) for error in model.schema_errors(value, v2_schema, variant)}
            require(row["mustInclude"] and all(tuple(pair) in errors for pair in row["mustInclude"]), "cross-version " + row["id"])
        checks += 1
    for row in vectors["migration"]:
        p = positives[row["positive"]]
        profile = _apply(p["profile"], row.get("profileOps", []))
        record = _apply(p["record"], row.get("ops", []))
        if row.get("rebindProfile"):
            record["profileDigest"] = "sha256:" + digest(canonical(profile))
        old1 = [copy.deepcopy(history1[index]) for index in row["v1Positives"]]
        old2 = [copy.deepcopy(history[index]) for index in row["v2Positives"]]
        for key, olds in (("v1Ops", old1), ("v2Ops", old2)):
            for change in row.get(key, []):
                olds[change["index"]] = _apply(olds[change["index"]], change["ops"])
        result = model.explain(model.check_migration, old1, old2, record, profile, v1_schema, v2_schema, schema,
                               row.get("noEarlierHistory", False))
        require(result == row["expect"], "migration vector " + row["id"])
        checks += 1
    return checks


def _round_subject(directory: str) -> dict[str, str]:
    """Earlier rounds keep the files they reviewed under roundN/ when those files changed later."""
    if directory == "CURRENT":
        return SUBJECT_PATHS
    require(directory in tuple(CONTRACT_DIR + "round%d/" % number for number in range(1, 6)),
            "closed review subject directory")
    return {name: directory + name if (ROOT / (directory + name)).is_file() else path for name, path in SUBJECT_PATHS.items()}


def validate_v3_status() -> None:
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == {
        "schemaVersion", "contract", "supersedes", "reviewRounds", "carriedFindings", "closedFindings", "contractState",
        "obligations", "independentReviewer", *FALSE_FLAGS,
    } and status["schemaVersion"] == "planeon.internal.native-profile-v3-status/v1"
            and status["contract"] == model.V3_RECORD[0]
            and status["supersedes"] == "planeon.internal.native-qualification/v2"
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in FALSE_FLAGS), "closed native profile v3 status")
    require(type(status["closedFindings"]) is dict and {"P1", "P3", "P4", "P5", "P6", "P7", "K1", "E1-CENSUS"}
            <= set(status["closedFindings"]), "the carried W02a, W02g and W02e findings are dispositioned")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and 1 <= len(rounds) <= 6, "review rounds")
    for number, row in enumerate(rounds, 1):
        require(type(row) is dict and set(row) == {"round", "record", "recordSha256", "verdict", "subjectDirectory"}
                and row["round"] == number
                and (row["subjectDirectory"] == "CURRENT") == (number == len(rounds)), "review round identity")
        raw = reviewed_bytes(row["record"])
        require(digest(raw) == row["recordSha256"], "review record drift: " + row["record"])
        review = parse(raw)
        require(type(review) is dict and review.get("schemaVersion") == "planeon.internal.native-profile-v3-review/v1"
                and review.get("round") == number and review.get("verdict") == row["verdict"]
                and row["verdict"] in ("PASS_FOR_SOURCE_PUBLICATION", "CHANGES_REQUIRED", "BLOCKED")
                and type(review.get("actions")) is dict
                and all(review["actions"][key] is False for key in review["actions"] if key != "referenceModelExecuted"),
                "review record " + str(number))
        require(number == len(rounds) or row["verdict"] != "PASS_FOR_SOURCE_PUBLICATION",
                "a passed round has no successor round")
        subject = _round_subject(row["subjectDirectory"])
        by_name = {next((n for n, p in SUBJECT_PATHS.items() if key in (n, p)), key): value
                   for key, value in review.get("subjectSha256", {}).items()}
        require(set(by_name) == set(subject) and len(by_name) == len(review.get("subjectSha256", {}))
                and all(digest(reviewed_bytes(path)) == by_name[name] for name, path in subject.items()),
                "review round " + str(number) + " is bound to its exact subject bytes")
    final = parse(reviewed_bytes(rounds[-1]["record"]))
    findings = final.get("findings")
    passed = final["verdict"] == "PASS_FOR_SOURCE_PUBLICATION"
    require(type(findings) is list and type(status["carriedFindings"]) is dict
            and set(status["carriedFindings"]) == {row.get("id") for row in findings}
            and (not passed or all(row.get("severity") in ("MINOR", "NOTE") for row in findings)),
            "every final finding is carried; a pass has no blocking or major finding")
    require(status["contractState"] == ("ADOPTED_DATA_CONTRACT" if passed else "CONTRACT_CANDIDATE"),
            "contract state follows the final independent review")


def validate_native_profile_v3() -> None:
    """The v3 contract is closed and replays exactly; predecessors are untouched; adoption follows the review."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "predecessor contract bytes must stay unchanged: " + path)
    schema = _json(SUBJECT_PATHS["qualification.schema.json"])
    model.jsonschema.Draft202012Validator.check_schema(schema)
    validate_v3_schema(schema, _json(CLOSURE_PATH))
    checks = validate_v3_vectors(schema, _json(SUBJECT_PATHS["vectors.json"]), _json(V1_DIR + "qualification.schema.json"),
                                 _json(V1_DIR + "vectors.json"), _json(V2_DIR + "qualification.schema.json"),
                                 _json(V2_DIR + "vectors.json"))
    require(checks >= sum(VECTOR_FLOORS.values()), "every v3 vector replays")
    validate_v3_status()


def validate() -> None:
    record = authority()
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "native profile v3 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 209 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 209-packet catalog")
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
            "closed source-only native-profile-v3 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted native-profile-v3 packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_native_profile_v3()


if __name__ == "__main__":
    validate()
    print("Native profile v3 contract valid: 209 current specifications; exact 208-packet predecessor; DATA_CHECK_ONLY, every E01-E12 obligation open.")
