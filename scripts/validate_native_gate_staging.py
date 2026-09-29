#!/usr/bin/env python3
"""Validate the source/native gate amendment and reconstruct exact accepted inputs.

This module reads only local source. An inverse is data from a SHA-pinned
authority, never executable historical code or a cached security verdict.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import stat
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/native-gate-staging-authority.json"
AUTHORITY_SHA256 = "f3b8c6247969b9844a1da74914e591951975e7c42fb06e10aff88a86e1429615"
POLICY_PATH = "architecture/native-gate-staging.json"
BACKLOG_PATH = "architecture/unified-roadmap-backlog.json"
VALIDATOR_PATH = "scripts/validate_native_gate_staging.py"
NEW_PACKET = "MET-UNIFY-008"
ACCEPTED_BASE = {
    "commit": "945de93f89c94f42f1d63bff7997e3d0fa704fc4",
    "tree": "19f27b2b9e499f7437d0ded35c2983209adca4b6",
}
OLD_UNIFIED_AUTHORITY_SHA256 = (
    "8174dee255536cc2ae9d7e5d3759ee8307b2cb25ebbbb741b78f1ad737e445dd"
)
GATED_PACKETS = (
    "CTRL-INTEGRATE-001", "MODEL-001", "EXEC-001", "RUN-001"
)
GATED_PATHS = frozenset("task-packets/" + name + ".yaml" for name in GATED_PACKETS)
COMMAND_PREFIX = ["uv", "run", "--offline", "--frozen", "--no-sync", "python"]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def parse(raw: bytes) -> Any:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, "duplicate authority member")
            value[key] = item
        return value

    def reject_constant(_: str) -> Any:
        raise ValueError("nonfinite authority number")

    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=reject_constant)


def relative_path(path: str) -> bool:
    return (type(path) is str and bool(path) and not path.startswith("/")
            and all(part not in ("", ".", "..") for part in path.split("/")))


def regular_bytes(path: str) -> bytes:
    require(relative_path(path), "relative source path")
    parent = ROOT
    for part in path.split("/")[:-1]:
        parent /= part
        require(stat.S_ISDIR(parent.lstat().st_mode), "linked source ancestor")
    target = parent / path.split("/")[-1]
    before = target.lstat()
    require(
        stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        and before.st_size <= 16_777_216,
        "bounded unlinked source file",
    )
    raw = target.read_bytes()
    after = target.lstat()
    identity = lambda row: (
        row.st_dev, row.st_ino, row.st_mode, row.st_nlink,
        row.st_size, row.st_mtime_ns, row.st_ctime_ns,
    )
    require(identity(before) == identity(after) and len(raw) == before.st_size,
            "source changed during read")
    return raw


def _checked_authority_raw() -> bytes:
    raw = regular_bytes(AUTHORITY_PATH)
    require(digest(raw) == AUTHORITY_SHA256, "native gate authority digest")
    return raw


def authority() -> dict[str, Any]:
    record = parse(_checked_authority_raw())
    require(
        type(record) is dict and set(record) == {
            "schemaVersion", "authorityPacket", "acceptedBase",
            "oldUnifiedAuthoritySha256", "baselinePacketIds",
            "changedFiles", "newFiles", "packetSha256", "policySha256",
            "validatorNormalizedSha256", "immutableLocks",
        },
        "closed native gate authority",
    )
    require(
        record["schemaVersion"] == "harness.planeon.ai/native-gate-staging-authority/v1"
        and record["authorityPacket"] == NEW_PACKET
        and record["acceptedBase"] == ACCEPTED_BASE
        and record["oldUnifiedAuthoritySha256"] == OLD_UNIFIED_AUTHORITY_SHA256
        and type(record["changedFiles"]) is dict
        and type(record["newFiles"]) is dict
        and type(record["immutableLocks"]) is dict
        and type(record["baselinePacketIds"]) is list
        and len(record["baselinePacketIds"]) == 189
        and len(set(record["baselinePacketIds"])) == 189
        and NEW_PACKET not in record["baselinePacketIds"]
        and GATED_PATHS <= set(record["changedFiles"]),
        "accepted 189-packet source scope",
    )
    return record


@lru_cache(maxsize=1)
def _config() -> Mapping[str, Any]:
    """Cache validated data, never a fresh authority-integrity verdict."""
    return MappingProxyType(authority())


def _canonical_base64(value: str) -> bytes:
    require(type(value) is str, "inverse hunk encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError("invalid inverse hunk encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value,
            "noncanonical inverse hunk")
    return raw


@lru_cache(maxsize=1)
def _projection_rules() -> Mapping[str, Mapping[str, Any]]:
    """Cache immutable inverse data only; callers still verify authority bytes."""
    changed = _config()["changedFiles"]
    rules: dict[str, Mapping[str, Any]] = {}
    for path, rule in changed.items():
        require(relative_path(path) and type(rule) is dict
                and set(rule) == {"beforeSha256", "afterSha256", "reverseHunks"},
                "closed inverse path and record")
        for key in ("beforeSha256", "afterSha256"):
            value = rule[key]
            require(type(value) is str and len(value) == 64
                    and all(char in "0123456789abcdef" for char in value),
                    "inverse digest shape")
        require(rule["beforeSha256"] != rule["afterSha256"]
                and type(rule["reverseHunks"]) is list
                and 0 < len(rule["reverseHunks"]) <= 4096,
                "nonempty bounded inverse")
        prior_at = -1
        prior_end = 0
        payload = 0
        hunks: list[tuple[int, bytes, bytes]] = []
        for hunk in rule["reverseHunks"]:
            require(type(hunk) is dict
                    and set(hunk) == {"at", "removeBase64", "insertBase64"}
                    and type(hunk["at"]) is int
                    and prior_at < hunk["at"] <= 16_777_216
                    and hunk["at"] >= prior_end,
                    "ordered inverse hunk")
            removed = _canonical_base64(hunk["removeBase64"])
            inserted = _canonical_base64(hunk["insertBase64"])
            require(removed != inserted, "ineffective inverse hunk")
            payload += len(removed) + len(inserted)
            require(payload <= 16_777_216, "bounded inverse payload")
            hunks.append((hunk["at"], removed, inserted))
            prior_at = hunk["at"]
            prior_end = hunk["at"] + len(removed)
        rules[path] = MappingProxyType({
            "beforeSha256": rule["beforeSha256"],
            "afterSha256": rule["afterSha256"],
            "reverseHunks": tuple(hunks),
        })
    return MappingProxyType(rules)


def _project_changed(path: str, raw: bytes, rule: Mapping[str, Any]) -> bytes:
    checksum = digest(raw)
    require(checksum in {rule["beforeSha256"], rule["afterSha256"]},
            "unreviewed current source: " + path)
    if checksum == rule["beforeSha256"]:
        return raw
    cursor = 0
    pieces: list[bytes] = []
    for at, removed, inserted in rule["reverseHunks"]:
        require(cursor <= at and at + len(removed) <= len(raw),
                "inverse hunk bounds")
        require(raw[at:at + len(removed)] == removed,
                "inverse hunk current bytes")
        pieces.extend((raw[cursor:at], inserted))
        cursor = at + len(removed)
    pieces.append(raw[cursor:])
    previous = b"".join(pieces)
    require(len(previous) <= 16_777_216
            and digest(previous) == rule["beforeSha256"],
            "accepted predecessor bytes")
    return previous


def historical_bytes(path: str, raw: bytes) -> bytes:
    """Return exact 945de93 bytes for one SHA-pinned changed current file."""
    _checked_authority_raw()
    require(relative_path(path) and type(raw) is bytes,
            "historical source path and bytes")
    rule = _projection_rules().get(path)
    if rule is None:
        require(path not in _new_file_paths(), "new source has no predecessor")
        return raw
    return _project_changed(path, raw, rule)


@lru_cache(maxsize=1)
def _new_file_paths() -> frozenset[str]:
    return frozenset(_config()["newFiles"])


def historical_test_bytes(raw: bytes) -> bytes:
    """Recognize a changed test by digest without guessing its path."""
    _checked_authority_raw()
    require(type(raw) is bytes, "test bytes required")
    checksum = digest(raw)
    matches = [
        (path, rule) for path, rule in _projection_rules().items()
        if path.startswith("tests/") and checksum == rule["afterSha256"]
    ]
    require(len(matches) <= 1, "ambiguous current test")
    if not matches:
        return raw
    path, rule = matches[0]
    return _project_changed(path, raw, rule)


def current_test_bytes(before: bytes) -> bytes:
    """Map an exact accepted test to its reviewed current test bytes."""
    _checked_authority_raw()
    require(type(before) is bytes, "test bytes required")
    checksum = digest(before)
    matches = [
        (path, rule) for path, rule in _projection_rules().items()
        if path.startswith("tests/") and checksum == rule["beforeSha256"]
    ]
    require(len(matches) <= 1, "ambiguous accepted test")
    if not matches:
        return before
    path, rule = matches[0]
    current = regular_bytes(path)
    require(digest(current) == rule["afterSha256"], "current test drift")
    require(_project_changed(path, current, rule) == before,
            "inexact forward test projection")
    return current


@lru_cache(maxsize=1)
def _baseline_ids() -> frozenset[str]:
    return frozenset(_config()["baselinePacketIds"])


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Validate the 190th packet and four revisions, then return 189 old objects."""
    _checked_authority_raw()
    require(type(packets) is dict and set(packets) == _baseline_ids() | {NEW_PACKET},
            "closed 190-packet catalog")
    record = _config()
    successor_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(successor_raw) == record["packetSha256"]
            and canonical(packets[NEW_PACKET]) == canonical(safe_load(successor_raw)),
            "changed native gate successor")
    previous = {name: packets[name] for name in _baseline_ids()}
    rules = _projection_rules()
    for name in GATED_PACKETS:
        path = "task-packets/" + name + ".yaml"
        raw = regular_bytes(path)
        rule = rules[path]
        require(digest(raw) == rule["afterSha256"]
                and canonical(packets[name]) == canonical(safe_load(raw)),
                "changed current packet: " + name)
        previous[name] = safe_load(_project_changed(path, raw, rule))
    return previous


def _validate_policy(record: Mapping[str, Any]) -> dict[str, Any]:
    raw = regular_bytes(POLICY_PATH)
    require(digest(raw) == record["policySha256"], "current gate policy digest")
    policy = parse(raw)
    require(type(policy) is dict and set(policy) == {
        "schemaVersion", "authorityPacket", "acceptedBase", "evidenceClass",
        "sourceCoding", "nativeQualification",
    }, "closed current gate policy")
    require(
        policy["schemaVersion"] == "harness.planeon.ai/native-gate-staging/v1"
        and policy["authorityPacket"] == NEW_PACKET
        and policy["acceptedBase"] == ACCEPTED_BASE
        and policy["evidenceClass"] == "SOURCE_GATE_AMENDMENT_NOT_NATIVE_ACCEPTANCE",
        "source-only gate identity",
    )
    source = policy["sourceCoding"]
    native = policy["nativeQualification"]
    require(type(source) is dict and set(source) == {
        "packetIds", "requires", "macosArm64",
        "nativeLinuxAmd64PassPrerequisite", "sourceAndCiCannotClaimRuntime",
        "expectedEvidenceQualifier",
    } and source["packetIds"] == list(GATED_PACKETS)
        and source["requires"] == "ALL_REMAINING_PREDECESSORS_CLOSED"
        and source["macosArm64"] == "CLEAN_ROOM_SOURCE_AND_ISOLATED_OFFLINE_ACCEPTANCE_ALLOWED"
        and source["nativeLinuxAmd64PassPrerequisite"] is False
        and source["sourceAndCiCannotClaimRuntime"] is True
        and type(source["expectedEvidenceQualifier"]) is str,
        "closed source-coding scope",
    )
    qualifier = source["expectedEvidenceQualifier"]
    require(
        "native Linux AMD64 PASS is not a source-coding prerequisite" in qualifier
        and "Linux release deployment or promotion" in qualifier
        and "fresh, independently verified CONF-LINUX-001 foundation PASS" in qualifier
        and "native evidence bound to this product's exact source, image, toolchain, host and trust state" in qualifier
        and "NOT_RUN_ENV_UNAVAILABLE never passes" in qualifier
        and "ARM64 requires separate native qualification" in qualifier
        and "tenant acceptance remains independent" in qualifier,
        "missing native-gate qualifier",
    )
    require(type(native) is dict and set(native) == {
        "foundationPacket", "foundationStatus", "requiredBefore",
        "freshIndependentAmd64PassRequired", "productEvidenceBinding",
        "campaignScopedTestDeploymentMayCollectEvidence",
        "arm64QualificationIndependent", "tenantAcceptanceIndependent",
        "unavailableIsPass",
    } and native["foundationPacket"] == "CONF-LINUX-001"
        and native["foundationStatus"] == "NOT_RUN_ENV_UNAVAILABLE"
        and native["requiredBefore"] == [
            "LINUX_RELEASE_DEPLOYMENT_OR_PROMOTION",
            "RUNTIME_ASSURANCE_QUALIFICATION",
            "PLATFORM_DEPLOYABLE_OR_CERTIFIED",
            "TENANT_ACCEPTANCE",
        ]
        and native["freshIndependentAmd64PassRequired"] is True
        and native["productEvidenceBinding"] == [
            "SOURCE", "IMAGE", "TOOLCHAIN", "HOST", "TRUST",
        ]
        and native["campaignScopedTestDeploymentMayCollectEvidence"] is True
        and native["arm64QualificationIndependent"] is True
        and native["tenantAcceptanceIndependent"] is True
        and native["unavailableIsPass"] is False,
        "native promotion gate cannot be bypassed",
    )
    return policy


def _validate_four_packet_deltas(policy: Mapping[str, Any]) -> None:
    qualifier = policy["sourceCoding"]["expectedEvidenceQualifier"]
    rules = _projection_rules()
    for name in GATED_PACKETS:
        path = "task-packets/" + name + ".yaml"
        current_raw = regular_bytes(path)
        rule = rules[path]
        require(digest(current_raw) == rule["afterSha256"],
                "stale or changed current packet: " + name)
        current = safe_load(current_raw)
        old = safe_load(_project_changed(path, current_raw, rule))
        require(type(current) is dict and type(old) is dict
                and set(current) == set(old)
                and type(old["predecessors"]) is list
                and old["predecessors"][-1:] == ["CONF-LINUX-001"]
                and current["predecessors"] == old["predecessors"][:-1]
                and type(old["expectedEvidence"]) is list
                and type(current["expectedEvidence"]) is list
                and old["expectedEvidence"][:-1] == current["expectedEvidence"][:-1]
                and old["expectedEvidence"][-1].startswith(
                    "Fresh CONF-LINUX-001 native Linux AMD64 PASS is required before runtime coding"
                )
                and current["expectedEvidence"][-1] == qualifier,
                "four-packet source/native boundary: " + name)
        expected = dict(old)
        expected["predecessors"] = old["predecessors"][:-1]
        expected["expectedEvidence"] = [*old["expectedEvidence"][:-1], qualifier]
        require(canonical(current) == canonical(expected),
                "unreviewed packet field: " + name)


def _validate_accepted_bridge(record: Mapping[str, Any]) -> None:
    """Bind predecessor digests to the unchanged 005 authority where available."""
    prior = parse(regular_bytes("architecture/unified-roadmap-authority.json"))
    require(type(prior) is dict and prior["authorityPacket"] == "MET-UNIFY-005"
            and type(prior["changedFiles"]) is dict
            and type(prior["newFiles"]) is dict
            and type(prior["baselinePackets"]) is dict,
            "accepted unified predecessor authority")
    for path, rule in record["changedFiles"].items():
        if path in prior["changedFiles"]:
            require(rule["beforeSha256"] == prior["changedFiles"][path]["afterSha256"],
                    "005 changed-file history bridge: " + path)
        elif path in prior["newFiles"]:
            require(rule["beforeSha256"] == prior["newFiles"][path],
                    "005 new-file history bridge: " + path)
    for name in GATED_PACKETS:
        path = "task-packets/" + name + ".yaml"
        require(record["changedFiles"][path]["beforeSha256"]
                == prior["baselinePackets"][name],
                "accepted product packet history bridge: " + name)


def _validate_current_backlog(record: Mapping[str, Any]) -> None:
    """Check the amended current projection, not only its 005 inverse."""
    raw = regular_bytes(BACKLOG_PATH)
    require(digest(raw) == record["changedFiles"][BACKLOG_PATH]["afterSha256"],
            "current backlog digest")
    backlog = parse(raw)
    require(type(backlog) is dict and type(backlog.get("counts")) is dict
            and type(backlog.get("items")) is list,
            "current backlog shape")
    counts = {
        "publishedPackets": 189,
        "unpublishedAdoptionAndExtensionProposals": 23,
        "currentPacketCandidateNotAcceptedBaseline": 1,
        "failedUnpublishedLocalCandidate": 2,
        "countedChecklistProjections": 14,
        "unpublishedSemanticProposals": 11,
        "postReleaseEvolutionMilestones": 3,
        "totalItems": 243,
    }
    items = backlog["items"]
    require(backlog["counts"] == counts and len(items) == 243
            and all(type(row) is dict and type(row.get("id")) is str for row in items),
            "current backlog counts")
    rows = {row["id"]: row for row in items}
    require(len(rows) == len(items)
            and sum(row.get("kind") == "PUBLISHED_PACKET" for row in items) == 189
            and sum(row.get("kind") == "COUNTED_MASTER_CHECKLIST_PROJECTION"
                    for row in items) == 14
            and sum(row.get("kind") == "CURRENT_PACKET_CANDIDATE_NOT_ACCEPTED_BASELINE"
                    for row in items) == 1
            and sum(row.get("kind") == "FAILED_UNPUBLISHED_LOCAL_CANDIDATE"
                    for row in items) == 2,
            "current backlog identity inventory")
    previous = rows["MET-UNIFY-005"]
    failed = rows["MET-UNIFY-006"]
    failed_successor = rows["MET-UNIFY-007"]
    current = rows[NEW_PACKET]
    prior_packet_sha = digest(regular_bytes("task-packets/MET-UNIFY-005.yaml"))
    require(previous["kind"] == "PUBLISHED_PACKET"
            and previous["status"] == "MERGED_SOURCE_RECORDED"
            and previous["publishedPacket"] is True
            and "accepted-main@" + ACCEPTED_BASE["commit"] in previous["evidenceRefs"]
            and "task-packets/MET-UNIFY-005.yaml@" + prior_packet_sha
                in previous["evidenceRefs"],
            "accepted 005 source publication row")
    require(failed["kind"] == "FAILED_UNPUBLISHED_LOCAL_CANDIDATE"
            and failed["status"] == "BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED"
            and failed["publishedPacket"] is False
            and failed["predecessorIds"] == ["MET-UNIFY-005"]
            and failed["executionAuthority"] == "NONE"
            and "LOCAL1" in failed["blockingReason"]
            and "LOCAL2" in failed["blockingReason"]
            and "no CI, PR, merge or exact-main evidence" in failed["blockingReason"]
            and "local-unpublished-commit@2e705d421b0bef21b0bc37fa62e4b5a6b63c468d"
                in failed["evidenceRefs"]
            and "task-packets/MET-UNIFY-006.yaml@18ba1a60e91965ac35d8a877ce5c57568f879f91b6374af8c4ed157c0b7101e4"
                in failed["evidenceRefs"],
            "failed unpublished 006 allowance provenance")
    require(failed_successor["kind"] == "FAILED_UNPUBLISHED_LOCAL_CANDIDATE"
            and failed_successor["status"] == "BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED"
            and failed_successor["publishedPacket"] is False
            and failed_successor["predecessorIds"] == ["MET-UNIFY-005"]
            and failed_successor["executionAuthority"] == "NONE"
            and all("LOCAL" + str(n) in failed_successor["blockingReason"]
                    for n in (1, 2, 3))
            and "local-unpublished-commit@47e775afd87443e9826e2f2e496cf2eae768399f"
                in failed_successor["evidenceRefs"]
            and "task-packets/MET-UNIFY-007.yaml@f4ae338db253af3d25c11568c5574808bbec5ef9df1258c1e0caecab960f3599"
                in failed_successor["evidenceRefs"],
            "failed unpublished 007 allowance provenance")
    require(current["kind"] == "CURRENT_PACKET_CANDIDATE_NOT_ACCEPTED_BASELINE"
            and current["status"] == "ONGOING_SOURCE_PUBLICATION"
            and current["publishedPacket"] is False
            and current["predecessorIds"] == ["MET-UNIFY-005"]
            and "task-packets/MET-UNIFY-008.yaml" in current["evidenceRefs"]
            and current["executionAuthority"] == "NOT_GRANTED_BY_THIS_RECORD",
            "008 is not accepted main or product execution")
    for name in GATED_PACKETS:
        path = "task-packets/" + name + ".yaml"
        packet_raw = regular_bytes(path)
        packet = safe_load(packet_raw)
        row = rows[name]
        require(row["kind"] == "PUBLISHED_PACKET"
                and row["publishedPacket"] is True
                and row["status"] == "WAITING_OTHER_PREDECESSORS"
                and row["predecessorIds"] == packet["predecessors"]
                and path + "@" + digest(packet_raw) in row["evidenceRefs"]
                and "Linux release deployment" in row["blockingReason"]
                and "native AMD64 foundation" in row["blockingReason"]
                and row["executionAuthority"] == "NOT_GRANTED_BY_THIS_RECORD",
                "current product source/native backlog row: " + name)
    checklist = rows["CHECKLIST:MET-UNIFY-005"]
    successor_checklist = rows["CHECKLIST:MET-UNIFY-008"]
    control_checklist = rows["CHECKLIST:CTRL-INTEGRATE-001"]
    require(checklist["kind"] == "COUNTED_MASTER_CHECKLIST_PROJECTION"
            and checklist["status"] == "MERGED_SOURCE_RECORDED"
            and checklist["publishedPacket"] is False
            and successor_checklist["kind"] == "COUNTED_MASTER_CHECKLIST_PROJECTION"
            and successor_checklist["status"] == "ONGOING_SOURCE_PUBLICATION"
            and successor_checklist["predecessorIds"] == ["MET-UNIFY-005"]
            and successor_checklist["publishedPacket"] is False
            and control_checklist["kind"] == "COUNTED_MASTER_CHECKLIST_PROJECTION"
            and control_checklist["status"] == "WAITING_OTHER_PREDECESSORS"
            and control_checklist["predecessorIds"]
                == rows["CTRL-INTEGRATE-001"]["predecessorIds"]
            and control_checklist["publishedPacket"] is False,
            "current counted checklist boundary")


def validate() -> None:
    record = authority()
    policy = _validate_policy(record)
    require(digest(regular_bytes("architecture/unified-roadmap-authority.json"))
            == OLD_UNIFIED_AUTHORITY_SHA256,
            "accepted unified authority changed")
    for path, checksum in record["immutableLocks"].items():
        require(relative_path(path) and digest(regular_bytes(path)) == checksum,
                "accepted source lock changed: " + path)
    _validate_accepted_bridge(record)
    _validate_current_backlog(record)
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "' + b'TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"],
            "normalized native gate validator drift")
    rules = _projection_rules()
    require(set(rules) == set(record["changedFiles"]),
            "unreviewed changed-source route")
    require(not (set(rules) & set(record["newFiles"]))
            and AUTHORITY_PATH not in record["newFiles"]
            and VALIDATOR_PATH not in record["newFiles"],
            "cyclic or ambiguous authority scope")
    for path, rule in rules.items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"],
                "current source drift: " + path)
        _project_changed(path, current, rule)
    for path, checksum in record["newFiles"].items():
        require(relative_path(path) and digest(regular_bytes(path)) == checksum,
                "new source drift: " + path)
    packet_path = "task-packets/" + NEW_PACKET + ".yaml"
    successor_raw = regular_bytes(packet_path)
    require(digest(successor_raw) == record["packetSha256"]
            and record["newFiles"].get(packet_path) == record["packetSha256"]
            and record["newFiles"].get(POLICY_PATH) == record["policySha256"],
            "current successor and policy binding")
    successor = safe_load(successor_raw)
    previous = safe_load(regular_bytes("task-packets/MET-UNIFY-005.yaml"))
    require(successor["id"] == NEW_PACKET
            and successor["repository"] == "Harness-Engineering"
            and successor["predecessors"] == ["MET-UNIFY-005"]
            and successor["sourceReuse"] == successor["prefetchCommands"] == []
            and successor["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
            and "liveCampaignExecution" not in successor,
            "source-only successor contract")
    require(type(successor["allowedPaths"]) is list
            and len(successor["allowedPaths"]) == len(set(successor["allowedPaths"]))
            and set(successor["allowedPaths"])
            == set(record["changedFiles"]) | set(record["newFiles"])
               | {AUTHORITY_PATH, VALIDATOR_PATH},
            "closed 008 allowed-path publication")
    commands = successor["offlineAcceptanceCommands"]
    require(len(commands) == 52
            and commands == [
                *previous["offlineAcceptanceCommands"][:-2],
                COMMAND_PREFIX + [VALIDATOR_PATH],
                *previous["offlineAcceptanceCommands"][-2:],
            ]
            and successor["offlineExecution"] == previous["offlineExecution"],
            "complete isolated predecessor acceptance")
    packet_files = sorted((ROOT / "task-packets").glob("*.yaml"))
    require(len(packet_files) == 190
            and {path.stem for path in packet_files}
            == _baseline_ids() | {NEW_PACKET},
            "closed current packet catalog")
    _validate_four_packet_deltas(policy)
    parsed = {path.stem: safe_load(regular_bytes("task-packets/" + path.name))
              for path in packet_files}
    require(set(historical_catalog(parsed)) == _baseline_ids(),
            "exact accepted packet catalog")


if __name__ == "__main__":
    try:
        validate()
    except (ValueError, TypeError, KeyError, OSError, UnicodeError) as exc:
        print("Native gate staging invalid: " + str(exc))
        raise SystemExit(1)
    print("Native gate staging source valid: 190 current packets; 189 accepted history; native qualification unpassed.")
