#!/usr/bin/env python3
"""Validate one source-only roadmap successor and its exact predecessor projection."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import stat
import zlib
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

try:
    from validate_ci_runner_admission import (
        authority as runner_authority,
        historical_bytes as runner_history,
        historical_test_bytes as runner_historical_test,
        current_test_bytes as runner_current_test,
        historical_catalog as runner_catalog,
    )
except ImportError:
    from scripts.validate_ci_runner_admission import (
        authority as runner_authority,
        historical_bytes as runner_history,
        historical_test_bytes as runner_historical_test,
        current_test_bytes as runner_current_test,
        historical_catalog as runner_catalog,
    )


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/unified-roadmap-authority.json"
AUTHORITY_SHA256 = "8174dee255536cc2ae9d7e5d3759ee8307b2cb25ebbbb741b78f1ad737e445dd"
BASE_COMMIT = "7a353b253bb257aa0abe2148e7fa62d7570f0b5a"
BASE_TREE = "b5497691afc5b74e21b596676cb4ca026220022b"
NEW_PACKET = "MET-UNIFY-005"
INDEX_PATH = "architecture/unified-roadmap-source-index.json"
MASTER_PATH = "docs/MASTER_DEVELOPMENT_PLAN.md"
ARCHIVE_PATH = "docs/history/master-development-plan-7a353b2.md"
DISPOSITIONS_PATH = "architecture/unified-requirement-dispositions.json"
BACKLOG_PATH = "architecture/unified-roadmap-backlog.json"
CHANGED_PATHS = frozenset({
    "README.md",
    "docs/DEVELOPMENT_STATUS.md",
    "docs/MASTER_DEVELOPMENT_PLAN.md",
    "docs/READINESS_INDEX.md",
    "docs/alpha-2/CANONICAL_REPAIR_PLAN.md",
    "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md",
    "docs/alpha-2/HOST_INTERFACE_PUBLICATION.md",
    "docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md",
    "docs/repositories/00-harness-engineering.md",
    "scripts/validate_accounting_scope.py",
    "scripts/validate_backend_timing.py",
    "scripts/validate_benchmark_transport.py",
    "scripts/validate_broker_handoff.py",
    "scripts/validate_canonical_repair_plan.py",
    "scripts/validate_catalog_traversal.py",
    "scripts/validate_ci_performance.py",
    "scripts/validate_completion_integration.py",
    "scripts/validate_completion_profiling.py",
    "scripts/validate_conformance_completion.py",
    "scripts/validate_conformance_consumer_closure.py",
    "scripts/validate_conformance_performance.py",
    "scripts/validate_conformance_performance_followup.py",
    "scripts/validate_conformance_publication.py",
    "scripts/validate_conformance_reference_measurement.py",
    "scripts/validate_conformance_successor_checkpoint.py",
    "scripts/validate_credential_lifecycle.py",
    "scripts/validate_credential_ordering.py",
    "scripts/validate_custody_handoff.py",
    "scripts/validate_document_repair_execution.py",
    "scripts/validate_enforcement_integration.py",
    "scripts/validate_factory_diagnostics.py",
    "scripts/validate_guard_cost_repair.py",
    "scripts/validate_guard_traversal.py",
    "scripts/validate_host_interface.py",
    "scripts/validate_linux_readiness.py",
    "scripts/validate_linux_repair.py",
    "scripts/validate_linux_test_ownership.py",
    "scripts/validate_live_backend_readiness.py",
    "scripts/validate_local_acceptance.py",
    "scripts/validate_model_api_inventory.py",
    "scripts/validate_model_fixture_scope.py",
    "scripts/validate_native_qualification.py",
    "scripts/validate_observation_enforcement.py",
    "scripts/validate_packet_scalar_repair.py",
    "scripts/validate_policy_observation.py",
    "scripts/validate_provider_adoption.py",
    "scripts/validate_proxy_contract.py",
    "scripts/validate_proxy_diagnostics.py",
    "scripts/validate_readiness.py",
    "scripts/validate_readiness_repairs.py",
    "scripts/validate_research_adoption.py",
    "scripts/validate_reuse.py",
    "scripts/validate_successor_inventory.py",
    "scripts/validate_validation_performance.py",
    "task-packets/README.md",
    "tests/test_accounting_scope.py",
    "tests/test_alpha2_readiness.py",
    "tests/test_backend_timing.py",
    "tests/test_benchmark_transport.py",
    "tests/test_broker_handoff.py",
    "tests/test_canonical_repair_plan.py",
    "tests/test_catalog_traversal.py",
    "tests/test_ci_performance.py",
    "tests/test_completion_integration.py",
    "tests/test_completion_profiling.py",
    "tests/test_conformance_completion.py",
    "tests/test_conformance_consumer_closure.py",
    "tests/test_conformance_performance.py",
    "tests/test_conformance_performance_followup.py",
    "tests/test_conformance_publication.py",
    "tests/test_conformance_reference_measurement.py",
    "tests/test_conformance_successor_checkpoint.py",
    "tests/test_credential_lifecycle.py",
    "tests/test_credential_ordering.py",
    "tests/test_custody_handoff.py",
    "tests/test_document_repair_execution.py",
    "tests/test_document_repair_plan.py",
    "tests/test_enforcement_integration.py",
    "tests/test_factory_diagnostics.py",
    "tests/test_guard_cost_repair.py",
    "tests/test_guard_traversal.py",
    "tests/test_host_interface.py",
    "tests/test_linux_readiness.py",
    "tests/test_linux_repair.py",
    "tests/test_linux_test_ownership.py",
    "tests/test_live_backend_readiness.py",
    "tests/test_local_acceptance.py",
    "tests/test_model_api_inventory.py",
    "tests/test_model_fixture_scope.py",
    "tests/test_native_qualification.py",
    "tests/test_observation_enforcement.py",
    "tests/test_packet_scalar_repair.py",
    "tests/test_policy_observation.py",
    "tests/test_provider_adoption.py",
    "tests/test_proxy_contract.py",
    "tests/test_proxy_diagnostics.py",
    "tests/test_research_adoption.py",
    "tests/test_reuse.py",
    "tests/test_successor_inventory.py",
    "tests/test_task_packets.py",
    "tests/test_validation_performance.py",
})


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def parse(raw: bytes) -> Any:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, "duplicate JSON member")
            value[key] = item
        return value

    def reject_constant(_: str) -> Any:
        raise ValueError("nonfinite JSON number")

    return json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant)


def regular_bytes(path: str) -> bytes:
    require(
        isinstance(path, str)
        and bool(path)
        and not path.startswith("/")
        and all(part not in ("", ".", "..") for part in path.split("/")),
        "relative source path",
    )
    parent = ROOT
    for part in path.split("/")[:-1]:
        parent /= part
        require(stat.S_ISDIR(parent.lstat().st_mode), "linked source ancestor")
    target = parent / path.split("/")[-1]
    before = target.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and before.st_size <= 16_777_216,
        "bounded unlinked source file",
    )
    raw = target.read_bytes()
    after = target.lstat()
    key = lambda row: (
        row.st_dev, row.st_ino, row.st_mode, row.st_nlink,
        row.st_size, row.st_mtime_ns, row.st_ctime_ns,
    )
    require(key(before) == key(after) and len(raw) == before.st_size, "source changed during read")
    return raw


# Exact bytes most recently proven to hash to the pin. Every call still reads
# the complete file; byte-identical input implies the identical digest, while
# any other bytes or pin are hashed in full before they are accepted.
_VERIFIED_AUTHORITY: tuple[str, bytes] | None = None


def _checked_authority_raw() -> bytes:
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "unified authority digest")
        if type(raw) is bytes:
            _VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw)
    return raw


def authority() -> dict[str, Any]:
    raw = _checked_authority_raw()
    value = parse(raw)
    require(
        isinstance(value, dict)
        and set(value) == {
            "schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets",
            "changedFiles", "newFiles", "sourceIndexSha256", "packetSha256",
            "acceptedMasterSha256", "validatorNormalizedSha256",
        },
        "closed unified authority",
    )
    require(
        value["schemaVersion"] == "harness.planeon.ai/unified-roadmap-authority/v1"
        and value["authorityPacket"] == NEW_PACKET
        and value["acceptedBase"] == {"commit": BASE_COMMIT, "tree": BASE_TREE}
        and isinstance(value["changedFiles"], dict)
        and isinstance(value["newFiles"], dict)
        and isinstance(value["baselinePackets"], dict),
        "accepted publication scope",
    )
    return value


def _canonical_base64(value: str) -> bytes:
    require(type(value) is str, "inverse hunk encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError("invalid inverse hunk encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical inverse hunk")
    return raw


def _load_projection_rules() -> Mapping[str, Mapping[str, Any]]:
    """Freeze interpretation of the exact SHA-pinned authority for lookups."""
    changed = authority()["changedFiles"]
    require(set(changed) == CHANGED_PATHS, "changed-source routing drift")
    rules: dict[str, Mapping[str, Any]] = {}
    for path, rule in changed.items():
        hunk_mode = type(rule) is dict and set(rule) == {
            "beforeSha256", "afterSha256", "reverseHunks"
        }
        snapshot_mode = type(rule) is dict and set(rule) == {
            "beforeSha256", "afterSha256", "beforeZlibBase64"
        }
        require(
            (hunk_mode or snapshot_mode)
            and all(
                type(rule[name]) is str
                and len(rule[name]) == 64
                and all(character in "0123456789abcdef" for character in rule[name])
                for name in ("beforeSha256", "afterSha256")
            )
            and rule["beforeSha256"] != rule["afterSha256"],
            "closed inverse source record",
        )
        if snapshot_mode:
            compressed = _canonical_base64(rule["beforeZlibBase64"])
            require(len(compressed) <= 16_777_216, "bounded compressed predecessor")
            rules[path] = MappingProxyType({
                "beforeSha256": rule["beforeSha256"],
                "afterSha256": rule["afterSha256"],
                "beforeCompressed": compressed,
            })
            continue
        require(
            type(rule["reverseHunks"]) is list
            and 0 < len(rule["reverseHunks"]) <= 4096,
            "closed inverse hunks",
        )
        hunks = []
        prior_position = -1
        prior_end = 0
        total_payload = 0
        for hunk in rule["reverseHunks"]:
            require(
                type(hunk) is dict
                and set(hunk) == {"at", "removeBase64", "insertBase64"}
                and type(hunk["at"]) is int
                and prior_position < hunk["at"] <= 16_777_216
                and hunk["at"] >= prior_end,
                "ordered inverse hunk",
            )
            removed = _canonical_base64(hunk["removeBase64"])
            inserted = _canonical_base64(hunk["insertBase64"])
            require(removed != inserted, "ineffective inverse hunk")
            total_payload += len(removed) + len(inserted)
            require(total_payload <= 16_777_216, "bounded inverse payload")
            hunks.append((hunk["at"], removed, inserted))
            prior_position = hunk["at"]
            prior_end = hunk["at"] + len(removed)
        rules[path] = MappingProxyType({
            "beforeSha256": rule["beforeSha256"],
            "afterSha256": rule["afterSha256"],
            "reverseHunks": tuple(hunks),
        })
    return MappingProxyType(rules)


# These are immutable data, never a cached result of checking the current file.
# Every public projection below freshly reads and hashes the entire authority
# before it uses a rule; each inverse is checked against the predecessor digest.
_PROJECTION_RULES = _load_projection_rules()
_TEST_PROJECTION_RULES = MappingProxyType({
    path: rule for path, rule in _PROJECTION_RULES.items() if path.startswith("tests/")
})


def _reconstruct_predecessor(raw: bytes, hunks: tuple[tuple[int, bytes, bytes], ...]) -> bytes:
    cursor = 0
    pieces = []
    for at, removed, inserted in hunks:
        require(cursor <= at and at + len(removed) <= len(raw), "inverse hunk bounds")
        require(raw[at:at + len(removed)] == removed, "inverse hunk current bytes")
        pieces.extend((raw[cursor:at], inserted))
        cursor = at + len(removed)
    pieces.append(raw[cursor:])
    previous = b"".join(pieces)
    require(len(previous) <= 16_777_216, "bounded predecessor bytes")
    return previous


def _inflate_predecessor(compressed: bytes) -> bytes:
    try:
        inflater = zlib.decompressobj()
        previous = inflater.decompress(compressed, 16_777_217)
    except zlib.error as exc:
        raise ValueError("invalid compressed predecessor") from exc
    require(
        len(previous) <= 16_777_216
        and inflater.eof
        and not inflater.unconsumed_tail
        and not inflater.unused_data,
        "bounded canonical predecessor decompression",
    )
    return previous


def _project_changed(path: str, raw: bytes, rule: Mapping[str, Any], current_digest: str) -> bytes:
    require(
        current_digest in (rule["beforeSha256"], rule["afterSha256"]),
        "unreviewed current source: " + path,
    )
    if current_digest == rule["beforeSha256"]:
        # The supplied bytes themselves are the exact accepted predecessor.
        return raw
    previous = (
        _inflate_predecessor(rule["beforeCompressed"])
        if "beforeCompressed" in rule
        else _reconstruct_predecessor(raw, rule["reverseHunks"])
    )
    require(digest(previous) == rule["beforeSha256"], "accepted predecessor bytes")
    return previous


def historical_bytes(path: str, raw: bytes) -> bytes:
    """Project only a pinned current file to its accepted predecessor bytes."""
    require(type(raw) is bytes, "source bytes required")
    if path in CHANGED_PATHS:
        rule = _PROJECTION_RULES.get(path)
        require(rule is not None, "code-pinned changed-source route")
        if digest(raw) == rule["beforeSha256"]:
            # This exact predecessor may be passed by an already-projected caller.
            # Recheck both authorities before treating it as idempotent.
            _checked_authority_raw()
            runner_authority()
            return raw
    raw = runner_history(path, raw)
    _checked_authority_raw()
    require(type(raw) is bytes, "source bytes required")
    if path not in CHANGED_PATHS:
        return raw
    rule = _PROJECTION_RULES.get(path)
    require(rule is not None, "code-pinned changed-source route")
    return _project_changed(path, raw, rule, digest(raw))


def historical_test_bytes(raw: bytes) -> bytes:
    """Map a current test to its old bytes without guessing a filename."""
    raw = runner_historical_test(raw)
    _checked_authority_raw()
    require(type(raw) is bytes, "test bytes required")
    current_digest = digest(raw)
    matches = [
        path for path, rule in _TEST_PROJECTION_RULES.items()
        if current_digest == rule["afterSha256"]
    ]
    require(len(matches) <= 1, "ambiguous current test")
    if not matches:
        return raw
    path = matches[0]
    return _project_changed(path, raw, _TEST_PROJECTION_RULES[path], current_digest)


def current_test_bytes(before: bytes) -> bytes:
    """Project a pinned accepted test to the exact reviewed current test."""
    _checked_authority_raw()
    require(type(before) is bytes, "test bytes required")
    before_digest = digest(before)
    matches = [
        path for path, rule in _TEST_PROJECTION_RULES.items()
        if before_digest == rule["beforeSha256"]
    ]
    require(len(matches) <= 1, "ambiguous accepted test")
    if not matches:
        return runner_current_test(before)
    path = matches[0]
    raw = runner_history(path, regular_bytes(path))
    require(digest(raw) == _TEST_PROJECTION_RULES[path]["afterSha256"], "current test drift")
    return runner_current_test(raw)


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Check and remove exactly this successor for the inherited 188-packet chain."""
    packets = runner_catalog(packets)
    record = authority()
    require(isinstance(packets, dict), "packet mapping")
    old_ids = set(record["baselinePackets"])
    require(
        len(old_ids) == 188,
        "exact accepted catalog identities",
    )
    require(set(packets) == old_ids | {NEW_PACKET}, "unexpected packet addition or loss")
    successor_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(successor_raw) == record["packetSha256"], "changed successor YAML")
    require(
        digest(canonical(packets[NEW_PACKET]))
        == digest(canonical(safe_load(successor_raw))),
        "changed successor packet",
    )
    return {name: packets[name] for name in old_ids}


def validate() -> None:
    record = authority()
    require(CHANGED_PATHS == set(record["changedFiles"]), "changed-source routing drift")
    # The authority cannot hash its own bytes. Normalize only the single embedded
    # authority literal to bind this validator without a digest cycle.
    validator_raw = runner_history(
        "scripts/validate_unified_roadmap.py",
        regular_bytes("scripts/validate_unified_roadmap.py"),
    )
    authority_literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder_literal = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(authority_literal) == 1, "unique authority literal")
    require(
        digest(validator_raw.replace(authority_literal, placeholder_literal))
        == record["validatorNormalizedSha256"],
        "normalized validator drift",
    )
    require(
        AUTHORITY_PATH not in record["newFiles"]
        and "scripts/validate_unified_roadmap.py" not in record["newFiles"],
        "cyclic authority digest",
    )
    old_ids = set(record["baselinePackets"])
    packet_files = sorted((ROOT / "task-packets").glob("*.yaml"))
    require(len(packet_files) == 194, "194 current packets")
    require({path.stem for path in packet_files} == old_ids | {NEW_PACKET, "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}, "closed packet catalog")
    for name, expected in record["baselinePackets"].items():
        raw = regular_bytes("task-packets/" + name + ".yaml")
        require(digest(raw) == expected, "changed predecessor YAML: " + name)
    successor_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(successor_raw) == record["packetSha256"], "changed successor YAML")
    successor = safe_load(successor_raw)
    require(
        successor["id"] == NEW_PACKET
        and successor["repository"] == "Harness-Engineering"
        and successor["predecessors"] == ["MET-ENFORCE-003"],
        "closed source-only successor",
    )
    previous = safe_load(regular_bytes("task-packets/MET-ENFORCE-003.yaml"))
    commands = successor["offlineAcceptanceCommands"]
    require(
        len(commands) == 51
        and commands[:-3] + commands[-2:] == previous["offlineAcceptanceCommands"]
        and commands[-3] == [
            "uv", "run", "--offline", "--frozen", "--no-sync", "python",
            "scripts/validate_unified_roadmap.py",
        ]
        and successor["offlineExecution"] == previous["offlineExecution"]
        and successor["prefetchCommands"] == successor["sourceReuse"] == []
        and successor["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
        and "liveCampaignExecution" not in successor,
        "unchanged isolated predecessor acceptance",
    )
    require(
        set(record["changedFiles"]) | set(record["newFiles"])
        | {AUTHORITY_PATH, "scripts/validate_unified_roadmap.py"}
        == set(successor["allowedPaths"]),
        "unreviewed or omitted packet path",
    )
    for path, rule in record["changedFiles"].items():
        raw = runner_history(path, regular_bytes(path))
        require(digest(raw) == rule["afterSha256"], "current source drift: " + path)
        require(digest(historical_bytes(path, raw)) == rule["beforeSha256"], "failed exact inverse")
    for path, expected in record["newFiles"].items():
        require(digest(runner_history(path, regular_bytes(path))) == expected, "new source drift: " + path)
    archive = regular_bytes(ARCHIVE_PATH)
    require(
        digest(archive) == record["acceptedMasterSha256"]
        and historical_bytes(MASTER_PATH, regular_bytes(MASTER_PATH)) == archive,
        "master history is not exact",
    )
    index_raw = regular_bytes(INDEX_PATH)
    require(digest(index_raw) == record["sourceIndexSha256"], "source inventory drift")
    index = parse(index_raw)
    require(
        len(index["documents"]) == 36
        and len(index["packets"]) == 188
        and len(index["proposals"]) == 23
        and len(index["attachments"]) == 4,
        "incomplete source inventory",
    )
    document_paths = [row["path"] for row in index["documents"]]
    require(len(set(document_paths)) == 36, "duplicate accepted document")
    for row in index["documents"]:
        current = regular_bytes(row["path"])
        require(
            digest(historical_bytes(row["path"], current)) == row["sha256"],
            "accepted document drift: " + row["path"],
        )
    require(
        {row["id"] for row in index["packets"]} == old_ids
        and all(
            row["sha256"] == record["baselinePackets"][row["id"]]
            for row in index["packets"]
        ),
        "source inventory differs from accepted packet bytes",
    )
    dispositions = parse(regular_bytes(DISPOSITIONS_PATH))
    expected_units = {
        row["path"] + "@" + row["sha256"] + "#L" + str(section["line"])
        for row in index["documents"] for section in row["sections"]
    } | {
        row["id"] + "@" + row["sha256"] + pointer
        for row in index["packets"] for pointer in row["requirementPointers"]
    }
    units = dispositions["units"]
    require(
        dispositions["acceptedBase"] == BASE_COMMIT
        and dispositions["counts"]["documentHeadingSpans"] == 923
        and dispositions["counts"]["packetRequirementPointers"] == 4302
        and dispositions["counts"]["totalUnits"] == len(units) == 5225
        and len(expected_units) == 5225
        and {row["id"] for row in units} == expected_units,
        "incomplete source-unit dispositions",
    )
    owners = {"R" + str(number).zfill(2) for number in range(13)}
    for row in units:
        require(
            row["ownerRepoId"] in owners
            and bool(row["harnessIds"])
            and bool(row["phase"])
            and isinstance(row["deliveryPacketIds"], list)
            and isinstance(row["acceptancePlanRefs"], list)
            and row["disposition"] in {"RETAINED", "COMBINED", "SUPERSEDED", "DEFERRED", "OPEN_REVIEW"}
            and bool(row["dispositionReason"])
            and isinstance(row["unresolvedMarkers"], list)
            and row["evidenceState"] == "SOURCE_ONLY_NOT_ACCEPTANCE",
            "unaccounted source-unit disposition",
        )
    require(
        sum(bool(row["unresolvedMarkers"]) for row in units)
        == dispositions["counts"]["unitsWithUnresolvedMarkers"] == 38
        and sum(row["disposition"] == "OPEN_REVIEW" for row in units)
        == dispositions["counts"]["dispositions"].get("OPEN_REVIEW", 0) == 0
        and dispositions["counts"]["reconciledOpenReviewSpans"] == 51,
        "hidden unresolved source units",
    )
    backlog = parse(regular_bytes(BACKLOG_PATH))
    items = backlog["items"]
    ids = [row["id"] for row in items]
    require(
        backlog["acceptedBase"] == BASE_COMMIT
        and backlog["counts"]["publishedPackets"] == 188
        and backlog["counts"]["currentPacketCandidateNotAcceptedBaseline"] == 1
        and backlog["counts"]["unpublishedAdoptionAndExtensionProposals"] == 23
        and backlog["counts"]["countedChecklistProjections"] == 13
        and backlog["counts"]["unpublishedSemanticProposals"] == 11
        and backlog["counts"]["postReleaseEvolutionMilestones"] == 3
        and backlog["counts"]["totalItems"] == len(items) == 239
        and len(set(ids)) == len(ids)
        and old_ids | {NEW_PACKET} | set(index["proposals"]) <= set(ids)
        and {"E1", "E2", "E3"} <= set(ids),
        "incomplete item-level backlog",
    )
    for row in items:
        require(
            row["ownerRepoId"] in owners
            and bool(row["description"])
            and bool(row["phase"])
            and bool(row["status"])
            and isinstance(row["predecessorIds"], list)
            and isinstance(row["blockingReason"], str)
            and bool(row["evidenceRefs"])
            and row["executionAuthority"] in {"NONE", "NOT_GRANTED_BY_THIS_RECORD"},
            "unaccounted backlog item",
        )
    for row in units:
        proposed = row.get("proposalPacketIds", [])
        require(
            isinstance(proposed, list)
            and set(proposed) <= set(ids)
            and (
                not proposed
                or row.get("deliveryJoinStatus")
                in {"WAITING_PACKET_PUBLICATION", "OWNER_PACKET_AND_QUALIFICATION_OPEN"}
            )
            and not (set(proposed) & old_ids),
            "proposal presented as published delivery",
        )
    master = regular_bytes(MASTER_PATH).decode("utf-8")
    for phrase in (
        "Require **at least one qualified baseline for every released harness capability**",
        "MET-UNIFY-005", "W01", "G04", "G09", "E01", "E12",
        "CONF-FIX-010", "NOT_DUE", "INTERFACE_NOT_PUBLISHED",
    ):
        require(phrase in master, "missing current roadmap obligation: " + phrase)
    require(
        "W01 COMPLETE" not in master
        and "TENANT_ACCEPTED" not in master,
        "unearned current status",
    )


if __name__ == "__main__":
    try:
        validate()
    except (ValueError, TypeError, KeyError, OSError, UnicodeError) as exc:
        print("Unified roadmap publication invalid: " + str(exc))
        raise SystemExit(1)
    print("Unified roadmap source valid: 194 packets; 188 immutable predecessor YAML; no product acceptance.")
