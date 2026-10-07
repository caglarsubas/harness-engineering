#!/usr/bin/env python3
"""Validate owner decision SECTOR-D1 (banking replaces white goods) and the exact 207-to-206 projection."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import stat
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/sector-direction-authority.json"
AUTHORITY_SHA256 = "27b38285e2a5dda341dc07f2f806315d0269fcfad4b41b8ee6e3f4abd44a3b10"
VALIDATOR_PATH = "scripts/validate_sector_direction.py"
BASE_COMMIT = "2c14e512d902a44425ffeec4b1dbb54a5dbbb284"
NEW_PACKET = "MET-SECTOR-001"
PREVIOUS_PACKET = "MET-ENFORCE-009"
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
            require(key not in result, "duplicate sector-direction authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite sector-direction authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "sector direction history authority digest")
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
    }, "closed sector direction history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/sector-direction-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 206
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 206-packet base")
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


SECTOR_PATH = "architecture/sector-direction.json"
SECTOR_DOC = "docs/alpha-2/SECTOR_DIRECTION.md"
MASTER_PATH = "docs/MASTER_DEVELOPMENT_PLAN.md"
# The detection pattern is fixed here and in the record; the disposition set must equal the predecessor
# packets whose exact accepted bytes match it.
SECTOR_PATTERN = r"(?i)white[- ]goods|whitegoods|white_goods"
DISPOSITIONS = {"SUPERSEDED_BY_SUCCESSOR": {"disposition", "successor"},
                "ID_RETAINED_SCOPE_RETARGETED": {"disposition", "newScope", "requires"},
                "SECTOR_FIXTURES_HISTORICAL": {"disposition", "note"},
                "HISTORICAL_EVIDENCE": {"disposition", "note"},
                "INCIDENTAL_REFERENCE": {"disposition", "note"}}
RETARGETED = ("CONF-A2-001", "CONF-WG-001")
REPOSITORIES = frozenset("R%02d" % number for number in range(13))
NON_CLAIMS = ("bankingPackBuilt", "ontologyPublished", "fixturesBuilt", "catalogChanged", "publishedPacketChanged",
              "backlogSnapshotChanged", "providerSelected", "campaignRun", "regulatoryApplicabilityAsserted",
              "tenantAcceptance")
DECISION = {"id": "SECTOR-D1", "decidedBy": "OWNER", "date": "2026-10-07", "packet": NEW_PACKET,
            "previousSector": "white-goods", "sector": "banking", "appliesFrom": "ALPHA_2",
            "appliesThrough": "FIRST_ENTERPRISE_RELEASE"}


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and value == value.strip()


def _sector_record(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate sector direction member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite sector direction number")

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)
    require(type(value) is dict and set(value) == {
        "schemaVersion", "decision", "domainSemantic", "detectionPattern", "publishedPacketDispositions",
        "successorProposals", "catalogFollowUps", "candidateRegulatoryInputs", "directionDocs",
        "unchangedAuthorities", "nonClaims"}, "closed sector direction record")
    require(value["schemaVersion"] == "planeon.internal.sector-direction/v1", "sector direction schema")
    return value


def validate_sector_direction(record: dict[str, Any], era: dict[str, bytes]) -> None:
    """Check the owner decision record against the exact accepted packets and this layer's documents.

    era holds this packet's reviewed bytes for every changed or new path it names."""
    sector = _sector_record(era[SECTOR_PATH])
    decision = sector["decision"]
    require(type(decision) is dict and set(decision) == set(DECISION) | {"statement"}
            and all(decision[key] == expected for key, expected in DECISION.items())
            and _text(decision["statement"]) and "banking" in decision["statement"].lower(),
            "owner decision SECTOR-D1 banking through the first enterprise release")
    domain = sector["domainSemantic"]
    require(type(domain) is dict and set(domain) == {"harness", "alphaCapability", "proposedNamespace", "conceptAreas"}
            and domain["harness"] == "knowledge.domain-semantic"
            and _text(domain["alphaCapability"]) and domain["alphaCapability"].startswith("Banking glossary and ontology")
            and domain["proposedNamespace"] == "urn:planeon:banking:*"
            and type(domain["conceptAreas"]) is list and domain["conceptAreas"]
            and all(_text(area) for area in domain["conceptAreas"])
            and len(set(domain["conceptAreas"])) == len(domain["conceptAreas"]),
            "banking domain-semantic scope")
    require(sector["detectionPattern"] == SECTOR_PATTERN, "fixed white-goods detection pattern")
    pattern = re.compile(SECTOR_PATTERN)
    mentioning = {name for name in record["baselinePackets"]
                  if pattern.search(regular_bytes("task-packets/" + name + ".yaml").decode("utf-8"))}
    dispositions = sector["publishedPacketDispositions"]
    require(type(dispositions) is dict and set(dispositions) == mentioning,
            "every predecessor packet naming white goods has exactly one disposition")
    successors = sector["successorProposals"]
    require(type(successors) is list and successors, "successor proposals")
    by_id: dict[str, dict[str, Any]] = {}
    for row in successors:
        require(type(row) is dict and set(row) == {
            "id", "ownerRepoId", "phase", "supersedes", "predecessorIds", "description", "status",
            "publishedPacket", "executionAuthority"}, "closed successor proposal")
        name = row["id"]
        require(type(name) is str and name not in by_id and name not in record["baselinePackets"]
                and name != NEW_PACKET
                and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for char in name),
                "new successor identity")
        require(row["ownerRepoId"] in REPOSITORIES and row["phase"] == "ALPHA_2"
                and row["status"] == "WAITING_PACKET_PUBLICATION" and row["publishedPacket"] is False
                and row["executionAuthority"] == "NONE"
                and _text(row["description"]) and "banking" in row["description"].lower(),
                "unpublished banking successor without execution authority: " + name)
        require(type(row["predecessorIds"]) is list and row["predecessorIds"]
                and len(set(row["predecessorIds"])) == len(row["predecessorIds"])
                and all(pred in record["baselinePackets"] or pred in by_id for pred in row["predecessorIds"]),
                "successor predecessors are accepted packets or earlier successors: " + name)
        by_id[name] = row
    for name, row in dispositions.items():
        require(type(row) is dict and row.get("disposition") in DISPOSITIONS
                and set(row) == DISPOSITIONS[row["disposition"]], "closed packet disposition: " + name)
        kind = row["disposition"]
        require((kind == "ID_RETAINED_SCOPE_RETARGETED") == (name in RETARGETED),
                "only CONF-A2-001 and CONF-WG-001 keep their IDs with banking scope")
        if kind == "SUPERSEDED_BY_SUCCESSOR":
            require(row["successor"] in by_id and by_id[row["successor"]]["supersedes"] == name,
                    "superseded packet names its successor: " + name)
        elif kind == "ID_RETAINED_SCOPE_RETARGETED":
            require(_text(row["newScope"]) and "banking" in row["newScope"] and _text(row["requires"])
                    and "revised packet" in row["requires"], "retargeted scope needs a revised packet: " + name)
        else:
            require(_text(row["note"]), "disposition note: " + name)
    require({row["supersedes"] for row in successors}
            == {name for name, row in dispositions.items() if row["disposition"] == "SUPERSEDED_BY_SUCCESSOR"}
            and len(successors) == len({row["supersedes"] for row in successors}),
            "one successor per superseded packet")
    unchanged = sector["unchangedAuthorities"]
    require(type(unchanged) is list and unchanged and len(set(unchanged)) == len(unchanged), "unchanged authorities")
    for path in unchanged:
        _path(path)
        require(path not in record["changedFiles"] and path not in record["newFiles"],
                "catalog or snapshot changed by this packet: " + path)
    follow = sector["catalogFollowUps"]
    require(type(follow) is list and follow and all(
        type(row) is dict and set(row) == {"path", "current", "proposed"} and row["path"] in unchanged
        and _text(row["current"]) and _text(row["proposed"]) and "banking" in row["proposed"]
        and pattern.search(row["current"]) for row in follow), "catalog follow-ups stay for a later packet")
    inputs = sector["candidateRegulatoryInputs"]
    require(type(inputs) is list and inputs and all(_text(row) for row in inputs)
            and len(set(inputs)) == len(inputs), "candidate regulatory inputs")
    claims = sector["nonClaims"]
    require(type(claims) is dict and set(claims) == set(NON_CLAIMS) and all(claims[key] is False for key in NON_CLAIMS),
            "sector direction cannot overclaim")
    docs = sector["directionDocs"]
    require(type(docs) is list and docs == sorted(set(docs)) and SECTOR_DOC in docs and MASTER_PATH in docs,
            "sorted direction documents")
    for path in docs:
        require(path in era, "direction document changed by this packet: " + path)
        text = era[path].decode("utf-8")
        require("SECTOR-D1" in text and "banking" in text, "direction document names SECTOR-D1: " + path)
    master = era[MASTER_PATH].decode("utf-8")
    require("The first sector pack is banking" in master and "The first sector pack is white goods" not in master,
            "master plan names banking as the first sector pack")


def validate() -> None:
    record = authority()
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "sector direction validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 207 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 207-packet catalog")
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
            "closed source-only sector-direction packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted sector-direction packet path")
    # This packet's reviewed bytes for the semantic check; a newer layer projects them back first.
    era: dict[str, bytes] = {}
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
        era[path] = current
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    for path in (SECTOR_PATH, SECTOR_DOC):
        require(path in record["newFiles"], "new sector source: " + path)
        raw = regular_bytes(path)
        require(digest(raw) == record["newFiles"][path], "new source drift: " + path)
        era[path] = raw
    validate_sector_direction(record, era)


if __name__ == "__main__":
    validate()
    print("Sector direction valid: 207 current specifications; exact 206-packet predecessor; SECTOR-D1 banking through the first enterprise release, nothing built or qualified.")
