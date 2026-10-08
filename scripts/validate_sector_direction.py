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
    import validate_verify_headroom as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_verify_headroom as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/sector-direction-authority.json"
AUTHORITY_SHA256 = "68ede9b501d76c352a8745e1b5d38f33371e26578b830f824af5793dae04f720"
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
    """Newest first: every newer authority, then this one, each read exactly once."""
    successor._checked_authority_raw()
    return _checked_own_authority_raw()


def _checked_own_authority_raw() -> bytes:
    """Fresh complete read of this layer's authority only; callers reach newer
    authorities through exactly one successor route per public call."""
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
    """Undo the newer successor, then this step; every authority is read once."""
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
    rule = _PROJECTION_RULES.get(path)
    # An exact 206-era byte string is already older than the successor layer.
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


SECTOR_PATH = "architecture/sector-direction.json"
SECTOR_DOC = "docs/alpha-2/SECTOR_DIRECTION.md"
MASTER_PATH = "docs/MASTER_DEVELOPMENT_PLAN.md"
# The detection pattern is fixed here and in the record; the disposition set must equal the predecessor
# packets whose exact accepted bytes match it.
SECTOR_PATTERN = r"(?i)white[- ]goods|whitegoods|white_goods"
DISPOSITIONS = {"SUPERSEDED_BY_SUCCESSOR": {"disposition", "successor"},
                "ID_RETAINED_SCOPE_RETARGETED": {"disposition", "newScope", "requires"},
                "SECTOR_FIXTURES_HISTORICAL": {"disposition", "note", "bankingInputs"},
                "OBLIGATION_TRANSFERRED": {"disposition", "note", "transfersTo"},
                "HISTORICAL_EVIDENCE": {"disposition", "note"},
                "WARM_SOURCE_REFERENCE_ONLY": {"disposition", "note"}}
RETARGETED = ("CONF-A2-001", "CONF-WG-001")
REPOSITORIES = frozenset("R%02d" % number for number in range(13))
NON_CLAIMS = ("bankingPackBuilt", "ontologyPublished", "fixturesBuilt", "catalogChanged", "publishedPacketChanged",
              "backlogSnapshotChanged", "providerSelected", "campaignRun", "regulatoryApplicabilityAsserted",
              "tenantAcceptance")
# Catalogs keep their white-goods entries until a later catalog packet; snapshots record an earlier state.
REQUIRED_UNCHANGED = {"architecture/providers.yaml": "CATALOG", "architecture/services.yaml": "CATALOG",
                      "docs/PROVIDER_MODULE_CATALOG.md": "CATALOG",
                      "architecture/unified-roadmap-backlog.json": "SNAPSHOT",
                      "architecture/unified-roadmap-source-index.json": "SNAPSHOT",
                      "docs/alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md": "SNAPSHOT"}
DECISION = {"id": "SECTOR-D1", "decidedBy": "OWNER", "date": "2026-10-07", "packet": NEW_PACKET,
            "previousSector": "white-goods", "sector": "banking", "appliesFrom": "ALPHA_2",
            "appliesThrough": "FIRST_ENTERPRISE_RELEASE",
            "statement": ("Banking replaces white goods as the first and only release sector from Alpha 2 through the "
                          "first enterprise release. The common eight-gate journey is unchanged; banking is its sector "
                          "overlay.")}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def reviewed_era(record: dict[str, Any]) -> dict[str, bytes]:
    """This packet's reviewed bytes for every document, new file and unchanged authority the sector check reads."""
    era: dict[str, bytes] = {}
    for path, rule in record["changedFiles"].items():
        if path.endswith(".md"):
            raw = reviewed_bytes(path)
            require(digest(raw) == rule["afterSha256"], "unreviewed current source: " + path)
            era[path] = raw
    for path, expected in record["newFiles"].items():
        raw = reviewed_bytes(path)
        require(digest(raw) == expected, "new source drift: " + path)
        era[path] = raw
    for path in REQUIRED_UNCHANGED:
        era[path] = reviewed_bytes(path)
    return era


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
        "successorProposals", "retainedPredecessorEdges", "catalogFollowUps", "candidateRegulatoryInputs",
        "directionDocs", "unchangedAuthorities", "nonClaims"}, "closed sector direction record")
    require(value["schemaVersion"] == "planeon.internal.sector-direction/v1", "sector direction schema")
    return value


def _proposals(sector: dict[str, Any], record: dict[str, Any], dispositions: dict[str, Any]) -> dict[str, Any]:
    proposals = sector["successorProposals"]
    require(type(proposals) is list and proposals, "successor proposals")
    superseded = {name for name, row in dispositions.items()
                  if type(row) is dict and row.get("disposition") == "SUPERSEDED_BY_SUCCESSOR"}
    by_id: dict[str, dict[str, Any]] = {}
    for row in proposals:
        require(type(row) is dict and set(row) == {
            "id", "ownerRepoId", "phase", "supersedes", "replacesInputsOf", "predecessorIds", "description", "status",
            "publishedPacket", "executionAuthority"}, "closed successor proposal")
        name = row["id"]
        require(type(name) is str and name not in by_id and name not in record["baselinePackets"]
                and name != NEW_PACKET and "BANK" in name
                and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for char in name),
                "new successor identity")
        require(row["ownerRepoId"] in REPOSITORIES and row["phase"] == "ALPHA_2"
                and row["status"] == "WAITING_PACKET_PUBLICATION" and row["publishedPacket"] is False
                and row["executionAuthority"] == "NONE"
                and _text(row["description"]) and "banking" in row["description"].lower(),
                "unpublished banking successor without execution authority: " + name)
        require((row["supersedes"] is None or row["supersedes"] in superseded)
                and type(row["replacesInputsOf"]) is list and row["replacesInputsOf"] == sorted(set(row["replacesInputsOf"]))
                and (row["supersedes"] is not None or row["replacesInputsOf"]),
                "successor supersedes a packet or replaces sector inputs: " + name)
        require(type(row["predecessorIds"]) is list and row["predecessorIds"]
                and len(set(row["predecessorIds"])) == len(row["predecessorIds"])
                and all((pred in record["baselinePackets"] and pred not in superseded) or pred in by_id
                        for pred in row["predecessorIds"]),
                "successor predecessors are retained accepted packets or earlier successors: " + name)
        by_id[name] = row
    return by_id


def validate_sector_direction(record: dict[str, Any], era: dict[str, bytes], packets: dict[str, Any]) -> None:
    """Check the owner decision record against the exact accepted packets and this packet's reviewed bytes."""
    sector = _sector_record(era[SECTOR_PATH])
    require(sector["decision"] == DECISION, "owner decision SECTOR-D1 banking through the first enterprise release")
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
    by_id = _proposals(sector, record, dispositions)
    fed: dict[str, set[str]] = {}
    for name, row in by_id.items():
        for packet in row["replacesInputsOf"]:
            fed.setdefault(packet, set()).add(name)
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
                    and "revision amendment" in row["requires"],
                    "retargeted scope needs a revision amendment: " + name)
        elif kind == "SECTOR_FIXTURES_HISTORICAL":
            require(_text(row["note"]) and type(row["bankingInputs"]) is list and row["bankingInputs"]
                    and row["bankingInputs"] == sorted(set(row["bankingInputs"]))
                    and set(row["bankingInputs"]) == fed.get(name, set()),
                    "historical sector inputs name their banking replacements: " + name)
        elif kind == "OBLIGATION_TRANSFERRED":
            require(_text(row["note"]) and row["transfersTo"] in by_id, "transferred obligation names its successor: " + name)
        else:
            require(_text(row["note"]), "disposition note: " + name)
    require({row["supersedes"] for row in by_id.values() if row["supersedes"] is not None}
            == {name for name, row in dispositions.items() if row["disposition"] == "SUPERSEDED_BY_SUCCESSOR"}
            and len([row for row in by_id.values() if row["supersedes"] is not None])
            == len({row["supersedes"] for row in by_id.values() if row["supersedes"] is not None}),
            "one successor per superseded packet")
    require(set(fed) <= {name for name, row in dispositions.items() if row["disposition"] == "SECTOR_FIXTURES_HISTORICAL"},
            "banking inputs replace only historical sector fixtures")
    superseded = {row["supersedes"] for row in by_id.values() if row["supersedes"] is not None}
    edges = sector["retainedPredecessorEdges"]
    dependents = {name: sorted(set(packets[name].get("predecessors") or []) & superseded)
                  for name in record["baselinePackets"]
                  if set(packets[name].get("predecessors") or []) & superseded}
    require(type(edges) is dict and set(edges) == {"rule", "dependents"} and _text(edges["rule"])
            and "accepted predecessor edges" in edges["rule"] and edges["dependents"] == dependents,
            "every accepted edge to a superseded packet is recorded and retained")
    unchanged = sector["unchangedAuthorities"]
    require(type(unchanged) is dict and set(unchanged) == set(REQUIRED_UNCHANGED), "closed unchanged authorities")
    for path, row in unchanged.items():
        require(type(row) is dict and set(row) == {"role", "sha256"} and row["role"] == REQUIRED_UNCHANGED[path]
                and path not in record["changedFiles"] and path not in record["newFiles"]
                and digest(era[path]) == row["sha256"], "catalog or snapshot changed by this packet: " + path)
    follow = sector["catalogFollowUps"]
    require(type(follow) is list and follow and all(
        type(row) is dict and set(row) == {"path", "current", "proposed"} and unchanged.get(row["path"], {}).get("role") == "CATALOG"
        and _text(row["current"]) and pattern.search(row["current"]) and row["current"] in era[row["path"]].decode("utf-8")
        and _text(row["proposed"]) and "banking" in row["proposed"].lower() and not pattern.search(row["proposed"])
        for row in follow), "catalog follow-ups name existing catalog text")
    for path, role in REQUIRED_UNCHANGED.items():
        if role == "CATALOG":
            rest = era[path].decode("utf-8")
            for current in sorted((row["current"] for row in follow if row["path"] == path), key=len, reverse=True):
                rest = rest.replace(current, "")
            require(not pattern.search(rest), "every white-goods catalog entry has a follow-up: " + path)
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
        require(path in era and (path in record["changedFiles"] or path in record["newFiles"]),
                "direction document changed by this packet: " + path)
        text = era[path].decode("utf-8")
        require("SECTOR-D1" in text and "banking" in text, "direction document names SECTOR-D1: " + path)
    master = era[MASTER_PATH].decode("utf-8")
    require("The first sector pack is banking" in master and "The first sector pack is white goods" not in master,
            "master plan names banking as the first sector pack")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "sector direction validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 212
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 212-packet catalog retaining the 207-packet checkpoint")
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
            "closed source-only sector-direction packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted sector-direction packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_sector_direction(record, reviewed_era(record), packets)


if __name__ == "__main__":
    validate()
    print("Sector direction valid: 212 current specifications; 207-packet checkpoint and exact 206-packet predecessor; SECTOR-D1 banking through the first enterprise release, nothing built or qualified.")
