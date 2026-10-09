#!/usr/bin/env python3
"""Sector catalog overlay (CATALOG-BANK v2, owner decision SECTOR-D1): the banking-era view of the catalogs.

providers.yaml, services.yaml and PROVIDER_MODULE_CATALOG.md stay byte-identical. Older validators read them as
immutable inputs, and many authority records pin them. The reviewed overlay (architecture/sector-catalog/overlay.json)
gives their effective, banking-era bytes, as exact counted substring replacements.

Two entry points:
- check(read, packets) validates one era: an overlay, its catalogs, the sector record and the R11 notice, read through
  an injected byte reader and judged against an injected packet set. A history-chain layer passes its reviewed_bytes
  and historical_catalog, so that later packets (publishing IND-BANK-005, rebasing the overlay) leave it valid.
- effective_bytes(path) and effective_catalog(path) serve the current tree. They run check() on the current files and
  the published packets first. Consumers must read the banking-era catalogs only through these two functions.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path

import yaml

try:
    from safe_yaml import SafeLoader
except ImportError:
    from scripts.safe_yaml import SafeLoader

ROOT = Path(__file__).resolve().parents[1]
OVERLAY_PATH = "architecture/sector-catalog/overlay.json"
SECTOR_PATH = "architecture/sector-direction.json"
PROVIDERS_PATH = "architecture/providers.yaml"
SCHEMA = "planeon.internal.sector-catalog-overlay/v1"
APPLIED = "APPLIED_BY_OVERLAY"
DEFERRED = "DEFERRED_UNTIL_SUCCESSOR_PUBLISHED"
MAX_BYTES = 16_777_216
PACKET_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _relative(path) -> str:
    require(type(path) is str and path and not path.startswith("/") and "\\" not in path and "\n" not in path
            and all(part not in ("", ".", "..") for part in path.split("/")), "unsafe repository path: %r" % (path,))
    return path


def disk_reader(root: Path = ROOT):
    """A reader of bounded, regular, single-link repository files under root, refusing linked ancestors."""
    def read(path: str) -> bytes:
        parent = root
        for part in _relative(path).split("/")[:-1]:
            parent /= part
            require(stat.S_ISDIR(parent.lstat().st_mode), "linked or missing ancestor: " + path)
        target = parent / path.split("/")[-1]
        before = target.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_BYTES,
                "bounded regular single-link file: " + path)
        raw = target.read_bytes()
        after = target.lstat()
        identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_size, row.st_mtime_ns,
                                row.st_ctime_ns)
        require(identity(before) == identity(after) and len(raw) == before.st_size, "file changed during read: " + path)
        return raw
    return read


def published_packets(root: Path = ROOT) -> frozenset:
    """The IDs of the published task packets: regular files task-packets/<ID>.yaml (links are not packets)."""
    folder = root / "task-packets"
    require(stat.S_ISDIR(folder.lstat().st_mode), "task-packets directory")
    return frozenset(entry.name[:-5] for entry in folder.iterdir()
                     if entry.name.endswith(".yaml") and stat.S_ISREG(entry.lstat().st_mode))


def _json(raw: bytes):
    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), "duplicate JSON member")
        return dict(items)

    def constant(name):
        raise ValueError("nonfinite JSON number: " + name)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    return value


class _UniqueKeyLoader(SafeLoader):
    """The pinned safe loader, whose mappings refuse duplicate keys."""


def _unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        require(key not in result, "duplicate YAML key %r" % (key,))
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _yaml(raw: bytes):
    return yaml.load(raw, Loader=_UniqueKeyLoader)


def _closed(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def _text(value, message, empty=False):
    require(type(value) is str and (empty or value) and "\x00" not in value, message)


def record(raw: bytes) -> dict:
    """The overlay record, fully closed and typed."""
    value = _json(raw)
    _closed(value, ("schemaVersion", "decision", "sectorDirection", "approach", "base", "applied", "deferred", "effective",
                    "distributionNotice", "nonClaims"), "closed overlay record")
    require(value["schemaVersion"] == SCHEMA and value["decision"] == "SECTOR-D1", "overlay schema and decision")
    _closed(value["sectorDirection"], ("path", "sha256"), "closed sector direction pin")
    require(value["sectorDirection"]["path"] == SECTOR_PATH and SHA256.match(value["sectorDirection"]["sha256"] or ""),
            "sector direction pin")
    _text(value["approach"], "approach text")
    for name in ("base", "effective"):
        require(type(value[name]) is dict and value[name], "digest map: " + name)
        for path, pin in value[name].items():
            _relative(path)
            require(type(pin) is str and SHA256.match(pin), "sha256 digest: " + path)
    require(set(value["base"]) == set(value["effective"]), "every overlaid catalog has a base and an effective digest")
    require(type(value["applied"]) is list and value["applied"] and type(value["deferred"]) is list, "entry lists")
    for entry in value["applied"]:
        _closed(entry, ("path", "current", "proposed", "occurrences", "disposition"), "closed applied entry")
        require(entry["disposition"] == APPLIED, "applied disposition")
    for entry in value["deferred"]:
        _closed(entry, ("path", "current", "proposed", "occurrences", "disposition", "blockedBy", "binding", "reason"),
                "closed deferred entry")
        require(entry["disposition"] == DEFERRED, "deferred disposition")
        require(type(entry["blockedBy"]) is str and PACKET_ID.match(entry["blockedBy"]), "blocking packet ID")
        _closed(entry["binding"], ("catalogKey", "packetId", "deliverableIndex"), "closed deferred binding")
        _text(entry["binding"]["catalogKey"], "binding catalog key")
        require(type(entry["binding"]["packetId"]) is str and PACKET_ID.match(entry["binding"]["packetId"]),
                "binding packet ID")
        require(type(entry["binding"]["deliverableIndex"]) is int and entry["binding"]["deliverableIndex"] >= 0,
                "binding deliverable index")
        _text(entry["reason"], "deferral reason")
    for entry in value["applied"] + value["deferred"]:
        require(entry["path"] in value["base"], "entry path is an overlaid catalog")
        _text(entry["current"], "current text")
        _text(entry["proposed"], "proposed text")
        require(entry["current"] != entry["proposed"], "a changing replacement")
        require(type(entry["occurrences"]) is int and entry["occurrences"] >= 1, "positive occurrence count")
    require(set(value["base"]) == {entry["path"] for entry in value["applied"] + value["deferred"]},
            "the overlaid catalogs are exactly the follow-up paths")
    notice = value["distributionNotice"]
    _closed(notice, ("path", "heading", "sectionSha256", "listItem", "proposal", "proposalPredecessor", "finding",
                     "replacesDirectionDocsEntry"), "closed distribution notice")
    _relative(notice["path"])
    require(SHA256.match(notice["sectionSha256"] or ""), "notice section digest")
    for name in ("heading", "listItem", "proposal", "proposalPredecessor", "finding", "replacesDirectionDocsEntry"):
        _text(notice[name], "notice " + name)
    require(type(value["nonClaims"]) is list and value["nonClaims"], "non-claims")
    for claim in value["nonClaims"]:
        _text(claim, "non-claim")
    return value


def _apply(path: str, raw: bytes, overlay: dict) -> bytes:
    require(digest(raw) == overlay["base"][path], "overlay base changed: " + path)
    text = raw.decode("utf-8")
    for entry in overlay["applied"]:
        if entry["path"] == path:
            require(text.count(entry["current"]) == entry["occurrences"], "overlay occurrence count: " + entry["current"])
            require(entry["proposed"] not in text, "overlay target already present: " + entry["proposed"])
            text = text.replace(entry["current"], entry["proposed"])
    out = text.encode("utf-8")
    require(digest(out) == overlay["effective"][path], "overlay effective digest: " + path)
    return out


def _section(text: str, heading: str) -> str:
    lines = text.split("\n")
    starts = [index for index, line in enumerate(lines) if line == heading]
    require(len(starts) == 1, "exactly one notice heading")
    end = next((index for index in range(starts[0] + 1, len(lines)) if lines[index].startswith("## ")), len(lines))
    return "\n".join(lines[starts[0]:end])


def _binding(providers, key):
    found = []

    def walk(value):
        if isinstance(value, dict):
            if key in value and isinstance(value[key], dict):
                found.append(value[key])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(providers)
    require(len(found) == 1, "exactly one catalog binding: " + key)
    return found[0]


def check(read, packets) -> dict:
    """Validate one era: its overlay, catalogs, sector record and R11 notice (through read), against its packet set."""
    require(isinstance(packets, (set, frozenset)) and all(type(name) is str for name in packets), "packet set")
    overlay = record(read(OVERLAY_PATH))
    sector_raw = read(SECTOR_PATH)
    require(overlay["sectorDirection"]["sha256"] == digest(sector_raw), "sector direction pin")
    sector = _json(sector_raw)
    follow = sorted((f["path"], f["current"], f["proposed"]) for f in sector["catalogFollowUps"])
    entries = sorted((e["path"], e["current"], e["proposed"]) for e in overlay["applied"] + overlay["deferred"])
    require(entries == follow and len(set(entries)) == len(entries), "the overlay covers exactly the SECTOR-D1 follow-ups")
    catalogs = {path: row["sha256"] for path, row in sector["unchangedAuthorities"].items() if row.get("role") == "CATALOG"}
    require(overlay["base"] == catalogs, "the overlay base is exactly the SECTOR-001 CATALOG pins")
    pattern = re.compile(sector["detectionPattern"])
    for path in overlay["base"]:
        raw = read(path)
        text = _apply(path, raw, overlay).decode("utf-8")
        base_text = raw.decode("utf-8")
        residue = text
        for entry in overlay["deferred"]:
            if entry["path"] == path:
                require(base_text.count(entry["current"]) == entry["occurrences"] == text.count(entry["current"])
                        and entry["proposed"] not in text, "deferred entry count and absence: " + entry["current"])
                residue = residue.replace(entry["current"], "")
        require(not pattern.search(residue), "no white-goods term outside the deferred entries: " + path)
    providers = _yaml(read(PROVIDERS_PATH))
    for entry in overlay["deferred"]:
        require(entry["blockedBy"] not in packets, "the deferred entry waits for the unpublished " + entry["blockedBy"])
        binding = entry["binding"]
        require(binding["packetId"] in packets, "the bound packet is published: " + binding["packetId"])
        require(_binding(providers, binding["catalogKey"]) == {
            "disposition": "REPOSITORY_PACKET", "packetId": binding["packetId"], "path": entry["current"],
            "deliverableIndex": binding["deliverableIndex"]}, "the deferred binding is unchanged: " + binding["catalogKey"])
    notice = overlay["distributionNotice"]
    doc = read(notice["path"]).decode("utf-8")
    require(digest(_section(doc, notice["heading"]).encode("utf-8")) == notice["sectionSha256"],
            "the R11 notice section is exactly the reviewed text")
    require(doc.count(notice["listItem"] + "\n") == 1 and "`" + notice["proposal"] + "`" not in notice["listItem"],
            "the DIST-004 list item names the proposal plain, exactly once")
    return overlay


def effective_bytes(path: str, root: Path = ROOT) -> bytes:
    """The banking-era bytes of one overlaid catalog in the current tree, after the full check."""
    read = disk_reader(root)
    overlay = check(read, published_packets(root))
    require(path in overlay["base"], "not an overlaid catalog: " + path)
    return _apply(path, read(path), overlay)


def effective_catalog(path: str, root: Path = ROOT):
    """The parsed banking-era catalog (YAML catalogs only), with duplicate keys refused."""
    require(path.endswith(".yaml"), "YAML catalogs only: " + path)
    return _yaml(effective_bytes(path, root))


if __name__ == "__main__":
    result = check(disk_reader(ROOT), published_packets(ROOT))
    print("Sector catalog overlay valid: %d applied, %d deferred, %d catalogs byte-identical to their base." % (
        len(result["applied"]), len(result["deferred"]), len(result["base"])))
