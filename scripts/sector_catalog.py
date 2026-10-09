#!/usr/bin/env python3
"""Sector catalog overlay (CATALOG-BANK v2, owner decision SECTOR-D1): the banking-era view of the catalogs.

providers.yaml, services.yaml and PROVIDER_MODULE_CATALOG.md stay byte-identical. Older validators read them as
immutable inputs, and many authority records pin them. The reviewed overlay (architecture/sector-catalog/overlay.json)
gives their effective, banking-era bytes. effective_bytes() applies it as exact, counted substring replacements and
refuses any base, count or digest mismatch. Banking-era consumers read catalogs only through effective_bytes() and
effective_catalog().
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

ROOT = Path(__file__).resolve().parents[1]
OVERLAY_PATH = "architecture/sector-catalog/overlay.json"
SECTOR_PATH = "architecture/sector-direction.json"
SCHEMA = "planeon.internal.sector-catalog-overlay/v1"
APPLIED = "APPLIED_BY_OVERLAY"
DEFERRED = "DEFERRED_UNTIL_SUCCESSOR_PUBLISHED"
MAX_BYTES = 16_777_216


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read(root: Path, path: str) -> bytes:
    target = root / path
    require(not target.is_symlink() and target.is_file(), "regular file required: " + path)
    raw = target.read_bytes()
    require(len(raw) <= MAX_BYTES, "file too large: " + path)
    return raw


def _closed(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def overlay(root: Path = ROOT) -> dict:
    """The overlay record, structurally closed."""
    record = json.loads(_read(root, OVERLAY_PATH))
    _closed(record, ("schemaVersion", "decision", "sectorDirection", "approach", "base", "applied", "deferred", "effective",
                     "distributionNotice", "nonClaims"), "closed overlay record")
    require(record["schemaVersion"] == SCHEMA and record["decision"] == "SECTOR-D1", "overlay schema and decision")
    _closed(record["sectorDirection"], ("path", "sha256"), "closed sector direction pin")
    require(type(record["base"]) is dict and set(record["base"]) == set(record["effective"]) and record["base"],
            "every overlaid catalog has a base and an effective digest")
    for entry in record["applied"]:
        _closed(entry, ("path", "current", "proposed", "occurrences", "disposition"), "closed applied entry")
        require(entry["disposition"] == APPLIED and entry["path"] in record["base"], "applied entry disposition and path")
        require(type(entry["occurrences"]) is int and entry["occurrences"] >= 1, "positive occurrence count")
        require(type(entry["current"]) is str and type(entry["proposed"]) is str and entry["current"] and entry["proposed"]
                and entry["current"] != entry["proposed"], "non-empty, changing replacement")
    for entry in record["deferred"]:
        _closed(entry, ("path", "current", "proposed", "occurrences", "disposition", "blockedBy", "binding", "reason"),
                "closed deferred entry")
        require(entry["disposition"] == DEFERRED and entry["path"] in record["base"], "deferred entry disposition and path")
    return record


def effective_bytes(path: str, raw: bytes, record: dict | None = None) -> bytes:
    """The banking-era bytes of one overlaid catalog, from its exact base bytes."""
    record = record if record is not None else overlay()
    require(path in record["base"], "not an overlaid catalog: " + path)
    require(type(raw) is bytes and digest(raw) == record["base"][path], "overlay base changed: " + path)
    text = raw.decode("utf-8")
    for entry in record["applied"]:
        if entry["path"] != path:
            continue
        require(text.count(entry["current"]) == entry["occurrences"], "overlay occurrence count: " + entry["current"])
        require(entry["proposed"] not in text, "overlay target already present: " + entry["proposed"])
        text = text.replace(entry["current"], entry["proposed"])
    out = text.encode("utf-8")
    require(digest(out) == record["effective"][path], "overlay effective digest: " + path)
    return out


def effective_catalog(path: str, root: Path = ROOT, record: dict | None = None):
    """The parsed banking-era catalog (YAML catalogs only)."""
    require(path.endswith(".yaml"), "YAML catalogs only: " + path)
    return safe_load(effective_bytes(path, _read(root, path), record))


def check(root: Path = ROOT) -> dict:
    """The whole overlay holds against the current tree; returns the record."""
    record = overlay(root)
    sector_raw = _read(root, SECTOR_PATH)
    require(record["sectorDirection"] == {"path": SECTOR_PATH, "sha256": digest(sector_raw)}, "sector direction pin")
    sector = json.loads(sector_raw)
    follow = [(f["path"], f["current"], f["proposed"]) for f in sector["catalogFollowUps"]]
    entries = [(e["path"], e["current"], e["proposed"]) for e in record["applied"] + record["deferred"]]
    require(sorted(entries) == sorted(follow) and len(set(entries)) == len(entries),
            "the overlay covers exactly the SECTOR-D1 catalog follow-ups")
    pattern = re.compile(sector["detectionPattern"])
    deferred_terms = [e["current"] for e in record["deferred"]]
    for path in record["base"]:
        raw = _read(root, path)
        text = effective_bytes(path, raw, record).decode("utf-8")
        residue = text
        for term in deferred_terms:
            residue = residue.replace(term, "")
        require(not pattern.search(residue), "no white-goods term outside the deferred entries: " + path)
    providers = safe_load(_read(root, "architecture/providers.yaml"))
    for entry in record["deferred"]:
        require(entry["blockedBy"] == "IND-BANK-005" and not (root / "task-packets/IND-BANK-005.yaml").exists(),
                "the deferred entry waits for the unpublished IND-BANK-005")
        binding = entry["binding"]
        implementation = _find_implementation(providers, binding["catalogKey"])
        require(implementation == {"disposition": "REPOSITORY_PACKET", "packetId": binding["packetId"],
                                   "path": entry["current"], "deliverableIndex": binding["deliverableIndex"]},
                "the deferred binding is unchanged: " + binding["catalogKey"])
        require((root / ("task-packets/%s.yaml" % binding["packetId"])).is_file(), "the bound packet is published")
    notice = record["distributionNotice"]
    doc = _read(root, notice["path"]).decode("utf-8")
    require(doc.count(notice["heading"] + "\n") == 1 and notice["proposal"] in doc and notice["proposalPredecessor"] in doc,
            "the R11 distribution notice is present")
    return record


def _find_implementation(providers, key):
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


if __name__ == "__main__":
    record = check()
    print("Sector catalog overlay valid: %d applied, %d deferred, %d catalogs byte-identical to their base." % (
        len(record["applied"]), len(record["deferred"]), len(record["base"])))
