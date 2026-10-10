#!/usr/bin/env python3
"""W01-AMEND: W02d's carried items as a reviewed amendment of the resolved W01 host-interface specification.

The resolved specification (architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md) stays byte-identical:
later layers freeze it. The amendment record (architecture/host-interface-amendment-w02d/amendment.json) lists exact,
counted substring replacements, each citing its owner decision. effective_spec() applies them to the pinned base bytes
and must give exactly the pinned effective bytes, which are published beside the record as the amended specification.

check(read) validates the record, the base and the published effective specification through an injected byte reader,
so a history-chain layer can pass its reviewed_bytes.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

SCHEMA = "planeon.internal.host-interface-amendment/v1"
RECORD_PATH = "architecture/host-interface-amendment-w02d/amendment.json"
BASE_PATH = "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md"
EFFECTIVE_PATH = "architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md"
DECIDED = "OWNER_DECIDED"
ITEM_KEYS = {"id", "section", "baseLines", "current", "proposed", "occurrences", "decisions", "source", "why"}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate amendment member: " + key)
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite amendment number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def check_record(record: Any) -> None:
    """A closed record: every item replaces exact text a stated number of times and cites decided owner decisions."""
    require(type(record) is dict and set(record) == {"schemaVersion", "amends", "base", "effective", "ownerDecisions",
                                                     "items", "notAmended"}
            and record["schemaVersion"] == SCHEMA, "closed amendment record")
    require(record["amends"] == "W01 HOST-INTERFACE-DRAFT-002" and record["base"].get("path") == BASE_PATH
            and record["effective"].get("path") == EFFECTIVE_PATH and set(record["base"]) == {"path", "sha256"}
            and set(record["effective"]) == {"path", "sha256"}, "amended base and effective paths")
    decisions = record["ownerDecisions"]
    require(type(decisions) is list and decisions
            and all(type(row) is dict and set(row) == {"id", "date", "state", "decision"} and row["state"] == DECIDED
                    for row in decisions), "every owner decision is decided")
    ids = [row["id"] for row in decisions]
    require(len(ids) == len(set(ids)), "unique owner decisions")
    items = record["items"]
    require(type(items) is list and items, "amendment items")
    seen = set()
    for item in items:
        require(type(item) is dict and set(item) == ITEM_KEYS and item["id"] not in seen, "closed amendment item")
        seen.add(item["id"])
        require(type(item["current"]) is str and type(item["proposed"]) is str and item["current"]
                and item["current"] != item["proposed"] and type(item["occurrences"]) is int and item["occurrences"] >= 1,
                "effective amendment item " + item["id"])
        require(type(item["decisions"]) is list and item["decisions"] and set(item["decisions"]) <= set(ids),
                "item %s cites decided owner decisions" % item["id"])
    require(type(record["notAmended"]) is list, "stated non-amendments")


def effective_spec(record: dict, base: bytes) -> bytes:
    """Apply every item in order; each current text must occur exactly its stated number of times, before and after."""
    require(digest(base) == record["base"]["sha256"], "pinned W01 base bytes")
    text = base.decode("utf-8")
    for item in record["items"]:
        require(text.count(item["current"]) == item["occurrences"], "item %s current text count" % item["id"])
        require(item["proposed"] not in text, "item %s proposed text already present" % item["id"])
        text = text.replace(item["current"], item["proposed"])
        require(text.count(item["proposed"]) == item["occurrences"], "item %s proposed text count" % item["id"])
    raw = text.encode("utf-8")
    require(digest(raw) == record["effective"]["sha256"], "pinned effective W01 bytes")
    return raw


def check(read: Callable[[str], bytes]) -> dict:
    """The record is closed, the base is the pinned W01 specification, and the published effective file is exact."""
    record = parse(read(RECORD_PATH))
    check_record(record)
    effective = effective_spec(record, read(BASE_PATH))
    require(read(EFFECTIVE_PATH) == effective, "published effective specification")
    return record
