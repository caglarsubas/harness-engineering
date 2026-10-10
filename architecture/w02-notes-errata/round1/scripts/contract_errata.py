#!/usr/bin/env python3
"""W02 notes errata: counted text replacements and added vectors for two adopted contracts. DATA_CHECK_ONLY.

An errata record never changes an adopted contract's bytes, version, rules or model. It names the adopted bytes by
digest, lists counted replacements (each `old` text occurs exactly `count` times in the text it applies to, and the
rows of one file apply in order), and publishes the effective text under `effective/`. A replacement in a model file
may change comments only: the effective module's syntax tree equals the adopted one, and no effective model is
published. Added vectors are replayed through the adopted model, imported unchanged, against its own positives.

`check_errata` and `replay_vectors` take a `read(path) -> bytes` callable, so a layer validator can pass its reviewed
bytes. Every refusal is a ValueError naming the refused rule.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from typing import Any, Callable

try:
    import native_qualification_v3 as native
except ModuleNotFoundError as exc:
    if exc.name != "native_qualification_v3":
        raise
    from scripts import native_qualification_v3 as native

ERRATA_DIR = "architecture/w02-notes-errata/"
ERRATA_SCHEMA = "planeon.internal.contract-errata/v1"
VECTORS_SCHEMA = "planeon.internal.native-profile-v3-errata-vectors/v1"
NATIVE_VECTORS = "architecture/native-profile-v3/vectors.json"
NATIVE_MODEL = "scripts/native_qualification_v3.py"
# The model bytes the native-profile-v3 round-6 review executed (review-round6.json subjectSha256).
NATIVE_MODEL_SHA256 = "2ef5c14ad5d8c962cf3703ccd076059685ed8dcc852059e4f863e8d9dc8965ad"
FALSE_FLAGS = ("versionRipple", "ruleChanged", "modelChanged", "nativeAcceptance", "tenantAcceptance")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse(raw: bytes) -> Any:
    def unique(pairs: list) -> dict:
        keys = [key for key, _ in pairs]
        require(len(keys) == len(set(keys)), "duplicate JSON key")
        return dict(pairs)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)


def apply_replacements(text: str, rows: list) -> str:
    """Apply one file's rows in order; each `old` occurs exactly `count` times in the text it is applied to."""
    for row in rows:
        require(type(row["count"]) is int and row["count"] >= 1 and row["old"] and row["old"] != row["new"],
                "malformed replacement: " + row["id"])
        require(text.count(row["old"]) == row["count"], "replacement count differs: " + row["id"])
        text = text.replace(row["old"], row["new"])
    return text


def check_errata(errata: Any, read: Callable[[str], bytes]) -> dict[str, bytes]:
    """The effective bytes of every replaced file, after checking the record against the adopted bytes."""
    require(type(errata) is dict and errata.get("schemaVersion") == ERRATA_SCHEMA, "not an errata record")
    require(all(errata.get(flag) is False for flag in FALSE_FLAGS) and errata.get("evidenceClass") == "DATA_CHECK_ONLY",
            "errata claims a version, rule, model or acceptance change")
    base = errata["base"]
    for path, sha in base.items():
        require(digest(read(path)) == sha, "adopted bytes differ: " + path)
    ids = [row["id"] for row in errata["replacements"]]
    require(len(ids) == len(set(ids)), "duplicate replacement id")
    rows_by_path: dict[str, list] = {}
    for row in errata["replacements"]:
        require(row["path"] in base and row["finding"] in errata["findings"], "replacement outside the record: " + row["id"])
        rows_by_path.setdefault(row["path"], []).append(row)
    require(set(rows_by_path) == set(errata["effective"]), "every replaced file has one effective entry")
    effective = {}
    for path, rows in rows_by_path.items():
        adopted = read(path)
        raw = apply_replacements(adopted.decode("utf-8"), rows).encode("utf-8")
        entry = errata["effective"][path]
        require(digest(raw) == entry["sha256"], "effective digest differs: " + path)
        if entry["kind"] == "PUBLISHED":
            require(entry["file"] == ERRATA_DIR + "effective/" + path.split("/", 1)[1] and read(entry["file"]) == raw,
                    "effective file differs: " + path)
            if path.endswith(".json"):
                parse(raw)
        else:
            require(entry == {"kind": "COMMENT_ONLY", "sha256": entry["sha256"]} and path.endswith(".py")
                    and ast.dump(ast.parse(raw)) == ast.dump(ast.parse(adopted)),
                    "model replacement changes more than comments: " + path)
        effective[path] = raw
    return effective


def _apply(value: Any, ops: list) -> Any:
    value = copy.deepcopy(value)
    for op in ops:
        require(op["op"] == "set", "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        node[last] = copy.deepcopy(op["value"])
    return value


def replay_vectors(vectors: Any, read: Callable[[str], bytes]) -> int:
    """Every added record case replays to its pinned result through the unchanged native v3 model."""
    require(type(vectors) is dict and vectors.get("schemaVersion") == VECTORS_SCHEMA
            and vectors.get("evidenceClass") == "DATA_CHECK_ONLY" and vectors.get("nativeAcceptance") is False,
            "not a native v3 errata vector file")
    source = read(NATIVE_VECTORS)
    require(vectors["positiveSource"] == {"path": NATIVE_VECTORS, "sha256": digest(source)}
            and vectors["model"] == {"path": NATIVE_MODEL, "sha256": NATIVE_MODEL_SHA256}
            and digest(read(NATIVE_MODEL)) == NATIVE_MODEL_SHA256, "errata vectors bound to the adopted v3 vectors and model")
    adopted = parse(source)
    schema = parse(read("architecture/native-profile-v3/qualification.schema.json"))
    require(digest(native.canonical(schema)) == native.SCHEMA_SHA256 == adopted["schemaSha256"], "v3 schema pin")
    ids = [row["id"] for kind in ("negative", "accepted") for row in vectors[kind]]
    require(len(ids) == len(set(ids)) and not set(ids) & {row["id"] for kind in ("negative", "accepted")
                                                          for row in adopted[kind]}, "errata vector ids are new")
    checks = 0
    for kind in ("negative", "accepted"):
        for row in vectors[kind]:
            require(row["target"] == "record", "closed vector target")
            p = adopted["positive"][row["positive"]]
            record = _apply(p["record"], row["ops"])
            result = native.explain(native.check_record, record, p["profile"], p["endpoints"], schema)
            require(result == (row["refusal"] if kind == "negative" else None), "%s vector %s" % (kind, row["id"]))
            checks += 1
    return checks
