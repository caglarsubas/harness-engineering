#!/usr/bin/env python3
"""W04-0: the independent enforcement test plan (traceability record) and the observation-window register schema.

DATA_CHECK_ONLY. The plan maps the eight test groups (TG-01..TG-08, the later verification matrix T01-T08 of the W01
review brief) to the twelve enforcement obligations E01-E12, the adopted W02 contract inputs (by path and sha256), the
acceptance items A01-A09, the packets that write them (W04-1..W04-7 in R12 and harness-onion) and the phase that may run
them (W04 offline, after W05's release set, or only in W06's native campaign). It writes no test and runs nothing.

check(read) validates the plan and the schema through an injected byte reader: closed shapes, unique ids in their own
namespaces (TG-nn, OW-nn), every E row covered or explicitly placed outside the test groups, native evidence never
assigned to a W04 run, and every contract input digest equal to the bytes it names.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

SCHEMA = "planeon.internal.enforcement-test-plan/v1"
WINDOW_SCHEMA = "planeon.internal.observation-windows/v1"
PLAN_PATH = "architecture/enforcement-test-plan/traceability.json"
WINDOWS_SCHEMA_PATH = "architecture/enforcement-test-plan/observation-windows.schema.json"
GROUPS = tuple("TG-%02d" % n for n in range(1, 9))
ROWS = tuple("E%02d" % n for n in range(1, 13))
ACCEPTANCE = tuple("A%02d" % n for n in range(1, 10))
PACKETS = tuple("W04-%d" % n for n in range(0, 8))
EVIDENCE = ("OFFLINE_CONTRACT", "SOURCE_OWNER_IMPLEMENTATION", "SOURCE_MULTIPROCESS_FAULT", "NATIVE_HOST",
            "NATIVE_LIFETIME", "BACKEND_INTEGRATION", "NATIVE_INTEGRATION", "SOURCE_AND_INSTALLED_MIGRATION")
PHASES = ("W04_OFFLINE", "AFTER_W05_RELEASE_SET", "W06_NATIVE_ONLY")
# Evidence classes that need the installed, enrolled host: never runnable before W06.
NATIVE_CLASSES = {"NATIVE_HOST", "NATIVE_LIFETIME", "NATIVE_INTEGRATION", "BACKEND_INTEGRATION"}
WINDOW_ID = re.compile(r"OW-\d{2,3}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate member: " + key)
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite number")

    require(type(raw) is bytes, "bytes required")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _ids(value: Any, allowed: tuple) -> bool:
    return (type(value) is list and all(type(v) is str for v in value) and len(set(value)) == len(value)
            and set(value) <= set(allowed))


def _closed(value: Any, keys: set, message: str) -> None:
    require(type(value) is dict and set(value) == keys, message)


def check_plan(plan: Any, read: Callable[[str], bytes]) -> None:
    _closed(plan, {"schemaVersion", "planLabel", "repository", "independence", "contracts", "testGroups", "obligations",
                   "acceptance", "packets", "observationWindows", "ownerDecisions", "notClaimed"}, "closed test plan")
    require(plan["schemaVersion"] == SCHEMA and plan["planLabel"] == "W04-0", "plan schema and label")
    repo = plan["repository"]
    _closed(repo, {"id", "name", "remote", "visibility", "currentVerification", "verificationDecision"}, "closed repository record")
    require(repo["id"] == "R12" and repo["name"] == "mas-harness-conformance-labs"
            and repo["remote"] == "https://github.com/caglarsubas/mas-harness-conformance-labs" and _text(repo["visibility"])
            and _text(repo["currentVerification"]) and _text(repo["verificationDecision"]), "R12 repository record")
    independence = plan["independence"]
    _closed(independence, {"rules", "attestationFields"}, "closed independence record")
    require(type(independence["rules"]) is list and len(independence["rules"]) >= 5 and all(_text(r) for r in independence["rules"])
            and independence["attestationFields"] == ["packet", "inputs", "r10SourceRead", "w03WorkInProgressRead", "reviewer"],
            "independence rules and attestation")
    contracts = plan["contracts"]
    require(type(contracts) is list and contracts, "contract inputs")
    names = []
    for row in contracts:
        _closed(row, {"name", "state", "files"}, "closed contract input")
        require(_text(row["name"]) and row["name"] not in names and row["state"] in ("ADOPTED_DATA_CONTRACT", "ADOPTED_AMENDMENT"),
                "adopted contract input " + str(row.get("name")))
        names.append(row["name"])
        require(type(row["files"]) is list and row["files"], "contract files " + row["name"])
        for item in row["files"]:
            _closed(item, {"path", "sha256"}, "closed contract file")
            require(type(item["path"]) is str and SHA256.match(str(item["sha256"])) is not None
                    and digest(read(item["path"])) == item["sha256"], "contract input bytes: " + str(item.get("path")))
    groups = plan["testGroups"]
    require(type(groups) is list and [g.get("id") for g in groups if type(g) is dict] == list(GROUPS), "the eight test groups")
    covered = set()
    for g in groups:
        _closed(g, {"id", "from", "title", "cases", "evidenceClass", "phases", "obligations", "contracts", "acceptance",
                    "packet", "r12Location"}, "closed test group " + g["id"])
        require(g["from"] == "T%02d" % int(g["id"][3:]) and _text(g["title"]) and type(g["cases"]) is list and g["cases"]
                and all(_text(c) for c in g["cases"]), "test group cases " + g["id"])
        require(g["evidenceClass"] in EVIDENCE and _ids(g["phases"], PHASES) and g["phases"]
                and _ids(g["obligations"], ROWS) and g["obligations"] and _ids(g["contracts"], tuple(names))
                and _ids(g["acceptance"], ACCEPTANCE) and g["packet"] in PACKETS[1:7] and _text(g["r12Location"]),
                "test group references " + g["id"])
        if g["evidenceClass"] in NATIVE_CLASSES:
            require(g["phases"] == ["W06_NATIVE_ONLY"], "native evidence runs only in W06: " + g["id"])
        covered |= set(g["obligations"])
    rows = plan["obligations"]
    require(type(rows) is list and [r.get("id") for r in rows if type(r) is dict] == list(ROWS), "the twelve obligations")
    for r in rows:
        _closed(r, {"id", "theme", "gates", "testGroups", "outsideTestGroups", "w04", "w06"}, "closed obligation " + r["id"])
        require(_text(r["theme"]) and _ids(r["testGroups"], GROUPS) and type(r["gates"]) is list
                and all(g in ("G04", "G05", "G06", "G07", "G09") for g in r["gates"]) and _text(r["w04"]) and _text(r["w06"]),
                "obligation " + r["id"])
        expected = sorted(g["id"] for g in groups if r["id"] in g["obligations"])
        require(sorted(r["testGroups"]) == expected, "obligation %s lists exactly the groups that cover it" % r["id"])
        require(bool(r["testGroups"]) or _text(r["outsideTestGroups"]),
                "obligation %s is covered by a test group or explicitly placed outside them" % r["id"])
        require(r["outsideTestGroups"] is None or _text(r["outsideTestGroups"]), "outside-groups note " + r["id"])
    acceptance = plan["acceptance"]
    require(type(acceptance) is list and [a.get("id") for a in acceptance if type(a) is dict] == list(ACCEPTANCE), "A01-A09")
    for a in acceptance:
        _closed(a, {"id", "evidence", "testGroups", "observationWindows", "outsideW04"}, "closed acceptance item")
        require(_text(a["evidence"]) and _ids(a["testGroups"], GROUPS) and type(a["observationWindows"]) is bool
                and (a["testGroups"] or a["observationWindows"] or _text(a["outsideW04"])), "acceptance " + a["id"])
    require(any(a["id"] == "A01" and a["observationWindows"] for a in acceptance), "A01 is the lost-window register")
    packets = plan["packets"]
    require(type(packets) is list and [p.get("id") for p in packets if type(p) is dict] == list(PACKETS), "W04-0..W04-7")
    for p in packets:
        _closed(p, {"id", "repository", "content", "earliest"}, "closed packet")
        require(p["repository"] in ("harness-onion", "mas-harness-conformance-labs") and _text(p["content"]) and _text(p["earliest"]),
                "packet " + p["id"])
    require([p["repository"] for p in packets] == ["harness-onion"] + ["mas-harness-conformance-labs"] * 6 + ["harness-onion"],
            "W04-0 and W04-7 are harness-onion records; W04-1..W04-6 are R12 source")
    windows = plan["observationWindows"]
    _closed(windows, {"schema", "register", "state", "fillAt"}, "closed observation-window entry")
    require(windows == {"schema": WINDOWS_SCHEMA_PATH, "register": None, "state": "SCHEMA_ONLY", "fillAt": "W04-7"},
            "the register is only specified here; W04-7 fills it")
    decisions = plan["ownerDecisions"]
    require(type(decisions) is list and [d.get("id") for d in decisions if type(d) is dict]
            == ["D-R12", "D-TOOL", "D-MAP", "D-OW", "D-ID"], "the W04 plan owner decisions")
    for d in decisions:
        _closed(d, {"id", "selected", "date", "decision"}, "closed owner decision")
        require(_text(d["selected"]) and _text(d["date"]) and _text(d["decision"]), "owner decision " + d["id"])
    require(type(plan["notClaimed"]) is list and len(plan["notClaimed"]) >= 3 and all(_text(n) for n in plan["notClaimed"]),
            "stated non-claims")


def check_window_schema(schema: Any) -> None:
    """The register schema demands an exhaustive register whose every window names its protected facts, old and new trace
    positions, lost window, exclusion proof, direct or indirect kind and autonomous-event latency."""
    _closed(schema, {"$schema", "$id", "title", "type", "additionalProperties", "required", "properties"}, "closed window schema")
    require(schema["$id"] == WINDOW_SCHEMA and schema["type"] == "object" and schema["additionalProperties"] is False,
            "window schema identity")
    props = schema["properties"]
    require(set(schema["required"]) == set(props) == {"schemaVersion", "candidateRevision", "exhaustive", "windows"}
            and props["exhaustive"] == {"const": True} and props["schemaVersion"] == {"const": WINDOW_SCHEMA},
            "an exhaustive register for one exact candidate revision")
    item = props["windows"].get("items", {})
    required = {"id", "kind", "protectedFacts", "oldTracePosition", "newTracePosition", "lostWindow", "exclusionProof",
                "autonomousEventLatency", "obligations", "tests"}
    require(props["windows"].get("type") == "array" and item.get("type") == "object" and item.get("additionalProperties") is False
            and set(item.get("required", [])) == required == set(item.get("properties", {}))
            and item["properties"]["id"].get("pattern") == WINDOW_ID.pattern.replace("\\Z", "$")
            and item["properties"]["kind"].get("enum") == ["DIRECT", "INDIRECT"], "closed window entries")


def check(read: Callable[[str], bytes]) -> dict:
    plan = parse(read(PLAN_PATH))
    check_plan(plan, read)
    check_window_schema(parse(read(WINDOWS_SCHEMA_PATH)))
    return plan
