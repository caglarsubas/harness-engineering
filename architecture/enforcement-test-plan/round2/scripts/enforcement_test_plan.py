#!/usr/bin/env python3
"""W04-0: the independent enforcement test plan (traceability record) and the observation-window register schema.

DATA_CHECK_ONLY. The plan maps the eight test groups (TG-01..TG-08, the later verification matrix T01-T08 of the W01
review brief) to the twelve enforcement obligations E01-E12, the adopted W02 contract inputs and source documents (by path
and sha256), the acceptance items A01-A09, the packets that write the tests (W04-1..W04-7) and the phase that may run each
case (W04 offline, after W05's release set, or only in W06's native campaign). It writes no test and runs nothing.

check(read) validates the plan and the schema through an injected byte reader. Beyond shape, it checks content against
the pinned sources: each group carries the matrix row's exact cases and evidence class, each obligation the resolved
specification's section 8 gate map, each acceptance item the design document's exact evidence text; native evidence never
runs before W06; the contract inputs are exactly the adopted set, pinned to their bytes; and the window schema forces an
exhaustive register over a stated boundary inventory.
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
BRIEF = "architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md"
SPEC = "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md"
DESIGN = "docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md"
SOURCES = (BRIEF, SPEC, DESIGN, "docs/alpha-2/ENFORCEMENT_FEASIBILITY.md", "docs/alpha-2/ENFORCEMENT_INTEGRATION.md",
           "architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md")
SELECTION = "architecture/backend-distribution/selection.json"
GROUPS = tuple("TG-%02d" % n for n in range(1, 9))
ROWS = tuple("E%02d" % n for n in range(1, 13))
ACCEPTANCE = tuple("A%02d" % n for n in range(1, 10))
PACKETS = tuple("W04-%d" % n for n in range(0, 8))
PHASES = ("W04_OFFLINE", "AFTER_W05_RELEASE_SET", "W06_NATIVE_ONLY")
# The matrix's evidence-class cell for each group, and the record's label for it.
EVIDENCE = {"Offline contract data tests": "OFFLINE_CONTRACT",
            "Source tests of actual owner implementations": "SOURCE_OWNER_IMPLEMENTATION",
            "Real multi-process/storage fault tests": "SOURCE_MULTIPROCESS_FAULT",
            "Independently authorized native Linux tests": "NATIVE_HOST",
            "Independent native lifetime tests": "NATIVE_LIFETIME",
            "Exact selected backend integration tests": "BACKEND_INTEGRATION",
            "Native integration plus retained resource evidence": "NATIVE_INTEGRATION",
            "Source and installed migration tests separately": "SOURCE_AND_INSTALLED_MIGRATION"}
# Evidence classes that need the installed, enrolled host: every case runs only in W06.
NATIVE_CLASSES = {"NATIVE_HOST", "NATIVE_LIFETIME", "NATIVE_INTEGRATION", "BACKEND_INTEGRATION"}
# Resolved specification section 8: gate-to-row map (E02 and E09 are untouched by the gates).
GATE_MAP = {"G04": ("E03", "E04", "E05", "E10"), "G05": ("E10", "E11", "E12"), "G06": ("E07",),
            "G07": ("E01", "E03", "E04", "E05", "E06", "E07", "E08", "E12"), "G09": ("E10",)}
GATE_SENTENCE = ("G04 → E03, E04, E05, E10;\n  G05 → E10, E11, E12; G06 → E07; G07 → E01, E03, E04, E05, E06, E07, E08, E12;\n"
                 "  G09 → E10.")
# The adopted contract set the tests consume (no superseded version).
CONTRACTS = {"I05 gate channel v3": "architecture/i05-gate-channel-v3/",
             "I06 backend profile v2": "architecture/i06-backend-profile-v2/",
             "I07 policy write v3": "architecture/i07-policy-write-v3/",
             "Admission semantics v3": "architecture/admission-semantics-v3/",
             "Native qualification profile v3": "architecture/native-profile-v3/",
             "SELinux matrix v4": "architecture/selinux-matrix-v2/",
             "Seccomp allowlists v2": "architecture/seccomp-allowlists-v2/",
             "W01 amendment W02D": "architecture/host-interface-amendment-w02d/"}
ADOPTED_STATES = ("ADOPTED_DATA_CONTRACT", "ADOPTED_AMENDMENT")
NOT_CLAIMED = ("No test is written or run; W04-1..W04-7 write them.",
               "No native evidence; every native case runs only in W06.",
               "E01-E12 stay OPEN_UNPROVEN.",
               "The observation-window register is not filled; W04-7 fills it at the exact candidate revision.")
ATTESTATION = ["packet", "lane", "inputs", "inputDigests", "r10SourceRead", "w03WorkInProgressRead",
               "implementationReadOrRunForExpectedResults", "reviewer"]
WINDOW_ID = "^OW-[0-9]{2,3}$"
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


def _table_row(text: str, first_cell: str) -> list:
    """The cells of the markdown table row whose first cell is exactly first_cell."""
    rows = [line for line in text.splitlines() if line.startswith("| " + first_cell + " |")]
    require(len(rows) == 1, "one source table row for " + first_cell)
    return [cell.strip() for cell in rows[0].strip().strip("|").split("|")]


def _pinned(item: Any, read: Callable[[str], bytes], message: str) -> None:
    _closed(item, {"path", "sha256"}, "closed pin")
    require(type(item["path"]) is str and type(item["sha256"]) is str and SHA256.match(item["sha256"]) is not None
            and digest(read(item["path"])) == item["sha256"], message + ": " + str(item.get("path")))


def check_plan(plan: Any, read: Callable[[str], bytes]) -> None:
    _closed(plan, {"schemaVersion", "planLabel", "repository", "independence", "sources", "w03Inputs", "contracts",
                   "testGroups", "obligations", "acceptance", "packets", "observationWindows", "ownerDecisions",
                   "notClaimed"}, "closed test plan")
    require(plan["schemaVersion"] == SCHEMA and plan["planLabel"] == "W04-0", "plan schema and label")
    repo = plan["repository"]
    _closed(repo, {"id", "name", "remote", "visibility", "currentVerification", "verificationDecision"}, "closed repository record")
    require(repo["id"] == "R12" and repo["name"] == "mas-harness-conformance-labs"
            and repo["remote"] == "https://github.com/caglarsubas/mas-harness-conformance-labs" and _text(repo["visibility"])
            and _text(repo["currentVerification"]) and _text(repo["verificationDecision"]), "R12 repository record")
    independence = plan["independence"]
    _closed(independence, {"rules", "attestationFields"}, "closed independence record")
    require(type(independence["rules"]) is list and len(independence["rules"]) >= 7 and all(_text(r) for r in independence["rules"])
            and independence["attestationFields"] == ATTESTATION, "independence rules and attestation")
    # Pinned source documents and the one allowed W03 record.
    require(type(plan["sources"]) is list and [s.get("path") for s in plan["sources"] if type(s) is dict] == list(SOURCES),
            "the pinned source documents")
    for item in plan["sources"]:
        _pinned(item, read, "source document bytes")
    texts = {item["path"]: read(item["path"]).decode("utf-8") for item in plan["sources"]}
    require(type(plan["w03Inputs"]) is list and len(plan["w03Inputs"]) == 1, "exactly one W03 input")
    _pinned(plan["w03Inputs"][0], read, "W03 selection record bytes")
    require(plan["w03Inputs"][0]["path"] == SELECTION, "the W03 input is the distribution selection record")
    # Contract inputs: exactly the adopted set, every file pinned to its bytes.
    contracts = plan["contracts"]
    require(type(contracts) is list and [c.get("name") for c in contracts if type(c) is dict] == list(CONTRACTS),
            "exactly the adopted contract inputs")
    for row in contracts:
        _closed(row, {"name", "state", "files"}, "closed contract input")
        directory = CONTRACTS[row["name"]]
        require(row["state"] in ADOPTED_STATES and parse(read(directory + "status.json")).get("contractState") == row["state"],
                "adopted contract state: " + row["name"])
        require(type(row["files"]) is list and row["files"] and any(f.get("path") == directory + "status.json" for f in row["files"]
                                                                       if type(f) is dict), "contract files " + row["name"])
        for item in row["files"]:
            _pinned(item, read, "contract input bytes")
    names = tuple(CONTRACTS)
    # Test groups: matrix row content, case phases, sources, obligations.
    groups = plan["testGroups"]
    require(type(groups) is list and all(type(g) is dict for g in groups) and [g.get("id") for g in groups] == list(GROUPS),
            "the eight test groups")
    for g in groups:
        _closed(g, {"id", "from", "title", "matrix", "evidenceClass", "cases", "obligations", "contracts", "acceptance",
                    "blockedBy", "packet", "r12Location"}, "closed test group " + g["id"])
        t = "T%02d" % int(g["id"][3:])
        row = _table_row(texts[BRIEF], t + " " + g["title"])
        require(g["from"] == t and _closed_matrix(g["matrix"]) and g["matrix"] == {"cases": row[1], "evidence": row[2]}
                and g["evidenceClass"] == EVIDENCE.get(row[2]), "test group %s carries its matrix row exactly" % g["id"])
        require(type(g["cases"]) is list and g["cases"] and all(type(c) is dict for c in g["cases"]), "cases " + g["id"])
        for c in g["cases"]:
            _closed(c, {"case", "source", "phase", "obligations"}, "closed case in " + g["id"])
            require(_text(c["case"]) and _text(c["source"]) and c["phase"] in PHASES and _ids(c["obligations"], ROWS)
                    and c["obligations"] and set(c["obligations"]) <= set(g["obligations"]), "case in %s: %s" % (g["id"], c.get("case")))
            if g["evidenceClass"] in NATIVE_CLASSES:
                require(c["phase"] == "W06_NATIVE_ONLY", "native evidence runs only in W06: " + g["id"])
        require(any(c["source"].startswith(BRIEF) for c in g["cases"]), "group %s cites its matrix row" % g["id"])
        require(_ids(g["obligations"], ROWS) and g["obligations"]
                and set(g["obligations"]) == {o for c in g["cases"] for o in c["obligations"]},
                "group %s obligations are exactly its cases' obligations" % g["id"])
        require(_ids(g["contracts"], names) and g["contracts"] and _ids(g["acceptance"], ACCEPTANCE)
                and type(g["blockedBy"]) is list and all(_text(b) for b in g["blockedBy"])
                and g["packet"] in PACKETS[2:7] and _text(g["r12Location"]), "test group references " + g["id"])
    # Obligations: gate map, coverage, W04/W06 text derived from the case phases.
    require(GATE_SENTENCE in texts[SPEC], "the section 8 gate map sentence")
    rows = plan["obligations"]
    require(type(rows) is list and all(type(r) is dict for r in rows) and [r.get("id") for r in rows] == list(ROWS),
            "the twelve obligations")
    for r in rows:
        _closed(r, {"id", "theme", "gates", "testGroups", "w04", "w06"}, "closed obligation " + r["id"])
        gates = sorted(gate for gate, covered in GATE_MAP.items() if r["id"] in covered)
        require(_text(r["theme"]) and r["gates"] == gates, "obligation %s carries the section 8 gates" % r["id"])
        expected = [g["id"] for g in groups if r["id"] in g["obligations"]]
        require(r["testGroups"] == expected and expected, "obligation %s is covered by exactly the groups that test it" % r["id"])
        early = sorted({g["id"] for g in groups for c in g["cases"] if r["id"] in c["obligations"] and c["phase"] != "W06_NATIVE_ONLY"})
        native = sorted({g["id"] for g in groups for c in g["cases"] if r["id"] in c["obligations"] and c["phase"] == "W06_NATIVE_ONLY"})
        require(r["w04"] == _w04_text(expected, early) and r["w06"] == _w06_text(native),
                "obligation %s states the W04/W06 split of its cases" % r["id"])
    # Acceptance items: exact design-document text; A01 the register; A07-A09 outside W04.
    acceptance = plan["acceptance"]
    require(type(acceptance) is list and all(type(a) is dict for a in acceptance) and [a.get("id") for a in acceptance] == list(ACCEPTANCE),
            "A01-A09")
    for a in acceptance:
        _closed(a, {"id", "evidence", "testGroups", "observationWindows", "outsideW04"}, "closed acceptance item")
        cells = _table_row(texts[DESIGN], a["id"])
        require(a["evidence"] == cells[1], "acceptance %s carries the design document's text" % a["id"])
        require(a["testGroups"] == [g["id"] for g in groups if a["id"] in g["acceptance"]], "acceptance %s groups" % a["id"])
        require(a["observationWindows"] is (a["id"] == "A01"), "only A01 is the window register")
        if a["id"] in ("A07", "A08", "A09"):
            require(a["testGroups"] == [] and _text(a["outsideW04"]), "acceptance %s is outside W04's test groups" % a["id"])
        else:
            require(a["outsideW04"] is None and (a["testGroups"] or a["observationWindows"]), "acceptance %s is in W04" % a["id"])
    packets = plan["packets"]
    require(type(packets) is list and all(type(p) is dict for p in packets) and [p.get("id") for p in packets] == list(PACKETS),
            "W04-0..W04-7")
    for p in packets:
        _closed(p, {"id", "repository", "content", "earliest"}, "closed packet")
        require(_text(p["content"]) and _text(p["earliest"]), "packet " + p["id"])
    require([p["repository"] for p in packets] == ["harness-onion"] + ["mas-harness-conformance-labs"] * 6 + ["harness-onion"],
            "W04-0 and W04-7 are harness-onion records; W04-1..W04-6 are R12 source")
    windows = plan["observationWindows"]
    _closed(windows, {"schema", "register", "state", "fillAt", "candidate"}, "closed observation-window entry")
    require(windows["schema"] == WINDOWS_SCHEMA_PATH and windows["register"] is None and windows["state"] == "SCHEMA_ONLY"
            and windows["fillAt"] == "W04-7" and _text(windows["candidate"]), "the register is only specified here; W04-7 fills it")
    decisions = plan["ownerDecisions"]
    require(type(decisions) is list and all(type(d) is dict for d in decisions)
            and [d.get("id") for d in decisions] == ["D-R12", "D-TOOL", "D-MAP", "D-OW", "D-ID"], "the W04 plan owner decisions")
    for d in decisions:
        _closed(d, {"id", "selected", "date", "decision"}, "closed owner decision")
        require(_text(d["selected"]) and _text(d["date"]) and _text(d["decision"]), "owner decision " + d["id"])
    require(plan["notClaimed"] == list(NOT_CLAIMED), "the stated non-claims")


def _closed_matrix(value: Any) -> bool:
    return type(value) is dict and set(value) == {"cases", "evidence"}


def _w04_text(groups: list, early: list) -> str:
    return "Writes the test source of %s; runs %s before W06." % (", ".join(groups), ", ".join(early) or "none of it")


def _w06_text(native: list) -> str:
    return ("Runs the native cases of %s on the enrolled AMD64 and ARM64 hosts and records the evidence." % ", ".join(native)
            if native else "No native case; W04's source evidence stands for this row until W07.")


def check_window_schema(schema: Any) -> None:
    """The register schema demands an exhaustive register over a stated boundary inventory of one exact candidate
    revision; every window names its boundary, the call removed or moved, the nested checks it took, its protected facts,
    trace positions, lost window, exclusion proof, the state keeping fresh checks, latency, rows and tests."""
    _closed(schema, {"$schema", "$id", "title", "type", "additionalProperties", "required", "properties"}, "closed window schema")
    require(schema["$id"] == WINDOW_SCHEMA and schema["type"] == "object" and schema["additionalProperties"] is False,
            "window schema identity")
    props = schema["properties"]
    top = {"schemaVersion", "candidateRepository", "candidateRevision", "exhaustive", "boundaryInventory", "windows"}
    require(set(schema["required"]) == set(props) == top and props["exhaustive"] == {"const": True}
            and props["schemaVersion"] == {"const": WINDOW_SCHEMA}
            and props["candidateRevision"].get("pattern") == "^[0-9a-f]{40}$"
            and props["boundaryInventory"].get("minItems") == 1 and props["windows"].get("minItems") == 1,
            "an exhaustive, non-empty register over a boundary inventory of one exact candidate revision")
    item = props["windows"].get("items", {})
    required = {"id", "kind", "boundary", "parentWindow", "removedOrMovedCall", "nestedChecksRemoved", "protectedFacts",
                "oldTracePosition", "newTracePosition", "lostWindow", "exclusionProof", "stateKeepingFreshChecks",
                "autonomousEventLatency", "obligations", "tests"}
    require(props["windows"].get("type") == "array" and item.get("type") == "object" and item.get("additionalProperties") is False
            and set(item.get("required", [])) == required == set(item.get("properties", {}))
            and item["properties"]["id"].get("pattern") == WINDOW_ID
            and item["properties"]["kind"].get("enum") == ["DIRECT", "INDIRECT"], "closed window entries")


def check_register(register: Any, schema: Any) -> None:
    """What the schema cannot say: unique window ids, every inventory boundary covered, every INDIRECT window naming an
    existing parent. W04-7 runs this on the filled register."""
    require(type(register) is dict and type(register.get("windows")) is list and type(register.get("boundaryInventory")) is list,
            "register shape")
    ids = [w.get("id") for w in register["windows"] if type(w) is dict]
    require(len(ids) == len(set(ids)) == len(register["windows"]) and all(type(i) is str and re.fullmatch(WINDOW_ID, i) for i in ids),
            "unique, anchored window ids")
    require({w.get("boundary") for w in register["windows"]} == set(register["boundaryInventory"]), "every boundary has a window")
    for w in register["windows"]:
        require((w.get("kind") == "INDIRECT") == (w.get("parentWindow") is not None)
                and (w.get("parentWindow") is None or w["parentWindow"] in ids), "indirect windows name their parent")


def check(read: Callable[[str], bytes]) -> dict:
    plan = parse(read(PLAN_PATH))
    check_plan(plan, read)
    check_window_schema(parse(read(WINDOWS_SCHEMA_PATH)))
    return plan
