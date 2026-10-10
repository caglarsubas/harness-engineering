#!/usr/bin/env python3
"""W04-0: the independent enforcement test plan (traceability record) and the observation-window register schema.

DATA_CHECK_ONLY. The plan maps the eight test groups (TG-01..TG-08, the later verification matrix T01-T08 of the W01
review brief) to the twelve enforcement obligations E01-E12, the adopted W02 contract inputs and source documents (by path
and sha256), the acceptance items A01-A09, the packets that write the tests (W04-1..W04-7) and the phase that may run each
case (W04 offline, after W05's release set, or only in W06's native campaign). It writes no test and runs nothing.

check(read) validates the plan and the schema through an injected byte reader. Every case carries a tag naming the source
item it answers. The model requires each matrix phrase (derived from the pinned brief's row), each counterexample 18-28,
each section 8 native item, the section 6.3 residual, the section 4.4 vectors, the ledger items and the W01 amendment's
native confirmations as cases in their group and phase; checks the matrix evidence class, the section 8 gate map and the
design document's acceptance text against the pinned sources; pins the contract file lists, the independence rules, the
packet map and the observation-window binding exactly; and requires the window schema to equal the one it builds.
check_register validates a filled register against that schema and the rules a schema cannot state.
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
LEDGER = "docs/alpha-2/ENFORCEMENT_FEASIBILITY.md"
INTEGRATION = "docs/alpha-2/ENFORCEMENT_INTEGRATION.md"
AMENDMENT = "architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md"
SOURCES = (BRIEF, SPEC, DESIGN, LEDGER, INTEGRATION, AMENDMENT)
SELECTION = {"path": "architecture/backend-distribution/selection.json", "commit": "104b11529b6448a2c208450e5fbbd677e5dd8069",
             "reviewState": "reviewed W03 record named by the owner via the lane monitor; on main from packet 221 (MET-ENFORCE-019)"}
GROUPS = tuple("TG-%02d" % n for n in range(1, 9))
TITLES = ("contract", "lifecycle", "persistence", "host", "clocks", "API/writers", "cleanup", "compatibility")
ROWS = tuple("E%02d" % n for n in range(1, 13))
ACCEPTANCE = tuple("A%02d" % n for n in range(1, 10))
PACKETS = tuple("W04-%d" % n for n in range(0, 8))
W4, W5, W6 = PHASES = ("W04_OFFLINE", "AFTER_W05_RELEASE_SET", "W06_NATIVE_ONLY")
EVIDENCE = {"Offline contract data tests": "OFFLINE_CONTRACT",
            "Source tests of actual owner implementations": "SOURCE_OWNER_IMPLEMENTATION",
            "Real multi-process/storage fault tests": "SOURCE_MULTIPROCESS_FAULT",
            "Independently authorized native Linux tests": "NATIVE_HOST",
            "Independent native lifetime tests": "NATIVE_LIFETIME",
            "Exact selected backend integration tests": "BACKEND_INTEGRATION",
            "Native integration plus retained resource evidence": "NATIVE_INTEGRATION",
            "Source and installed migration tests separately": "SOURCE_AND_INSTALLED_MIGRATION"}
# The phases a matrix case may take, by evidence class: offline contract data now; owner implementations and fault tests
# only against W05's release (never W03 source); native classes only in W06; migration source after W05, installed in W06.
MATRIX_PHASES = {"OFFLINE_CONTRACT": {W4}, "SOURCE_OWNER_IMPLEMENTATION": {W5}, "SOURCE_MULTIPROCESS_FAULT": {W5},
                 "NATIVE_HOST": {W6}, "NATIVE_LIFETIME": {W6}, "BACKEND_INTEGRATION": {W6}, "NATIVE_INTEGRATION": {W6},
                 "SOURCE_AND_INSTALLED_MIGRATION": {W5, W6}}
NATIVE_CLASSES = {"NATIVE_HOST", "NATIVE_LIFETIME", "NATIVE_INTEGRATION", "BACKEND_INTEGRATION"}
GATE_MAP = {"G04": ("E03", "E04", "E05", "E10"), "G05": ("E10", "E11", "E12"), "G06": ("E07",),
            "G07": ("E01", "E03", "E04", "E05", "E06", "E07", "E08", "E12"), "G09": ("E10",)}
GATE_SENTENCE = ("G04 → E03, E04, E05, E10;\n  G05 → E10, E11, E12; G06 → E07; G07 → E01, E03, E04, E05, E06, E07, E08, E12;\n"
                 "  G09 → E10.")
# Tagged items beyond the matrix: tag -> (groups, phase, text that must be in the named source).
COUNTEREXAMPLES = {18: ("TG-02", W5), 19: ("TG-04", W6), 20: ("TG-06", W6), 21: ("TG-03", W5), 22: ("TG-02", W5),
                   23: ("TG-01", W4), 24: ("TG-06", W6), 25: ("TG-04", W6), 26: ("TG-06", W6), 27: ("TG-04", W6),
                   28: ("TG-04", W6)}
REQUIRED = {
    "S8-CLOSURE": (("TG-04", "TG-06"), W6, SPEC, "completeness of the §2 closure on a real host"),
    "S8-KERNEL-FACTS": (("TG-04",), W6, SPEC, "whether the §5.1 kernel facts hold on the enrolled kernel and policy"),
    "S8-POLICYLOAD": (("TG-04",), W6, SPEC, "`secure_mode_policyload` conditionals in the pinned binary policy"),
    "S8-FREEZE": (("TG-04", "TG-05"), W6, SPEC, "freeze-before-user-space under CLONE_INTO_CGROUP on the enrolled kernel (T04/T05)"),
    "S8-C2C3": (("TG-02", "TG-03"), W6, SPEC, "C2/C3 flush/stamp behaviour under load and restart (T02/T03)"),
    "S8-A2": (("TG-06",), W6, SPEC, "allowlists against real defaulting (T06)"),
    "S63-SOURCE": (("TG-02",), W5, SPEC, "It\nstays a T02 source case and a native case."),
    "S63-NATIVE": (("TG-02",), W6, SPEC, "It\nstays a T02 source case and a native case."),
    "S44": (("TG-08",), W4, SPEC, "### 4.4 Rejection vectors (T08 additions)"),
    "LEDGER-E01": (("TG-04",), W6, LEDGER, "Transient rename/restore, aliases, retained writers, relabel and mode changes"),
    "LEDGER-E02": (("TG-04",), W6, LEDGER, "Close/dup/reuse/inheritance/ancillary injection"),
    "LEDGER-E09": (("TG-02",), W4, LEDGER, "Reentrancy/wrong owner/partial construction/state corruption fail sticky; explicit trusted-code boundary"),
    "O-T04-AMEND": (("TG-04",), W6, AMENDMENT, "O-T04-AMEND (native confirmation)"),
    "CODEC": (("TG-01",), W5, BRIEF, "| T01 contract |"),
    "CONTRACT-DATA": (("TG-01",), W4, BRIEF, "| T01 contract |"),
    "INSTALLED": (("TG-08",), W6, BRIEF, "Source and installed migration tests separately"),
}
# A phrase each tagged case's text must carry, so a required case cannot be emptied.
KEYS = {"S8-CLOSURE": "section 2 closure", "S8-KERNEL-FACTS": "section 5.1 kernel facts", "S8-POLICYLOAD": "secure_mode_policyload",
        "S8-FREEZE": "CLONE_INTO_CGROUP", "S8-C2C3": "C2/C3", "S8-A2": "A2 field allowlists", "S63-SOURCE": "section 6.3 residual",
        "S63-NATIVE": "section 6.3 residual", "S44": "section 4.4 rejection vectors", "LEDGER-E01": "transient rename and restore",
        "LEDGER-E02": "ancillary injection", "LEDGER-E09": "explicit trusted-code boundary", "O-T04-AMEND": "Seccomp_filters: 2",
        "CODEC": "W05's released build", "CONTRACT-DATA": "replay offline", "INSTALLED": "installed host",
        "CE18": "RBAC", "CE19": "host containment", "CE20": "kubeconfig", "CE21": "gate restarts", "CE22": "connection K",
        "CE23": "WRITE_OBJECT", "CE24": "ClusterRole", "CE25": "datastore restore", "CE26": "CSR", "CE27": "GET_FD_BY_ID",
        "CE28": "O_PATH"}
# Per-group contract inputs, acceptance items and R12 locations, as reviewed.
GROUP_CONTRACTS = {"TG-01": ("I05 gate channel v3", "I06 backend profile v2", "I07 policy write v3", "Admission semantics v3", "Native qualification profile v3", "SELinux matrix v4", "Seccomp allowlists v2", "W01 amendment W02D"),
                   "TG-02": ("I05 gate channel v3", "I07 policy write v3", "Admission semantics v3"),
                   "TG-03": ("I05 gate channel v3", "I07 policy write v3"),
                   "TG-04": ("Native qualification profile v3", "SELinux matrix v4", "Seccomp allowlists v2", "W01 amendment W02D"),
                   "TG-05": ("I05 gate channel v3", "Native qualification profile v3", "W01 amendment W02D"),
                   "TG-06": ("I06 backend profile v2", "I07 policy write v3", "Admission semantics v3"),
                   "TG-07": ("I05 gate channel v3", "Native qualification profile v3", "W01 amendment W02D"),
                   "TG-08": ("I05 gate channel v3", "I06 backend profile v2", "Native qualification profile v3", "W01 amendment W02D")}
GROUP_ACCEPTANCE = {"TG-01": ("A06",), "TG-02": ("A02", "A05", "A06"), "TG-03": ("A05", "A06"), "TG-04": ("A03", "A04"),
                    "TG-05": ("A02", "A05"), "TG-06": ("A06",), "TG-07": ("A06",), "TG-08": ("A06",)}
GROUP_LOCATION = {"TG-01": "tests/enforcement/tg01_contract/", "TG-02": "tests/enforcement/tg02_lifecycle/",
                  "TG-03": "tests/enforcement/tg03_persistence/", "TG-04": "probes/enforcement/tg04_host/ (static Rust+musl probes)",
                  "TG-05": "probes/enforcement/tg05_clocks/ (static Rust+musl probes)",
                  "TG-06": "tests/enforcement/tg06_api_writers/ (against the selected Kubernetes v1.37.1 set)",
                  "TG-07": "tests/enforcement/tg07_cleanup/", "TG-08": "tests/enforcement/tg08_compatibility/ (source and installed parts kept separate)"}
# The original owner decisions, verbatim, and the pending clarification of D-OW.
DECISION_TEXT = {"D-R12": ("a", "W04 source lives in R12 mas-harness-conformance-labs; the owner sets up its verification route (the repository already exists)"),
                 "D-TOOL": ("a", "Python 3.12 + pytest for the source and offline groups; static Rust+musl probe binaries for the native TG-04/TG-05 probes"),
                 "D-MAP": ("accepted", "W04-0 defines the TG-to-E map; W04 delivers test source and the offline-runnable part; all native execution is W06's"),
                 "D-OW": ("accepted", "The observation-window register schema now (W04-0); the register is filled at the exact candidate revision in W04-7 after W05"),
                 "D-ID": ("accepted", "New ids TG-01..TG-08 and OW-nn, distinct from the I05 vector ids T001-T120 and the W01-W08 work labels")}
DECISION_STATES = ("ACCEPTED", "PENDING")
CONTRACTS = {"I05 gate channel v3": ("architecture/i05-gate-channel-v3/", ("channel.schema.json", "outcome-mapping.json", "vectors.json", "status.json"), "scripts/i05_gate_channel_v3.py"),
             "I06 backend profile v2": ("architecture/i06-backend-profile-v2/", ("criteria.json", "vectors.json", "status.json"), "scripts/i06_backend_profile_v2.py"),
             "I07 policy write v3": ("architecture/i07-policy-write-v3/", ("channel.schema.json", "policy-kinds.json", "vectors.json", "status.json"), "scripts/i07_policy_write_v3.py"),
             "Admission semantics v3": ("architecture/admission-semantics-v3/", ("allowlists.json", "admission-manifests/planeon-a2.json", "vectors.json", "status.json"), "scripts/admission_semantics_v3.py"),
             "Native qualification profile v3": ("architecture/native-profile-v3/", ("qualification.schema.json", "vectors.json", "status.json"), "scripts/native_qualification_v3.py"),
             "SELinux matrix v4": ("architecture/selinux-matrix-v2/", ("matrix.json", "vectors.json", "status.json"), "scripts/selinux_matrix_v2.py"),
             "Seccomp allowlists v2": ("architecture/seccomp-allowlists-v2/", ("syscalls.json", "allowlists.json", "vectors.json", "status.json"), "scripts/seccomp_allowlists_v2.py"),
             "W01 amendment W02D": ("architecture/host-interface-amendment-w02d/", ("amendment.json", "HOST_INTERFACE_SPEC.md", "status.json"), "scripts/host_interface_amendment.py")}
ADOPTED_STATES = ("ADOPTED_DATA_CONTRACT", "ADOPTED_AMENDMENT")
GROUP_PACKETS = {"TG-01": "W04-2", "TG-02": "W04-3", "TG-03": "W04-3", "TG-04": "W04-4", "TG-05": "W04-4", "TG-06": "W04-5",
                 "TG-07": "W04-5", "TG-08": "W04-6"}
BLOCKERS = {"D-W02A-F2": "a production W02a backend profile naming the selected components, their canonical paths, confined types and verity digests (selection open item; native qualification v3 has none yet); gates the W06 run of every native case, not the writing of its source",
            "D-SC01-PEER": "the I06 successor accepting etcd's single AF_UNIX peer listener (selection open item); gates the W06 run of TG-06's native cases"}
INDEPENDENCE = (
    "W04 source lives in R12, separate from W03's R10 operator repository; no source crosses (ENFORCEMENT_INTEGRATION.md:110-114).",
    "Only the parallel lane authors W04; W03's authors write no W04 source, and W04's authors read no W03 source or work in progress.",
    "Allowed W03 inputs are reviewed records the owner names (today only the distribution selection record, pinned in w03Inputs) and, later, W05's released artifact digests.",
    "Expected results come from the adopted contracts' reference models and vectors, never from reading or running the implementation; implementations are run only as the subject under test, from W05's release.",
    "Every W04 packet carries an independence attestation with the fields below, and its separate-agent reviewer checks it.",
    "R12 never implements or self-certifies the enforcement premise (ENFORCEMENT_INTEGRATION.md:93).",
    "The new toolchains stay in W04's enforcement test area; the stdlib-only R12 reader is not extended (ENFORCEMENT_INTEGRATION.md:100-102).",
    "Agents never send personal data in network requests, headers or queries.")
ATTESTATION = ["packet", "lane", "inputs", "inputDigests", "r10SourceRead", "w03WorkInProgressRead",
               "implementationReadOrRunForExpectedResults", "reviewer"]
WINDOWS = {"schema": WINDOWS_SCHEMA_PATH, "register": None, "state": "SCHEMA_ONLY", "fillAt": "W04-7",
           "subject": "the R12 observation reader (mas-harness-conformance-labs), which owns the observation calls (OBSERVATION_ENFORCEMENT_DESIGN.md:226)",
           "baseline": "the R12 accepted main revision the inventory is taken from, recorded in the register",
           "enforcementContext": "the exact R10 operator revision in W05's release set, which the exclusion proofs rely on",
           "removals": "null until W07's reader-successor candidate proposes them against this register"}
PACKET_TABLE = (
    ("W04-0", "harness-onion", "This traceability record and the observation-window register schema", "after packet 221 (MET-ENFORCE-019) merges, which brings the selection record to main"),
    ("W04-1", "mas-harness-conformance-labs", "Enforcement test area bootstrap: pinned Python 3.12 + pytest and Rust+musl toolchains kept out of the stdlib-only reader, offline CI gates, contract snapshots imported by sha256, the independence attestation", "after the owner's R12 verification route"),
    ("W04-2", "mas-harness-conformance-labs", "TG-01 contract tests", "after W04-1"),
    ("W04-3", "mas-harness-conformance-labs", "TG-02 and TG-03 lifecycle and persistence fault tests", "after W04-1"),
    ("W04-4", "mas-harness-conformance-labs", "TG-04 and TG-05 native probe source", "after W04-1"),
    ("W04-5", "mas-harness-conformance-labs", "TG-06 and TG-07 backend and cleanup integration tests", "after W04-1"),
    ("W04-6", "mas-harness-conformance-labs", "TG-08 compatibility and migration tests", "after W04-1"),
    ("W04-7", "harness-onion", "The exhaustive observation-window register of the R12 reader at its baseline, with W05's enforcement context, generated by a pinned inventory tool reviewed in the same packet and re-run by its reviewer", "after W05's release set"))
NOT_CLAIMED = ("No test is written or run; W04-1..W04-7 write them.",
               "No native evidence; every native case runs only in W06.",
               "E01-E12 stay OPEN_UNPROVEN.",
               "The observation-window register is not filled; W04-7 fills it at the R12 reader's baseline.")
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


def _read(read: Callable[[str], bytes], path: str) -> bytes:
    try:
        raw = read(path)
    except (OSError, KeyError) as exc:
        raise ValueError("missing input: " + path) from exc
    require(type(raw) is bytes, "bytes required: " + path)
    return raw


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _ids(value: Any, allowed: tuple) -> bool:
    return (type(value) is list and all(type(v) is str for v in value) and len(set(value)) == len(value)
            and set(value) <= set(allowed))


def _closed(value: Any, keys: set, message: str) -> None:
    require(type(value) is dict and set(value) == keys, message)


def _table_row(text: str, first_cell: str) -> list:
    rows = [line for line in text.splitlines() if line.startswith("| " + first_cell + " |")]
    require(len(rows) == 1, "one source table row for " + first_cell)
    return [cell.strip() for cell in rows[0].strip().strip("|").split("|")]


def matrix_phrases(cell: str) -> list:
    """The matrix cell's cases: comma-separated, the last pair joined by ' and '."""
    parts = cell.split(", ")
    return parts[:-1] + parts[-1].split(" and ")


def _pinned(item: Any, read: Callable[[str], bytes], keys: set, message: str) -> None:
    _closed(item, keys, "closed pin")
    require(type(item["path"]) is str and type(item["sha256"]) is str and SHA256.match(item["sha256"]) is not None
            and digest(_read(read, item["path"])) == item["sha256"], message + ": " + str(item.get("path")))


def _w04_text(groups: list, early: list) -> str:
    return "Writes the test source of %s; runs %s before W06." % (", ".join(groups), ", ".join(early) or "none of it")


def _w06_text(native: list) -> str:
    return ("Runs the native cases of %s on the enrolled AMD64 and ARM64 hosts and records the evidence." % ", ".join(native)
            if native else "No native case; W04's source evidence stands for this row until W07.")


def check_plan(plan: Any, read: Callable[[str], bytes]) -> None:
    _closed(plan, {"schemaVersion", "planLabel", "repository", "independence", "sources", "w03Inputs", "contracts",
                   "testGroups", "obligations", "acceptance", "packets", "observationWindows", "blockers", "ownerDecisions",
                   "notClaimed"}, "closed test plan")
    require(plan["schemaVersion"] == SCHEMA and plan["planLabel"] == "W04-0", "plan schema and label")
    repo = plan["repository"]
    _closed(repo, {"id", "name", "remote", "visibility", "currentVerification", "verificationDecision"}, "closed repository record")
    require(repo["id"] == "R12" and repo["name"] == "mas-harness-conformance-labs"
            and repo["remote"] == "https://github.com/caglarsubas/mas-harness-conformance-labs" and _text(repo["visibility"])
            and _text(repo["currentVerification"]) and _text(repo["verificationDecision"]), "R12 repository record")
    require(plan["independence"] == {"rules": list(INDEPENDENCE), "attestationFields": ATTESTATION}, "the independence rules")
    require(type(plan["sources"]) is list and [s.get("path") for s in plan["sources"] if type(s) is dict] == list(SOURCES),
            "the pinned source documents")
    for item in plan["sources"]:
        _pinned(item, read, {"path", "sha256"}, "source document bytes")
    texts = {p: _read(read, p).decode("utf-8") for p in SOURCES}
    require(type(plan["w03Inputs"]) is list and len(plan["w03Inputs"]) == 1, "exactly one W03 input")
    selection = plan["w03Inputs"][0]
    _pinned(selection, read, {"path", "sha256", "commit", "reviewState"}, "W03 selection record bytes")
    require({k: selection[k] for k in ("path", "commit", "reviewState")} == SELECTION, "the W03 selection record")
    # Contract inputs: exactly the adopted set and file lists, every file pinned.
    contracts = plan["contracts"]
    require(type(contracts) is list and [c.get("name") for c in contracts if type(c) is dict] == list(CONTRACTS),
            "exactly the adopted contract inputs")
    for row in contracts:
        _closed(row, {"name", "state", "files"}, "closed contract input")
        directory, files, model = CONTRACTS[row["name"]]
        require(row["state"] in ADOPTED_STATES and parse(_read(read, directory + "status.json")).get("contractState") == row["state"],
                "adopted contract state: " + row["name"])
        require(type(row["files"]) is list and [f.get("path") for f in row["files"] if type(f) is dict]
                == [directory + f for f in files] + [model], "contract file list " + row["name"])
        for item in row["files"]:
            _pinned(item, read, {"path", "sha256"}, "contract input bytes")
    names = tuple(CONTRACTS)
    # Test groups.
    groups = plan["testGroups"]
    require(type(groups) is list and all(type(g) is dict for g in groups) and [g.get("id") for g in groups] == list(GROUPS),
            "the eight test groups")
    tags = {}
    for g, title in zip(groups, TITLES):
        _closed(g, {"id", "from", "title", "matrix", "evidenceClass", "cases", "obligations", "contracts", "acceptance",
                    "packet", "r12Location"}, "closed test group " + g["id"])
        t = "T%02d" % int(g["id"][3:])
        row = _table_row(texts[BRIEF], t + " " + title)
        require(g["from"] == t and g["title"] == title and g["matrix"] == {"cases": row[1], "evidence": row[2]}
                and g["evidenceClass"] == EVIDENCE.get(row[2]), "test group %s carries its matrix row exactly" % g["id"])
        require(type(g["cases"]) is list and g["cases"] and all(type(c) is dict for c in g["cases"]), "cases " + g["id"])
        for c in g["cases"]:
            _closed(c, {"tag", "case", "source", "phase", "obligations", "blockedBy"}, "closed case in " + g["id"])
            require(_text(c["tag"]) and _text(c["case"]) and type(c["source"]) is str
                    and any(c["source"].startswith(p) for p in SOURCES + (SELECTION["path"],)) and c["phase"] in PHASES
                    and _ids(c["obligations"], ROWS) and c["obligations"], "case in %s: %s" % (g["id"], c.get("tag")))
            require((g["id"], c["tag"]) not in tags, "unique case tag in %s: %s" % (g["id"], c["tag"]))
            tags[g["id"], c["tag"]] = c
            if g["evidenceClass"] in NATIVE_CLASSES:
                require(c["phase"] == W6, "native evidence runs only in W06: " + g["id"])
            if g["evidenceClass"] in ("SOURCE_OWNER_IMPLEMENTATION", "SOURCE_MULTIPROCESS_FAULT") and c["phase"] == W4:
                require(c["tag"] == "LEDGER-E09", "owner-implementation cases run only against W05's release: " + c["tag"])
            blockers = ["D-W02A-F2"] * (c["phase"] == W6) + ["D-SC01-PEER"] * (c["phase"] == W6 and g["id"] == "TG-06")
            require(c["blockedBy"] == blockers, "case %s in %s lists exactly the blockers of its run" % (c["tag"], g["id"]))
            if c["tag"] in KEYS:
                require(KEYS[c["tag"]] in c["case"], "case %s in %s keeps its content" % (c["tag"], g["id"]))
        for phrase in matrix_phrases(row[1]):
            c = tags.get((g["id"], "MATRIX:" + phrase))
            require(c is not None and c["case"].startswith(phrase) and c["source"].startswith(BRIEF)
                    and c["phase"] in MATRIX_PHASES[g["evidenceClass"]], "matrix case %s in %s" % (phrase, g["id"]))
        require(_ids(g["obligations"], ROWS) and g["obligations"] == sorted({o for c in g["cases"] for o in c["obligations"]}),
                "group %s obligations are exactly its cases' obligations" % g["id"])
        require(g["contracts"] == list(GROUP_CONTRACTS[g["id"]]) and g["acceptance"] == list(GROUP_ACCEPTANCE[g["id"]])
                and g["packet"] == GROUP_PACKETS[g["id"]] and g["r12Location"] == GROUP_LOCATION[g["id"]],
                "test group references " + g["id"])
    for number, (group, phase) in COUNTEREXAMPLES.items():
        require(("\n%d. " % number) in texts[SPEC], "counterexample %d in the specification" % number)
        c = tags.get((group, "CE%d" % number))
        require(c is not None and c["phase"] == phase and c["source"] == SPEC + " section 9 (%d)" % number,
                "counterexample %d in %s" % (number, group))
    for tag, (in_groups, phase, source, text) in REQUIRED.items():
        require(text in texts[source], "source text for " + tag)
        for group in in_groups:
            c = tags.get((group, tag))
            require(c is not None and c["phase"] == phase and c["source"].startswith(source), "%s in %s" % (tag, group))
    e09 = tags[("TG-02", "LEDGER-E09")]["case"]
    require("explicit trusted-code boundary" in e09 and "partial acquisition" in e09 and "original-resource-only cleanup" in e09,
            "the E09 case carries the trusted-code boundary and resource substitution")
    # Obligations.
    require(GATE_SENTENCE in texts[SPEC], "the section 8 gate map sentence")
    rows = plan["obligations"]
    require(type(rows) is list and all(type(r) is dict for r in rows) and [r.get("id") for r in rows] == list(ROWS),
            "the twelve obligations")
    for r in rows:
        _closed(r, {"id", "theme", "gates", "testGroups", "w04", "w06"}, "closed obligation " + r["id"])
        require(_text(r["theme"]) and r["gates"] == sorted(g for g, cov in GATE_MAP.items() if r["id"] in cov),
                "obligation %s carries the section 8 gates" % r["id"])
        expected = [g["id"] for g in groups if r["id"] in g["obligations"]]
        require(r["testGroups"] == expected and expected, "obligation %s is covered by exactly the groups that test it" % r["id"])
        early = sorted({g["id"] for g in groups for c in g["cases"] if r["id"] in c["obligations"] and c["phase"] != W6})
        native = sorted({g["id"] for g in groups for c in g["cases"] if r["id"] in c["obligations"] and c["phase"] == W6})
        require(r["w04"] == _w04_text(expected, early) and r["w06"] == _w06_text(native),
                "obligation %s states the W04/W06 split of its cases" % r["id"])
    acceptance = plan["acceptance"]
    require(type(acceptance) is list and all(type(a) is dict for a in acceptance) and [a.get("id") for a in acceptance] == list(ACCEPTANCE),
            "A01-A09")
    for a in acceptance:
        _closed(a, {"id", "evidence", "testGroups", "observationWindows", "outsideW04"}, "closed acceptance item")
        require(a["evidence"] == _table_row(texts[DESIGN], a["id"])[1], "acceptance %s carries the design document's text" % a["id"])
        require(a["testGroups"] == [g["id"] for g in groups if a["id"] in g["acceptance"]], "acceptance %s groups" % a["id"])
        require(a["observationWindows"] is (a["id"] == "A01"), "only A01 is the window register")
        if a["id"] == "A01":
            require(a["testGroups"] == [] and a["outsideW04"] == A01_SPLIT.get(_selected(plan, "D-OW-1")),
                    "A01 follows owner decision D-OW-1")
        elif a["id"] in ("A07", "A08", "A09"):
            require(a["testGroups"] == [] and _text(a["outsideW04"]), "acceptance %s is outside W04's test groups" % a["id"])
        else:
            require(a["outsideW04"] is None and (a["testGroups"] or a["observationWindows"]), "acceptance %s is in W04" % a["id"])
    require(plan["blockers"] == [{"id": b, "text": t} for b, t in BLOCKERS.items()], "the blockers")
    require(plan["packets"] == [{"id": i, "repository": r, "content": c, "earliest": e} for i, r, c, e in PACKET_TABLE],
            "the packet table")
    require(plan["observationWindows"] == WINDOWS, "the observation-window binding")
    decisions = plan["ownerDecisions"]
    require(type(decisions) is list and all(type(d) is dict for d in decisions)
            and [d.get("id") for d in decisions] == ["D-R12", "D-TOOL", "D-MAP", "D-OW", "D-ID", "D-OW-1"], "the W04 plan owner decisions")
    for d in decisions:
        _closed(d, {"id", "selected", "date", "state", "decision"}, "closed owner decision")
        require(d["state"] in DECISION_STATES and _text(d["date"]) and _text(d["decision"]), "owner decision " + d["id"])
        if d["id"] in DECISION_TEXT:
            require((d["selected"], d["decision"], d["state"]) == DECISION_TEXT[d["id"]] + ("ACCEPTED",),
                    "owner decision %s is recorded verbatim" % d["id"])
    one = decisions[-1]
    require(one["decision"] == D_OW_1 and ((one["state"], one["selected"]) == ("PENDING", None)
                                          or (one["state"] == "ACCEPTED" and one["selected"] in A01_SPLIT)),
            "owner decision D-OW-1: the question and its state")
    require(plan["notClaimed"] == list(NOT_CLAIMED), "the stated non-claims")


D_OW_1 = ("Clarification of D-OW: the observation windows are the R12 reader's calls (OBSERVATION_ENFORCEMENT_DESIGN.md:226). "
          "A: W04-7 registers the reader's current calls at a pinned baseline with W05's enforcement context and W07 adds the "
          "removal half (A01 split; ENFORCEMENT_INTEGRATION.md:125 amended through the roadmap). B: W04-7 waits for a W07 "
          "candidate so A01 completes in W04. C: bind the register to R10's calls (not recommended).")
A01_SPLIT = {None: None, "A": "the lost-window half (removed or moved calls, exclusion proofs) is W07's, against W04-7's baseline register (D-OW-1 A)",
             "B": None, "C": None}


def _selected(plan: dict, decision: str) -> Any:
    rows = [d for d in plan.get("ownerDecisions", []) if type(d) is dict and d.get("id") == decision]
    return rows[0].get("selected") if len(rows) == 1 and rows[0].get("state") == "ACCEPTED" else None


def check_publishable(plan: dict) -> None:
    """A plan with a pending owner decision is not published."""
    require(all(d["state"] == "ACCEPTED" for d in plan["ownerDecisions"]), "an owner decision is pending")


def window_schema() -> dict:
    """The exact register schema: one R12 reader baseline revision, W05's enforcement context, an inventory generated
    mechanically by a pinned tool, and windows whose removal fields stay null until a W07 candidate revision exists."""
    nonempty = {"type": "string", "minLength": 1}
    strings = {"type": "array", "items": nonempty}
    rev = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
    window = {"type": "object", "additionalProperties": False,
              "required": ["id", "kind", "boundary", "parentWindow", "observationCall", "nestedChecks", "protectedFacts",
                           "tracePosition", "autonomousEventLatency", "obligations", "tests", "removal"],
              "properties": {"id": {"type": "string", "pattern": WINDOW_ID}, "kind": {"enum": ["DIRECT", "INDIRECT"]},
                             "boundary": nonempty, "parentWindow": {"type": ["string", "null"], "pattern": WINDOW_ID},
                             "observationCall": nonempty, "nestedChecks": strings, "protectedFacts": dict(strings, minItems=1),
                             "tracePosition": nonempty, "autonomousEventLatency": nonempty,
                             "obligations": {"type": "array", "items": {"enum": list(ROWS)}, "minItems": 1, "uniqueItems": True},
                             "tests": dict(strings, minItems=1),
                             "removal": {"type": ["object", "null"], "additionalProperties": False,
                                         "required": ["removedOrMovedCall", "newTracePosition", "lostWindow", "exclusionProof",
                                                      "stateKeepingFreshChecks"],
                                         "properties": {"removedOrMovedCall": nonempty,
                                                        "newTracePosition": {"type": ["string", "null"], "minLength": 1},
                                                        "lostWindow": nonempty, "exclusionProof": nonempty,
                                                        "stateKeepingFreshChecks": strings}}}}
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": WINDOW_SCHEMA,
            "title": "Exhaustive direct and indirect observation-window register of the R12 reader at one baseline revision (W04-7); removals per W07 candidate",
            "type": "object", "additionalProperties": False,
            "required": ["schemaVersion", "readerRepository", "baselineRevision", "enforcementContext", "candidateRevision",
                         "inventory", "exhaustive", "windows"],
            "properties": {"schemaVersion": {"const": WINDOW_SCHEMA},
                           "readerRepository": {"const": "mas-harness-conformance-labs"},
                           "baselineRevision": rev,
                           "enforcementContext": {"type": "object", "additionalProperties": False,
                                                  "required": ["r10Revision", "harnessOnionRevision"],
                                                  "properties": {"r10Revision": rev, "harnessOnionRevision": rev}},
                           "candidateRevision": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
                           "inventory": {"type": "object", "additionalProperties": False,
                                         "required": ["generator", "generatorSha256", "boundaries"],
                                         "properties": {"generator": nonempty, "generatorSha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                                        "boundaries": {"type": "array", "items": nonempty, "minItems": 1, "uniqueItems": True}}},
                           "exhaustive": {"const": True}, "windows": {"type": "array", "items": window, "minItems": 1}}}


def check_window_schema(schema: Any) -> None:
    require(schema == window_schema(), "the exact observation-window register schema")


def validate_instance(schema: dict, value: Any, where: str = "$") -> None:
    """A stdlib validator for exactly the JSON Schema keywords window_schema() uses."""
    if "const" in schema:
        require(type(value) is type(schema["const"]) and value == schema["const"], where + ": const")
    if "enum" in schema:
        require(value in schema["enum"], where + ": enum")
    kinds = schema.get("type")
    if kinds is not None:
        kinds = kinds if type(kinds) is list else [kinds]
        names = {"string": str, "object": dict, "array": list, "null": type(None)}
        require(any(type(value) is names[k] for k in kinds), where + ": type")
    if type(value) is str:
        if "minLength" in schema:
            require(len(value) >= schema["minLength"], where + ": minLength")
        if "pattern" in schema:
            pattern = schema["pattern"]
            require(pattern.startswith("^") and pattern.endswith("$") and re.fullmatch(pattern[1:-1], value) is not None,
                    where + ": pattern")
    if type(value) is list:
        require(len(value) >= schema.get("minItems", 0), where + ": minItems")
        if schema.get("uniqueItems"):
            require(len({json.dumps(v, sort_keys=True) for v in value}) == len(value), where + ": uniqueItems")
        for i, item in enumerate(value):
            validate_instance(schema.get("items", {}), item, "%s[%d]" % (where, i))
    if type(value) is dict:
        require(set(schema.get("required", [])) <= set(value), where + ": required")
        if schema.get("additionalProperties") is False:
            require(set(value) <= set(schema.get("properties", {})), where + ": additionalProperties")
        for key, item in value.items():
            if key in schema.get("properties", {}):
                validate_instance(schema["properties"][key], item, where + "." + key)


def check_register(register: Any) -> None:
    """A filled register: valid against the schema; unique ids; every inventory boundary covered; INDIRECT windows name an
    existing parent, never themselves, and every parent chain ends at a DIRECT window; removals only with a W07 candidate."""
    validate_instance(window_schema(), register)
    windows = register["windows"]
    ids = [w["id"] for w in windows]
    require(len(ids) == len(set(ids)), "unique window ids")
    require({w["boundary"] for w in windows} == set(register["inventory"]["boundaries"]), "every boundary has a window")
    by_id = {w["id"]: w for w in windows}
    for w in windows:
        require((w["kind"] == "INDIRECT") == (w["parentWindow"] is not None), "indirect windows and only they name a parent")
        seen, current = set(), w
        while current["kind"] == "INDIRECT":
            require(current["parentWindow"] in by_id and current["parentWindow"] not in seen and current["parentWindow"] != current["id"],
                    "parent chain of %s ends at a DIRECT window" % w["id"])
            seen.add(current["id"])
            current = by_id[current["parentWindow"]]
        require(register["candidateRevision"] is not None or w["removal"] is None, "removals need a W07 candidate revision")


def check(read: Callable[[str], bytes]) -> dict:
    plan = parse(_read(read, PLAN_PATH))
    check_plan(plan, read)
    check_window_schema(parse(_read(read, WINDOWS_SCHEMA_PATH)))
    return plan
