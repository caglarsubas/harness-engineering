#!/usr/bin/env python3
"""W03 plan record (architecture/w03-plan/plan.json): toolchain decision, R10 scope, obligation register, packet plan.

check(read) validates the closed record through an injected byte reader:
- the two toolchains partition W02d's seven roles;
- every obligation names packets that the plan defines;
- every repository source it cites exists.
"""
from __future__ import annotations

import json
import re

RECORD_PATH = "architecture/w03-plan/plan.json"
SCHEMA = "planeon.internal.w03-plan/v1"
ALLOWLISTS_PATH = "architecture/seccomp-allowlists/allowlists.json"
ALLOWLISTS_V2_PATH = "architecture/seccomp-allowlists-v2/allowlists.json"
RUST_COMMITS = {"1.99.0": "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4"}
MUSL_PATCHES = ["CVE-2025-26519", "CVE-2026-40200", "CVE-2026-6042"]
MUSL_THREAD_FLAGS = 0x7D0F00  # musl 1.2.5 pthread_create.c:243-245
LINES = re.compile(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*\Z")
OWNER_QUESTIONS = ("Q1", "Q2", "Q3", "Q5")
WHERE = ("meta", "owner-root", "R10", "native", "other")
MAX_BYTES = 4_194_304
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
OBLIGATION_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\Z")
PACKET_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\Z")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def _json(raw: bytes):
    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), "duplicate plan key")
        return dict(items)

    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "plan record size")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda name: (_ for _ in ()).throw(ValueError("nonfinite plan number")))


def _closed(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def _text(value, message):
    require(type(value) is str and value != "" and "\x00" not in value, message)


def _texts(value, message):
    require(type(value) is list and value and all(type(item) is str and item for item in value)
            and len(set(value)) == len(value), message)


def _source(read, source):
    """A cited repository source must exist, and its line range or anchor must be inside it."""
    if source.startswith("W01-AMEND (MET-ENFORCE-018, pending merge) "):
        return
    path, _, where = source.partition(":")
    require(path and not path.startswith("/") and "\\" not in path
            and all(part not in ("", ".", "..") for part in path.split("/")), "unsafe source path: " + source)
    try:
        raw = read(path)
    except OSError:
        raise ValueError("cited source missing: " + source) from None
    if where:
        text = raw.decode("utf-8")
        if LINES.fullmatch(where):
            count = text.count("\n") + (0 if text.endswith("\n") else 1)
            numbers = [int(n) for piece in where.split(",") for n in piece.split("-")]
            require(all(1 <= n <= count for n in numbers), "cited lines outside the file: " + source)
        else:
            require(where in text, "cited anchor not in the file: " + source)


def check(read) -> dict:
    try:
        return _check(read)
    except (TypeError, KeyError, AttributeError, IndexError) as error:
        raise ValueError("malformed plan record: %s" % error) from None


def _check(read) -> dict:
    value = _json(read(RECORD_PATH))
    _closed(value, ("schemaVersion", "ownerDecisions", "toolchains", "buildToolchains", "scope", "packets", "obligations",
                    "notClaimed"), "closed plan record")
    require(value["schemaVersion"] == SCHEMA, "plan schema")
    decisions = value["ownerDecisions"]
    require(type(decisions) is list and [row.get("id") for row in decisions if type(row) is dict] == list(OWNER_QUESTIONS),
            "owner decisions Q1, Q2, Q3, Q5 in order")
    for row in decisions:
        _closed(row, ("id", "selected", "summary"), "closed owner decision")
        require(row["selected"] == "a", "the owner chose option a throughout")
        _text(row["summary"], "decision summary")
    tool = value["toolchains"]
    _closed(tool, ("CPYTHON_3_12", "RUST_MUSL_STATIC"), "the two toolchains")
    cpython, rust = tool["CPYTHON_3_12"], tool["RUST_MUSL_STATIC"]
    _closed(cpython, ("roles", "python", "libc"), "closed CPython toolchain")
    require(cpython["python"] == "3.12.14", "CPython 3.12.14")
    _text(cpython["libc"], "CPython libc rule")
    _closed(rust, ("roles", "rust", "targets", "linking", "musl", "threads", "startupRecheck", "startupConstraints",
                   "crates"), "closed Rust toolchain")
    recheck = rust["startupRecheck"]
    _closed(recheck, ("reference", "pinned", "result", "findings"), "closed start-up re-check")
    require(recheck["result"] in ("SAME_STARTUP_SYSCALLS", "W02D_CHANGE_NEEDED") and recheck["pinned"].startswith(
        "Rust " + rust["rust"]["version"]), "start-up re-check result for the pinned Rust")
    _text(recheck["reference"], "re-check reference")
    _texts(recheck["findings"], "re-check findings")
    _closed(rust["rust"], ("version", "commit"), "Rust pin")
    require(RUST_COMMITS.get(rust["rust"]["version"]) == rust["rust"]["commit"], "the Rust version's release commit")
    require(rust["targets"] == ["aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl"], "the two musl targets")
    _closed(rust["musl"], ("version", "patches", "source"), "musl pin")
    require(rust["musl"]["version"] == "1.2.5" and rust["musl"]["patches"] == MUSL_PATCHES, "musl 1.2.5 and its patches as bundled")
    _text(rust["musl"]["source"], "musl source")
    _closed(rust["threads"], ("syscall", "flags", "source", "w02d"), "thread creation record")
    require(rust["threads"]["syscall"] == "clone", "musl creates threads with clone")
    require(type(rust["threads"]["flags"]) is str and re.fullmatch(r"0x[0-9a-f]+", rust["threads"]["flags"])
            and int(rust["threads"]["flags"], 16) == MUSL_THREAD_FLAGS, "musl 1.2.5's documented thread flags")
    require(MUSL_THREAD_FLAGS & 0x7E030900 == 0x10900, "musl's thread flags pass W02d NATIVE_STATIC's thread rule")
    for key in ("linking", "crates"):
        _text(rust[key], "Rust " + key)
    _texts(rust["startupConstraints"], "start-up constraints")
    allowlists = _json(read(ALLOWLISTS_PATH))
    roles = set(allowlists["roles"])
    _texts(cpython["roles"], "CPython roles")
    _texts(rust["roles"], "Rust roles")
    require(set(cpython["roles"]) | set(rust["roles"]) == roles and not set(cpython["roles"]) & set(rust["roles"]),
            "the toolchains partition W02d's roles")
    for role in cpython["roles"]:
        require(allowlists["roles"][role].get("runtimeBase") == "CPYTHON_3_12", "CPython roles use W02d's CPython base")
    for role in rust["roles"]:
        require(allowlists["roles"][role].get("runtimeBase") == "NATIVE_STATIC", "Rust roles use W02d's native base")
    build = value["buildToolchains"]
    _closed(build, ("GO_AGENT_BUILD",), "build toolchains")
    _closed(build["GO_AGENT_BUILD"], ("for", "go", "moduleCache", "build"), "closed Go build toolchain")
    require(build["GO_AGENT_BUILD"]["go"].startswith("1.26.7"), "the Go build uses R10's pinned Go 1.26.7")
    for key in ("for", "moduleCache", "build"):
        _text(build["GO_AGENT_BUILD"][key], "Go build " + key)
    scope = value["scope"]
    _closed(scope, ("repository", "root", "modules", "support", "signer", "amends"), "closed scope")
    require(scope["repository"] == "caglarsubas/mas-harness-operator" and scope["root"] == "host-enforcement/"
            and scope["modules"] == ["containment", "broker", "observer", "gate", "writer"]
            and scope["support"] == ["host-image", "enrollment"], "owner decision Q5 scope")
    for key in ("signer", "amends"):
        _text(scope[key], "scope " + key)
    packets = value["packets"]
    require(type(packets) is list and packets, "packets")
    for row in packets:
        _closed(row, ("id", "where", "summary"), "closed packet")
        require(PACKET_ID.fullmatch(row["id"]) and row["where"] in WHERE, "packet id and place")
        _text(row["summary"], "packet summary")
    packet_ids = [row["id"] for row in packets]
    require(len(packet_ids) == len(set(packet_ids)), "duplicate packet")
    obligations = value["obligations"]
    require(type(obligations) is list and obligations, "obligations")
    for row in obligations:
        _closed(row, ("id", "source", "text", "packets", "scope"), "closed obligation")
        require(OBLIGATION_ID.fullmatch(row["id"]), "obligation id")
        _text(row["source"], "obligation source")
        _text(row["text"], "obligation text")
        _texts(row["packets"], "obligation packets")
        require(set(row["packets"]) <= set(packet_ids), "obligation packets are planned: " + row["id"])
        require(row["scope"] in ("W03", "OUTSIDE_W03") and (row["scope"] == "OUTSIDE_W03") == ("R12" in row["packets"]),
                "only an obligation outside W03 goes to R12, and then only there: " + row["id"])
        require(row["scope"] == "W03" or row["packets"] == ["R12"], "an outside obligation names R12 alone")
        _source(read, row["source"])
    ids = [row["id"] for row in obligations]
    require(len(ids) == len(set(ids)), "duplicate obligation")
    by_id = {row["id"]: row for row in obligations}
    require("W02D-V3" in packet_ids and "SEC-8" in by_id and "W02D-V3" in by_id["SEC-8"]["packets"],
            "owner decision Q-S (S-b): W02d v3 discharges the steady-state calls")
    try:
        v2 = _json(read(ALLOWLISTS_V2_PATH))
    except OSError:
        v2 = None
    if v2 is None:
        require("W02D-V2" in packet_ids and any(row["packets"] == ["W02D-V2"] for row in obligations),
                "until W02d v2 is merged, its merge is a registered precondition")
    else:
        require(any(rule.get("name") == "poll" for rule in v2["runtimeBases"]["NATIVE_STATIC"]["rules"]),
                "W02d v2's NATIVE_STATIC grants poll")
    _texts(value["notClaimed"], "non-claims")
    return value


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    check(lambda path: (root / path).read_bytes())
    print("W03 plan valid: toolchains partition the W02d roles; every obligation has a planned packet.")
