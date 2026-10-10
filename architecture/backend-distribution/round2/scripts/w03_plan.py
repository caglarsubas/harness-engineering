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


def check(read) -> dict:
    value = _json(read(RECORD_PATH))
    _closed(value, ("schemaVersion", "ownerDecisions", "toolchains", "scope", "packets", "obligations", "notClaimed"),
            "closed plan record")
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
    require(re.fullmatch(r"1\.[0-9]+\.[0-9]+", rust["rust"]["version"]) and COMMIT.fullmatch(rust["rust"]["commit"]),
            "Rust version and commit")
    require(rust["targets"] == ["aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl"], "the two musl targets")
    _closed(rust["musl"], ("version", "patches", "source"), "musl pin")
    require(rust["musl"]["version"] == "1.2.5", "musl 1.2.5 as bundled")
    _closed(rust["threads"], ("syscall", "flags", "source", "w02d"), "thread creation record")
    require(rust["threads"]["syscall"] == "clone", "musl creates threads with clone")
    flags = int(rust["threads"]["flags"], 16)
    require(flags & 0x7E030900 == 0x10900, "musl's thread flags pass W02d NATIVE_STATIC's thread rule")
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
        _closed(row, ("id", "source", "text", "packets"), "closed obligation")
        require(OBLIGATION_ID.fullmatch(row["id"]), "obligation id")
        _text(row["source"], "obligation source")
        _text(row["text"], "obligation text")
        _texts(row["packets"], "obligation packets")
        require(set(row["packets"]) <= set(packet_ids), "obligation packets are planned: " + row["id"])
        if row["source"].startswith("architecture/"):
            read(row["source"].split(":", 1)[0])
    ids = [row["id"] for row in obligations]
    require(len(ids) == len(set(ids)), "duplicate obligation")
    _texts(value["notClaimed"], "non-claims")
    return value


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    check(lambda path: (root / path).read_bytes())
    print("W03 plan valid: toolchains partition the W02d roles; every obligation has a planned packet.")
