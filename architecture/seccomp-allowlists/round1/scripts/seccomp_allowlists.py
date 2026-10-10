#!/usr/bin/env python3
"""Per-role, per-architecture seccomp allowlists (W02d): closed data, reference decision, compiler and digest.

DATA_CHECK_ONLY reference model for the seccomp half of HOST-INTERFACE-DRAFT-002 section 5.3 (mode 2, default
KILL_PROCESS) and the bpf command limit of section 5.1, for the seven roles on x86_64 and aarch64 at the pinned
kernel v6.12.

- `effective_rules(policy, table, role, arch)` merges a role's runtime base and duty rows into one rule per syscall.
- `decide(...)` is the reference semantics: KILL_PROCESS for a wrong architecture, an x32 call, an unlisted syscall or
  a listed syscall whose argument conditions all fail; ALLOW otherwise.
- `compile_filter(...)` emits the deterministic classic-BPF program a role installs; `run_filter(...)` interprets a
  program on one `struct seccomp_data`; the vectors show the two agree.
- `filter_digest(...)` is the SHA-256 of the program as the kernel receives it (the `sock_filter` array,
  little-endian): the record's `seccompFilterDigest` (owner decision W02d-Q3).
- `check_policy(...)` refuses a policy that grants what W01 sections 5.1 and 5.3 deny.

It is not a filter installed on a host, and it proves nothing about the role code that will run under it.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any

ARCHES = ("x86_64", "aarch64")
ROLES = ("SERVER", "OBSERVER", "BROKER", "EFFECT_GATE", "WORKER", "POLICY_WRITER", "HOST_CONTAINMENT")
DIGEST_SLOT_ROLES = ("SERVER", "OBSERVER", "BROKER", "EFFECT_GATE", "WORKER")   # the record has no slot for the others
RUNTIME_BASES = ("CPYTHON_3_12", "NATIVE_STATIC")

# include/uapi/linux/seccomp.h and include/uapi/linux/filter.h, bpf_common.h at v6.12 (cited in the policy data)
RET_KILL_PROCESS = 0x80000000
RET_ALLOW = 0x7FFF0000
LD_W_ABS = 0x20     # BPF_LD | BPF_W | BPF_ABS
JEQ_K = 0x15        # BPF_JMP | BPF_JEQ | BPF_K
JGE_K = 0x35        # BPF_JMP | BPF_JGE | BPF_K
AND_K = 0x54        # BPF_ALU | BPF_AND | BPF_K
RET_K = 0x06        # BPF_RET | BPF_K
OFFSET_NR, OFFSET_ARCH, OFFSET_ARGS = 0, 4, 16       # struct seccomp_data
FULL = 0xFFFFFFFF


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


# ---------------------------------------------------------------- rules

def _check_condition(cond: Any) -> None:
    require(type(cond) is dict and set(cond) == {"arg", "mask", "eq"} and type(cond["arg"]) is int and 0 <= cond["arg"] <= 5
            and type(cond["mask"]) is int and 0 < cond["mask"] <= FULL and type(cond["eq"]) is int
            and 0 <= cond["eq"] <= FULL and cond["eq"] & cond["mask"] == cond["eq"], "closed argument condition: " + repr(cond))


def _check_rule(rule: Any) -> None:
    require(type(rule) is dict and set(rule) <= {"name", "when"} and type(rule.get("name")) is str, "closed rule: " + repr(rule))
    if "when" in rule:
        require(type(rule["when"]) is list and rule["when"] and all(type(alt) is list and alt for alt in rule["when"]),
                "closed alternatives: " + rule["name"])
        for alternative in rule["when"]:
            for cond in alternative:
                _check_condition(cond)


def effective_rules(policy: dict, table: dict, role: str, arch: str) -> dict[str, Any]:
    """name -> None (unconditional) or a list of alternatives, each a list of conditions (AND inside, OR across).
    A name absent on the architecture is dropped there; an unconditional grant absorbs conditional ones."""
    entry = policy["roles"][role]
    rules = list(policy["runtimeBases"][entry["runtimeBase"]]["rules"])
    for duty in entry["duties"]:
        rules += duty["rules"]
    merged: dict[str, Any] = {}
    for rule in rules:
        _check_rule(rule)
        require(rule["name"] in table["syscalls"], "syscall outside the closed table: " + rule["name"])
        if table["syscalls"][rule["name"]][arch] is None:
            continue
        when = rule.get("when")
        if rule["name"] in merged and merged[rule["name"]] is None:
            continue
        if when is None:
            merged[rule["name"]] = None
        else:
            known = merged.setdefault(rule["name"], [])
            for alternative in when:
                if alternative not in known:
                    known.append(alternative)
    return merged


def numbered(table: dict, arch: str, rules: dict[str, Any]) -> list[tuple[int, str, Any]]:
    entries = sorted((table["syscalls"][name][arch]["nr"], name, when) for name, when in rules.items())
    require(len({nr for nr, _, _ in entries}) == len(entries), "two names share one syscall number on " + arch)
    return entries


# ---------------------------------------------------------------- reference decision

def _holds(alternative: list, args: list[int]) -> bool:
    return all((args[c["arg"]] & FULL) & c["mask"] == c["eq"] for c in alternative)


def decide(policy: dict, table: dict, role: str, arch: str, audit_arch: int, nr: int, args: list[int]) -> int:
    """The action the role's filter takes for one call. Only the low 32 bits of an argument are compared: every
    filtered argument is an int or unsigned int the kernel truncates (stated per condition in the policy)."""
    arch_data = table["arches"][arch]
    if audit_arch != arch_data["auditArch"]:
        return RET_KILL_PROCESS
    if arch_data["x32Bit"] is not None and nr >= arch_data["x32Bit"]:
        return RET_KILL_PROCESS
    for number, _, when in numbered(table, arch, effective_rules(policy, table, role, arch)):
        if number == nr:
            return RET_ALLOW if when is None or any(_holds(alt, args) for alt in when) else RET_KILL_PROCESS
    return RET_KILL_PROCESS


# ---------------------------------------------------------------- compiler, interpreter and digest

def _ins(code: int, jt: int, jf: int, k: int) -> tuple[int, int, int, int]:
    require(0 <= jt <= 255 and 0 <= jf <= 255 and 0 <= k <= FULL, "classic-BPF field out of range")
    return (code, jt, jf, k)


def _body(when: Any) -> list[tuple[int, int, int, int]]:
    """Instructions after a matched syscall number; every path ends in a return."""
    if when is None:
        return [_ins(RET_K, 0, 0, RET_ALLOW)]
    blocks = []
    for alternative in when:
        block = []
        for cond in alternative:
            block.append(("ld", cond))
            if cond["mask"] != FULL:
                block.append(("and", cond))
            block.append(("jeq", cond))
        block.append(("allow", None))
        blocks.append(block)
    out: list[tuple[int, int, int, int]] = []
    for index, block in enumerate(blocks):
        size = len(block)
        for position, (kind, cond) in enumerate(block):
            if kind == "ld":
                out.append(_ins(LD_W_ABS, 0, 0, OFFSET_ARGS + 8 * cond["arg"]))
            elif kind == "and":
                out.append(_ins(AND_K, 0, 0, cond["mask"]))
            elif kind == "jeq":
                # A failed condition jumps past the rest of this alternative to the next one (or the final kill).
                out.append(_ins(JEQ_K, 0, size - position - 1, cond["eq"]))
            else:
                out.append(_ins(RET_K, 0, 0, RET_ALLOW))
    out.append(_ins(RET_K, 0, 0, RET_KILL_PROCESS))
    return out


def compile_filter(policy: dict, table: dict, role: str, arch: str) -> list[tuple[int, int, int, int]]:
    """Deterministic program: check the architecture, refuse x32 on x86_64, then one number test per allowed syscall
    in ascending number order, each followed by its own body; anything else is KILL_PROCESS."""
    arch_data = table["arches"][arch]
    program = [_ins(LD_W_ABS, 0, 0, OFFSET_ARCH), _ins(JEQ_K, 1, 0, arch_data["auditArch"]),
               _ins(RET_K, 0, 0, RET_KILL_PROCESS), _ins(LD_W_ABS, 0, 0, OFFSET_NR)]
    if arch_data["x32Bit"] is not None:
        program += [_ins(JGE_K, 0, 1, arch_data["x32Bit"]), _ins(RET_K, 0, 0, RET_KILL_PROCESS)]
    for nr, _, when in numbered(table, arch, effective_rules(policy, table, role, arch)):
        body = _body(when)
        program.append(_ins(JEQ_K, 0, len(body), nr))
        program += body
    program.append(_ins(RET_K, 0, 0, RET_KILL_PROCESS))
    require(len(program) <= 4096, "a classic-BPF program has at most 4096 instructions")
    return program


def program_bytes(program: list[tuple[int, int, int, int]]) -> bytes:
    return b"".join(struct.pack("<HBBI", *instruction) for instruction in program)


def filter_digest(policy: dict, table: dict, role: str, arch: str) -> str:
    return "sha256:" + hashlib.sha256(program_bytes(compile_filter(policy, table, role, arch))).hexdigest()


def seccomp_data(nr: int, audit_arch: int, args: list[int], ip: int = 0) -> bytes:
    return struct.pack("<iIQ6Q", nr, audit_arch, ip, *args)


def run_filter(program: list[tuple[int, int, int, int]], data: bytes) -> int:
    """Interpret the instruction subset the compiler emits, as the kernel's classic-BPF interpreter would."""
    a, pc = 0, 0
    while True:
        require(0 <= pc < len(program), "classic-BPF program fell off its end")
        code, jt, jf, k = program[pc]
        if code == LD_W_ABS:
            require(k % 4 == 0 and k + 4 <= len(data), "aligned in-bounds load")
            a = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif code == AND_K:
            a &= k
            pc += 1
        elif code == JEQ_K:
            pc += 1 + (jt if a == k else jf)
        elif code == JGE_K:
            pc += 1 + (jt if a >= k else jf)
        elif code == RET_K:
            return k
        else:
            raise ValueError("instruction outside the compiler's subset: 0x%x" % code)


# ---------------------------------------------------------------- what W01 denies

def check_policy(policy: dict, table: dict) -> None:
    """Refuse a policy whose effective rules grant what W01 sections 5.1, 5.3 and 5.4 deny on either architecture."""
    require(set(policy["roles"]) == set(ROLES) and set(policy["runtimeBases"]) == set(RUNTIME_BASES), "closed roles and bases")
    deny = table["deniedEverywhere"]
    for role in ROLES:
        entry = policy["roles"][role]
        require(entry["runtimeBase"] in RUNTIME_BASES and (entry["runtimeBase"] == "CPYTHON_3_12") == (role in ("SERVER", "WORKER")),
                "runtime base of " + role)
        require(all(duty.get("source") and duty.get("row") and duty["rules"] for duty in entry["duties"]),
                "every duty cites its row: " + role)
        for arch in ARCHES:
            rules = effective_rules(policy, table, role, arch)
            for name in deny:
                require(name not in rules, "W01 denies %s to %s (%s)" % (name, role, arch))
            require(("execveat" in rules) == (role == "BROKER") and "execve" not in rules, "exec only through the broker's execveat: " + role)
            if role == "BROKER":
                require(rules["execveat"] == [[{"arg": 4, "mask": FULL, "eq": table["constants"]["AT_EMPTY_PATH"]}]],
                        "the broker's execveat only with flags AT_EMPTY_PATH")
            require(("clone3" in rules) == (role == "BROKER"), "clone3 only for the broker: " + role)
            if role == "BROKER":
                require(rules["clone3"] is None, "clone3 cannot be argument-filtered; the broker's grant is unconditional")
            thread = table["constants"]["CLONE_THREAD_REQUIRED"]
            if "clone" in rules:
                require(rules["clone"] is not None and all(
                    any(c["arg"] == 0 and c["mask"] & thread["mask"] == thread["mask"] and c["eq"] & thread["mask"] == thread["eq"]
                        for c in alt) for alt in rules["clone"]), "clone only as a thread, without namespace flags: " + role)
            if "bpf" in rules:
                allowed = {7, 15, 16} | ({5, 6, 8} if role == "HOST_CONTAINMENT" else set())
                require(rules["bpf"] is not None and all(
                    any(c["arg"] == 0 and c["mask"] == FULL and c["eq"] in allowed for c in alt) for alt in rules["bpf"]),
                        "bpf only with the commands W01 section 5.1 allows: " + role)
                require(role not in ("EFFECT_GATE", "WORKER", "POLICY_WRITER"), "no bpf for " + role)
            if role in ("WORKER",):
                require("socket" not in rules and "socketpair" not in rules, "the worker creates no socket")
            if "memfd_create" in rules:
                require(rules["memfd_create"] == [[{"arg": 1, "mask": FULL, "eq": table["constants"]["MFD_CLOEXEC_ALLOW_SEALING"]}]],
                        "memfd_create only with MFD_CLOEXEC | MFD_ALLOW_SEALING: " + role)
