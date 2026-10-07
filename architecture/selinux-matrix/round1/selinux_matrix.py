#!/usr/bin/env python3
"""SELinux domain, type, boolean and permission matrix (W02e): closed data and its evaluator.

DATA_CHECK_ONLY reference model for the planeon and qualification-backend SELinux policy the reviewed
W01 design selects (HOST-INTERFACE-DRAFT-002 sections 2.1 P1/P2/P4/P5/P9, 2.3, 4.1-4.3, 5.1-5.5) and
the W02a v2 record leaves to W02e (label slots and the confined backend types).

- `allowed` answers one access question (state, source domain, target, class, permission) from the
  matrix: True or False when the matrix is closed over the target or class, None outside it.
- `check_matrix` checks that the matrix is closed and well formed: every domain, type, boolean, class
  and permission is declared, and every label is a well-formed context.
- `failed_assertions` evaluates the deny properties derived from W01 in every boot state and returns
  the ones that do not hold.
- `w02a_slots` derives the label values the W02a v2 record leaves open.

It is not a policy module, a compiled policy or an observation of a host.
"""
from __future__ import annotations

import re
from typing import Any

MATRIX_VERSION = "planeon.internal.selinux-matrix/v1"
BOOLEANS = ("planeon_containment_enabled", "planeon_maintenance_mode", "secure_mode_policyload")
STATES = ("ENROLLED_CONTAINMENT", "ENROLLED_SEALED", "MAINTENANCE_BOOT")
DOMAIN_KINDS = ("RESIDENT_ROLE", "LIFECYCLE", "MAINTENANCE", "BACKEND", "CONTAINER", "ADMIN", "SYSTEM")
TYPE_CATEGORIES = ("ENTRYPOINT", "INTERPRETER", "SEALED_CONFIG", "UNIT_FILE", "CREDENTIAL", "SOCKET_FILE",
                   "CGROUP", "BPF_PIN", "SEAL_MARKER", "JOURNAL", "RUNTIME_DIR", "DATA", "CONTAINER_FILE")
ACCESS_GROUPS = ("READ", "WRITE", "RELABEL", "EXECUTE", "ENTRYPOINT")
FILE_CLASSES = ("file", "dir", "sock_file", "lnk_file")
# Each file-class permission in one access group (SELinux classmap names, Linux v6.12).
FILE_PERMS = {
    "READ": ("read", "open", "getattr", "map", "ioctl", "lock", "search", "watch", "watch_reads"),
    "WRITE": ("write", "append", "create", "unlink", "link", "rename", "setattr", "add_name", "remove_name",
              "rmdir", "reparent", "mounton"),
    "RELABEL": ("relabelfrom", "relabelto"),
    "EXECUTE": ("execute", "execute_no_trans"),
    "ENTRYPOINT": ("entrypoint",),
}
CAPABILITY = ("chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap",
              "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
              "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
              "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap")
CAPABILITY2 = ("mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
               "checkpoint_restore")
CAP_CLASSES = {"capability": CAPABILITY, "capability2": CAPABILITY2, "cap_userns": CAPABILITY, "cap2_userns": CAPABILITY2}
PROCESS_PERMS = ("transition", "dyntransition", "setexec", "ptrace", "execmem", "execstack", "execheap", "setsockcreate")
SOCKET_PERMS = ("connectto", "create", "bind", "listen", "accept")
PORT_PERMS = ("name_bind", "name_connect")
BPF_PERMS = ("prog_load", "prog_run", "map_create", "map_read", "map_write")
SECURITY_PERMS = ("setbool", "load_policy", "setenforce")
SERVICE_PERMS = ("start", "stop", "reload", "status", "enable", "disable")
SECURITY_OBJECT = "security_t"
OTHER_DOMAIN = "OTHER_DOMAIN"      # any domain the matrix does not declare
ANY_DOMAIN = "ANY_DOMAIN"          # a grant to every domain (public, non-secret reads only)
CONTEXT = re.compile(r"^system_u:(system_r|object_r):([a-z0-9_]+_t):s0$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def holds(when: dict | None, booleans: dict) -> bool:
    return when is None or all(booleans[name] == value for name, value in when.items())


def granted(entries: list, domain: str, booleans: dict) -> bool:
    return any(e["domain"] in (domain, ANY_DOMAIN) and holds(e.get("when"), booleans) for e in entries)


def _index(matrix: dict) -> tuple[dict, dict, dict, dict]:
    domains = {d["name"]: d for d in matrix["domains"]}
    types = {t["name"]: t for t in matrix["types"]}
    sockets = {s["object"]: s for s in matrix["sockets"]}
    ports = {p["type"]: p for p in matrix["ports"]}
    return domains, types, sockets, ports


def allowed(matrix: dict, state: str, source: str, target: str, cls: str, perm: str) -> bool | None:
    """One access decision. True or False where the matrix is closed (its own types, sockets, ports and
    domains, and the capability, bpf, security, process and service classes); None outside it."""
    booleans = matrix["states"][state]
    domains, types, sockets, ports = _index(matrix)
    if cls in FILE_CLASSES:
        if target in domains:
            # /proc access to another process (peer qualification) is the ptrace read check: class file, read.
            return cls == "file" and perm == "read" and any(
                e["domain"] == source and e["target"] == target and holds(e.get("when"), booleans)
                for e in matrix["process"]["peerRead"])
        if target not in types:
            return None
        group = next((g for g, perms in FILE_PERMS.items() if perm in perms), None)
        require(group is not None, "unknown file permission " + perm)
        entry = types[target]
        return cls in entry["classes"] and granted(entry["access"].get(group, []), source, booleans)
    if cls in CAP_CLASSES:
        require(perm in CAP_CLASSES[cls], "unknown capability " + perm)
        return target == source and any(c["class"] == cls and c["capability"] == perm and holds(c.get("when"), booleans)
                                        for c in matrix["capabilities"].get(source, []))
    if cls == "process":
        require(perm in PROCESS_PERMS, "unknown process permission " + perm)
        if perm == "transition":
            # Effective only with execute on the entrypoint type for the source and entrypoint for the target.
            return any(t["from"] == source and t["to"] == target and holds(t.get("when"), booleans)
                       and granted(types[t["via"]]["access"].get("EXECUTE", []), source, booleans)
                       and granted(types[t["via"]]["access"].get("ENTRYPOINT", []), target, booleans)
                       for t in matrix["transitions"])
        return any(e["domain"] == source and e.get("target", source) == target and holds(e.get("when"), booleans)
                   for e in matrix["process"][perm])
    if cls == "unix_stream_socket":
        require(perm in SOCKET_PERMS, "unknown socket permission " + perm)
        if target not in sockets:
            return None
        sock = sockets[target]
        if perm == "connectto":
            return granted(sock["connect"], source, booleans)
        return source == sock["listener"]
    if cls == "tcp_socket":
        require(perm in PORT_PERMS, "unknown port permission " + perm)
        if target not in ports:
            return None
        return granted(ports[target]["bind" if perm == "name_bind" else "connect"], source, booleans)
    if cls == "bpf":
        require(perm in BPF_PERMS, "unknown bpf permission " + perm)
        if perm == "prog_run":
            return any(e["domain"] == source and e["object"] == target and holds(e.get("when"), booleans)
                       for e in matrix["bpf"]["prog_run"])
        return target == source and granted(matrix["bpf"][perm], source, booleans)
    if cls == "security":
        require(perm in SECURITY_PERMS, "unknown security permission " + perm)
        return target == SECURITY_OBJECT and granted(matrix["security"][perm], source, booleans)
    if cls == "service":
        require(perm in SERVICE_PERMS, "unknown service permission " + perm)
        if target not in types or types[target]["category"] != "UNIT_FILE":
            return None
        return any(e["domain"] == source and target in e["units"] and holds(e.get("when"), booleans)
                   for e in matrix["service"][perm])
    return None


def _entries(value: Any) -> list:
    return value if type(value) is list else []


def check_matrix(matrix: dict) -> None:
    """Closed and well formed: every name declared once, every reference resolved, every label a context."""
    require(type(matrix) is dict and set(matrix) == {
        "schemaVersion", "policyCapabilities", "booleans", "states", "domains", "types", "transitions", "capabilities",
        "sockets", "ports", "bpf", "security", "process", "service", "assertions"} and matrix["schemaVersion"] == MATRIX_VERSION,
        "closed matrix")
    require(set(matrix["booleans"]) == set(BOOLEANS) and set(matrix["states"]) == set(STATES)
            and all(set(v) == set(BOOLEANS) and all(x in (0, 1) for x in v.values()) for v in matrix["states"].values()),
            "closed booleans and states")
    # A socket object is a type of its own (set by the listener with setsockcreate) or the listener's domain.
    names = [d["name"] for d in matrix["domains"]] + [t["name"] for t in matrix["types"]] + \
        [s["object"] for s in matrix["sockets"] if s["object"] != s["listener"]] + [p["type"] for p in matrix["ports"]]
    require(len(names) == len(set(names)) and not {OTHER_DOMAIN, ANY_DOMAIN} & set(names), "every domain and type declared once")
    domains, types, sockets, ports = _index(matrix)
    require(all(d["kind"] in DOMAIN_KINDS and set(d) == {"name", "kind", "subject", "label"} for d in matrix["domains"]),
            "closed domain rows")
    for d in matrix["domains"]:
        m = CONTEXT.match(d["label"])
        require(m is not None and m.group(1) == "system_r" and m.group(2) == d["name"], "process context of " + d["name"])
        # W02a round-2 N1: backend components and qualification Pods run only in the confined qualk8s types this
        # matrix defines; upstream unconfined or privileged types (kubelet_t, container_runtime_t, spc_t,
        # unconfined_t, ...) cannot appear, because every domain name is fixed by its kind.
        prefix = {"BACKEND": "qualk8s_", "CONTAINER": "qualk8s_", "SYSTEM": "init_t"}.get(d["kind"], "planeon_")
        require(d["name"] == "init_t" if d["kind"] == "SYSTEM" else d["name"].startswith(prefix),
                "domain name fixed by its kind: " + d["name"])

    def known(entries, what, public=False):
        for e in entries:
            require((e["domain"] in domains or (public and e["domain"] == ANY_DOMAIN))
                    and set(e.get("when") or {}) <= set(BOOLEANS), what + ": " + str(e))

    for t in matrix["types"]:
        require(set(t) == {"name", "category", "label", "classes", "access"} and t["category"] in TYPE_CATEGORIES
                and set(t["classes"]) <= set(FILE_CLASSES) and t["classes"] and set(t["access"]) <= set(ACCESS_GROUPS),
                "closed type row " + t["name"])
        m = CONTEXT.match(t["label"])
        require(m is not None and m.group(1) == "object_r" and m.group(2) == t["name"], "object context of " + t["name"])
        for group, entries in t["access"].items():
            # Only READ of a non-secret type may be granted to every domain.
            known(entries, "type " + t["name"], public=group == "READ" and t["category"] in (
                "ENTRYPOINT", "INTERPRETER", "SEALED_CONFIG", "UNIT_FILE"))
    for s in matrix["sockets"]:
        require(set(s) == {"object", "listener", "file", "connect"} and s["listener"] in domains and s["file"] in types
                and types[s["file"]]["category"] == "SOCKET_FILE", "socket " + s["object"])
        if s["object"] != s["listener"]:
            require(any(e["domain"] == s["listener"] for e in matrix["process"]["setsockcreate"]),
                    "a socket type of its own needs the listener's setsockcreate: " + s["object"])
        known(s["connect"], "socket " + s["object"])
    for p in matrix["ports"]:
        require(CONTEXT.match(p["label"]) and CONTEXT.match(p["label"]).group(2) == p["type"], "port context " + p["type"])
        known(p["bind"] + p["connect"], "port " + p["type"])
    for t in matrix["transitions"]:
        require(set(t) <= {"from", "to", "via", "when"} and t["from"] in domains and t["to"] in domains and t["via"] in types
                and types[t["via"]]["category"] in ("ENTRYPOINT", "CONTAINER_FILE")
                and set(t.get("when") or {}) <= set(BOOLEANS),
                "transition %s -> %s via %s needs an entrypoint type" % (t["from"], t["to"], t["via"]))
    for t in matrix["transitions"]:
        require(any(allowed(matrix, state, t["from"], t["to"], "process", "transition") for state in STATES),
                "transition %s -> %s via %s is never effective" % (t["from"], t["to"], t["via"]))
    for domain, caps in matrix["capabilities"].items():
        require(domain in domains and all(c["class"] in CAP_CLASSES and c["capability"] in CAP_CLASSES[c["class"]]
                                          for c in caps), "capabilities of " + domain)
    require(set(matrix["bpf"]) == set(BPF_PERMS) and set(matrix["security"]) == set(SECURITY_PERMS)
            and set(matrix["process"]) == set(PROCESS_PERMS[1:]) | {"peerRead"} and set(matrix["service"]) == set(SERVICE_PERMS),
            "closed class tables")
    for perm in BPF_PERMS:
        known(matrix["bpf"][perm], "bpf " + perm)
    for perm in SECURITY_PERMS:
        known(matrix["security"][perm], "security " + perm)
    for perm, entries in matrix["process"].items():
        known(entries, "process " + perm)
        require(all(e.get("target", e["domain"]) in domains for e in entries), "process target " + perm)
    for perm in SERVICE_PERMS:
        known(matrix["service"][perm], "service " + perm)
        require(all(set(e["units"]) <= {t for t in types if types[t]["category"] == "UNIT_FILE"} for e in matrix["service"][perm]),
                "service units " + perm)


def _sources(matrix: dict) -> list[str]:
    return [d["name"] for d in matrix["domains"]] + [OTHER_DOMAIN]


def failed_assertions(matrix: dict) -> list[str]:
    """Every assertion is a deny property: for each listed state, no domain outside `allow` gets the access
    on any listed target. Returns the identifiers of assertions that do not hold."""
    failed = []
    for a in matrix["assertions"]:
        ok = True
        for state in a["states"]:
            for target in a["targets"]:
                for source in _sources(matrix):
                    if source in a["allow"]:
                        continue
                    for perm in a["perms"]:
                        result = allowed(matrix, state, source, source if target == "SELF" else target, a["class"], perm)
                        if result is not False:
                            ok = False
        if not ok:
            failed.append(a["id"])
    return failed


def apply_ops(value: Any, ops: list) -> Any:
    """A copy of `value` with closed path operations applied (set, delete, append); used by mutation vectors."""
    import copy
    value = copy.deepcopy(value)
    for op in ops:
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        elif op["op"] == "append":
            node[last].append(copy.deepcopy(op["value"]))
        else:
            require(op["op"] == "delete", "closed mutation operation")
            del node[last]
    return value


def w02a_slots(matrix: dict) -> dict:
    """The label values the W02a v2 record leaves open: role cgroups, bpffs pins and the seal marker."""
    types = {t["name"]: t for t in matrix["types"]}
    roles = ("SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE")
    cgroup = {"SERVER": "planeon_cgroup_server_t", "OBSERVER": "planeon_cgroup_observer_t", "BROKER": "planeon_cgroup_broker_t",
              "WORKER": "planeon_cgroup_worker_t", "EFFECT_GATE": "planeon_cgroup_gate_t"}
    return {"roleCgroupLabels": {role: types[cgroup[role]]["label"] for role in roles},
            "bpfPinLabel": types["planeon_bpf_pin_t"]["label"],
            "sealMarkerLabel": types["planeon_seal_t"]["label"]}
