#!/usr/bin/env python3
"""v2 native qualification record: expected/native-capture DATA consistency only.

Reference model for `planeon.internal.native-qualification/v2` (profile
SELINUX_FSVERITY_CGROUP_BPF_V2). It never inspects a kernel, never mints a native
handle and never grants authority; every result is DATA_CHECK_ONLY. The v1 schema,
vectors and reference model are unchanged and keep their own meaning.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime
from typing import Any

import jsonschema

SCHEMA_PATH = "architecture/native-profile-v2/qualification.schema.json"
SCHEMA_SHA256 = "a148be7341ae6be14a29839725bc6d088825635cf189dca58e798902433f35d7"
V1_SCHEMA_PATH = "architecture/native-qualification-inputs/qualification.schema.json"
ROLES = ("SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE")
HOOKS = ("INET_SOCK_CREATE", "INET4_BIND", "INET6_BIND", "INET4_CONNECT", "INET6_CONNECT",
         "UDP4_SENDMSG", "UDP6_SENDMSG")
HOOK_DIRS = {hook: hook.lower().replace("_", "-") for hook in HOOKS}
ROLE_DIRS = {"SERVER": "proxy-server", "OBSERVER": "policy-observer", "BROKER": "capacity-broker",
             "WORKER": "probe-worker", "EFFECT_GATE": "effect-gate"}
PIN_ROOT = "/sys/fs/bpf/planeon"
SLICE = "/sys/fs/cgroup/planeon.slice"
NO_API_IDENTITY = ("APISERVER", "DATASTORE", "CONTAINER_RUNTIME")
MAX_BYTES = 262144
TIME = "%Y-%m-%dT%H:%M:%SZ"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _bounded(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    budget = [MAX_BYTES] if budget is None else budget
    require(depth <= 16, "depth exceeded")
    kind = type(value)
    require(kind in (dict, list, str, int, bool, type(None)), "non-data value")
    budget[0] -= len(value) if kind is str else 1
    require(budget[0] >= 0, "size exceeded")
    if kind is int:
        require(abs(value) <= 9007199254740991, "integer overflow")
    elif kind is str:
        require(all(32 <= ord(char) <= 126 for char in value), "ASCII data required")
    elif kind is dict:
        for key, item in value.items():
            require(type(key) is str, "string key required")
            _bounded(key, depth + 1, budget)
            _bounded(item, depth + 1, budget)
    elif kind is list:
        for item in value:
            _bounded(item, depth + 1, budget)


def _shape(value: Any, variant: str, schema: dict) -> None:
    require(digest(canonical(schema)) == SCHEMA_SHA256, "unreviewed v2 qualification schema")
    _bounded(value)
    require(len(canonical(value)) <= MAX_BYTES, "bounded qualification data")
    validator = jsonschema.Draft202012Validator({"$ref": "#/$defs/" + variant, "$defs": schema["$defs"]})
    error = jsonschema.exceptions.best_match(validator.iter_errors(value))
    if error is not None:
        raise error


def _path(path: str) -> None:
    require(type(path) is str and path.startswith("/")
            and all(part not in ("", ".", "..") for part in path[1:].split("/")), "canonical installed path")


def _moment(value: str) -> datetime:
    moment = datetime.strptime(value, TIME)
    require(moment.strftime(TIME) == value, "canonical UTC time")
    return moment


def _endpoint_rows(rows: list) -> dict:
    require(type(rows) is list and 1 <= len(rows) <= 16, "bounded signed endpoints")
    by_id = {}
    for row in rows:
        require(type(row) is dict and set(row) == {"endpointId", "kind", "addressFamily", "ipAddress", "port"}
                and row["endpointId"] not in by_id, "unique closed endpoint tuples")
        ip = ipaddress.ip_address(row["ipAddress"])
        require(str(ip) == row["ipAddress"] and not ip.is_unspecified and not ip.is_multicast
                and not (ip.version == 6 and (ip.ipv4_mapped is not None or ip.scope_id is not None)),
                "fixed canonical numeric endpoint")
        require(row["addressFamily"] == ("IPV4" if ip.version == 4 else "IPV6")
                and row["kind"] in ("CAMPAIGN_PROXY", "KUBERNETES_API_PROXY")
                and type(row["port"]) is int and 1 <= row["port"] <= 65535, "endpoint family/type")
        by_id[row["endpointId"]] = row
    return by_id


def check_record(record: Any, profile: Any, endpoints: Any, schema: dict) -> None:
    """Expected-data consistency of one v2 record; raises with the first refused rule."""
    _shape(record, "record", schema)
    require(record["profileDigest"] == "sha256:" + digest(canonical(profile)), "profile substitution")
    binding = profile["binding"]
    require(record["scope"] == {key: binding[key] for key in record["scope"]}, "scope substitution")
    start, end = _moment(record["scope"]["validFrom"]), _moment(record["scope"]["expiresAt"])
    require(0 < (end - start).total_seconds() <= 900, "canonical half-open window")
    signed = _endpoint_rows(endpoints)
    require(record["endpointTuples"] == endpoints, "endpoint tuple substitution")
    proxy = signed.get(binding["endpointId"])
    api = signed.get(binding["apiEndpointId"]) if binding["apiEndpointId"] is not None else None
    resources = bool(profile["resources"])
    require(proxy is not None and proxy["kind"] == "CAMPAIGN_PROXY"
            and ((api is not None and api["kind"] == "KUBERNETES_API_PROXY") if resources
                 else binding["apiEndpointId"] is None), "profile endpoint kinds")
    internal = record["internalEndpoints"][0]
    ip = ipaddress.ip_address(internal["ipAddress"])
    require(ip.is_loopback and internal["addressFamily"] == ("IPV4" if ip.version == 4 else "IPV6")
            and internal["endpointId"] not in signed
            and all((row["ipAddress"], row["port"]) != (internal["ipAddress"], internal["port"])
                    for row in signed.values()), "loopback apiserver endpoint must stay internal")
    require(record["selinux"]["status"]["sequence"] % 2 == 0, "unstable policy epoch")

    files = {}
    for row in record["files"]:
        _path(row["path"])
        require(row["path"] not in files and row["sha256"] != row["verityDigest"],
                "duplicate file or conflated digest")
        files[row["path"]] = row
        occupied = set()
        for segment in row["executableSegments"]:
            key = (segment["offset"], segment["length"], segment["permissions"])
            require(key not in occupied and segment["offset"] + segment["length"]
                    <= ((row["size"] + 4095) // 4096) * 4096, "executable segment outside artifact")
            occupied.add(key)
    require(sum(row["size"] for row in files.values()) <= 1073741824, "code inventory bound")

    def custody(paths: list, executable: str, artifact: str, interpreter: str | None) -> None:
        require(set(paths) <= set(files) and executable in paths
                and files[executable]["sha256"] == artifact, "artifact custody")
        if interpreter is not None:
            require(interpreter in paths, "interpreter not enrolled")
        loaded = interpreter or executable
        require(files[loaded]["mode"] == "0555" and files[loaded]["executableSegments"],
                "actual executable missing")

    used: dict[str, str] = {}
    program_ids: set[int] = set()
    for role in ROLES:
        row = record["roles"][role]
        custody(row["filePaths"], row["executable"], row["artifactDigest"], row["interpreterPath"])
        for path in row["filePaths"]:
            used.setdefault(path, role)
        listen, outbound = row["listenEndpointIds"], row["outboundEndpointIds"]
        if role == "SERVER":
            require(listen == [binding["endpointId"]]
                    and outbound == ([binding["apiEndpointId"]] if resources else []), "server endpoints differ")
            bound_ports = [proxy["port"]]
        elif role == "EFFECT_GATE":
            require(listen == ([binding["apiEndpointId"]] if resources else [])
                    and outbound == [internal["endpointId"]], "gate endpoints differ")
            bound_ports = [api["port"]] if resources else []
        elif role == "OBSERVER":
            require(listen == [] and outbound == [internal["endpointId"]], "observer endpoints differ")
            bound_ports = []
        else:
            require(listen == [] and outbound == [], role.lower() + " network grant")
            bound_ports = []
        if role in ("SERVER", "EFFECT_GATE"):
            needs_low_port = any(port < 1024 for port in bound_ports)
            require(("CAP_NET_BIND_SERVICE" in row["capabilities"]) == needs_low_port,
                    "CAP_NET_BIND_SERVICE only for a signed port below 1024")
        for hook in HOOKS:
            program = row["bpfPrograms"][hook]
            require(program["programType"] == (9 if hook == "INET_SOCK_CREATE" else 18)
                    and program["instructionBytes"] % 8 == 0, "wrong kernel program type/length")
            require(program["pinPath"] == "%s/%s/%s" % (PIN_ROOT, ROLE_DIRS[role], HOOK_DIRS[hook]),
                    "program pin outside the sealed layout")
            require(program["programId"] not in program_ids, "program shared between hooks or roles")
            program_ids.add(program["programId"])

    lifecycle = record["lifecycleSubjects"]
    for name, row in lifecycle.items():
        custody(row["filePaths"], row["executable"], row["artifactDigest"], None)
        for path in row["filePaths"]:
            require(used.get(path) in (None, name), "lifecycle code shared with a resident role")
            used.setdefault(path, name)

    role_labels = {record["roles"][role]["processLabel"] for role in ROLES}
    role_labels |= {row["processLabel"] for row in lifecycle.values()}
    for name, row in record["backendComponents"].items():
        custody(row["filePaths"], row["executable"], row["artifactDigest"], None)
        for path in row["filePaths"]:
            require(not str(used.get(path, "")).startswith(ROLES + ("HOST_CONTAINMENT", "POLICY_WRITER")),
                    "backend code shared with a planeon role")
            used.setdefault(path, "backend")
        _path(row["cgroupPath"])
        require(row["processLabel"] not in role_labels
                and not row["processLabel"].startswith("system_u:system_r:planeon_"),
                "backend component in a planeon domain")
        require(row["cgroupPath"] != SLICE and not row["cgroupPath"].startswith(SLICE + "/"),
                "backend component inside the planeon slice")
        require((row["apiIdentity"] is None) == (name in NO_API_IDENTITY), "backend API identity")
    require(set(used) == set(files), "unowned code inventory")


def check_capture(record: Any, capture: Any, role: str, schema: dict, previous: Any = None) -> None:
    """Detached model capture only. Production inspects the kernel through its own owner."""
    _shape(record, "record", schema)
    _shape(capture, "capture", schema)
    require(type(role) is str and role in ROLES and capture["role"] == role
            and capture["qualificationDigest"] == "sha256:" + digest(canonical(record)), "capture binding")
    require(capture["host"] == record["host"], "wrong boot/kernel")
    status = record["selinux"]["status"]
    require(status["sequence"] % 2 == 0 and capture["selinuxBefore"] == status == capture["selinuxAfter"]
            and capture["kernelPolicyDigest"] == record["selinux"]["policyDigest"], "active policy changed")
    require(capture["booleansObserved"] == record["selinux"]["booleans"]
            and capture["hardeningObserved"] == record["hardening"], "host lock state differs")
    now = _moment(capture["observedAt"])
    start, end = _moment(record["scope"]["validFrom"]), _moment(record["scope"]["expiresAt"])
    require(start <= now < end, "expired capture")
    a, b, d = (capture[k] for k in ("inspectionStartedMs", "inspectionFinishedMs", "deadlineMs"))
    require(a <= b < d and b - a <= 2000 and d - a <= 900000, "inspection deadline")
    expected, actual = record["roles"][role], capture["process"]
    for field in ("uid", "gid", "processLabel", "namespaceInodes", "cgroup", "seccompMode",
                  "noNewPrivs", "capabilities"):
        require(actual[field] == expected[field], "process/kernel custody differs")
    rows = {row["path"]: row for row in record["files"]}
    observed = {}
    for item in capture["files"]:
        path = item["entry"]["path"]
        require(path not in observed and path in expected["filePaths"] and item["entry"] == rows[path]
                and item["contentDigest"] == rows[path]["sha256"]
                and item["measuredVerity"] == rows[path]["verityDigest"], "file measurement differs")
        observed[path] = item
    require(set(observed) == set(expected["filePaths"]), "incomplete loaded-code closure")
    mappings = [dict(path=path, **segment, device=observed[path]["device"], inode=observed[path]["inode"])
                for path in expected["filePaths"] for segment in rows[path]["executableSegments"]]
    key = lambda m: (m["path"], m["offset"], m["length"], m["permissions"], m["device"], m["inode"])
    require(sorted(capture["executableMaps"], key=key) == sorted(mappings, key=key),
            "missing or injected executable map")
    for hook in HOOKS:
        item, pinned = capture["bpfPrograms"][hook], expected["bpfPrograms"][hook]
        require(item["program"] == pinned and item["pinPath"] == pinned["pinPath"]
                and item["localIds"] == [pinned["programId"]] and item["effectiveIds"] == item["localIds"],
                "effective kernel filter differs")
    if previous is not None:
        require(not validate_capture(record, previous, role, schema), "invalid retained capture")
        for field in ("host", "process", "files", "executableMaps", "bpfPrograms", "selinuxBefore",
                      "selinuxAfter", "kernelPolicyDigest", "booleansObserved", "hardeningObserved"):
            require(capture[field] == previous[field], "retained native identity changed")
        require(capture["inspectionStartedMs"] >= previous["inspectionFinishedMs"]
                and capture["observedAt"] >= previous["observedAt"]
                and capture["deadlineMs"] == previous["deadlineMs"], "rollback or renewed lifetime")


def check_lifecycle_capture(record: Any, capture: Any, schema: dict) -> None:
    """Absence of the one-shot containment subject after its seal; data only."""
    _shape(record, "record", schema)
    _shape(capture, "lifecycleCapture", schema)
    require(capture["qualificationDigest"] == "sha256:" + digest(canonical(record))
            and capture["host"] == record["host"], "lifecycle capture binding")
    now = _moment(capture["observedAt"])
    start, end = _moment(record["scope"]["validFrom"]), _moment(record["scope"]["expiresAt"])
    require(start <= now < end, "expired lifecycle capture")
    require(capture["sealMarker"] == record["hardening"]["sealMarker"], "seal marker differs")
    require(capture["cgroup"]["path"] == record["lifecycleSubjects"]["HOST_CONTAINMENT"]["cgroupPath"]
            and capture["cgroup"]["populated"] == 0 and capture["domainProcessCount"] == 0,
            "containment subject still resident")
    require(capture["booleansObserved"] == record["selinux"]["booleans"], "host lock state differs")


def check_migration(v1_records: Any, v2_record: Any, schema: dict) -> None:
    """v1 to v2 needs a maintenance reboot and fresh nonces; v1 data is never reinterpreted."""
    _shape(v2_record, "record", schema)
    require(type(v1_records) is list and v1_records, "retained v1 records required")
    for old in v1_records:
        require(type(old) is dict and old.get("schemaVersion") == "planeon.internal.native-qualification/v1",
                "only v1 records are migration predecessors")
        require(old["host"]["bootId"] != v2_record["host"]["bootId"], "v2 enrollment without a maintenance reboot")
        require(old["scope"]["runNonce"] != v2_record["scope"]["runNonce"]
                and old["scope"]["capacityNonce"] != v2_record["scope"]["capacityNonce"], "nonce reused across versions")


ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, jsonschema.ValidationError)


def explain(check: Any, *args: Any) -> str | None:
    """None when `check` accepts; otherwise the refused rule (schema refusals name the JSON path)."""
    try:
        check(*args)
    except jsonschema.ValidationError as exc:
        return "schema %s %s" % (exc.json_path, exc.validator)
    except ERRORS as exc:
        return str(exc) if type(exc) is ValueError else type(exc).__name__
    return None


def _result(check: Any, message: str, *args: Any) -> list[str]:
    return [] if explain(check, *args) is None else [message]


def validate_record(record: Any, profile: Any, endpoints: Any, schema: dict) -> list[str]:
    return _result(check_record, "invalid DATA_CHECK_ONLY v2 qualification record; no native authority",
                   record, profile, endpoints, schema)


def validate_capture(record: Any, capture: Any, role: str, schema: dict, previous: Any = None) -> list[str]:
    return _result(check_capture, "invalid DATA_CHECK_ONLY v2 capture; no native authority",
                   record, capture, role, schema, previous)


def validate_lifecycle_capture(record: Any, capture: Any, schema: dict) -> list[str]:
    return _result(check_lifecycle_capture, "invalid DATA_CHECK_ONLY v2 lifecycle capture; no native authority",
                   record, capture, schema)


def validate_migration(v1_records: Any, v2_record: Any, schema: dict) -> list[str]:
    return _result(check_migration, "invalid v1-to-v2 migration; no native authority", v1_records, v2_record, schema)


def refused_by_schema(value: Any, schema: dict, variant: str) -> bool:
    """True when `value` is not a valid `variant` of the given schema (cross-version checks)."""
    try:
        jsonschema.Draft202012Validator({"$ref": "#/$defs/" + variant, "$defs": schema["$defs"]}).validate(value)
    except jsonschema.ValidationError:
        return True
    return False
