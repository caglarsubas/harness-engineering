#!/usr/bin/env python3
"""v2 native qualification record: expected/native-capture DATA consistency only.

Reference model for `planeon.internal.native-qualification/v2` (profile
SELINUX_FSVERITY_CGROUP_BPF_V2). It never inspects a kernel, never mints a native
handle and never grants authority; every result is DATA_CHECK_ONLY. The v1 schema and
vectors are unchanged, and the logic of the v1 reference model is unchanged.

`check_*` functions raise with the first refused rule. A single check is NOT an
acceptance decision: only `check_qualification` combines the record, one capture per
resident role, the lifecycle capture, one observation per backend component and the
v1-to-v2 migration rules for one boot and validity window.

Precondition: `profile` is already valid under the pinned proxy profile contract
(`scripts/validate_proxy_contract.py`, `validate_profile`). This model additionally
refuses resource labels that do not carry the binding's nonces, and any v1 nonce
carried into v2 data.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime
from typing import Any

import jsonschema

SCHEMA_SHA256 = "1d9935bf04f555e776ef2c8effbe6ad86227d37479af232f44fa217ea21a077e"
V1_SCHEMA_SHA256 = "8e184d60df63863bc627c1655887c32012490e3c7211f8f9a38baee67f64d4cf"
V2_RECORD = ("planeon.internal.native-qualification/v2", "SELINUX_FSVERITY_CGROUP_BPF_V2")
V2_CAPTURE = "planeon.internal.native-qualification-capture/v2"
V2_LIFECYCLE = "planeon.internal.native-qualification-lifecycle/v2"
V2_BACKEND = "planeon.internal.native-qualification-backend/v2"
SEAL_VERSION = "planeon.internal.containment-seal/v1"
ROLES = ("SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE")
SINGLE_PROCESS_ROLES = ("SERVER", "OBSERVER", "BROKER", "EFFECT_GATE")
LIFECYCLE = ("HOST_CONTAINMENT", "POLICY_WRITER")
HOOKS = ("INET_SOCK_CREATE", "INET4_BIND", "INET6_BIND", "INET4_CONNECT", "INET6_CONNECT",
         "UDP4_SENDMSG", "UDP6_SENDMSG")
HOOK_DIRS = {hook: hook.lower().replace("_", "-") for hook in HOOKS}
ROLE_DIRS = {"SERVER": "proxy-server", "OBSERVER": "policy-observer", "BROKER": "capacity-broker",
             "WORKER": "probe-worker", "EFFECT_GATE": "effect-gate"}
DELEGATED_CHILDREN = ["broker", "probe-worker"]
PIN_ROOT = "/sys/fs/bpf/planeon"
CGROUP_ROOT = "/sys/fs/cgroup"
SLICE = CGROUP_ROOT + "/planeon.slice"
REQUIRED_BACKEND = ("APISERVER", "DATASTORE", "CONTROLLER_MANAGER", "SCHEDULER", "KUBELET", "CONTAINER_RUNTIME")
NO_API_CLIENT = ("DATASTORE", "CONTAINER_RUNTIME")
# Unconfined or privileged types in common reference policies. W02e replaces this
# denylist with the closed allowed-type matrix for every backend component.
FORBIDDEN_BACKEND_TYPES = ("unconfined_t", "unconfined_service_t", "init_t", "initrc_t", "kernel_t", "spc_t",
                           "sysadm_t", "unlabeled_t")
MAX_BYTES = 262144
PLANEON_CODE_BYTES = 536870912
BACKEND_CODE_BYTES = 4294967296
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


def schema_errors(value: Any, schema: dict, variant: str) -> list:
    validator = jsonschema.Draft202012Validator({"$ref": "#/$defs/" + variant, "$defs": schema["$defs"]})
    return list(validator.iter_errors(value))


def _shape(value: Any, variant: str, schema: dict) -> None:
    require(digest(canonical(schema)) == SCHEMA_SHA256, "unreviewed v2 qualification schema")
    _bounded(value)
    require(len(canonical(value)) <= MAX_BYTES, "bounded qualification data")
    error = jsonschema.exceptions.best_match(schema_errors(value, schema, variant))
    if error is not None:
        raise error


def _path(path: str) -> None:
    require(type(path) is str and path.startswith("/")
            and all(part not in ("", ".", "..") for part in path[1:].split("/")), "canonical installed path")


def _moment(value: str) -> datetime:
    moment = datetime.strptime(value, TIME)
    require(moment.strftime(TIME) == value, "canonical UTC time")
    return moment


def _within(record: dict, observed: str, message: str) -> None:
    now = _moment(observed)
    start, end = _moment(record["scope"]["validFrom"]), _moment(record["scope"]["expiresAt"])
    require(start <= now < end, message)


def _strings(value: Any) -> list[str]:
    if type(value) is str:
        return [value]
    if type(value) is dict:
        return [s for key, item in value.items() for s in [key] + _strings(item)]
    if type(value) is list:
        return [s for item in value for s in _strings(item)]
    return []


def _same_set(observed: list, enrolled: list) -> bool:
    return len(set(observed)) == len(observed) and sorted(observed) == sorted(enrolled)


def _endpoint_rows(rows: list) -> dict:
    require(type(rows) is list and 1 <= len(rows) <= 16, "bounded signed endpoints")
    by_id, tuples = {}, set()
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
        require((row["ipAddress"], row["port"]) not in tuples, "duplicate signed endpoint tuple")
        tuples.add((row["ipAddress"], row["port"]))
        by_id[row["endpointId"]] = row
    return by_id


def expected_seal_digest(record: dict) -> str:
    """Marker content: boot, active policy, containment artifact and every enrolled program."""
    programs = sorted(record["roles"][role]["bpfPrograms"][hook]["programId"] for role in ROLES for hook in HOOKS)
    content = {"schemaVersion": SEAL_VERSION, "bootId": record["host"]["bootId"],
               "policyDigest": record["selinux"]["policyDigest"],
               "containmentArtifactDigest": record["lifecycleSubjects"]["HOST_CONTAINMENT"]["artifactDigest"],
               "programIds": programs}
    return "sha256:" + digest(canonical(content))


class _Owners:
    """Code ownership by path and by content digest; one owner class per byte string."""

    def __init__(self) -> None:
        self.by_path: dict[str, str] = {}
        self.by_content: dict[str, str] = {}

    def own(self, paths: list, rows: dict, owner: str, executable: str, artifact: str, interpreter: str | None) -> None:
        require(set(paths) <= set(rows) and executable in paths and rows[executable]["sha256"] == artifact,
                "artifact custody")
        if interpreter is not None:
            require(interpreter in paths, "interpreter not enrolled")
        loaded = interpreter or executable
        require(rows[loaded]["mode"] == "0555" and rows[loaded]["executableSegments"], "actual executable missing")
        for path in paths:
            for table, key in ((self.by_path, path), (self.by_content, rows[path]["sha256"]),
                               (self.by_content, rows[path]["verityDigest"])):
                previous = table.setdefault(key, owner)
                if previous != owner:
                    require(not {previous, owner} <= set(LIFECYCLE), "lifecycle subjects share code")
                    require(False, "code shared across owner classes")


def check_record(record: Any, profile: Any, endpoints: Any, schema: dict) -> None:
    """Expected-data consistency of one v2 record; raises with the first refused rule."""
    require(type(record) is dict and (record.get("schemaVersion"), record.get("qualificationProfile")) == V2_RECORD,
            "not a v2 record")
    _shape(record, "record", schema)
    require(record["profileDigest"] == "sha256:" + digest(canonical(profile)), "profile substitution")
    binding = profile["binding"]
    require(record["scope"] == {key: binding[key] for key in record["scope"]}, "scope substitution")
    start, end = _moment(record["scope"]["validFrom"]), _moment(record["scope"]["expiresAt"])
    require(0 < (end - start).total_seconds() <= 900, "canonical half-open window")
    labels = {"planeon.ai/run-nonce": binding["runNonce"], "planeon.ai/tenant-id": binding["tenantId"]}
    require(all(row["manifest"]["metadata"]["labels"] == labels for row in profile["resources"]),
            "profile resource labels differ from the binding")
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

    def inventory(rows: list, bound: int) -> dict:
        files = {}
        for row in rows:
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
        require(sum(row["size"] for row in files.values()) <= bound, "code inventory bound")
        return files

    files = inventory(record["files"], PLANEON_CODE_BYTES)
    backend_files = inventory(record["backendFiles"], BACKEND_CODE_BYTES)
    require(not set(files) & set(backend_files), "planeon and backend inventories overlap")
    owners = _Owners()

    program_ids: set[int] = set()
    inodes: set[int] = set()
    for role in ROLES:
        row = record["roles"][role]
        owners.own(row["filePaths"], files, "role", row["executable"], row["artifactDigest"], row["interpreterPath"])
        require(row["cgroup"]["inode"] not in inodes, "duplicate cgroup inode")
        inodes.add(row["cgroup"]["inode"])
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
            require(("CAP_NET_BIND_SERVICE" in row["capabilities"]) == any(port < 1024 for port in bound_ports),
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
    for name in LIFECYCLE:
        row = lifecycle[name]
        owners.own(row["filePaths"], files, name, row["executable"], row["artifactDigest"], None)
    require(set(owners.by_path) == set(files), "unowned planeon code")
    require(record["hardening"]["sealMarker"]["digest"] == expected_seal_digest(record),
            "seal marker does not bind this boot")

    components = record["backendComponents"]
    require(sorted(components) == sorted(record["backendProfile"]["componentKeys"])
            and set(REQUIRED_BACKEND) <= set(components), "backend components differ from the implementation profile")
    planeon_labels = {record["roles"][role]["processLabel"] for role in ROLES}
    planeon_labels |= {row["processLabel"] for row in lifecycle.values()}
    labels_seen, cgroups_seen, identities_seen = set(), set(), set()
    for name in sorted(components):
        row = components[name]
        owners.own(row["filePaths"], backend_files, "backend", row["executable"], row["artifactDigest"], None)
        domain = row["processLabel"].split(":")[2]
        require(row["processLabel"] not in planeon_labels and not domain.startswith("planeon_"),
                "backend component in a planeon domain")
        require(domain not in FORBIDDEN_BACKEND_TYPES, "backend component in an unconfined or privileged domain")
        require(row["processLabel"] not in labels_seen, "backend components share a domain")
        labels_seen.add(row["processLabel"])
        _path(row["cgroupPath"])
        require(row["cgroupPath"].startswith(CGROUP_ROOT + "/"), "backend cgroup outside cgroupfs")
        require(row["cgroupPath"] != SLICE and not row["cgroupPath"].startswith(SLICE + "/"),
                "backend component inside the planeon slice")
        require(row["cgroupPath"] not in cgroups_seen, "backend components share a cgroup")
        cgroups_seen.add(row["cgroupPath"])
        if name in NO_API_CLIENT:
            require(row["apiIdentities"] == [], "backend API identity")
        elif name != "APISERVER":
            require(row["apiIdentities"] != [], "backend API identity")
        require(not set(row["apiIdentities"]) & identities_seen, "backend components share an API identity")
        identities_seen |= set(row["apiIdentities"])
    require(set(owners.by_path) - set(files) == set(backend_files), "unowned backend code")


def check_capture(record: Any, capture: Any, role: str, schema: dict, previous: Any = None) -> None:
    """Detached model capture of one resident role. Production inspects the kernel through its own owner."""
    require(type(capture) is dict and capture.get("schemaVersion") == V2_CAPTURE, "not a v2 capture")
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
    _within(record, capture["observedAt"], "expired capture")
    a, b, d = (capture[k] for k in ("inspectionStartedMs", "inspectionFinishedMs", "deadlineMs"))
    require(a <= b < d and b - a <= 2000 and d - a <= 900000, "inspection deadline")
    expected, actual = record["roles"][role], capture["process"]
    for field in ("uid", "gid", "processLabel", "namespaceInodes", "cgroup", "seccompMode", "seccompDefaultAction",
                  "seccompFilterDigest", "noNewPrivs", "rlimitCore"):
        require(actual[field] == expected[field], "process/kernel custody differs")
    require(_same_set(actual["capPermitted"], expected["capabilities"])
            and _same_set(actual["capEffective"], expected["capabilities"])
            and _same_set(actual["capBounding"], expected["capabilities"])
            and actual["capAmbient"] == [] and actual["capInheritable"] == [],
            "capability sets differ from the enrolled set")
    me = {"pid": actual["pid"], "startTicks": actual["startTicks"], "processLabel": actual["processLabel"]}
    members = capture["cgroupMembers"]
    if role in SINGLE_PROCESS_ROLES:
        require(members == [me], "unenrolled cgroup member")
    else:
        require(me in members and len(members) <= expected["cgroup"]["pidsMax"]
                and len({(m["pid"], m["startTicks"]) for m in members}) == len(members)
                and all(m["processLabel"] == expected["processLabel"] for m in members), "unenrolled cgroup member")
    children = capture["delegatedChildren"]
    if role == "BROKER":
        require(type(children) is list and sorted(children) == DELEGATED_CHILDREN, "delegated broker subtree differs")
    else:
        require(children is None, "delegated broker subtree differs")
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
                and item["pinLabel"] == pinned["pinLabel"]
                and item["localIds"] == [pinned["programId"]] and item["effectiveIds"] == item["localIds"],
                "effective kernel filter differs")
    if previous is not None:
        require(explain(check_capture, record, previous, role, schema) is None, "invalid retained capture")
        for field in ("host", "process", "files", "executableMaps", "bpfPrograms", "selinuxBefore", "selinuxAfter",
                      "kernelPolicyDigest", "booleansObserved", "hardeningObserved", "cgroupMembers",
                      "delegatedChildren"):
            require(capture[field] == previous[field], "retained native identity changed")
        require(capture["inspectionStartedMs"] >= previous["inspectionFinishedMs"]
                and capture["observedAt"] >= previous["observedAt"]
                and capture["deadlineMs"] == previous["deadlineMs"], "rollback or renewed lifetime")


def check_lifecycle_capture(record: Any, capture: Any, schema: dict) -> None:
    """Absence of the one-shot containment subject after its seal; data only."""
    require(type(capture) is dict and capture.get("schemaVersion") == V2_LIFECYCLE, "not a v2 lifecycle capture")
    _shape(record, "record", schema)
    _shape(capture, "lifecycleCapture", schema)
    require(capture["qualificationDigest"] == "sha256:" + digest(canonical(record))
            and capture["host"] == record["host"], "lifecycle capture binding")
    _within(record, capture["observedAt"], "expired lifecycle capture")
    require(capture["sealMarker"] == record["hardening"]["sealMarker"], "seal marker differs")
    require(capture["runFsType"] == record["hardening"]["runFsType"], "seal marker not on a per-boot filesystem")
    require(capture["cgroup"]["path"] == record["lifecycleSubjects"]["HOST_CONTAINMENT"]["cgroupPath"]
            and capture["cgroup"]["state"] in ("ABSENT", "EMPTY") and capture["domainProcessCount"] == 0,
            "containment subject still resident")
    require(capture["booleansObserved"] == record["selinux"]["booleans"], "host lock state differs")


def check_backend_capture(record: Any, capture: Any, schema: dict) -> None:
    """Observation of one backend component's process against its record entry; data only."""
    require(type(capture) is dict and capture.get("schemaVersion") == V2_BACKEND, "not a v2 backend capture")
    _shape(record, "record", schema)
    _shape(capture, "backendCapture", schema)
    require(capture["qualificationDigest"] == "sha256:" + digest(canonical(record))
            and capture["host"] == record["host"], "backend capture binding")
    _within(record, capture["observedAt"], "expired backend capture")
    entry = record["backendComponents"].get(capture["component"])
    require(entry is not None, "backend capture for an unrecorded component")
    executable = {row["path"]: row for row in record["backendFiles"]}[entry["executable"]]
    require(capture["process"]["processLabel"] == entry["processLabel"]
            and capture["process"]["cgroupPath"] == entry["cgroupPath"]
            and capture["executable"] == {"path": entry["executable"], "contentDigest": executable["sha256"],
                                          "measuredVerity": executable["verityDigest"]}, "backend observation differs")


def check_migration(v1_records: Any, v2_record: Any, v2_profile: Any, v1_schema: dict, schema: dict) -> None:
    """v1 to v2 needs a maintenance reboot and fresh nonces; v1 data is never reinterpreted."""
    _shape(v2_record, "record", schema)
    require(v2_record["profileDigest"] == "sha256:" + digest(canonical(v2_profile)), "profile substitution")
    require(digest(canonical(v1_schema)) == V1_SCHEMA_SHA256, "unreviewed v1 schema")
    require(type(v1_records) is list and v1_records, "retained v1 records required")
    old_nonces: set[str] = set()
    for old in v1_records:
        require(type(old) is dict and old.get("schemaVersion") == "planeon.internal.native-qualification/v1"
                and not schema_errors(old, v1_schema, "record"), "predecessor is not a valid v1 record")
        require(old["host"]["bootId"] != v2_record["host"]["bootId"], "v2 enrollment without a maintenance reboot")
        old_nonces |= {old["scope"]["runNonce"], old["scope"]["capacityNonce"]}
    new_nonces = {v2_record["scope"]["runNonce"], v2_record["scope"]["capacityNonce"]}
    require(not new_nonces & old_nonces, "nonce reused across versions")
    require(not set(_strings(v2_profile)) & old_nonces and not set(_strings(v2_record)) & old_nonces,
            "v1 nonce carried into v2 data")


def check_qualification(record: Any, profile: Any, endpoints: Any, captures: Any, lifecycle: Any,
                        backend_captures: Any, v1_records: Any, v1_schema: dict, schema: dict) -> None:
    """The only acceptance-shaped check: everything for one boot and window, still DATA_CHECK_ONLY."""
    check_record(record, profile, endpoints, schema)
    require(type(captures) is list and sorted(c.get("role") for c in captures) == sorted(ROLES),
            "one capture per resident role")
    for capture in captures:
        check_capture(record, capture, capture["role"], schema)
    check_lifecycle_capture(record, lifecycle, schema)
    require(type(backend_captures) is list
            and sorted(c.get("component") for c in backend_captures) == sorted(record["backendComponents"]),
            "one observation per backend component")
    for capture in backend_captures:
        check_backend_capture(record, capture, schema)
    check_migration(v1_records, record, profile, v1_schema, schema)


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


def refusal_under(value: Any, schema: dict, variant: str) -> str | None:
    """Best-match schema refusal of `value` as `variant` of `schema` (any version), or None."""
    error = jsonschema.exceptions.best_match(schema_errors(value, schema, variant))
    return None if error is None else "schema %s %s" % (error.json_path, error.validator)


def _result(check: Any, message: str, *args: Any) -> list[str]:
    return [] if explain(check, *args) is None else [message]


def validate_record(record: Any, profile: Any, endpoints: Any, schema: dict) -> list[str]:
    return _result(check_record, "invalid DATA_CHECK_ONLY v2 qualification record; no native authority",
                   record, profile, endpoints, schema)


def validate_capture(record: Any, capture: Any, role: str, schema: dict, previous: Any = None) -> list[str]:
    return _result(check_capture, "invalid DATA_CHECK_ONLY v2 capture; no native authority",
                   record, capture, role, schema, previous)


def validate_qualification(*args: Any) -> list[str]:
    return _result(check_qualification, "invalid DATA_CHECK_ONLY v2 qualification; no native authority", *args)
