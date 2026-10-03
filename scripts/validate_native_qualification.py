#!/usr/bin/env python3
"""Expected/native-capture DATA consistency only; never invokes native inspection."""
from __future__ import annotations

import ast
import ipaddress
from pathlib import Path

import jsonschema
import yaml

try:
    from safe_yaml import safe_load
    from validate_proxy_contract import canonical, digest, parse, regular_bytes, CASES, _bounded
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts.validate_proxy_contract import canonical, digest, parse, regular_bytes, CASES, _bounded

try:
    from validate_conformance_performance import historical_bytes as performance_history, current_test_bytes as performance_current, validate_additions as performance_additions
except ImportError:
    from scripts.validate_conformance_performance import historical_bytes as performance_history, current_test_bytes as performance_current, validate_additions as performance_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/native-qualification-amendment.json"
BEFORE_PATH = "architecture/native-qualification-inputs/meta-before.json"
SCHEMA_PATH = "architecture/native-qualification-inputs/qualification.schema.json"
VECTORS_PATH = "architecture/native-qualification-inputs/vectors.json"
CHECKPOINT_PATH = "architecture/credential-ordering-inputs/checkpoint.json"
RECORD_SHA256 = "e2bfb957a5d22ceab2dc46b2631d3842570eebfec31ee8241320991887dacb98"
PACKET_SHA256 = "63ef06efd5a6ae1cd86b27dec0e9b0921028a4e80fe53a5a6fed1a65f8c5c349"
SCHEMA_SHA256 = "8e184d60df63863bc627c1655887c32012490e3c7211f8f9a38baee67f64d4cf"
ZERO = "sha256:" + "0" * 64
BRIDGED_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md","docs/adr/0004-sol-high-packet-boundary.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_broker_handoff.py","scripts/validate_ci_performance.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_proxy_contract.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_broker_handoff.py","tests/test_ci_performance.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_proxy_contract.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])
ROLES = ("SERVER", "OBSERVER", "BROKER", "WORKER")
HOOKS = ("INET_SOCK_CREATE", "INET4_BIND", "INET6_BIND", "INET4_CONNECT", "INET6_CONNECT", "UDP4_SENDMSG", "UDP6_SENDMSG")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pinned(record):
    require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256,
            "exact qualification authority required")


def _record():
    record = parse(regular_bytes(ROOT, RECORD_PATH))
    pinned(record)
    return record


def validate_additions(packets):
    try:
        require(type(packets) is dict and digest(canonical(packets.get("MET-REPAIR-015"))) == PACKET_SHA256,
                "exact qualification packet required")
        return performance_additions(packets)
    except (ValueError, TypeError, RecursionError):
        return ["missing or changed native qualification packet"]


def apply_recipe(before, recipe):
    require(type(before) is bytes and type(recipe) is dict
            and set(recipe) == {"beforeSha256", "afterSha256", "replacements"}
            and digest(before) == recipe["beforeSha256"], "exact before bytes required")
    result = before
    require(type(recipe["replacements"]) is list, "ordered recipe required")
    for row in recipe["replacements"]:
        require(type(row) is dict and set(row) == {"before", "after", "count"}
                and type(row["before"]) is type(row["after"]) is str
                and type(row["count"]) is int and row["count"] > 0
                and row["before"] and row["before"] != row["after"], "closed effective recipe required")
        old, new = row["before"].encode(), row["after"].encode()
        require(result.count(old) == row["count"], "recipe cardinality differs")
        result = result.replace(old, new)
    require(digest(result) == recipe["afterSha256"], "unreviewed replacement bytes")
    return result


def historical_bytes(path, raw):
    """Check exact current replacements before exposing old bytes to old pins."""
    raw = performance_history(path, raw)
    if path not in BRIDGED_PATHS:
        return raw
    record = _record()
    rule = record["metaRecipes"].get(path)
    if rule is None or not rule["replacements"]:
        return raw
    require(type(raw) is bytes and digest(raw) == rule["afterSha256"], "current bytes differ: " + path)
    before = raw
    for replacement in reversed(rule["replacements"]):
        current, old = replacement["after"].encode(), replacement["before"].encode()
        require(before.count(current) == replacement["count"], "inverse recipe cardinality")
        before = before.replace(current, old)
    require(digest(before) == rule["beforeSha256"] and apply_recipe(before, rule) == raw, "invalid inverse recipe")
    return before


def current_test_bytes(before):
    require(type(before) is bytes, "test source bytes required")
    record = _record()
    input_digest = digest(before)
    matches = [r for p, r in record["metaRecipes"].items()
               if p.startswith("tests/") and r["beforeSha256"] == input_digest]
    if not matches:
        require(input_digest in record["unchangedTests"].values(), "unreviewed unchanged test source")
        return performance_current(before)
    require(len(matches) == 1, "exact predecessor test source required")
    return performance_current(apply_recipe(before, matches[0]))


def _shape(value, variant, schema):
    require(digest(canonical(schema)) == SCHEMA_SHA256, "unreviewed qualification schema")
    _bounded(value)
    require(len(canonical(value)) <= 262144, "bounded qualification data")
    def ascii_fields(item):
        if type(item) is str:
            require(all(32 <= ord(c) <= 126 for c in item), "ASCII data required")
        elif type(item) is dict:
            for k, v in item.items():
                ascii_fields(k)
                ascii_fields(v)
        elif type(item) is list:
            for v in item:
                ascii_fields(v)
    ascii_fields(value)
    jsonschema.Draft202012Validator({"$ref": "#/$defs/" + variant, "$defs": schema["$defs"]}).validate(value)


def _path(path):
    require(type(path) is str and path.startswith("/")
            and all(x not in ("", ".", "..") for x in path[1:].split("/")), "canonical installed path")


def _endpoint_rows(rows):
    require(type(rows) is list and 1 <= len(rows) <= 16, "bounded signed endpoints")
    ids = set()
    for row in rows:
        require(type(row) is dict and set(row) == {"endpointId","kind","addressFamily","ipAddress","port"}
                and row["endpointId"] not in ids, "unique closed endpoint tuples")
        ids.add(row["endpointId"])
        ip = ipaddress.ip_address(row["ipAddress"])
        require(str(ip) == row["ipAddress"] and not ip.is_unspecified and not ip.is_multicast
                and not (ip.version == 6 and (ip.ipv4_mapped is not None or ip.scope_id is not None)),
                "fixed canonical numeric endpoint")
        require(row["addressFamily"] == ("IPV4" if ip.version == 4 else "IPV6")
                and row["kind"] in ("CAMPAIGN_PROXY","KUBERNETES_API_PROXY")
                and type(row["port"]) is int and 1 <= row["port"] <= 65535, "endpoint family/type")
    return ids


def validate_record(record, profile, endpoints, schema):
    """Expected-data consistency; caller values do not provide native authority."""
    try:
        _shape(record, "record", schema)
        require(record["profileDigest"] == "sha256:" + digest(canonical(profile)), "profile substitution")
        binding = profile["binding"]
        require(record["scope"] == {k:binding[k] for k in record["scope"]}, "scope substitution")
        from datetime import datetime
        start, end = [datetime.strptime(record["scope"][k], "%Y-%m-%dT%H:%M:%SZ")
                      for k in ("validFrom","expiresAt")]
        require(start.strftime("%Y-%m-%dT%H:%M:%SZ") == record["scope"]["validFrom"]
                and end.strftime("%Y-%m-%dT%H:%M:%SZ") == record["scope"]["expiresAt"]
                and 0 < (end-start).total_seconds() <= 900, "canonical half-open window")
        ids = _endpoint_rows(endpoints)
        require(record["endpointTuples"] == endpoints, "endpoint tuple substitution")
        proxy = next((r for r in endpoints if r["endpointId"] == binding["endpointId"]), None)
        api = next((r for r in endpoints if r["endpointId"] == binding["apiEndpointId"]), None)
        require(proxy is not None and proxy["kind"] == "CAMPAIGN_PROXY"
                and ((api is not None and api["kind"] == "KUBERNETES_API_PROXY")
                     if profile["resources"] else binding["apiEndpointId"] is None), "profile endpoint kinds")
        status = record["selinux"]["status"]
        require(status["sequence"] % 2 == 0, "unstable policy epoch")
        files = {}
        for row in record["files"]:
            _path(row["path"])
            require(row["path"] not in files and row["sha256"] != row["verityDigest"],
                    "duplicate file or conflated digest")
            files[row["path"]] = row
            occupied = set()
            for segment in row["executableSegments"]:
                key = (segment["offset"],segment["length"],segment["permissions"])
                require(key not in occupied and segment["offset"] + segment["length"]
                        <= ((row["size"] + 4095)//4096)*4096, "executable segment outside artifact")
                occupied.add(key)
        require(sum(r["size"] for r in files.values()) <= 536870912, "code inventory bound")
        used = set()
        for role in ROLES:
            row = record["roles"][role]
            paths = row["filePaths"]
            require(set(paths) <= set(files) and row["executable"] in paths
                    and files[row["executable"]]["sha256"] == row["artifactDigest"], "role artifact custody")
            if row["interpreterPath"] is not None:
                require(row["interpreterPath"] in paths, "interpreter not enrolled")
            executable = row["interpreterPath"] or row["executable"]
            require(files[executable]["mode"] == "0555" and files[executable]["executableSegments"],
                    "actual executable missing")
            used.update(paths)
            require(set(row["outboundEndpointIds"]) <= ids, "network scope expanded")
            if role == "WORKER":
                require(not row["outboundEndpointIds"], "worker network grant")
            if role == "SERVER":
                require(row["outboundEndpointIds"] == ([binding["apiEndpointId"]] if profile["resources"] else []),
                        "server API leg differs")
            for hook in HOOKS:
                prog = row["bpfPrograms"][hook]
                require(prog["programType"] == (9 if hook == "INET_SOCK_CREATE" else 18)
                        and prog["instructionBytes"] % 8 == 0, "wrong kernel program type/length")
        require(used == set(files), "unowned code inventory")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, jsonschema.ValidationError):
        return ["invalid DATA_CHECK_ONLY qualification record; no native authority"]


def validate_capture(record, capture, role, schema, previous=None):
    """Detached model capture only. Production must inspect kernel via its owner."""
    try:
        _shape(record, "record", schema)
        _shape(capture, "capture", schema)
        require(type(role) is str and role in ROLES and capture["role"] == role
                and capture["qualificationDigest"] == "sha256:" + digest(canonical(record)), "capture binding")
        require(capture["host"] == record["host"], "wrong boot/kernel")
        status = record["selinux"]["status"]
        require(status["sequence"] % 2 == 0 and capture["selinuxBefore"] == status == capture["selinuxAfter"]
                and capture["kernelPolicyDigest"] == record["selinux"]["policyDigest"], "active policy changed")
        from datetime import datetime
        now = datetime.strptime(capture["observedAt"], "%Y-%m-%dT%H:%M:%SZ")
        start, end = [datetime.strptime(record["scope"][k], "%Y-%m-%dT%H:%M:%SZ")
                      for k in ("validFrom","expiresAt")]
        require(now.strftime("%Y-%m-%dT%H:%M:%SZ") == capture["observedAt"] and start <= now < end,
                "expired capture")
        a,b,d = [capture[k] for k in ("inspectionStartedMs","inspectionFinishedMs","deadlineMs")]
        require(a <= b < d and b-a <= 2000 and d-a <= 900000, "inspection deadline")
        expected, actual = record["roles"][role], capture["process"]
        for field in ("uid","gid","processLabel","namespaceInodes","cgroup","seccompMode"):
            require(actual[field] == expected[field], "process/kernel custody differs")
        rows = {r["path"]:r for r in record["files"]}
        observed = {}
        for item in capture["files"]:
            p = item["entry"]["path"]
            require(p not in observed and p in expected["filePaths"] and item["entry"] == rows[p]
                    and item["contentDigest"] == rows[p]["sha256"]
                    and item["measuredVerity"] == rows[p]["verityDigest"], "file measurement differs")
            observed[p] = item
        require(set(observed) == set(expected["filePaths"]), "incomplete loaded-code closure")
        mappings = []
        for p in expected["filePaths"]:
            for segment in rows[p]["executableSegments"]:
                mappings.append(dict(path=p, **segment,device=observed[p]["device"],inode=observed[p]["inode"]))
        key = lambda m: (m["path"],m["offset"],m["length"],m["permissions"],m["device"],m["inode"])
        require(sorted(capture["executableMaps"],key=key) == sorted(mappings,key=key), "missing or injected executable map")
        for hook in HOOKS:
            item, pinned_program = capture["bpfPrograms"][hook], expected["bpfPrograms"][hook]
            require(item["program"] == pinned_program and item["localIds"] == [pinned_program["programId"]]
                    and item["effectiveIds"] == item["localIds"], "effective kernel filter differs")
        if previous is not None:
            require(not validate_capture(record, previous, role, schema), "invalid retained capture")
            for field in ("host","process","files","executableMaps","bpfPrograms","selinuxBefore","selinuxAfter","kernelPolicyDigest"):
                require(capture[field] == previous[field], "retained native identity changed")
            require(capture["inspectionStartedMs"] >= previous["inspectionFinishedMs"]
                    and capture["observedAt"] >= previous["observedAt"]
                    and capture["deadlineMs"] == previous["deadlineMs"], "rollback or renewed lifetime")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, jsonschema.ValidationError):
        return ["invalid DATA_CHECK_ONLY capture; no native authority"]


def _tests(raw):
    names = []
    def visit(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                names.append(prefix + node.name)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
    visit(ast.parse(raw).body)
    require(len(names) == len(set(names)), "duplicate test identity")
    return names


def load_qualification_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    return record, {p:regular_bytes(root,p) for p in
                    {*record["protectedFiles"],*record["inputFiles"],*record["metaRecipes"]}}


def validate_qualification_authority(packets, record, inputs):
    try:
        pinned(record)
        require(not validate_additions(packets), "qualification packet differs")
        pins = {**record["protectedFiles"],**record["inputFiles"],
                **{p:r["afterSha256"] for p,r in record["metaRecipes"].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), "exact current inputs")
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(performance_history(path, inputs[path])) == checksum, "current input changed: "+path)
        old = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/")}
        require(len(old) == 143 and len(packets) == 194 and set(packets) == old | {"MET-REPAIR-015", "MET-PERF-002", "CONF-PERF-001", "MET-PERF-003", "CONF-PERF-002", "MET-PERF-004", "CONF-PERF-003", "MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001", "MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010", "MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}, "exact catalog")
        for name in old | {"MET-REPAIR-015"}:
            require(canonical(packets[name]) == canonical(safe_load(inputs["task-packets/"+name+".yaml"])), "packet bytes")
        packet = packets["MET-REPAIR-015"]
        previous = packets["MET-REPAIR-014"]["offlineAcceptanceCommands"]
        require(packet["offlineAcceptanceCommands"] == [*previous[:-2],
            ["uv","run","--offline","--frozen","--no-sync","python","scripts/validate_native_qualification.py"],
            *previous[-2:]] and len(packet["offlineAcceptanceCommands"]) == 23, "full cumulative commands")
        require(packet["allowedPaths"] == record["ownedPaths"], "path grant")
        before = parse(inputs[BEFORE_PATH])
        require(before["baseCommit"] == record["metaBaseline"] and set(before["files"]) == set(record["metaRecipes"]), "before inventory")
        for path, rule in record["metaRecipes"].items():
            raw = before["files"][path].encode()
            require(apply_recipe(raw,rule) == performance_history(path, inputs[path]), "unreviewed replacement")
            if path.startswith("tests/"):
                require(_tests(raw) == _tests(inputs[path]), "predecessor test lost")
        require(all(p in record["protectedFiles"] and digest(performance_history(p, inputs[p])) == checksum
                    for p,checksum in record["unchangedTests"].items()), "unchanged test pins")
        checkpoint = parse(inputs[CHECKPOINT_PATH])
        require(checkpoint["commit"] == record["sourceBaseline"]["commit"]
                and checkpoint["tree"] == record["sourceBaseline"]["tree"]
                and len(checkpoint["files"]) == 127 and sum(map(len,checkpoint["tests"].values())) == 327,
                "product predecessor checkpoint changed")
        for name, dispatch in record["dispatch"].items():
            require(packets[name]["allowedPaths"] == dispatch["paths"]
                    and packets[name]["offlineAcceptanceCommands"] == dispatch["commands"], "product scope changed")
        schema, vectors = parse(inputs[SCHEMA_PATH]), parse(inputs[VECTORS_PATH])
        jsonschema.Draft202012Validator.check_schema(schema)
        require(vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["nativeAcceptance"] is False
                and vectors["tenantAcceptance"] is False, "evidence promotion")
        for sample in vectors["positive"]:
            require(not validate_record(sample["record"],sample["profile"],sample["endpoints"],schema), "positive record")
            for capture in sample["captures"]:
                require(not validate_capture(sample["record"],capture,capture["role"],schema), "positive capture")
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError,jsonschema.ValidationError,jsonschema.SchemaError,yaml.YAMLError) as exc:
        return ["invalid qualification authority: "+(str(exc) if type(exc) is ValueError else type(exc).__name__)]


def main():
    try:
        packets = {p.stem:safe_load(regular_bytes(ROOT,str(p.relative_to(ROOT)))) for p in (ROOT/"task-packets").glob("*.yaml")}
        errors = validate_qualification_authority(packets,*load_qualification_inputs(ROOT))
    except (OSError,ValueError,TypeError,RecursionError,yaml.YAMLError):
        errors = ["native qualification authority unavailable"]
    for error in errors:
        print("ERROR: "+error)
    if not errors:
        print("Native qualification authority valid: 194 packets; 127/327 checkpoint; DATA_CHECK_ONLY; product/native NOT_RUN.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
