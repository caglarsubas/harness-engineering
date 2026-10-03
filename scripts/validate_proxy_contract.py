#!/usr/bin/env python3
"""Pinned proxy profile DATA oracle, never authentication or mutation authority."""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
import stat

import jsonschema
import yaml

try:
    from safe_yaml import safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import safe_load as safe_yaml_load

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/proxy-contract-amendment.json"
RECORD_SHA256 = "bf9b679d00e7ecd98b9d8c576ecd17201145a281c0019c2ca718607483048733"
PACKET_SHA256 = "91d5beb52180cb106b286cc298d4665ceb1ff186f9bb0d7770df5c01b8712426"
SCHEMA_SHA256 = "e3f3c175b51b0f93b6865e37d7d27624403891cc372542d719bc34a8381884a6"
ADDITIONS = ("MET-REPAIR-009", "MET-REPAIR-010", "MET-REPAIR-011", "CONF-FIX-004", "MET-PERF-001", "MET-REPAIR-012", "CONF-FIX-005", "MET-REPAIR-013", "MET-REPAIR-014", "MET-REPAIR-015", "MET-PERF-002", "CONF-PERF-001", "MET-PERF-003", "CONF-PERF-002", "MET-PERF-004", "CONF-PERF-003", "MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001", "MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010")
CASES = ["HOST_ISOLATION_NEGATIVES","LINUX_TARGET_BUILD","FULL_PREDECESSOR_REGRESSION","CONTROL_CONTAINER_STARTUP","POSTGRES_MIGRATION_AND_RLS","DURABLE_RESTART","ARBITRARY_NON_ROOT_UID","READ_ONLY_ROOT_FILESYSTEM","KUBERNETES_SMOKE","DEFAULT_DENY_NETWORK"]
PATHS = ["/v1/linux-baseline/" + item.lower().replace("_", "-") for item in CASES]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    output = {}
    for key, value in items:
        if key in output:
            raise ValueError("duplicate JSON member")
        output[key] = value
    return output


def reject_constant(_):
    raise ValueError("nonfinite JSON")


def parse(raw):
    if type(raw) is not bytes or len(raw) > 2097152:
        raise ValueError("bounded authority bytes required")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)


def regular_bytes(root, relative):
    if type(relative) is not str or relative.startswith("/") or "\\" in relative:
        raise ValueError("relative authority path required")
    parts = relative.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError("noncanonical authority path")
    path = root
    for index, part in enumerate(parts):
        path = path / part
        info = path.lstat()
        kind = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if not kind(info.st_mode) or index == len(parts) - 1 and info.st_nlink != 1:
            raise ValueError("linked or nonregular input")
    return path.read_bytes()


def load_proxy_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    if digest(canonical(record)) != RECORD_SHA256:
        raise ValueError("unreviewed proxy contract authority")
    return record, {p: regular_bytes(root, p) for p in
                    {*record["protectedFiles"], *record["inputFiles"]}}


def validate_additions(packets):
    try:
        if type(packets) is not dict or digest(canonical(packets.get(ADDITIONS[0]))) != PACKET_SHA256:
            return ["exact proxy prerequisite packet required"]
        try:
            from validate_policy_observation import validate_additions as observation_additions
        except ImportError:
            from scripts.validate_policy_observation import validate_additions as observation_additions
        return observation_additions(packets)
    except (TypeError, ValueError, RecursionError):
        return ["malformed proxy prerequisite packet"]


def _require(ok, message):
    if not ok:
        raise ValueError(message)


def _time(value):
    result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    _require(result.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "canonical UTC time required")
    return result


def _bounded(value, depth=0, budget=None):
    # Exact builtins only; charge aliased containers per occurrence before encoding.
    if budget is None:
        budget = [262144]
    _require(depth <= 16, "profile depth exceeded")
    kind = type(value)
    _require(kind in (dict, list, str, int, bool, type(None)), "non-data value")
    budget[0] -= len(value) if kind is str else 1
    _require(budget[0] >= 0, "profile size exceeded")
    if kind is int:
        _require(abs(value) <= 9007199254740991, "integer overflow")
    if kind is dict:
        for key, item in value.items():
            _require(type(key) is str, "string key required")
            _bounded(key, depth + 1, budget)
            _bounded(item, depth + 1, budget)
    elif kind is list:
        for item in value:
            _bounded(item, depth + 1, budget)


def validate_profile(profile, schema):
    """Pure shape/consistency checks only. Never verifies a certificate or authority."""
    try:
        _require(digest(canonical(schema)) == SCHEMA_SHA256, "reviewed schema required")
        _bounded(profile)
        _require(len(canonical(profile)) <= 262144, "profile size exceeded")
        jsonschema.Draft202012Validator(schema).validate(profile)
        binding, entries, policy = profile["binding"], profile["capacityEntries"], profile["policy"]
        start, end = _time(binding["validFrom"]), _time(binding["expiresAt"])
        _require(0 < (end - start).total_seconds() <= 900, "profile validity exceeded")
        subject = binding["serviceAccountSubject"]
        _require(subject.startswith("system:serviceaccount:" + binding["namespace"] + ":"), "subject namespace mismatch")
        credentials = entries["credentialIdentities"]
        expected_credentials = [(binding["endpointId"], "CAMPAIGN_PROXY_CLIENT_MTLS")]
        if profile["resources"]:
            _require(binding["apiEndpointId"] is not None and binding["apiEndpointId"] != binding["endpointId"],
                     "separate API endpoint required")
            expected_credentials.append((binding["apiEndpointId"], "KUBERNETES_PROXY_SERVER_MTLS"))
        else:
            _require(binding["apiEndpointId"] is None, "unused API endpoint forbidden")
        _require([(c["endpointId"], c["purpose"]) for c in credentials] == expected_credentials, "credential inventory mismatch")
        for item in credentials:
            _require(item["subject"] == subject and item["expiresAt"] == binding["expiresAt"], "credential binding mismatch")
        for field in ("certificateDigest", "clientSpkiDigest"):
            _require(len({c[field] for c in credentials}) == len(credentials), "client/server credential reuse")
        rule = entries["campaignProxyRules"][0]
        _require(rule["endpointId"] == binding["endpointId"] and rule["namespace"] == binding["namespace"]
                 and rule["paths"] == PATHS, "fixed proxy rule mismatch")
        reference_ids = set()
        references = entries["preexistingResourceRefs"]
        for item in references:
            key = (item["apiVersion"], item["kind"], item["namespace"], item["name"])
            _require(item["namespace"] == binding["namespace"] and key not in reference_ids, "duplicate or foreign reference")
            reference_ids.add(key)
        for kind, uid_key, digest_key in (("ResourceQuota", "resourceQuotaUid", "resourceQuotaDigest"),
                ("LimitRange", "limitRangeUid", "limitRangeDigest"), ("ServiceAccount", "serviceAccountUid", "serviceAccountDigest")):
            matches = [r for r in references if r["kind"] == kind]
            _require(len(matches) == 1 and matches[0]["uid"] == policy[uid_key]
                     and matches[0]["observedDigest"] == policy[digest_key], "required policy reference mismatch")
            if kind == "ServiceAccount":
                _require(matches[0]["name"] == subject.rsplit(":", 1)[1], "service account name mismatch")
        _require(len({r["uid"] for r in references}) == len(references), "duplicate resource UID")
        expected_labels = {"planeon.ai/run-nonce": binding["runNonce"], "planeon.ai/tenant-id": binding["tenantId"]}
        names, units, required_gvk, required_api = set(), dict.fromkeys(profile["quota"], 0), {}, set()
        kinds = {"Pod": ("pods", "pods"), "ConfigMap": ("configmaps", "configMaps"), "Service": ("services", "services")}
        images = set()
        for row in profile["resources"]:
            manifest = row["manifest"]
            raw = canonical(manifest)
            _require(len(raw) <= 16384 and row["manifestDigest"] == "sha256:" + digest(raw), "manifest digest or size mismatch")
            meta, kind = manifest["metadata"], manifest["kind"]
            key = (kind, meta["name"])
            _require(key not in names and meta["namespace"] == binding["namespace"]
                     and meta["labels"] == expected_labels, "resource scope or logical identity mismatch")
            _require(("v1", kind, meta["namespace"], meta["name"]) not in reference_ids, "existing resource takeover")
            names.add(key)
            required_gvk.setdefault(kind, set()).add(meta["name"])
            api_resource, unit = kinds[kind]
            units[unit] += 1
            required_api.update((binding["apiEndpointId"], verb, api_resource, meta["name"]) for verb in ("create", "get", "delete"))
            if kind == "Pod":
                spec = manifest["spec"]
                _require(spec["serviceAccountName"] == subject.rsplit(":", 1)[1], "pod service account mismatch")
                container = spec["containers"][0]
                quantities = container["resources"]
                _require(quantities["requests"] == quantities["limits"], "unequal requests and limits")
                units["cpuMillis"] += int(quantities["limits"]["cpu"][:-1])
                units["memoryBytes"] += int(quantities["limits"]["memory"])
                units["ephemeralStorageBytes"] += int(quantities["limits"]["ephemeral-storage"])
                images.add(container["image"])
            elif kind == "Service":
                _require(manifest["spec"]["selector"] == expected_labels, "foreign selector")
        observed_gvk = {}
        for rule in entries["permittedGvksAndVerbs"]:
            _require(rule["kind"] not in observed_gvk, "duplicate GVK rule")
            observed_gvk[rule["kind"]] = set(rule["names"])
        _require(observed_gvk == required_gvk, "exact GVK/name grants required")
        api = set()
        for rule in entries["kubernetesApiRules"]:
            key = (rule["endpointId"], rule["verb"], rule["resource"], rule["name"])
            _require(rule["namespace"] == binding["namespace"] and key not in api, "API scope or duplicate rule")
            api.add(key)
        _require(api == required_api, "exact server API rules required")
        _require(images == set(profile["localImages"]), "image substitution or unused image")
        _require(all(units[k] <= profile["quota"][k] for k in units), "quota exceeded")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError,
            jsonschema.ValidationError, jsonschema.SchemaError):
        return ["invalid strict proxy profile data"]


def validate_proxy_contract(packets, record, inputs):
    try:
        if digest(canonical(record)) != RECORD_SHA256 or type(inputs) is not dict:
            return ["exact reviewed proxy authority required"]
        errors = validate_additions(packets)
        pins = {**record["protectedFiles"], **record["inputFiles"]}
        old_ids = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/")}
        if len(old_ids) != 134 or len(record["protectedFiles"]) != 176 or set(packets) != old_ids | set(ADDITIONS) | {"MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}:
            errors.append("exact historical 134 plus exact proxy, observation and custody prerequisites required")
        if set(inputs) != set(pins):
            errors.append("exact proxy authority input inventory required")
        for path, checksum in pins.items():
            raw = inputs.get(path)
            if type(raw) is not bytes or digest(raw) != checksum:
                errors.append("immutable proxy input changed: " + path)
            elif path.startswith("task-packets/") and canonical(packets.get(Path(path).stem)) != canonical(safe_yaml_load(raw)):
                errors.append("packet semantics/bytes differ: " + path)
        baseline = parse(inputs["architecture/proxy-contract-inputs/baseline.json"])
        if (baseline["commit"] != record["sourceBaseline"]["commit"] or len(baseline["files"]) != 127
                or baseline["testCount"] != 279 or sum(map(len, baseline["tests"].values())) != 279
                or baseline["tree"] != record["sourceBaseline"]["tree"]):
            errors.append("127-file/279-ID exact source baseline required")
        schema = parse(inputs[record["profile"]["schemaPath"]])
        vectors = parse(inputs[record["profile"]["vectorsPath"]])
        jsonschema.Draft202012Validator.check_schema(schema)
        errors.extend(validate_profile(vectors["positive"], schema))
        if vectors["evidenceClass"] != "UNIT_VERIFICATION_ONLY" or vectors["nativeAcceptance"] is not False:
            errors.append("fixture evidence promotion forbidden")
        return errors
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError, yaml.YAMLError,
            jsonschema.SchemaError):
        return ["malformed proxy authority"]


def main():
    try:
        packets = {p.stem: safe_yaml_load(regular_bytes(ROOT, str(p.relative_to(ROOT))))
                   for p in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_proxy_contract(packets, *load_proxy_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError) as exc:
        errors = ["proxy authority unavailable: " + type(exc).__name__]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Proxy prerequisite valid: 194 packets; 176 immutable authority files; 127-file/279-ID source checkpoint; product/native NOT_RUN.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
