#!/usr/bin/env python3
"""Protected observation DATA oracle. No socket, product import or execution grant."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import yaml

try:
    from safe_yaml import safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import safe_load as safe_yaml_load

try:
    from validate_proxy_contract import (canonical, digest, parse, regular_bytes, _bounded,
                                         _time, _require, validate_profile)
except ImportError:
    from scripts.validate_proxy_contract import (canonical, digest, parse, regular_bytes,
                                                _bounded, _time, _require, validate_profile)

try:
    from validate_credential_ordering import historical_bytes, current_test_bytes, validate_additions as ordering_additions
except ImportError:
    from scripts.validate_credential_ordering import historical_bytes, current_test_bytes, validate_additions as ordering_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/policy-observation-amendment.json"
RECORD_SHA256 = "a579f7464ddd1b8de2e888734b9c249f13e9fccc02ad3001e6114f1d74332734"
PACKET_SHA256 = "fe936ede385abb790dbba18d05fa007184296eb81bd23fcf5ae5d14e0b8be112"
SCHEMA_SHA256 = "d4ac4deef49bea39ff7d010e3fe75d75ac446b3d87db4b2e59ee49ef12d02e72"
ADDITIONS = ("MET-REPAIR-010", "MET-REPAIR-011", "CONF-FIX-004", "MET-PERF-001", "MET-REPAIR-012", "CONF-FIX-005", "MET-REPAIR-013", "MET-REPAIR-014", "MET-REPAIR-015", "MET-PERF-002", "CONF-PERF-001", "MET-PERF-003", "CONF-PERF-002", "MET-PERF-004", "CONF-PERF-003", "MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001", "MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010")
ZERO = "sha256:" + "0" * 64
POLICIES = ("admissionPolicy", "resourceQuota", "limitRange", "serviceAccount",
            "rbac", "networkPolicy", "mutationBroker")


def validate_additions(packets):
    try:
        if type(packets) is not dict or digest(canonical(packets.get(ADDITIONS[0]))) != PACKET_SHA256:
            return ["exact policy-observation prerequisite packet required"]
        try:
            from validate_custody_handoff import validate_additions as custody_additions
        except ImportError:
            from scripts.validate_custody_handoff import validate_additions as custody_additions
        return custody_additions(packets)
    except (TypeError, ValueError, RecursionError):
        return ["malformed observation packet"]


def load_observation_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    if digest(canonical(record)) != RECORD_SHA256:
        raise ValueError("unreviewed observation authority")
    return record, {p: regular_bytes(root, p) for p in
                    {*record["protectedFiles"], *record["inputFiles"]}}


def _ascii_fields(value):
    # Every field in this private protocol has an ASCII grammar. JSON Schema's
    # end anchor may match before a final newline; reject that ambiguity here.
    if type(value) is str:
        _require(all(32 <= ord(char) <= 126 for char in value), "non-ASCII or control field")
    elif type(value) is dict:
        for key, child in value.items():
            _ascii_fields(key)
            _ascii_fields(child)
    elif type(value) is list:
        for child in value:
            _ascii_fields(child)


def _shape(value, variant, schema, maximum):
    _bounded(value)
    _ascii_fields(value)
    _require(len(canonical(value)) <= maximum, "observation bytes exceeded")
    spec = {"$ref": "#/$defs/" + variant, "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator(spec).validate(value)


def validate_messages(binding, request, observation, profile, schema, now, previous=None):
    """Detached shape/consistency only; expected state must have independent custody."""
    try:
        _require(digest(canonical(schema)) == SCHEMA_SHA256, "reviewed schema required")
        _shape(binding, "binding", schema, 65536)
        _shape(request, "request", schema, 16384)
        _shape(observation, "observation", schema, 65536)
        _bounded(profile)
        _require(binding["profileDigest"] == "sha256:" + digest(canonical(profile)), "profile digest")
        scope = {k: v for k, v in profile["binding"].items() if k != "apiEndpointId"}
        _require(binding["scope"] == scope, "independent profile scope")
        _require(binding["namespace"] == {"name": scope["namespace"], "uid": profile["policy"]["namespaceUid"]},
                 "namespace binding")
        refs = profile["capacityEntries"]["preexistingResourceRefs"]
        for key in POLICIES:
            expected = binding["projections"][key]
            _require(expected["projectionDigest"] == profile["policy"][key + "Digest"], "policy digest")
            _require(expected["namespace"] in (None, scope["namespace"]), "foreign policy")
            if key in ("resourceQuota", "limitRange", "serviceAccount"):
                kind = {"resourceQuota": "ResourceQuota", "limitRange": "LimitRange", "serviceAccount": "ServiceAccount"}[key]
                matches = [r for r in refs if r["kind"] == kind]
                _require(len(matches) == 1, "required reference")
                ref = matches[0]
                _require(expected == {**{k: ref[k] for k in ("apiVersion", "kind", "namespace", "name", "uid")},
                                      "projectionDigest": ref["observedDigest"]}, "policy identity")
            actual = {k: v for k, v in observation["projections"][key].items() if k != "resourceVersion"}
            _require(actual == expected, "observed identity or digest")
        _require({k: observation["namespace"][k] for k in ("name", "uid")} == binding["namespace"], "observed namespace")
        _require(request["bindingDigest"] == "sha256:" + digest(canonical(binding))
                 and request["runNonce"] == scope["runNonce"], "request binding")
        for field in ("bindingDigest", "runNonce", "challenge", "sequence", "previousObservationDigest"):
            _require(observation[field] == request[field], "response substitution")
        if previous is None:
            _require(request["sequence"] == 1 and request["previousObservationDigest"] == ZERO, "initial chain")
        else:
            _shape(previous, "observation", schema, 65536)
            _require(previous["bindingDigest"] == request["bindingDigest"]
                     and previous["runNonce"] == request["runNonce"]
                     and request["sequence"] == previous["sequence"] + 1
                     and request["previousObservationDigest"] == "sha256:" + digest(canonical(previous)), "chain gap")
            _require(observation["observerBootId"] == previous["observerBootId"]
                     and observation["generation"] == previous["generation"]
                     and request["challenge"] != previous["challenge"], "restart, drift or reused challenge")
            _require(_time(observation["observedAt"]) >= _time(previous["observedAt"]), "clock rollback")
        start, end, instant = _time(observation["observedAt"]), _time(observation["expiresAt"]), _time(now)
        _require(_time(scope["validFrom"]) <= start <= instant < end <= _time(scope["expiresAt"]), "stale or future")
        _require(0 < (end - start).total_seconds() <= 5, "freshness window")
        _require(observation["enforcement"] == {"policyGeneration": observation["generation"],
                                               **binding["enforcementPins"]}, "enforcement proof mismatch")
        for unit, requested in profile["quota"].items():
            hard, used = observation["quota"]["hard"][unit], observation["quota"]["used"][unit]
            _require(type(requested) is int and 0 <= requested <= 9007199254740991
                     and used <= hard and requested <= hard - used, "actual quota headroom")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError,
            jsonschema.ValidationError, jsonschema.SchemaError):
        return ["invalid protected observation data"]


def validate_observation_contract(packets, record, inputs):
    try:
        if digest(canonical(record)) != RECORD_SHA256 or type(inputs) is not dict:
            return ["exact observation authority required"]
        errors = validate_additions(packets)
        old_ids = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/")}
        if len(old_ids) != 135 or set(packets) != old_ids | set(ADDITIONS) | {"MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}:
            errors.append("135 immutable predecessors plus exact observation and custody packets required")
        pins = {**record["protectedFiles"], **record["inputFiles"]}
        if set(inputs) != set(pins):
            errors.append("exact observation input inventory required")
        for path, checksum in pins.items():
            raw = historical_bytes(path, inputs.get(path))
            if type(raw) is not bytes or digest(raw) != checksum:
                errors.append("immutable observation input changed: " + path)
            elif path.startswith("task-packets/") and canonical(packets.get(Path(path).stem)) != canonical(safe_yaml_load(raw)):
                errors.append("predecessor packet differs: " + path)
        baseline = parse(inputs["architecture/proxy-contract-inputs/baseline.json"])
        if len(baseline["files"]) != 127 or baseline["testCount"] != 279 or sum(map(len, baseline["tests"].values())) != 279:
            errors.append("127-file/279-ID baseline required")
        schema = parse(inputs[record["channel"]["schemaPath"]])
        vectors = parse(inputs[record["channel"]["vectorsPath"]])
        profile = parse(inputs["architecture/proxy-contract-inputs/vectors.json"])["positive"]
        profile_schema = parse(inputs["architecture/proxy-contract-inputs/profile.schema.json"])
        jsonschema.Draft202012Validator.check_schema(schema)
        errors.extend(validate_profile(profile, profile_schema))
        positive = vectors["positive"]
        errors.extend(validate_messages(**positive, profile=profile, schema=schema))
        if vectors["evidenceClass"] != "UNIT_VERIFICATION_ONLY" or vectors["nativeAcceptance"] is not False:
            errors.append("observation data cannot grant native acceptance")
        return errors
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, yaml.YAMLError,
            jsonschema.SchemaError):
        return ["malformed observation authority"]


def main():
    try:
        packets = {p.stem: safe_yaml_load(regular_bytes(ROOT, str(p.relative_to(ROOT))))
                   for p in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_observation_contract(packets, *load_observation_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        errors = ["observation authority unavailable"]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Policy observation authority valid: 194 packets; unchanged 127-file/279-ID baseline; DATA_CHECK_ONLY, product/native NOT_RUN.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
