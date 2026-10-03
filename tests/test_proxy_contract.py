"""Independent data-contract tests. No product imports, TLS, credentials or probes."""
from copy import deepcopy
import ast
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_proxy_contract import (CASES, RECORD_SHA256, canonical, digest,
    load_proxy_inputs, parse, regular_bytes, validate_additions, validate_profile, validate_proxy_contract)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "architecture/proxy-contract-inputs/profile.schema.json").read_bytes())
VECTORS = json.loads((ROOT / "architecture/proxy-contract-inputs/vectors.json").read_bytes())


@pytest.fixture
def authority():
    packets = {p.stem: safe_yaml_load(p.read_text()) for p in (ROOT / "task-packets").glob("*.yaml")}
    return packets, *load_proxy_inputs(ROOT)


def nested_objects(value, path=()):
    if isinstance(value, dict):
        yield path, value
        for name, child in value.items():
            yield from nested_objects(child, path + (name,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from nested_objects(child, path + (index,))


def at(document, path):
    for item in path:
        document = document[item]
    return document


OBJECT_PATHS = [path for path, _ in nested_objects(VECTORS["positive"])]
REQUIRED_FIELDS = [(path, key) for path, obj in nested_objects(VECTORS["positive"]) for key in obj]


def test_exact_catalog_profile_and_recorded_source_checkpoint(authority):
    packets, record, inputs = authority
    assert validate_proxy_contract(*authority) == []
    assert len(packets) == 194 and len(record["protectedFiles"]) == 176
    assert digest(canonical(record)) == RECORD_SHA256
    baseline = parse(inputs["architecture/proxy-contract-inputs/baseline.json"])
    assert len(baseline["files"]) == 127 and baseline["testCount"] == 279
    assert sum(map(len, baseline["tests"].values())) == 279
    assert baseline["sourceClosure"]["mainReplay"]["tests"] == 279
    assert baseline["sourceClosure"]["ci"]["runId"] == 34182386653
    assert baseline["sourceClosure"]["nativeAcceptance"] is False
    assert record["diagnosis"]["productTestsRun"] == 0
    assert record["diagnosis"]["classification"] == "SOURCE_INSPECTION_ONLY"


def test_positive_data_is_not_execution_or_authentication():
    assert validate_profile(VECTORS["positive"], SCHEMA) == []
    assert VECTORS["evidenceClass"] == "UNIT_VERIFICATION_ONLY"
    assert VECTORS["nativeAcceptance"] is False


@pytest.mark.parametrize("vector", VECTORS["negative"], ids=lambda v: v["label"])
def test_independent_negative_vectors(vector):
    changed = deepcopy(VECTORS["positive"])
    parent = at(changed, vector["path"][:-1])
    parent[vector["path"][-1]] = deepcopy(vector["value"])
    assert validate_profile(changed, SCHEMA)


@pytest.mark.parametrize("path", OBJECT_PATHS, ids=str)
def test_every_nested_profile_object_rejects_unknown_fields(path):
    changed = deepcopy(VECTORS["positive"])
    at(changed, path)["unreviewedAuthority"] = True
    assert validate_profile(changed, SCHEMA)


@pytest.mark.parametrize("path,key", REQUIRED_FIELDS, ids=str)
def test_every_nested_required_member_is_required(path, key):
    changed = deepcopy(VECTORS["positive"])
    del at(changed, path)[key]
    assert validate_profile(changed, SCHEMA)


def test_all_schema_objects_are_closed_not_only_the_root():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    objects = [obj for _, obj in nested_objects(SCHEMA) if obj.get("type") == "object"]
    assert len(objects) >= 20
    for obj in objects:
        assert obj["additionalProperties"] is False
        assert set(obj["required"]) == set(obj["properties"])
    for _, obj in nested_objects(SCHEMA):
        if "$ref" in obj:
            assert obj["$ref"].startswith("#/$defs/")


def test_each_capacity_array_has_closed_rows_or_explicit_empty_support():
    fields = SCHEMA["properties"]["capacityEntries"]["properties"]
    assert set(fields) == {"kubernetesApiRules", "campaignProxyRules", "permittedGvksAndVerbs",
        "preexistingResourceRefs", "preallocatedStorageRefs", "preallocatedAcceleratorRefs", "credentialIdentities"}
    for name, spec in fields.items():
        if name in ("preallocatedStorageRefs", "preallocatedAcceleratorRefs"):
            assert spec["maxItems"] == 0
        else:
            item = SCHEMA["$defs"][spec["items"]["$ref"].rsplit("/", 1)[1]]
            assert item["additionalProperties"] is False
            assert spec["maxItems"] <= 256 and spec["uniqueItems"] is True


def test_logical_duplicates_reject_even_with_different_bytes():
    for field in ("preexistingResourceRefs", "kubernetesApiRules", "permittedGvksAndVerbs"):
        changed = deepcopy(VECTORS["positive"])
        row = deepcopy(changed["capacityEntries"][field][0])
        if field == "preexistingResourceRefs":
            row["uid"] = "different-uid"
        elif field == "permittedGvksAndVerbs":
            row["names"] = ["different-name"]
        else:
            row["endpointId"] = "different-endpoint"
        changed["capacityEntries"][field].append(row)
        assert validate_profile(changed, SCHEMA)


def sample_kind(kind):
    profile = deepcopy(VECTORS["positive"])
    meta = deepcopy(profile["resources"][0]["manifest"]["metadata"])
    if kind == "Pod":
        amount = {"cpu": "100m", "memory": "1048576", "ephemeral-storage": "1048576"}
        image = "registry.local/probe@sha256:" + "3" * 64
        manifest = {"apiVersion": "v1", "kind": kind, "metadata": meta, "spec": {
            "restartPolicy": "Never", "serviceAccountName": "campaign", "automountServiceAccountToken": False,
            "enableServiceLinks": False, "hostNetwork": False, "hostPID": False, "hostIPC": False,
            "containers": [{"name": "probe", "image": image, "imagePullPolicy": "Never",
                "resources": {"requests": amount, "limits": dict(amount)},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                    "runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"},
                    "capabilities": {"drop": ["ALL"]}}}]}}
        profile["quota"] = dict(pods=1, configMaps=0, services=0, cpuMillis=100,
                                memoryBytes=1048576, ephemeralStorageBytes=1048576)
        profile["localImages"] = [image]
        resource = "pods"
    else:
        manifest = {"apiVersion": "v1", "kind": "Service", "metadata": meta,
            "spec": {"type": "ClusterIP", "selector": dict(meta["labels"]),
                "ports": [{"name": "probe", "protocol": "TCP", "port": 8080, "targetPort": 8080}]}}
        profile["quota"] = dict(pods=0, configMaps=0, services=1, cpuMillis=0, memoryBytes=0, ephemeralStorageBytes=0)
        resource = "services"
    profile["resources"] = [{"manifest": manifest, "manifestDigest": "sha256:" + hashlib.sha256(canonical(manifest)).hexdigest()}]
    profile["capacityEntries"]["permittedGvksAndVerbs"][0]["kind"] = kind
    for rule in profile["capacityEntries"]["kubernetesApiRules"]:
        rule["resource"] = resource
    return profile


@pytest.mark.parametrize("kind", ["Pod", "Service"])
def test_other_allowed_templates_and_exact_quota(kind):
    assert validate_profile(sample_kind(kind), SCHEMA) == []


@pytest.mark.parametrize("kind,path,value", [
    ("Pod", ("hostNetwork",), True), ("Pod", ("hostPID",), True),
    ("Pod", ("automountServiceAccountToken",), True), ("Pod", ("initContainers",), []),
    ("Pod", ("containers", 0, "image"), "registry.local/probe:latest"),
    ("Pod", ("containers", 0, "imagePullPolicy"), "IfNotPresent"),
    ("Pod", ("containers", 0, "imagePullPolicy"), "Always"),
    ("Pod", ("containers", 0, "securityContext", "seccompProfile", "type"), "Unconfined"),
    ("Pod", ("containers", 0, "command"), ["/bin/sh"]),
    ("Pod", ("containers", 0, "securityContext", "runAsUser"), 0),
    ("Pod", ("containers", 0, "securityContext", "readOnlyRootFilesystem"), False),
    ("Pod", ("containers", 0, "resources", "limits", "cpu"), "0.1"),
    ("Pod", ("containers", 0, "resources", "limits", "memory"), "1Gi"),
    ("Service", ("type",), "LoadBalancer"), ("Service", ("type",), "ExternalName"),
    ("Service", ("type",), "NodePort"), ("Service", ("ports", 0, "nodePort"), 32000),
    ("Service", ("selector", "planeon.ai/run-nonce"), "other-run"),
])
def test_signed_but_unsafe_manifest_still_refuses(kind, path, value):
    profile = sample_kind(kind)
    manifest = profile["resources"][0]["manifest"]
    at(manifest["spec"], path[:-1])[path[-1]] = value
    profile["resources"][0]["manifestDigest"] = "sha256:" + digest(canonical(manifest))
    assert validate_profile(profile, SCHEMA)


@pytest.mark.parametrize("path", [("imagePullPolicy",), ("securityContext", "seccompProfile")])
def test_missing_runtime_safety_defaults_are_not_inferred(path):
    profile = sample_kind("Pod")
    manifest = profile["resources"][0]["manifest"]
    del at(manifest["spec"]["containers"][0], path[:-1])[path[-1]]
    profile["resources"][0]["manifestDigest"] = "sha256:" + digest(canonical(manifest))
    assert validate_profile(profile, SCHEMA)


@pytest.mark.parametrize("field", ["namespaceUid", "resourceQuotaUid", "limitRangeUid", "serviceAccountUid",
                                  "admissionPolicyDigest", "resourceQuotaDigest", "limitRangeDigest", "rbacDigest"])
def test_policy_members_cannot_be_missing_or_be_truth_flags(field):
    changed = deepcopy(VECTORS["positive"])
    changed["policy"][field] = True
    assert validate_profile(changed, SCHEMA)


def test_unsupported_storage_is_unavailable_not_silently_expanded():
    for name in ("preallocatedStorageRefs", "preallocatedAcceleratorRefs"):
        changed = deepcopy(VECTORS["positive"])
        changed["capacityEntries"][name] = [{"preexisting": True}]
        assert validate_profile(changed, SCHEMA)


@pytest.mark.parametrize("value", [None, [], "verified", True, 1, float("nan")])
def test_malformed_profiles_fail_closed(value):
    assert validate_profile(value, SCHEMA)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{'])
def test_duplicate_nonfinite_and_malformed_authority_json_refuses(raw):
    with pytest.raises((ValueError, TypeError)):
        parse(raw)


def test_cycles_depth_and_expanded_aliases_are_bounded():
    cycle = {}; cycle["cycle"] = cycle
    assert validate_profile(cycle, SCHEMA)
    value = "x" * 1024
    for _ in range(10):
        value = [value] * 16
    assert validate_profile({"expanded": value}, SCHEMA)


@pytest.mark.parametrize("field", ["profile", "dispatchGate", "sourceBaseline", "diagnosis", "evidence", "protectedFiles", "extra"])
def test_authority_cannot_be_widened_or_evidence_promoted(authority, field):
    packets, record, inputs = authority
    changed = deepcopy(record); changed[field] = True
    assert validate_proxy_contract(packets, changed, inputs)


@pytest.mark.parametrize("operation", ["missing", "extra", "bytes", "packet"])
def test_exact_immutable_input_inventory(authority, operation):
    packets, record, inputs = authority
    modified = dict(inputs)
    path = next(iter(record["protectedFiles"]))
    if operation == "missing": del modified[path]
    elif operation == "extra": modified["UNAUTHORIZED"] = b"x"
    elif operation == "bytes": modified[path] += b" "
    else:
        packets = deepcopy(packets)
        packets["CONF-LIVE-003"]["allowedPaths"].append("UNAUTHORIZED")
    assert validate_proxy_contract(packets, record, modified)


@pytest.mark.parametrize("field,value", [("allowedPaths", ["src/"]), ("prefetchCommands", [["curl", "x"]]),
                                       ("predecessors", []), ("repository", "mas-harness-conformance-labs")])
def test_new_packet_is_exact_and_all_predecessor_catalogs_check_it(authority, field, value):
    from scripts.validate_successor_inventory import load_successor_inputs, validate_successor_inventory
    from scripts.validate_packet_scalar_repair import load_scalar_inputs, validate_scalar_repair
    from scripts.validate_live_backend_readiness import load_live_inputs, validate_live_backend_readiness
    packets = deepcopy(authority[0]); packets["MET-REPAIR-009"][field] = value
    assert validate_additions(packets)
    assert validate_successor_inventory(packets, *load_successor_inputs(ROOT))
    assert validate_scalar_repair(packets, *load_scalar_inputs(ROOT))
    assert validate_live_backend_readiness(packets, *load_live_inputs(ROOT))


def test_data_oracle_cannot_import_or_execute_product_or_network_code():
    tree = ast.parse((ROOT / "scripts/validate_proxy_contract.py").read_text())
    imports = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    imports += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    assert not any(name.startswith(("harness_conformance", "socket", "ssl", "subprocess", "ctypes")) for name in imports)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"exec", "eval", "compile", "__import__"}


def test_readonly_authority_no_links_and_no_caller_path_inventory(tmp_path):
    import os
    source = tmp_path / "plain"; source.write_bytes(b"{}")
    (tmp_path / "link").symlink_to(source)
    os.link(source, tmp_path / "hard")
    for path in ("plain", "hard", "link", "../plain", "/plain", "a//b"):
        with pytest.raises((ValueError, OSError)):
            regular_bytes(tmp_path, path)
    (tmp_path / "architecture").mkdir()
    (tmp_path / "architecture/proxy-contract-amendment.json").write_bytes(b'{"inputFiles":{"../secret":"x"}}')
    with pytest.raises(ValueError):
        load_proxy_inputs(tmp_path)


def test_dispatch_preserves_product_and_runtime_boundaries(authority):
    packets, record, _ = authority
    assert record["dispatchGate"]["before"] == "CONF-LIVE-003"
    assert record["dispatchGate"]["consumerAllowedPathsUnchanged"] is True
    assert record["dispatchGate"]["stageCounts"] == [110, 120, 127, 135, 141, 146, 151]
    assert len(packets["CONF-LIVE-003"]["allowedPaths"]) == 8
    assert len(packets["CONF-LIVE-003"]["offlineAcceptanceCommands"]) == 8
    assert len(packets["MET-REPAIR-009"]["offlineAcceptanceCommands"]) == 15
    assert "liveCampaignExecution" not in packets["MET-REPAIR-009"]
    assert not record["dispatchGate"]["runtimeUnblocked"]
    text = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text().split("## Historical MET-REPAIR-008 publication checkpoint")[0]
    assert "MET-REPAIR-009" in text and "CONF-LIVE-003" in text and "ONGOING" in text
    assert "279" in text and "NOT_RUN_ENV_UNAVAILABLE" in text
