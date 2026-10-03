"""Observation protocol tests are DATA_ONLY, never installed-peer or live proof."""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_policy_observation import (ZERO, RECORD_SHA256, SCHEMA_SHA256,
    canonical, digest, load_observation_inputs, validate_additions,
    validate_messages, validate_observation_contract)
from scripts.validate_proxy_contract import validate_profile, regular_bytes

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "architecture/policy-observation-inputs/channel.schema.json").read_bytes())
VECTORS = json.loads((ROOT / "architecture/policy-observation-inputs/vectors.json").read_bytes())
PROFILE = json.loads((ROOT / "architecture/proxy-contract-inputs/vectors.json").read_bytes())["positive"]
PROFILE_SCHEMA = json.loads((ROOT / "architecture/proxy-contract-inputs/profile.schema.json").read_bytes())


@pytest.fixture
def authority():
    packets = {p.stem: safe_yaml_load(p.read_text()) for p in (ROOT / "task-packets").glob("*.yaml")}
    return packets, *load_observation_inputs(ROOT)


def validate(value):
    return validate_messages(**value, profile=PROFILE, schema=SCHEMA)


def nested(value, path=()):
    if type(value) is dict:
        yield path, value
        for key, child in value.items():
            yield from nested(child, path + (key,))
    elif type(value) is list:
        for i, child in enumerate(value):
            yield from nested(child, path + (i,))


def at(value, path):
    for key in path:
        value = value[key]
    return value


OBJECTS = [(kind, path) for kind in ("binding", "request", "observation")
           for path, _ in nested(VECTORS["positive"][kind])]
FIELDS = [(kind, path, field) for kind, path in OBJECTS
          for field in at(VECTORS["positive"][kind], path)]


def test_exact_catalog_and_independent_source_evidence(authority):
    packets, record, inputs = authority
    assert validate_observation_contract(*authority) == []
    assert len(packets) == 194 and len(record["protectedFiles"]) == 186
    assert digest(canonical(record)) == RECORD_SHA256
    assert digest(canonical(SCHEMA)) == SCHEMA_SHA256
    baseline = json.loads(inputs["architecture/proxy-contract-inputs/baseline.json"])
    assert baseline["commit"] == "7205075d2f234b622dd61072803b754f1dffeb79"
    assert len(baseline["files"]) == 127 and sum(map(len, baseline["tests"].values())) == 279
    assert record["diagnosis"]["productTestsRun"] == record["diagnosis"]["liveRequestsRun"] == 0
    assert record["diagnosis"]["classification"] == "SOURCE_INSPECTION_ONLY"
    assert record["channel"]["producerAvailable"] is False
    assert record["channel"]["installationAuthorized"] is False


def test_positive_is_only_data_and_never_native_authority():
    assert validate(deepcopy(VECTORS["positive"])) == []
    assert VECTORS["evidenceClass"] == "UNIT_VERIFICATION_ONLY"
    assert VECTORS["nativeAcceptance"] is False


@pytest.mark.parametrize("vector", VECTORS["negative"], ids=lambda v: v["label"])
def test_independent_negative_vectors(vector):
    value = deepcopy(VECTORS["positive"])
    at(value[vector["document"]], vector["path"][:-1])[vector["path"][-1]] = vector["value"]
    assert validate(value)


@pytest.mark.parametrize("kind,path", OBJECTS, ids=str)
def test_every_nested_message_object_is_closed(kind, path):
    value = deepcopy(VECTORS["positive"])
    at(value[kind], path)["verified"] = True
    assert validate(value)


@pytest.mark.parametrize("kind,path,field", FIELDS, ids=str)
def test_every_message_member_is_required(kind, path, field):
    value = deepcopy(VECTORS["positive"])
    del at(value[kind], path)[field]
    assert validate(value)


@pytest.mark.parametrize("kind", ("binding", "request", "observation"))
@pytest.mark.parametrize("bad", (None, [], True, 1, "verified", float("nan")))
def test_wrong_document_types_never_become_authority(kind, bad):
    value = deepcopy(VECTORS["positive"]); value[kind] = bad
    assert validate(value)


def test_complete_closed_schema_with_local_refs():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    for _, value in nested(SCHEMA):
        if value.get("type") == "object":
            assert value["additionalProperties"] is False
            assert set(value["properties"]) == set(value["required"])
        if "$ref" in value:
            assert value["$ref"].startswith("#/$defs/")


@pytest.mark.parametrize("bad", ["100\n", "100\r", "100\u0000", "\u00e9", "100\t", "\u202e100"])
def test_control_unicode_and_final_newline_fields_are_not_canonical_ids(bad):
    value = deepcopy(VECTORS["positive"])
    value["observation"]["namespace"]["resourceVersion"] = bad
    assert validate(value)


@pytest.mark.parametrize("resource", ["namespaces", "resourcequotas", "limitranges",
    "serviceaccounts", "roles", "rolebindings", "clusterrolebindings",
    "validatingadmissionpolicies", "networkpolicies"])
def test_observation_does_not_expand_existing_api_grants(resource):
    value = deepcopy(PROFILE)
    rule = deepcopy(value["capacityEntries"]["kubernetesApiRules"][0])
    rule.update(verb="get", resource=resource)
    value["capacityEntries"]["kubernetesApiRules"].append(rule)
    assert validate_profile(value, PROFILE_SCHEMA)
    assert validate_profile(PROFILE, PROFILE_SCHEMA) == []


@pytest.mark.parametrize("field", ["url", "argv", "namespace", "resource", "verb", "socket",
    "credentialFileReference", "fd", "trusted", "token", "signature", "nativeAcceptance"])
def test_request_cannot_select_transport_or_mutation_or_authority(field):
    value = deepcopy(VECTORS["positive"]); value["request"][field] = True
    assert validate(value)


def chained():
    value = deepcopy(VECTORS["positive"])
    previous = deepcopy(value["observation"])
    value["previous"] = previous
    for obj in (value["request"], value["observation"]):
        obj["sequence"] = 2
        obj["challenge"] = "d" * 64
        obj["previousObservationDigest"] = "sha256:" + digest(canonical(previous))
    value["observation"]["observedAt"] = "2026-09-08T00:00:02Z"
    value["observation"]["expiresAt"] = "2026-09-08T00:00:06Z"
    value["now"] = "2026-09-08T00:00:03Z"
    return value


def test_contiguous_observation_chain_requires_same_boot_and_generation():
    assert validate(chained()) == []


@pytest.mark.parametrize("field,bad", [("observerBootId", "12345678-1234-1234-1234-123456789abd"),
    ("generation", "c" * 64), ("sequence", 3), ("challenge", "a" * 64),
    ("previousObservationDigest", ZERO), ("observedAt", "2026-09-08T00:00:00Z")])
def test_restart_replay_gap_generation_drift_and_clock_rollback_refuse(field, bad):
    value = chained(); value["observation"][field] = bad
    # Preserve response echo for tests of semantic chain restrictions.
    if field in value["request"]:
        value["request"][field] = bad
    if field == "generation":
        value["observation"]["enforcement"]["policyGeneration"] = bad
    assert validate(value)


@pytest.mark.parametrize("bad", ["2026-09-08T00:00:00Z", "2026-09-08T00:00:05Z",
    "2026-09-08T00:00:06Z", "2026-09-08T00:00:02+00:00", "2026-09-08T00:00:02.0Z"])
def test_half_open_utc_freshness_and_future_observations(bad):
    value = deepcopy(VECTORS["positive"]); value["now"] = bad
    assert validate(value)


@pytest.mark.parametrize("key", ["admissionFenceDigest", "rbacClosureDigest",
    "networkEnforcementDigest", "hostPreflightDigest"])
def test_each_enforcement_pin_is_required_and_must_match(key):
    value = deepcopy(VECTORS["positive"])
    value["observation"]["enforcement"][key] = ZERO
    assert validate(value)


def test_actual_quota_and_whole_run_reservation_are_independent():
    value = deepcopy(VECTORS["positive"])
    value["observation"]["quota"]["used"]["configMaps"] = 1
    assert validate(value) == []
    value["observation"]["quota"]["used"]["configMaps"] = 2
    assert validate(value)


def test_empty_resource_profile_still_requires_observation_not_api_access():
    profile = deepcopy(PROFILE)
    profile["resources"] = []
    profile["quota"] = {k: 0 for k in profile["quota"]}
    profile["binding"]["apiEndpointId"] = None
    profile["capacityEntries"]["credentialIdentities"] = profile["capacityEntries"]["credentialIdentities"][:1]
    profile["capacityEntries"]["kubernetesApiRules"] = []
    profile["capacityEntries"]["permittedGvksAndVerbs"] = []
    assert validate_profile(profile, PROFILE_SCHEMA) == []
    value = deepcopy(VECTORS["positive"])
    value["binding"]["profileDigest"] = "sha256:" + digest(canonical(profile))
    for doc in ("request", "observation"):
        value[doc]["bindingDigest"] = "sha256:" + digest(canonical(value["binding"]))
    assert validate_messages(**value, profile=profile, schema=SCHEMA) == []
    value["observation"] = None
    assert validate_messages(**value, profile=profile, schema=SCHEMA)


def test_cycles_depth_and_exponential_aliases_are_bounded():
    for cyclic in (False, True):
        value = deepcopy(VECTORS["positive"])
        large = {}
        if cyclic:
            large["cycle"] = large
        else:
            large = "x" * 1024
            for _ in range(12):
                large = [large] * 16
        value["observation"] = large
        assert validate(value)


@pytest.mark.parametrize("mode", ["missing", "extra", "bytes", "semantic"])
def test_complete_protected_authority_inventory(authority, mode):
    packets, record, inputs = authority
    changed = dict(inputs)
    path = "task-packets/CONF-LIVE-003.yaml"
    if mode == "missing": del changed[path]
    elif mode == "extra": changed["UNAUTHORIZED"] = b"x"
    elif mode == "bytes": changed[path] += b" "
    else:
        packets = deepcopy(packets); packets["CONF-LIVE-003"]["allowedPaths"].append("src/")
    assert validate_observation_contract(packets, record, changed)


@pytest.mark.parametrize("field", ["channel", "protectedFiles", "inputFiles", "dispatchGate", "evidence", "extra"])
def test_amendment_cannot_be_widened_or_promoted(authority, field):
    packets, record, inputs = authority
    value = deepcopy(record); value[field] = True
    assert validate_observation_contract(packets, value, inputs)


@pytest.mark.parametrize("field,bad", [("allowedPaths", ["src/"]), ("predecessors", []),
    ("repository", "mas-harness-conformance-labs"), ("offlineAcceptanceCommands", [])])
def test_predecessor_catalogs_validate_exact_new_packet(authority, field, bad):
    from scripts.validate_proxy_contract import load_proxy_inputs, validate_proxy_contract
    from scripts.validate_successor_inventory import load_successor_inputs, validate_successor_inventory
    from scripts.validate_packet_scalar_repair import load_scalar_inputs, validate_scalar_repair
    from scripts.validate_live_backend_readiness import load_live_inputs, validate_live_backend_readiness
    packets = deepcopy(authority[0]); packets["MET-REPAIR-010"][field] = bad
    assert validate_additions(packets)
    assert validate_proxy_contract(packets, *load_proxy_inputs(ROOT))
    assert validate_successor_inventory(packets, *load_successor_inputs(ROOT))
    assert validate_scalar_repair(packets, *load_scalar_inputs(ROOT))
    assert validate_live_backend_readiness(packets, *load_live_inputs(ROOT))


def test_no_product_network_or_execution_import_in_oracle():
    tree = ast.parse((ROOT / "scripts/validate_policy_observation.py").read_bytes())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            assert not any(n.startswith(("harness_conformance", "socket", "ssl", "subprocess", "ctypes")) for n in names)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile", "__import__"}


def test_unknown_authority_cannot_choose_paths(tmp_path):
    (tmp_path / "architecture").mkdir()
    (tmp_path / "architecture/policy-observation-amendment.json").write_bytes(b'{"protectedFiles":{"../secret":"x"}}')
    with pytest.raises(ValueError):
        load_observation_inputs(tmp_path)


def test_exact_dispatch_and_source_only_ownership(authority):
    packets, record, _ = authority
    gate = record["dispatchGate"]
    assert gate["before"] == "CONF-LIVE-003" and gate["requiresCompletedPacket"] == "MET-REPAIR-010"
    assert gate["consumerAllowedPathsUnchanged"] is True
    assert gate["stageCounts"] == [110, 120, 127, 135, 141, 146, 151]
    assert not gate["runtimeUnblocked"]
    assert len(packets["CONF-LIVE-003"]["allowedPaths"]) == 8
    assert len(packets["CONF-LIVE-003"]["offlineAcceptanceCommands"]) == 8
    assert len(packets["MET-REPAIR-010"]["offlineAcceptanceCommands"]) == 16
    assert "liveCampaignExecution" not in packets["MET-REPAIR-010"]
    assert packets["MET-REPAIR-010"]["sourceReuse"] == []
    current = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text().split("## Historical MET-REPAIR-009")[0]
    assert "during `MET-REPAIR-010` publication" in current
    assert "279" in current and "NOT_RUN_ENV_UNAVAILABLE" in current
    assert "| Alpha 2 authority | `MET-REPAIR-009` | DONE" in current
    assert "| Alpha 2 backend | `CONF-LIVE-003` | WAITING" in current
    assert record["previousClosure"]["timeoutRelaxed"] is False
    assert record["previousClosure"]["firstAttempt"] == "NOT_PASS_NESTED_PREDECESSOR_420_SECOND_TIMEOUT"
