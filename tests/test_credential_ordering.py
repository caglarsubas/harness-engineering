"""Independent source/data tests, not a TLS handshake, observation or native run."""
import ast
from copy import deepcopy
import json
from pathlib import Path

import pytest
from scripts.validate_broker_handoff import historical_bytes as broker_history

from scripts.safe_yaml import safe_load
from scripts.validate_credential_ordering import (
    BEFORE_PATH, CHECKPOINT_PATH, SOURCE_PATH, VECTORS_PATH, CLIENT_TRACE, SERVER_TRACE,
    apply_recipe, canonical, current_test_bytes, digest, historical_bytes,
    load_ordering_inputs, validate_additions, validate_credential_ordering,
    validate_recipes, validate_trace,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem: safe_load(p.read_bytes()) for p in (ROOT / "task-packets").glob("*.yaml")}
    return packets, *load_ordering_inputs(ROOT)


def test_exact_142_catalog_and_corrected_127_327_checkpoint(authority):
    packets, record, inputs = authority
    assert validate_credential_ordering(*authority) == []
    assert len(packets) == 194
    assert len([p for p in record["protectedFiles"] if p.startswith("task-packets/")]) == 141
    checkpoint = json.loads(inputs[CHECKPOINT_PATH])
    assert len(checkpoint["files"]) == 127
    assert sum(map(len, checkpoint["tests"].values())) == 327
    assert record["sourceBaseline"]["commit"] == "9df7dd7f2df8ac64096ef37d8df259761947d552"
    assert record["sourceBaseline"]["tree"] == "1310cc74cc0ed39cfeb1068e998a0f78502a4be4"
    assert record["dispatchGate"]["stageCounts"] == [110,120,127,135,141,146,151]
    assert len(packets["CONF-LIVE-003"]["allowedPaths"]) == 8
    assert len(packets["CONF-LIVE-003"]["offlineAcceptanceCommands"]) == 8
    assert len(packets["MET-REPAIR-013"]["offlineAcceptanceCommands"]) == 21


def test_approved_exception_does_not_move_server_execution_gate(authority):
    rule = authority[1]["ordering"]
    assert rule["exceptionPurpose"] == "CAMPAIGN_PROXY_CLIENT_MTLS"
    assert rule["clientGuardMeaning"] == "CLIENT_AUTHENTICATION_ELIGIBILITY"
    assert rule["serverObserverOnly"] is True
    assert rule["serverPolicyBeforeCredentialsAndEffects"] is True
    assert rule["transactionalGenerationFenceRequired"] is True
    assert not any(rule[k] for k in ("clientObserverAccess", "newEndpoint", "newPublicField",
                                   "authenticationGrantsExecution", "clientCredentialBeforeLocalGates"))
    assert authority[1]["evidence"]["nativeAcceptance"] is False
    assert authority[1]["evidence"]["tenantAcceptance"] is False
    assert authority[1]["evidence"]["productExecution"] == "NOT_RUN"


def test_source_inspection_establishes_real_guard_and_socket_dependency(authority):
    source = json.loads(authority[2][SOURCE_PATH])["files"]
    from scripts.validate_custody_handoff import definitions
    linux = source["src/harness_conformance/live_linux_boundary.py"].encode()
    _, regions = definitions(linux)
    a, b, _ = regions["_LateResources.credential_bytes"]
    method = linux[a:b]
    assert method.index(b"self._guard()") < method.index(b"os.open(")
    a, b, _ = regions["_LateResources.transport"]
    method = linux[a:b]
    assert method.index(b"self.raw is not None") < method.index(b"socket.socket(")
    supervisor = source["src/harness_conformance/live_supervisor.py"].encode()
    _, regions = definitions(supervisor)
    a, b, _ = regions["_require_current_credential_policy"]
    assert b"guard(context, context._deadline) is None" in supervisor[a:b]
    assert all(not key.startswith("warm") for key in source)


@pytest.mark.parametrize("role,resources", [("CLIENT", False), ("CLIENT", True), ("SERVER", False), ("SERVER", True)])
def test_complete_data_sequences_remain_non_authorizing(authority, role, resources):
    vectors = json.loads(authority[2][VECTORS_PATH])
    trace = vectors["client" if role == "CLIENT" else "server" if resources else "serverWithoutResources"]
    assert validate_trace(role, trace, resources=resources) == []
    assert vectors["evidenceClass"] == "DATA_CHECK_ONLY"
    assert vectors["nativeAcceptance"] is vectors["tenantAcceptance"] is False


@pytest.mark.parametrize("role,trace", [("CLIENT", CLIENT_TRACE), ("SERVER", SERVER_TRACE)])
def test_every_gate_omission_swap_duplicate_and_unknown_event_refuses(role, trace):
    for index in range(len(trace)):
        omitted = list(trace[:index] + trace[index+1:])
        duplicated = list(trace[:index] + (trace[index],) + trace[index:])
        changed = list(trace)
        changed[index] = "POLICY_LOST"
        assert validate_trace(role, omitted, resources=True), (role, index)
        assert validate_trace(role, duplicated, resources=True), (role, index)
        assert validate_trace(role, changed, resources=True), (role, index)
        if index + 1 < len(trace):
            swapped = list(trace)
            swapped[index:index+2] = reversed(swapped[index:index+2])
            assert validate_trace(role, swapped, resources=True), (role, index)


@pytest.mark.parametrize("injection", ["OBSERVER_CONNECTION", "UPSTREAM_CREDENTIAL", "FIXED_PROBE",
    "MUTATION", "NATIVE_PASS", "TENANT_ACCEPTANCE", "REDIRECT", "TLS_EARLY_DATA"])
def test_client_authentication_does_not_grant_other_operations(injection):
    trace = list(CLIENT_TRACE)
    trace.insert(6, injection)
    assert validate_trace("CLIENT", trace)


@pytest.mark.parametrize("fault", ["absent-observer", "stale-policy", "revoked-key", "generation-drift",
    "quota-exhausted", "post-io-loss", "ambiguous-cleanup", "no-fence"])
def test_authenticated_server_requests_cannot_skip_denied_effects(fault):
    trace = list(SERVER_TRACE)
    index = trace.index("POLICY_OBSERVED") if fault == "absent-observer" else trace.index("GENERATION_FENCED")
    trace[index] = fault.upper()
    assert validate_trace("SERVER", trace, resources=True)
    zero = [event for event in trace if event != "UPSTREAM_CREDENTIAL"]
    assert validate_trace("SERVER", zero)


@pytest.mark.parametrize("role,trace,resources", [(None, [], False), ("OTHER", [], False),
    ("CLIENT", tuple(CLIENT_TRACE), False), ("CLIENT", list(CLIENT_TRACE), 1),
    ("SERVER", [True], True), ("SERVER", [], "false")])
def test_closed_data_types_refuse_truthy_or_selected_authority(role, trace, resources):
    assert validate_trace(role, trace, resources=resources)


@pytest.mark.parametrize("field", ["allowedPaths", "predecessors", "sourceReuse", "contracts",
    "offlineAcceptanceCommands", "excluded", "offlineExecution"])
def test_packet_scope_and_full_acceptance_cannot_be_relaxed(authority, field):
    packets = deepcopy(authority[0])
    packets["MET-REPAIR-013"][field] = {} if field == "offlineExecution" else [{"unexpected": True}]
    assert validate_additions(packets)
    assert validate_credential_ordering(packets, *authority[1:])


@pytest.mark.parametrize("field", ["ordering", "dispatchGate", "protectedFiles", "inputFiles",
    "metaRecipes", "metaChanges", "sourceBaseline", "evidence", "extra"])
def test_authority_substitution_or_enlargement_refuses(authority, field):
    record = deepcopy(authority[1])
    record[field] = {}
    assert validate_credential_ordering(authority[0], record, authority[2])


def test_each_locked_input_is_checked_and_unknown_or_missing_files_refuse(authority):
    packets, record, inputs = authority
    # One independent hash comparison per input, without re-running a giant
    # full validation for every unchanged byte of the same catalog.
    pins = {**record["protectedFiles"], **record["inputFiles"],
            **{p:r["afterSha256"] for p,r in record["metaChanges"].items()}}
    assert set(pins) == set(inputs)
    for path, checksum in pins.items():
        assert digest(broker_history(path, inputs[path])) == checksum
        assert digest(inputs[path] + b" ") != checksum
    for path in ("AGENTS.md", BEFORE_PATH, CHECKPOINT_PATH, SOURCE_PATH, VECTORS_PATH,
                 "task-packets/CONF-LIVE-003.yaml", "scripts/validate_readiness.py"):
        changed = dict(inputs)
        changed[path] += b" "
        assert validate_credential_ordering(packets, record, changed), path
    changed = dict(inputs)
    del changed[BEFORE_PATH]
    assert validate_credential_ordering(packets, record, changed)
    assert validate_credential_ordering(packets, record, {**inputs, "unowned": b"x"})
    assert validate_credential_ordering({k:v for k,v in packets.items() if k != "MET-REPAIR-013"}, record, inputs)


def test_current_and_historical_test_and_agents_bytes_are_distinct_and_checked(authority):
    _, record, inputs = authority
    before = json.loads(inputs[BEFORE_PATH])["files"]
    current = {p: inputs[p] for p in record["metaRecipes"]}
    assert validate_recipes(record, inputs[BEFORE_PATH], current) == []
    for path, recipe in record["metaRecipes"].items():
        old = before[path].encode()
        assert apply_recipe(old, recipe) == broker_history(path, current[path])
        assert historical_bytes(path, current[path]) == old
        if path.startswith("tests/"):
            assert current_test_bytes(old) == current[path]
        changed = dict(current)
        changed[path] += b"\n# unreviewed change\n"
        assert validate_recipes(record, inputs[BEFORE_PATH], changed), path
        if recipe["replacements"]:
            with pytest.raises(ValueError):
                historical_bytes(path, old)
            with pytest.raises(ValueError):
                historical_bytes(path, changed[path])
    assert current["AGENTS.md"] != before["AGENTS.md"].encode()
    assert b"server-side" in current["AGENTS.md"]


def test_recipe_cardinality_and_unknown_test_bytes_refuse(authority):
    record, inputs = authority[1:]
    raw = json.loads(inputs[BEFORE_PATH])["files"]["AGENTS.md"].encode()
    rule = deepcopy(record["metaRecipes"]["AGENTS.md"])
    rule["replacements"][0]["count"] += 1
    with pytest.raises(ValueError):
        apply_recipe(raw, rule)
    with pytest.raises(ValueError):
        current_test_bytes(b"def test_unknown():\n    assert True\n")


def test_no_snapshot_execution_network_or_credential_primitive_in_data_oracle():
    tree = ast.parse((ROOT / "scripts/validate_credential_ordering.py").read_bytes())
    forbidden = {"exec", "eval", "compile", "__import__", "socket", "connect", "Popen", "system", "load_cert_chain"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            assert name not in forbidden


def test_current_roadmap_keeps_completed_source_and_waiting_native_separate():
    current = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text().split("## Historical MET-REPAIR-015 publication checkpoint\n",1)[1].split("## Historical MET-REPAIR-012")[0]
    assert "during `MET-REPAIR-015` publication" in current
    assert "MET-REPAIR-012 / PR106 | DONE_SOURCE_GATES" in current
    assert "CONF-FIX-005 / PR11 | DONE_SOURCE_GATES" in current
    assert "MET-REPAIR-015 | ONGOING" in current
    assert "127 files / 327 tests" in current
    assert "NOT_RUN_ENV_UNAVAILABLE" in current and "effort transition NOT_DUE" in current
