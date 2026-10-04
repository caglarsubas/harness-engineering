"""Independent negative vectors for the early Linux roadmap authority."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_linux_readiness import validate_linux_readiness

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def inputs():
    packets = {
        path.stem: safe_yaml_load(path.read_text())
        for path in (ROOT / "task-packets").glob("*.yaml")
    }
    policy = json.loads((ROOT / "architecture/linux-readiness.json").read_text())
    return packets, policy


def test_current_publication_is_authority_only(inputs):
    packets, policy = inputs
    assert validate_linux_readiness(packets, policy) == []
    assert policy["publicationEvidence"] == "ROADMAP_AUTHORITY_ONLY"
    assert policy["gate"]["status"] == "WAITING"
    assert all(target["status"] == "NOT_RUN_ENV_UNAVAILABLE" for target in policy["targets"])
    assert policy["completedCorrection"]["linuxProof"] is False
    assert policy["currentPacketCount"] == 118  # Immutable historical policy.
    assert len(packets) == 194


@pytest.mark.parametrize(("path", "replacement"), [
    (["productionKernel"], "Darwin"),
    (["currentPacketCount"], 115),
    (["gate", "status"], "PASS"),
    (["gate", "unavailableUnblocksRuntimeCoding"], True),
    (["gate", "maximumEvidenceAgeHours"], 0),
    (["gate", "runtimeCodingRequires"], "SOURCE_MERGE"),
    (["gate", "invalidateOn"], []),
    (["targets", 0, "execution"], "EMULATED"),
    (["targets", 0, "status"], "PASS"),
    (["targets", 1, "requiredFor"], "OPTIONAL"),
    (["build", "hostOutputReuse"], "ALLOWED"),
    (["build", "downloads"], "ALLOWED"),
    (["build", "targetNativeDependencies"], 1),
    (["build", "requiredBindings"], []),
    (["evidence", "sourceOrFixtureCanPass"], True),
    (["evidence", "emulationCanQualifyNative"], True),
    (["evidence", "missingMandatoryCaseCanPass"], True),
    (["evidence", "acceptCallerVerificationBoolean"], True),
    (["evidence", "runtimeTransport"], "RAW_DOCKER_SOCKET"),
    (["evidence", "axes"], ["TENANT_ACCEPTANCE"]),
    (["billing", "hostedRunners"], True),
    (["billing", "paidApis"], True),
    (["billing", "thirdPartyKeys"], True),
    (["billing", "rawContainerSockets"], True),
    (["billing", "newProvisioning"], True),
    (["requiredCases"], ["CONTROL_CONTAINER_STARTUP"]),
    (["laterCertificationOwners"], []),
    (["completedCorrection", "mergeCommit"], "0" * 40),
    (["completedCorrection", "exactMain", "passed"], 0),
    (["completedCorrection", "exactMain", "logSha256"], "0" * 64),
    (["completedCorrection", "linuxProof"], True),
])
def test_weakened_policy_rejected(inputs, path, replacement):
    packets, policy = inputs
    target = policy
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    assert validate_linux_readiness(packets, policy)


@pytest.mark.parametrize("packet_id", ["MET-LINUX-001", "MET-LINUX-002", "CONF-LINUX-001"])
@pytest.mark.parametrize("field", [
    "predecessors", "allowedPaths", "contracts", "deliverables",
    "excluded", "offlineAcceptanceCommands", "offlineExecution", "expectedEvidence",
])
def test_missing_authority_field_rejected(inputs, packet_id, field):
    packets, policy = inputs
    del packets[packet_id][field]
    assert validate_linux_readiness(packets, policy)


@pytest.mark.parametrize("packet_id", ["MET-LINUX-001", "MET-LINUX-002", "CONF-LINUX-001"])
def test_added_write_or_source_authority_rejected(inputs, packet_id):
    packets, policy = inputs
    modified = deepcopy(packets)
    modified[packet_id]["allowedPaths"].append("Makefile")
    assert validate_linux_readiness(modified, policy)
    modified = deepcopy(packets)
    modified[packet_id]["sourceReuse"] = [{"copyAuthority": "ALL"}]
    assert validate_linux_readiness(modified, policy)


@pytest.mark.parametrize("packet_id", ["MODEL-001", "EXEC-001", "RUN-001", "CTRL-INTEGRATE-001"])
def test_runtime_predecessor_and_stricter_evidence_both_required(inputs, packet_id):
    packets, policy = inputs
    modified = deepcopy(packets)
    modified[packet_id]["predecessors"].remove("CONF-LINUX-001")
    assert validate_linux_readiness(modified, policy)
    modified = deepcopy(packets)
    modified[packet_id]["expectedEvidence"].pop()
    assert validate_linux_readiness(modified, policy)


def test_live_boundary_cannot_be_weakened(inputs):
    packets, policy = inputs
    for key, value in (
        ("launcherArgv", ["python3", "inner.py"]),
        ("ciEvidenceUse", "ALLOWED"),
        ("capacityAuthorization", "NONE"),
        ("networkIsolation", "ALLOW_ALL"),
        ("allowedEvidenceAxes", ["TENANT_ACCEPTANCE"]),
        ("revocationRequired", False),
    ):
        modified = deepcopy(packets)
        modified["CONF-LINUX-001"]["liveCampaignExecution"][key] = value
        assert validate_linux_readiness(modified, policy)


@pytest.mark.parametrize("value", [None, [], "", 118, True])
def test_malformed_catalog_or_record_fails_closed(inputs, value):
    packets, policy = inputs
    assert validate_linux_readiness(value, policy)
    assert validate_linux_readiness(packets, value)


def test_unknown_fields_and_non_json_values_fail_closed(inputs):
    packets, policy = inputs
    policy["unexpected"] = True
    assert validate_linux_readiness(packets, policy)
    policy["unexpected"] = float("nan")
    assert validate_linux_readiness(packets, policy)


def test_correction_and_contract_source_exceptions_preserved(inputs):
    packets, policy = inputs
    assert packets["CTRL-FIX-003"]["predecessors"] == ["CTRL-FIX-002", "CON-FIX-001"]
    assert packets["CON-MODEL-001"]["predecessors"] == [
        "CON-007", "MET-OBS-MODEL-001", "CON-FIX-001", "CTRL-FIX-003",
        "MET-REPAIR-005",
        "MET-REPAIR-006",
    ]
    assert policy["gate"]["sourceOnlyExceptions"] == ["CTRL-FIX-003", "CON-MODEL-001"]
