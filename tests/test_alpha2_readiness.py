from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load

from scripts.validate_alpha2_readiness import validate_checkpoint, validate_model_authority


ROOT = Path(__file__).resolve().parents[1]


def inputs():
    packets = {path.stem: safe_yaml_load(path.read_text())
               for path in (ROOT / "task-packets").glob("*.yaml")}
    boundary = json.loads((ROOT / "architecture/model-evidence-boundary.json").read_text())
    return packets, boundary


def test_model_prerequisite_chain_and_checkpoint_are_closed():
    packets, boundary = inputs()
    assert validate_model_authority(packets, boundary) == []
    assert validate_checkpoint(ROOT, packets) == []


@pytest.mark.parametrize("packet_id", ["MET-A2-001", "MET-OBS-MODEL-001", "CON-MODEL-001", "MODEL-001"])
def test_missing_prerequisites_fail_closed(packet_id):
    packets, boundary = inputs()
    packets[packet_id]["predecessors"] = []
    assert validate_model_authority(packets, boundary)


@pytest.mark.parametrize("field,value", [
    ("sourcePaths", ["tests/test_scheduler.py"]),
    ("sourcePaths", ["contracts/prometa-model-usage-v2.schema.json", "tests/test_scheduler.py"]),
    ("sourceCodeExecution", "ALLOWED"), ("commit", "0" * 40),
    ("copyAuthority", "COPY_AUTHORIZED"), ("ciEvidenceUse", "ALLOWED"),
    ("implementationIdentityAccess", "ALLOWED"),
    ("outputPath", "architecture/observations/data-harness-v1.json"),
])
def test_model_observation_cannot_expand(field, value):
    packets, boundary = inputs()
    packets["MET-OBS-MODEL-001"]["referenceObservationExecution"][field] = value
    assert validate_model_authority(packets, boundary)


@pytest.mark.parametrize("field", ["originalSourceTests", "originalSourceBehavioralParity", "structuralObservation"])
def test_structural_or_destination_results_cannot_be_source_test_pass(field):
    packets, boundary = inputs()
    boundary["evidenceKinds"][field] = "PASS"
    assert validate_model_authority(packets, boundary)


@pytest.mark.parametrize("field,value", [
    ("sourceExecution", "ALLOWED"), ("copyAuthority", "COPY_AUTHORIZED"),
    ("originalBaselineSubstitution", "ALLOWED"), ("liveEvidence", "PASS"),
    ("implementationGate", []), ("releaseGate", "PASS"), ("unexpected", True),
])
def test_evidence_boundary_is_closed(field, value):
    packets, boundary = inputs()
    boundary[field] = value
    assert validate_model_authority(packets, boundary)


@pytest.mark.parametrize("packet_id", ["MODEL-001", "CON-MODEL-001"])
def test_missing_baseline_disclaimer_is_rejected(packet_id):
    packets, boundary = inputs()
    packets[packet_id]["expectedEvidence"] = ["Source parity PASS"]
    assert validate_model_authority(packets, boundary)


@pytest.mark.parametrize("packet_id", ["MET-OBS-MODEL-001", "CON-MODEL-001"])
def test_path_ownership_cannot_widen(packet_id):
    packets, boundary = inputs()
    packets[packet_id]["allowedPaths"].append("PORTING.yaml")
    assert validate_model_authority(packets, boundary)


def test_historical_phase_zero_cardinality_is_not_rewritten():
    audit = json.loads((ROOT / "docs/phase-0/phase-0-backtest.json").read_text())
    assert audit["cardinality"]["taskPackets"] == 107
    packets, _ = inputs()
    assert len(packets) == 194
