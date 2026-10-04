from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load
from fixture_yaml import dump_fixture


ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VALIDATOR = _load_module("met_002_reuse_validator", ROOT / "scripts/validate_reuse.py")
LOCKER_TESTS = _load_module("met_002_locker_tests", ROOT / "ci/test_warm_snapshot.py")


class TestWarmSnapshotLocker(LOCKER_TESTS.WarmSnapshotTest):
    """Run the synthetic locker contract tests as part of packet acceptance."""


@pytest.fixture()
def authority_root(tmp_path: Path) -> Path:
    destination = tmp_path / "repository"
    destination.mkdir()
    for directory in ("architecture", "schemas", "legal", "task-packets"):
        shutil.copytree(ROOT / directory, destination / directory)
    (destination / "docs").mkdir()
    shutil.copytree(ROOT / "docs/phase-0", destination / "docs/phase-0")
    return destination


def _read_yaml(path: Path) -> dict:
    value = safe_yaml_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write_yaml(path: Path, value: dict) -> None:
    path.write_text(
        dump_fixture(value),
        encoding="utf-8",
    )


def _validate(root: Path):
    return VALIDATOR.validate_reuse(root, check_toolchain=False)


def test_canonical_authorities_are_closed_and_deterministic() -> None:
    report = VALIDATOR.validate_reuse(ROOT, check_toolchain=False)

    assert report.accounted_source_inputs == 5
    assert report.public_sha_pins == 5
    assert report.metadata_omitted_inputs == 0
    assert report.task_packets == 194
    assert report.tree_discovery_records == 905
    assert report.blob_pending_records == 4202
    assert report.blob_copy_authorized_records == 0
    assert report.porting_authorization_records == 0
    assert report.classified_spdx_expressions > 0
    assert set(report.authority_digests) == set(VALIDATOR.AUTHORITY_PATHS)
    assert len(report.authority_digests) == 15
    assert all(len(digest) == 64 for digest in report.authority_digests.values())
    assert report.render().endswith("reuse validation passed")


def test_duplicate_yaml_authority_key_is_rejected(authority_root: Path) -> None:
    path = authority_root / "architecture/reuse-map.yaml"
    with path.open("a", encoding="utf-8") as stream:
        stream.write("\nsources: []\n")

    with pytest.raises(VALIDATOR.ReuseValidationError, match="duplicate YAML key"):
        _validate(authority_root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("commit", "0" * 40),
        ("licenseDisposition", "repository-license-is-enough"),
    ],
)
def test_public_source_identity_and_license_claim_are_exact(
    authority_root: Path,
    field: str,
    value: str,
) -> None:
    path = authority_root / "architecture/reuse-map.yaml"
    authority = _read_yaml(path)
    authority["sources"][0][field] = value
    _write_yaml(path, authority)

    with pytest.raises(VALIDATOR.ReuseValidationError):
        _validate(authority_root)


def test_source_inventory_cannot_authorize_copying(authority_root: Path) -> None:
    path = authority_root / "architecture/reuse-map.yaml"
    authority = _read_yaml(path)
    authority["sourceInventory"]["copyAuthorization"] = "COPY_AUTHORIZED"
    _write_yaml(path, authority)

    with pytest.raises(VALIDATOR.ReuseValidationError):
        _validate(authority_root)


def test_observation_and_path_index_must_match_exactly(authority_root: Path) -> None:
    path = authority_root / "architecture/reuse-path-index.yaml"
    authority = _read_yaml(path)
    source = next(
        item
        for item in authority["sources"]
        if item["repository"].endswith("agent-hook-v2.git")
    )
    source["paths"][0]["gitObject"] = "0" * 40
    _write_yaml(path, authority)

    with pytest.raises(
        VALIDATOR.ReuseValidationError,
        match="observed source metadata conflicts",
    ):
        _validate(authority_root)


def test_excluded_source_feature_path_is_rejected(authority_root: Path) -> None:
    path = authority_root / "architecture/reuse-path-index.yaml"
    authority = _read_yaml(path)
    source = next(
        item
        for item in authority["sources"]
        if item["repository"].endswith("llm_inference_engine.git")
    )
    blob = next(item for item in source["paths"] if item["kind"] == "blob")
    blob["path"] = "openrouter/hosted-endpoint.py"
    source["paths"].sort(key=lambda item: item["path"])
    _write_yaml(path, authority)

    with pytest.raises(
        VALIDATOR.ReuseValidationError,
        match="matches prohibited source feature pattern",
    ):
        _validate(authority_root)


def test_pending_blob_cannot_be_promoted_in_current_index(authority_root: Path) -> None:
    path = authority_root / "architecture/reuse-path-index.yaml"
    authority = _read_yaml(path)
    blob = next(
        item
        for source in authority["sources"]
        for item in source["paths"]
        if item["kind"] == "blob"
    )
    blob["recordType"] = "BLOB_COPY_AUTHORIZED"
    blob["reuseDisposition"] = "COPY_AUTHORIZED"
    _write_yaml(path, authority)

    with pytest.raises(VALIDATOR.ReuseValidationError):
        _validate(authority_root)


def test_current_authorization_index_rejects_every_record(authority_root: Path) -> None:
    path = authority_root / "architecture/porting-authorization-index.yaml"
    authority = _read_yaml(path)
    authority["authorizations"] = [{"authorizationId": "PA-FORBIDDEN-001"}]
    _write_yaml(path, authority)

    with pytest.raises(VALIDATOR.ReuseValidationError):
        _validate(authority_root)


def test_task_packet_cannot_claim_port_candidate(authority_root: Path) -> None:
    path = authority_root / "task-packets/MET-002.yaml"
    packet = _read_yaml(path)
    packet["sourceReuse"][0]["reuseMode"] = "PORT_CANDIDATE"
    _write_yaml(path, packet)

    with pytest.raises(
        VALIDATOR.ReuseValidationError,
        match="forbidden current reuse mode",
    ):
        _validate(authority_root)


def test_license_policy_cannot_be_made_fail_open(authority_root: Path) -> None:
    path = authority_root / "legal/third-party-license-policy.yaml"
    policy = _read_yaml(path)
    policy["evaluation"]["failClosed"] = False
    _write_yaml(path, policy)

    with pytest.raises(
        VALIDATOR.ReuseValidationError,
        match="classification must fail closed",
    ):
        _validate(authority_root)


def test_content_license_cannot_be_reclassified_as_code(authority_root: Path) -> None:
    path = authority_root / "docs/phase-0/dependency-license-inventory.json"
    inventory = json.loads(path.read_text(encoding="utf-8"))
    record = next(
        item
        for item in inventory["discoveredExpressions"]
        if item["expression"] == "CC-BY-4.0"
    )
    record["useKind"] = "CODE_DEPENDENCY"
    path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(VALIDATOR.ReuseValidationError, match="not constrained"):
        _validate(authority_root)


def test_lgpl_dependency_requires_explicit_release_review(authority_root: Path) -> None:
    path = authority_root / "docs/phase-0/dependency-license-inventory.json"
    inventory = json.loads(path.read_text(encoding="utf-8"))
    record = next(
        item
        for item in inventory["discoveredExpressions"]
        if item["expression"] == "LGPL-3.0-or-later"
    )
    record["releaseOutcome"] = "ALLOW"
    path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(VALIDATOR.ReuseValidationError, match="does not fail closed"):
        _validate(authority_root)


def _porting_document(state: str) -> dict:
    return {
        "schemaVersion": "harness.planeon.ai/porting-record/v1alpha1",
        "destinationRepository": "mas-harness-contracts",
        "records": [
            {
                "authorizationId": "PA-MET-002-001",
                "state": state,
                "sourceRepository": (
                    "git@github.com:caglarsubas/llm_inference_engine.git"
                ),
                "sourceCommit": "1" * 40,
                "sourcePath": "README.md",
                "sourceGitObject": "2" * 40,
                "destinationPath": "provenance/README.md",
                "transformationIntent": "ATTRIBUTED_ADAPTATION",
                "parityIntent": "CONTRACT_PARITY",
                "authorizationRecord": {
                    "path": "evidence/authorization.json",
                    "sha256": "3" * 64,
                },
            }
        ],
    }


def _porting_validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(
        (ROOT / "schemas/porting-record.schema.json").read_text(encoding="utf-8")
    )
    return jsonschema.Draft202012Validator(schema)


def test_destination_prepared_record_contains_no_source_material_result() -> None:
    validator = _porting_validator()
    document = _porting_document("DESTINATION_PREPARED")
    validator.validate(document)

    document["records"][0]["destinationGitObject"] = "4" * 40
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(document)


def test_applied_record_requires_non_circular_result_evidence() -> None:
    validator = _porting_validator()
    document = _porting_document("APPLIED")
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(document)

    document["records"][0].update(
        {
            "destinationGitObject": "4" * 40,
            "parityEvidence": {
                "path": "evidence/parity.json",
                "sha256": "5" * 64,
            },
            "sourceMaterialCommit": "6" * 40,
        }
    )
    validator.validate(document)
