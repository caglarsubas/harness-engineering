from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
import yaml
from scripts.safe_yaml import safe_load as safe_yaml_load


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts/validate_architecture.py"
SPEC = importlib.util.spec_from_file_location("validate_architecture", VALIDATOR_PATH)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


@pytest.fixture()
def authority_root(tmp_path: Path) -> Path:
    shutil.copytree(ROOT / "architecture", tmp_path / "architecture")
    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    return tmp_path


def _load(path: Path) -> dict:
    value = safe_yaml_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write(path: Path, value: dict) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def test_canonical_architecture_reports_packet_evidence() -> None:
    report = VALIDATOR.validate_architecture(ROOT)
    assert report.base_sources == 6
    assert report.repositories == 13
    assert report.harnesses == 16
    assert report.services == 28
    assert report.provider_modules == 87
    assert set(report.repository_orders) == {
        "buildArtifact",
        "contractSource",
        "releaseSet",
        "runtimeIntegration",
    }
    assert "architecture validation passed" in report.render()


def test_duplicate_yaml_key_is_rejected(authority_root: Path) -> None:
    taxonomy = authority_root / "architecture/taxonomy.yaml"
    taxonomy.write_text(
        taxonomy.read_text(encoding="utf-8") + "\nschemaVersion: duplicate\n",
        encoding="utf-8",
    )
    with pytest.raises(VALIDATOR.DuplicateYamlKeyError, match="duplicate YAML key"):
        VALIDATOR.validate_architecture(authority_root, check_toolchain=False)


def test_base_scope_hash_is_pinned(authority_root: Path) -> None:
    scope = authority_root / "architecture/base-scope-sources.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8").replace(
            "bcee4ea4d8a2acf7bd7f51ae5b1297036010ff23186b5a59c6c506eef4358d31",
            "0" * 64,
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(VALIDATOR.ArchitectureValidationError, match="SHA-256"):
        VALIDATOR.validate_architecture(authority_root, check_toolchain=False)


def test_repository_contract_cycle_is_rejected(authority_root: Path) -> None:
    path = authority_root / "architecture/repositories.yaml"
    registry = _load(path)
    registry["dependencyGraphs"]["contractSource"]["edges"].append(
        {"consumer": "contracts", "provider": "sdks"}
    )
    for record in registry["repositories"]:
        if record["id"] == "contracts":
            record["dependsOn"] = ["sdks"]
    _write(path, registry)
    with pytest.raises(VALIDATOR.ArchitectureValidationError, match="dependency cycle"):
        VALIDATOR.validate_architecture(authority_root, check_toolchain=False)


def test_harness_cycle_is_rejected(authority_root: Path) -> None:
    path = authority_root / "architecture/taxonomy.yaml"
    taxonomy = _load(path)
    for harness in taxonomy["harnesses"]:
        if harness["id"] == "runtime.infrastructure":
            harness["requires"].append(
                {"id": "runtime.experience", "type": "always"}
            )
    _write(path, taxonomy)
    with pytest.raises(VALIDATOR.ArchitectureValidationError, match="harness dependency cycle"):
        VALIDATOR.validate_architecture(authority_root, check_toolchain=False)


def test_service_repository_ownership_is_enforced(authority_root: Path) -> None:
    path = authority_root / "architecture/services.yaml"
    text = path.read_text(encoding="utf-8").replace(
        "ownerRepository: mas-harness-operator",
        "ownerRepository: mas-harness-control-plane",
        1,
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(VALIDATOR.ArchitectureValidationError, match="repository owner changed"):
        VALIDATOR.validate_architecture(authority_root, check_toolchain=False)


def test_service_schema_rejects_false_evidence_state(authority_root: Path) -> None:
    path = authority_root / "architecture/services.yaml"
    text = path.read_text(encoding="utf-8").replace(
        "implementationStatus: PLANNED",
        "implementationStatus: LIVE",
        1,
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(VALIDATOR.ArchitectureValidationError, match="schema violation"):
        VALIDATOR.validate_architecture(authority_root, check_toolchain=False)


def test_provider_module_unknown_dependency_is_rejected(authority_root: Path) -> None:
    path = authority_root / "architecture/providers.yaml"
    text = path.read_text(encoding="utf-8").replace(
        "    dependencies: []",
        "    dependencies: [module.unknown]",
        1,
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(VALIDATOR.ArchitectureValidationError, match="unknown provider"):
        VALIDATOR.validate_architecture(authority_root, check_toolchain=False)


def test_repository_owner_id_is_canonical(authority_root: Path) -> None:
    path = authority_root / "architecture/taxonomy.yaml"
    taxonomy = _load(path)
    infrastructure = next(
        harness
        for harness in taxonomy["harnesses"]
        if harness["id"] == "runtime.infrastructure"
    )
    infrastructure["ownerRepository"] = "runtime-plane"
    _write(path, taxonomy)
    with pytest.raises(VALIDATOR.ArchitectureValidationError, match="repository owner changed"):
        VALIDATOR.validate_architecture(authority_root, check_toolchain=False)


def test_packet_wrapper_requires_named_trusted_outer_boundary() -> None:
    wrapper = (ROOT / "ci/verify-offline.sh").read_text(encoding="utf-8")
    assert 'HARNESS_OFFLINE_ENFORCED:-0' in wrapper
    assert 'HARNESS_OFFLINE_BACKEND:-' in wrapper
    assert 'HARNESS_OFFLINE_SESSION_ID:-' in wrapper
    assert 'exec python3 -I "$runner"' in wrapper
    assert "UV_OFFLINE UV_FROZEN UV_NO_SYNC" in wrapper
