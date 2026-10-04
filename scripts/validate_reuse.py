#!/usr/bin/env python3
"""Validate the MET-002 reference-only source and porting authorities."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema
from jsonschema._utils import unbool as _unbool, uniq as _pinned_uniq
import yaml

try:
    from safe_yaml import SafeLoader as MetaSafeLoader, safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import SafeLoader as MetaSafeLoader, safe_load as safe_yaml_load


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_PACKAGES = {
    "PyYAML": "6.0.2",
    "jsonschema": "4.24.0",
    "pytest": "8.4.2",
}

EXPECTED_PUBLIC_SOURCES = {
    "git@github.com:caglarsubas/llm_inference_engine.git": {
        "commit": "6815c21cb10a4d7dc0b4804f6bb223afb4321e97",
        "destinations": [
            "contracts",
            "model-plane",
            "runtime-plane",
            "trust-plane",
            "distribution",
            "conformance-labs",
        ],
        "excluded": [
            "openrouter",
            "tunnels",
            "hosted-endpoints",
            "ghcr",
            "runtime-model-downloads",
        ],
        "excludedPathPatterns": [
            r"(?i)(^|[/_\\.-])(openrouter|tunnel|hosted[_-]?provider|hosted[_-]?endpoint)([/_\\.-]|$)"
        ],
        "records": {"TREE_DISCOVERY": 8, "BLOB_PENDING": 204},
    },
    "git@github.com:caglarsubas/data-source-harness.git": {
        "commit": "858281f4b845ffacfe05cdb2c40a402c237d4c54",
        "destinations": [
            "contracts",
            "knowledge-plane",
            "execution-plane",
            "trust-plane",
            "industry-packs",
            "distribution",
            "conformance-labs",
        ],
        "excluded": [
            "hmac-production-signing",
            "fused-retrieval-memory-runtime-state",
        ],
        "excludedPathPatterns": [r"(?i)(^|[/_\\.-])hmac([^/_\\.-]*)([/_\\.-]|$)"],
        "records": {"TREE_DISCOVERY": 12, "BLOB_PENDING": 311},
    },
    "git@github.com:caglarsubas/agent-hook-v2.git": {
        "commit": "2b521dc03a43b994bc52c76652306b1a77bf9572",
        "destinations": [
            "contracts",
            "control-plane",
            "execution-plane",
            "trust-plane",
            "operator",
            "conformance-labs",
        ],
        "excluded": [
            "live-cloud-actions",
            "hosted-provider-keys",
            "direct-production-mutation",
            "embedded-credentials",
            "billable-observability",
        ],
        "excludedPathPatterns": [
            r"(?i)(^|/)(?:\.env|id_rsa|id_ed25519|credentials\.json|service-account\.json)$"
        ],
        "records": {"TREE_DISCOVERY": 822, "BLOB_PENDING": 3046},
        "observation": {
            "packetId": "MET-OBS-AH-001",
            "path": "architecture/observations/agent-hook-v2-tree.json",
            "sha256": "0c94377f0ae6bf7ec7d70d521c411ff6883614cb2cebca2a1243cea1ce775339",
        },
    },
    "git@github.com:caglarsubas/orchestra-openshift-reference-lab.git": {
        "commit": "ba615515af84760a0accb31c37b815f9820f06d2",
        "destinations": [
            "runtime-plane",
            "trust-plane",
            "operator",
            "distribution",
            "conformance-labs",
        ],
        "excluded": [
            "cloud-provisioning",
            "billable-capacity-creation",
            "cluster-credential-material",
            "mutable-images",
        ],
        "excludedPathPatterns": [
            r"(?i)(^|/)(?:\.env|id_rsa|id_ed25519|credentials\.json|service-account\.json)$"
        ],
        "records": {"TREE_DISCOVERY": 39, "BLOB_PENDING": 404},
        "observation": {
            "packetId": "MET-OBS-OCP-001",
            "path": "architecture/observations/orchestra-openshift-reference-lab-tree.json",
            "sha256": "c0cab3b3c294ab0db09f19215ad51f3ca5b09c71bb007fef2b894f7588d3f41b",
        },
    },
    "git@github.com:caglarsubas/planeon-orchestra-python-sdk.git": {
        "commit": "3a4012d809e6ed00a3f05be940c5278eac20a166",
        "destinations": [
            "contracts",
            "sdks",
            "control-plane",
            "execution-plane",
            "conformance-labs",
        ],
        "excluded": [
            "provider-keys",
            "hosted-endpoints",
            "remote-telemetry-defaults",
            "proprietary-compatibility-shortcuts",
        ],
        "excludedPathPatterns": [
            r"(?i)(^|/)(?:\.env|id_rsa|id_ed25519|credentials\.json|service-account\.json)$"
        ],
        "records": {"TREE_DISCOVERY": 24, "BLOB_PENDING": 237},
        "observation": {
            "packetId": "MET-OBS-SDK-001",
            "path": "architecture/observations/planeon-orchestra-python-sdk-tree.json",
            "sha256": "aa41c2d2b781e6776724367b3cf931d23b6812cc14ecb4a27c4f6c0b69ef61d7",
        },
    },
}

EXPECTED_SOURCE_INVENTORY = {
    "approvedRepositoryCount": 5,
    "publiclyRecordedCount": 5,
    "metadataOmittedCount": 0,
    "copyAuthorization": "NONE",
}

EXPECTED_CURRENT_INVENTORY = {
    "treeDiscoveryRecords": 905,
    "blobPendingRecords": 4202,
    "blobCopyAuthorizedRecords": 0,
    "portingAuthorizationRecords": 0,
}

AUTHORITY_PATHS = (
    "architecture/reuse-map.yaml",
    "architecture/reuse-map.schema.json",
    "architecture/reuse-path-index.yaml",
    "architecture/porting-authorization-index.yaml",
    "schemas/reuse-path-index.schema.json",
    "schemas/porting-authorization.schema.json",
    "schemas/porting-record.schema.json",
    "legal/source-reuse-authorization.yaml",
    "legal/third-party-license-policy.yaml",
    "docs/phase-0/dependency-license-inventory.json",
    "architecture/observations/agent-hook-v2-tree.json",
    "architecture/observations/orchestra-openshift-reference-lab-tree.json",
    "architecture/observations/planeon-orchestra-python-sdk-tree.json",
    "docs/phase-0/phase-0-backtest.json",
    "docs/phase-0/PHASE_0_BACKTEST.md",
)

EXPECTED_REPOSITORIES = {
    "Harness-Engineering",
    "mas-harness-contracts",
    "mas-harness-sdks",
    "mas-harness-industry-packs",
    "mas-harness-control-plane",
    "mas-harness-runtime-plane",
    "mas-harness-model-plane",
    "mas-harness-knowledge-plane",
    "mas-harness-execution-plane",
    "mas-harness-trust-plane",
    "mas-harness-operator",
    "mas-harness-distribution",
    "mas-harness-conformance-labs",
}

EXPECTED_DEPENDENCY_EXPRESSIONS = {
    "0BSD",
    "Apache-2.0",
    "Apache-2.0 AND LGPL-3.0-or-later",
    "Apache-2.0 AND LGPL-3.0-or-later AND MIT",
    "Apache-2.0 OR BSD-2-Clause",
    "Apache-2.0 OR BSD-3-Clause",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC-BY-4.0",
    "ISC",
    "LGPL-3.0-or-later",
    "MIT",
    "MPL-2.0",
    "PSF-2.0",
    "W3C-20150513",
}

EXPECTED_PHASE_ZERO_REPOSITORY_COMMITS = {
    "Harness-Engineering": "2bf8819737149b847ee1ecd534ba472338afd1aa",
    "mas-harness-contracts": "2146278a95344cd2a8e22596b2f315b46edffc88",
    "mas-harness-sdks": "bd26ede4fea094de7fe53b784d50c1c51e001938",
    "mas-harness-industry-packs": "118296af0bcf85ef1a4983c23725c215ba6c91ed",
    "mas-harness-control-plane": "97e461aa22e34002c7407555750a93b69f1b750c",
    "mas-harness-runtime-plane": None,
    "mas-harness-model-plane": None,
    "mas-harness-knowledge-plane": "2056405d747f10bcea36f089fcd6f2de474b3ee5",
    "mas-harness-execution-plane": None,
    "mas-harness-trust-plane": "ac5184fe3e993043d97620e3e3e9a03e3d816b78",
    "mas-harness-operator": "0fa716fae4009f4fc63861f808f9e794f8925999",
    "mas-harness-distribution": "6ef7273f0674c3d39f2bd5becf084a4fd16c590c",
    "mas-harness-conformance-labs": "30877d289d389b29d3da9eb9a3c083c9ebc33382",
}

EXPECTED_DEPENDENCY_EVIDENCE = {
    "control-plane-package-lock": {
        "sourceSha256": "362ccf86489852256e36585ad1241c76a9c094d04cf8a35c9c2554e2f5e15cf7",
        "componentCount": 167,
        "licensedComponentCount": 167,
        "missingLicenseCount": 0,
    },
    "ind-wg-001-wheelhouse": {
        "sourceSha256": "d4875eb83cfca4774fd0c84f91647bda759cc32cd0beb75191600c68894f7951",
        "componentCount": 19,
        "licensedComponentCount": 19,
        "missingLicenseCount": 0,
    },
    "trust-001-wheelhouse": {
        "sourceSha256": "9ebb156068bd98fdf89bd428df8358b75af92d9ddff509a3bc445f07a3451652",
        "componentCount": 4,
        "licensedComponentCount": 4,
        "missingLicenseCount": 0,
    },
    "trust-002-wheelhouse": {
        "sourceSha256": "93872c0cd488177149b81d26eb65610f34dd12ba3acc7189fc6e8e2f159cabac",
        "componentCount": 4,
        "licensedComponentCount": 4,
        "missingLicenseCount": 0,
    },
}

SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class ReuseValidationError(ValueError):
    """A MET-002 authority is malformed or makes an unsupported reuse claim."""


class DuplicateYamlKeyError(ReuseValidationError):
    """A YAML authority repeats a mapping key."""


class DuplicateJsonKeyError(ReuseValidationError):
    """A JSON authority repeats an object key."""


class UniqueKeySafeLoader(MetaSafeLoader):
    """PyYAML safe loader that refuses duplicate mapping keys."""


def _construct_unique_yaml_mapping(
    loader: UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise DuplicateYamlKeyError(
                f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}"
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_yaml_mapping,
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = yaml.load(stream, Loader=UniqueKeySafeLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ReuseValidationError(f"cannot read YAML authority {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReuseValidationError(f"YAML authority must be a mapping: {path}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ReuseValidationError(f"cannot read JSON authority {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReuseValidationError(f"JSON authority must be an object: {path}")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReuseValidationError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ReuseValidationError(f"cannot hash authority {path}: {exc}") from exc
    return digest.hexdigest()


def _validate_toolchain() -> None:
    _require(
        sys.version_info[:2] == (3, 12),
        f"Python 3.12 required, found {sys.version.split()[0]}",
    )
    for package, expected in EXPECTED_PACKAGES.items():
        try:
            actual = version(package)
        except PackageNotFoundError as exc:
            raise ReuseValidationError(f"required package is missing: {package}") from exc
        _require(actual == expected, f"{package}=={expected} required, found {actual}")


class _UnhashableJson(Exception):
    pass


def _json_identity(value: Any) -> Any:
    # Hashable form whose equality is jsonschema's `equal` for decoded JSON:
    # booleans stay distinct from numbers, 1 == 1.0, and member order is
    # irrelevant for objects but significant for arrays.
    if value is True:
        return (0,)
    if value is False:
        return (1,)
    if value is None:
        return (2,)
    kind = type(value)
    if kind is str:
        return (3, value)
    if kind is int or (kind is float and value == value and value not in (float("inf"), float("-inf"))):
        return (4, value)
    if kind is list:
        return (5, tuple(_json_identity(item) for item in value))
    if kind is dict and all(type(key) is str for key in value):
        return (6, frozenset((key, _json_identity(item)) for key, item in value.items()))
    raise _UnhashableJson


def _identity_unique(container: Any) -> bool | None:
    # Verdict of pinned uniq's all-pairs `equal` fallback, which it takes when
    # sorting raises; None whenever the pinned uniq itself must decide, i.e.
    # for sortable arrays (its sort-then-adjacent result is kept exactly),
    # non-JSON or non-finite values, and recursion-limit cases.
    try:
        sorted(_unbool(item) for item in container)
    except (NotImplementedError, TypeError):
        try:
            identities = [_json_identity(item) for item in container]
        except (_UnhashableJson, RecursionError):
            return None
        return len(set(identities)) == len(identities)
    except RecursionError:
        return None
    return None


def _unique_json(container: Any) -> bool:
    verdict = _identity_unique(container)
    return _pinned_uniq(container) if verdict is None else verdict


def _unique_items(validator: Any, unique: Any, instance: Any, schema: Any) -> Any:
    # Same verdict and message as pinned jsonschema 4.24.0 uniqueItems; only
    # its quadratic all-pairs fallback (e.g. arrays of objects) is replaced.
    if unique and validator.is_type(instance, "array"):
        verdict = _identity_unique(instance)
        if verdict is None:
            # Called at the pinned keyword's own stack depth.
            verdict = _pinned_uniq(instance)
        if not verdict:
            yield jsonschema.ValidationError(f"{instance!r} has non-unique elements")


_Draft202012Validator = jsonschema.validators.extend(
    jsonschema.Draft202012Validator, {"uniqueItems": _unique_items},
)


def _validate_schema(
    instance: Any,
    schema_path: Path,
    label: str,
) -> dict[str, Any]:
    schema = load_json(schema_path)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = _Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )
    except jsonschema.SchemaError as exc:
        raise ReuseValidationError(f"{label} schema is invalid: {exc.message}") from exc
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise ReuseValidationError(
            f"{label} schema violation at {location}: {error.message}"
        )
    return schema


def _safe_relative_path(path: str, *, tree: bool) -> bool:
    if not path or path.startswith("/") or "\\" in path:
        return False
    normalized = path[:-1] if tree and path.endswith("/") else path
    if not normalized or PurePosixPath(normalized).is_absolute():
        return False
    if any(part in {"", ".", ".."} for part in PurePosixPath(normalized).parts):
        return False
    return path.endswith("/") if tree else not path.endswith("/")


def _validate_reuse_map(root: Path) -> tuple[dict[str, dict[str, Any]], int]:
    reuse_map = load_yaml(root / "architecture/reuse-map.yaml")
    _validate_schema(
        reuse_map,
        root / "architecture/reuse-map.schema.json",
        "reuse map",
    )
    sources = reuse_map.get("sources")
    _require(isinstance(sources, list), "reuse map sources must be a list")
    source_by_repository = {
        source.get("repository"): source
        for source in sources
        if isinstance(source, dict)
    }
    _require(
        len(sources) == len(source_by_repository) == 5
        and set(source_by_repository) == set(EXPECTED_PUBLIC_SOURCES),
        "reuse map must contain exactly the five approved public SHA-pinned sources",
    )
    for repository, expected in EXPECTED_PUBLIC_SOURCES.items():
        source = source_by_repository[repository]
        _require(
            source
            == {
                "repository": repository,
                "commit": expected["commit"],
                "licenseDisposition": "path-review-required-before-copy",
                "destinations": expected["destinations"],
                "excluded": expected["excluded"],
                "excludedPathPatterns": expected["excludedPathPatterns"],
            },
            f"reuse source contract changed for {repository}",
        )
        for pattern in source["excludedPathPatterns"]:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ReuseValidationError(
                    f"reuse source {repository} has invalid exclusion pattern: {exc}"
                ) from exc
    _require(
        reuse_map.get("sourceInventory") == EXPECTED_SOURCE_INVENTORY,
        "source inventory must account for five public repositories and authorize no copying",
    )
    _require(
        reuse_map.get("pathAuthority") == "architecture/reuse-path-index.yaml"
        and reuse_map.get("authorizationAuthority")
        == "legal/source-reuse-authorization.yaml",
        "reuse map authority links changed",
    )
    return source_by_repository, EXPECTED_SOURCE_INVENTORY["approvedRepositoryCount"]


def _validate_path_index(
    root: Path,
    source_by_repository: dict[str, dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    index = load_yaml(root / "architecture/reuse-path-index.yaml")
    _validate_schema(
        index,
        root / "schemas/reuse-path-index.schema.json",
        "reuse path index",
    )
    _require(
        index.get("generatedFrom")
        == "107 task packets plus three signed exact-commit full-tree observations; all current source paths are reference-only and validation status is reported separately",
        "reuse path index generation statement changed",
    )
    _require(
        index.get("defaultReuseDisposition")
        == "REFERENCE_ONLY_PENDING_PATH_REVIEW"
        and index.get("copyAuthorizationDisposition") == "COPY_AUTHORIZED",
        "reuse path index disposition contract changed",
    )
    sources = index.get("sources")
    _require(isinstance(sources, list), "reuse path index sources must be a list")
    indexed_sources = {
        source.get("repository"): source
        for source in sources
        if isinstance(source, dict)
    }
    _require(
        len(sources) == len(indexed_sources) == 5
        and set(indexed_sources) == set(EXPECTED_PUBLIC_SOURCES),
        "reuse path index public source set changed",
    )

    indexed_paths: dict[tuple[str, str], dict[str, Any]] = {}
    record_counts = {
        "TREE_DISCOVERY": 0,
        "BLOB_PENDING": 0,
        "BLOB_COPY_AUTHORIZED": 0,
    }
    for repository, expected in EXPECTED_PUBLIC_SOURCES.items():
        source = indexed_sources[repository]
        _require(
            source.get("commit") == expected["commit"],
            f"reuse path source commit changed for {repository}",
        )
        _require(
            source.get("licenseDisposition")
            == source_by_repository[repository]["licenseDisposition"]
            == "path-review-required-before-copy"
            and source.get("authorization")
            == "recorded-repository-scope-authorization",
            f"reuse path source {repository} overstates authorization",
        )
        paths = source.get("paths")
        _require(isinstance(paths, list), f"reuse path source {repository} paths must be a list")
        path_names = [entry.get("path") for entry in paths if isinstance(entry, dict)]
        _require(
            len(path_names) == len(paths) == len(set(path_names)),
            f"reuse path source {repository} has duplicate or malformed paths",
        )
        _require(path_names == sorted(path_names), f"reuse path source {repository} is not deterministic")
        source_counts = {"TREE_DISCOVERY": 0, "BLOB_PENDING": 0}
        for entry in paths:
            path = entry["path"]
            record_type = entry["recordType"]
            kind = entry["kind"]
            _require(
                SHA1_PATTERN.fullmatch(str(entry.get("gitObject", ""))) is not None,
                f"reuse path {(repository, path)} lacks an immutable Git object",
            )
            _require(
                _safe_relative_path(path, tree=kind == "tree"),
                f"reuse path {(repository, path)} is not a safe relative {kind} path",
            )
            key = (repository, path)
            _require(key not in indexed_paths, f"duplicate reuse path {key}")
            if kind == "tree":
                _require(
                    record_type == "TREE_DISCOVERY"
                    and entry.get("useModes") == ["DISCOVERY_ONLY"]
                    and entry.get("reuseDisposition") == "DISCOVERY_ONLY"
                    and entry.get("eligibleForCopyAuthorization") is False
                    and entry.get("requiredBeforeCopy")
                    == ["replaceWithExactIndexedBlobs"],
                    f"reuse tree {key} is not discovery-only",
                )
            else:
                _require(
                    kind == "blob"
                    and record_type == "BLOB_PENDING"
                    and entry.get("useModes") == ["REFERENCE_ONLY"]
                    and entry.get("reuseDisposition")
                    == "REFERENCE_ONLY_PENDING_PATH_REVIEW"
                    and entry.get("eligibleForCopyAuthorization") is True,
                    f"reuse blob {key} is not pending path review",
                )
                _require(
                    entry.get("requiredBeforeCopy")
                    == [
                        "ownerOrLicenseGrantEvidenceRecorded",
                        "spdxDispositionRecorded",
                        "thirdPartyAndGeneratedContentReviewed",
                        "excludedFeatureScanPassed",
                        "portingRecordPrepared",
                    ],
                    f"reuse blob {key} promotion gates changed",
                )
            _require(
                entry.get("ownershipEvidence")
                == {
                    "status": "REPOSITORY_SCOPE_CONSENT_ONLY",
                    "authority": "legal/source-reuse-authorization.yaml",
                    "authorshipClaim": "NONE",
                },
                f"reuse path {key} overstates ownership evidence",
            )
            _require(
                entry.get("licenseEvidence")
                == {
                    "status": "NOT_YET_VERIFIED",
                    "authority": "legal/third-party-license-policy.yaml",
                    "inferredFromRepositoryOwnership": False,
                },
                f"reuse path {key} infers or overstates license evidence",
            )
            for pattern in source_by_repository[repository]["excludedPathPatterns"]:
                _require(
                    re.search(pattern, path) is None,
                    f"reuse path {key} matches prohibited source feature pattern",
                )
            source_counts[record_type] += 1
            record_counts[record_type] += 1
            indexed_paths[key] = entry
        _require(
            source_counts == expected["records"],
            f"reuse path source counts changed for {repository}: {source_counts}",
        )
    _require(
        record_counts
        == {
            "TREE_DISCOVERY": 905,
            "BLOB_PENDING": 4202,
            "BLOB_COPY_AUTHORIZED": 0,
        }
        and len(indexed_paths) == 5107,
        f"reuse path inventory changed: {record_counts}",
    )
    return indexed_paths


def _validate_task_packet_closure(
    root: Path,
    indexed_paths: dict[tuple[str, str], dict[str, Any]],
) -> int:
    packet_paths = sorted((root / "task-packets").glob("*.yaml"))
    # The Phase-0 report/index are immutable 107-packet historical snapshots.
    # Current closure includes three Alpha-2 entry and four corrective packets.
    _require(len(packet_paths) == 194, f"expected 194 task packets, found {len(packet_paths)}")
    referenced: set[tuple[str, str]] = set()
    for packet_path in packet_paths:
        packet = load_yaml(packet_path)
        packet_id = packet.get("id")
        for source in packet.get("sourceReuse", []):
            _require(isinstance(source, dict), f"packet {packet_id} has malformed sourceReuse")
            repository = source.get("repository")
            _require(repository in EXPECTED_PUBLIC_SOURCES, f"packet {packet_id} cites an unknown public source")
            _require(
                source.get("commit") == EXPECTED_PUBLIC_SOURCES[repository]["commit"],
                f"packet {packet_id} cites a mutable or wrong source commit",
            )
            reuse_mode = source.get("reuseMode")
            _require(
                reuse_mode in {"DISCOVERY_ONLY", "REFERENCE_ONLY"},
                f"packet {packet_id} contains forbidden current reuse mode {reuse_mode!r}",
            )
            strategy = str(source.get("strategy", "")).casefold()
            _require(
                "implementation access" in strategy and "forbidden" in strategy,
                f"packet {packet_id} source strategy does not prohibit implementation access",
            )
            paths = source.get("paths")
            _require(
                isinstance(paths, list)
                and paths
                and all(isinstance(path, str) and path for path in paths)
                and len(paths) == len(set(paths)),
                f"packet {packet_id} source paths are empty, duplicated, or malformed",
            )
            for path in paths:
                key = (repository, path)
                _require(key in indexed_paths, f"packet {packet_id} cites unindexed source path {key}")
                expected_record = (
                    "TREE_DISCOVERY" if reuse_mode == "DISCOVERY_ONLY" else "BLOB_PENDING"
                )
                _require(
                    indexed_paths[key].get("recordType") == expected_record,
                    f"packet {packet_id} source mode conflicts with indexed path {key}",
                )
                referenced.add(key)
    observed: set[tuple[str, str]] = set()
    for repository, expected in EXPECTED_PUBLIC_SOURCES.items():
        observation = expected.get("observation")
        if not isinstance(observation, dict):
            continue
        report_path = root / observation["path"]
        _require(
            _sha256(report_path) == observation["sha256"],
            f"tree observation digest changed for {repository}",
        )
        report = load_json(report_path)
        authority = report.get("authority", {})
        _require(
            authority.get("packetId") == observation["packetId"]
            and authority.get("repository") == repository
            and authority.get("commit") == expected["commit"]
            and authority.get("packetObservation", {}).get("copyAuthority")
            == "NONE"
            and report.get("isolationEvidence", {}).get("copyAuthority") == "NONE",
            f"tree observation authority changed for {repository}",
        )
        sources = report.get("sources")
        _require(isinstance(sources, list), f"tree observation sources missing for {repository}")
        raw_paths = [source.get("path") for source in sources if isinstance(source, dict)]
        _require(
            len(raw_paths) == len(sources) == len(set(raw_paths))
            and raw_paths == sorted(raw_paths),
            f"tree observation paths are malformed, duplicated, or unordered for {repository}",
        )
        counts = {"TREE_DISCOVERY": 0, "BLOB_PENDING": 0}
        for source in sources:
            object_type = source.get("objectType")
            _require(object_type in {"tree", "blob"}, f"unknown observed object type for {repository}")
            path = f"{source['path']}/" if object_type == "tree" else source["path"]
            key = (repository, path)
            record_type = "TREE_DISCOVERY" if object_type == "tree" else "BLOB_PENDING"
            _require(key in indexed_paths, f"observed source path is unindexed: {key}")
            _require(
                indexed_paths[key].get("recordType") == record_type
                and indexed_paths[key].get("kind") == object_type
                and indexed_paths[key].get("gitObject") == source.get("gitObject"),
                f"observed source metadata conflicts with indexed path {key}",
            )
            _require(key not in observed, f"duplicate observed source path {key}")
            observed.add(key)
            counts[record_type] += 1
        _require(
            counts == expected["records"],
            f"tree observation counts changed for {repository}: {counts}",
        )
    _require(not referenced & observed, "task-packet and full-tree observation closures overlap")
    _require(
        referenced | observed == set(indexed_paths),
        "reuse path index must exactly equal packet references plus signed tree observations",
    )
    return len(packet_paths)


def _validate_authorization_protocol(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    authorization_index = load_yaml(root / "architecture/porting-authorization-index.yaml")
    authorization_schema = _validate_schema(
        authorization_index,
        root / "schemas/porting-authorization.schema.json",
        "porting authorization index",
    )
    _require(
        authorization_index
        == {
            "schemaVersion": "harness.planeon.ai/porting-authorization-index/v1alpha1",
            "status": "DISABLED_FAIL_CLOSED",
            "admissionEnabled": False,
            "authorizations": [],
        },
        "porting authorization index must remain disabled and empty",
    )
    _require(
        authorization_schema.get("properties", {})
        .get("authorizations", {})
        .get("maxItems")
        == 0,
        "current porting authorization schema does not reject every authorization",
    )
    porting_record_schema = load_json(root / "schemas/porting-record.schema.json")
    try:
        jsonschema.Draft202012Validator.check_schema(porting_record_schema)
    except jsonschema.SchemaError as exc:
        raise ReuseValidationError(
            f"destination porting-record schema is invalid: {exc.message}"
        ) from exc

    authorization = load_yaml(root / "legal/source-reuse-authorization.yaml")
    _require(
        authorization.get("status") == "recorded-repository-scope-authorization"
        and authorization.get("targetLicense") == "Apache-2.0"
        and authorization.get("scopeSource") == "architecture/reuse-map.yaml",
        "source authorization scope changed",
    )
    acquisition = authorization.get("acquisition", {})
    _require(
        acquisition
        == {
            "checkout": "detached-read-only-snapshot",
            "lockTool": "ci/lock_warm_snapshot.py",
            "directArgvOnly": True,
            "sourceCommitVerification": "required-before-and-after-reference-session",
            "objectInventoryVerification": "required-before-and-after-reference-session-with-lazy-fetch-disabled",
            "workingTreeCleanVerification": "required-before-and-after-reference-session",
            "filesystemEnforcement": "REMOVE_ALL_WRITE_BITS_AND_REQUIRE_OS_READ_ONLY_MOUNT_OR_SEPARATE_UNPRIVILEGED_OBSERVER",
            "implementationIdentityAccess": "forbidden",
            "observationIdentity": "separate-unprivileged-source-observer",
            "fetchRemoteAfterMaterialization": "disabled",
            "pushRemote": "forbidden",
            "pushCredentials": "forbidden",
            "sourceFilesystemWrites": "forbidden",
            "importMethod": "forbidden-until-approved-two-repository-transaction",
            "pathAuthority": "architecture/reuse-path-index.yaml",
            "authorizationAuthority": "architecture/porting-authorization-index.yaml",
            "authorizationSchema": "schemas/porting-authorization.schema.json",
            "destinationRecordSchema": "schemas/porting-record.schema.json",
        },
        "warm-source acquisition contract is not exact and separated",
    )
    state_machine = authorization.get("authorizationStateMachine", {})
    _require(
        state_machine.get("initial") == "REFERENCE_ONLY_PENDING_PATH_REVIEW"
        and state_machine.get("promotableTo") == "COPY_AUTHORIZED"
        and state_machine.get("admissionEnabled") is False
        and state_machine.get("admissionDisabledReason")
        == "NO_OFFLINE_SIGNATURE_AND_EVIDENCE_VERIFIER_IMPLEMENTED"
        and state_machine.get("currentCopyAuthorizedCount") == 0
        and state_machine.get("futurePromotionRequiresPacketRevision") is True
        and state_machine.get("futureAdmissionEnablementRequires")
        == [
            "canonicalAuthorizationSignatureVerifier",
            "pinnedOfflineApproverKeyFingerprint",
            "trackedEvidencePathDigestVerification",
            "exactPathIndexAuthorizationPacketDestinationJoin",
            "destinationPreparedAndAppliedRecordVerification",
        ],
        "porting admission is not fail-disabled pending a future verifier",
    )
    transaction = authorization.get("twoRepositoryTransaction", {})
    _require(
        transaction.get("joinKey") == "authorizationId"
        and transaction.get("phases")
        == ["SOURCE_APPROVED", "DESTINATION_PREPARED", "APPLIED"]
        and transaction.get("sourceRepositoryMutation") == "forbidden"
        and transaction.get("missingOrMismatchedRecord") == "DENY_COPY"
        and "source-material commit" in str(transaction.get("applyRule", ""))
        and "never self-referential" in str(transaction.get("mergeRule", "")),
        "two-repository porting transaction is circular or fail-open",
    )
    expected_observations = []
    for repository, expected in EXPECTED_PUBLIC_SOURCES.items():
        observation = expected.get("observation")
        if not isinstance(observation, dict):
            continue
        expected_observations.append(
            {
                "packetId": observation["packetId"],
                "repository": repository,
                "commit": expected["commit"],
                "report": observation["path"],
                "reportSha256": observation["sha256"],
                "treeRecords": expected["records"]["TREE_DISCOVERY"],
                "blobRecords": expected["records"]["BLOB_PENDING"],
                "copyAuthority": "NONE",
            }
        )
    _require(
        authorization.get("observationEvidence") == expected_observations,
        "source authorization observation evidence is incomplete or stale",
    )
    _require(
        authorization.get("currentInventory") == EXPECTED_CURRENT_INVENTORY,
        "source authorization current inventory is stale",
    )
    return authorization, porting_record_schema


def _validate_license_policy(root: Path) -> int:
    policy = load_yaml(root / "legal/third-party-license-policy.yaml")
    _require(
        policy.get("schemaVersion") == "harness.planeon.ai/license-policy/v1alpha1"
        and policy.get("policyVersion") == "0.3.0"
        and policy.get("coreLicense") == "Apache-2.0",
        "third-party license policy identity changed",
    )
    evaluation = policy.get("evaluation", {})
    _require(
        evaluation.get("failClosed") is True
        and evaluation.get("expressionMatching") == "EXACT_SPDX_EXPRESSION"
        and evaluation.get("allExpressionsMustBeClassified") is True
        and evaluation.get("unknownExpressionOutcome") == "DENY_UNKNOWN_LICENSE"
        and evaluation.get("emptyLicenseSetOutcome") == "DENY_MISSING_LICENSE"
        and evaluation.get("catalogSources")
        == [
            {
                "path": "architecture/providers.yaml",
                "licenseField": "modules[].license.spdx[]",
                "useAuthority": "PROVIDER_MODULE",
            },
            {
                "path": "docs/phase-0/dependency-license-inventory.json",
                "licenseField": "discoveredExpressions[].expression",
                "useAuthority": "PHASE_ZERO_DEPENDENCY",
            },
        ],
        "third-party license classification must fail closed",
    )
    default_allowed = set(policy.get("defaultAllowedSpdx", []))
    exceptions = {
        item.get("expression")
        for item in policy.get("allowedExceptionExpressions", [])
        if isinstance(item, dict)
    }
    open_content = {
        item.get("expression")
        for item in policy.get("openContentSpdx", [])
        if isinstance(item, dict)
    }
    optional_review = set(policy.get("optionalExplicitReview", []))
    unresolved = set(policy.get("plannedUnresolvedSpdx", []))
    denied = set(policy.get("deniedForDefaultDistribution", []))
    categories = [
        default_allowed,
        exceptions,
        open_content,
        optional_review,
        unresolved,
        denied,
    ]
    for index, left in enumerate(categories):
        for right in categories[index + 1 :]:
            _require(not left & right, "SPDX classification categories overlap")
    _require(
        unresolved == {"NOASSERTION"}
        and policy.get("plannedUnresolvedRule", {}).get("releaseOutcome")
        == "DENY_RELEASE"
        and policy.get("deniedRule", {}).get("overrideAllowed") is False
        and policy.get("deniedRule", {}).get("releaseOutcome") == "DENY_RELEASE",
        "unresolved or denied licenses can enter a release",
    )
    _require(
        {"0BSD", "PSF-2.0", "W3C-20150513"} <= default_allowed
        and {
            "Apache-2.0 OR BSD-2-Clause",
            "Apache-2.0 OR BSD-3-Clause",
        }
        <= exceptions
        and "CC-BY-4.0" in open_content
        and {
            "LGPL-3.0-only",
            "LGPL-3.0-or-later",
            "Apache-2.0 AND LGPL-3.0-or-later",
            "Apache-2.0 AND LGPL-3.0-or-later AND MIT",
        }
        <= optional_review,
        "Phase-0 dependency SPDX decisions are incomplete",
    )
    cc_by = next(
        (
            item
            for item in policy.get("openContentSpdx", [])
            if isinstance(item, dict) and item.get("expression") == "CC-BY-4.0"
        ),
        {},
    )
    _require(
        cc_by.get("allowedKinds") == ["ARTIFACT"]
        and "non-runtime-code content only" in str(cc_by.get("allowedUse", "")),
        "CC-BY-4.0 must remain content-only",
    )
    _require(
        policy.get("optionalExplicitReviewRule", {}).get(
            "releaseOutcomeWithoutApprovedDecision"
        )
        == "DENY_RELEASE",
        "LGPL and copyleft review must deny release without an approved decision",
    )
    path_policy = policy.get("pathDecisionPolicy", {})
    _require(
        path_policy.get("default") == "REFERENCE_ONLY_PENDING_PATH_REVIEW"
        and path_policy.get("missingEvidence") == "DENY_COPY"
        and path_policy.get("repositoryOwnershipInferenceAllowed") is False
        and path_policy.get("rootLicenseInheritanceAllowed") is False
        and path_policy.get("portingRecordRequiredPerBlob") is True,
        "path-level license decision policy is fail-open",
    )

    classified = set().union(*categories)

    inventory = load_json(root / "docs/phase-0/dependency-license-inventory.json")
    _require(
        inventory.get("schemaVersion")
        == "harness.planeon.ai/phase-zero-dependency-license-inventory/v1alpha1"
        and inventory.get("policy") == "legal/third-party-license-policy.yaml",
        "Phase-0 dependency license inventory identity changed",
    )
    repository_records = inventory.get("repositories")
    _require(isinstance(repository_records, list), "dependency repository inventory must be a list")
    repository_by_name = {
        record.get("repository"): record
        for record in repository_records
        if isinstance(record, dict)
    }
    _require(
        set(repository_by_name) == EXPECTED_REPOSITORIES
        and len(repository_by_name) == len(repository_records) == 13,
        "dependency inventory must account for all thirteen planned repositories exactly once",
    )
    for repository, commit in EXPECTED_PHASE_ZERO_REPOSITORY_COMMITS.items():
        record = repository_by_name[repository]
        if commit is None:
            _require(
                record.get("sourceState") == "PLANNED_NOT_CREATED"
                and record.get("mainCommit") is None
                and record.get("licenseSha256") is None
                and record.get("releaseDisposition") == "NOT_RELEASE_CANDIDATE",
                f"uncreated repository {repository} is overstated",
            )
        else:
            _require(
                record.get("sourceState") == "PUBLIC_MAIN_PRESENT"
                and record.get("mainCommit") == commit
                and record.get("sourceLicense") == "Apache-2.0"
                and re.fullmatch(r"[0-9a-f]{64}", str(record.get("licenseSha256", "")))
                and str(record.get("releaseDisposition", "")).startswith("BLOCKED_UNTIL_"),
                f"repository license evidence is missing or stale for {repository}",
            )

    evidence_sources = inventory.get("evidenceSources")
    _require(isinstance(evidence_sources, list), "dependency evidence sources must be a list")
    evidence_by_id = {
        source.get("id"): source
        for source in evidence_sources
        if isinstance(source, dict)
    }
    _require(
        set(evidence_by_id) == set(EXPECTED_DEPENDENCY_EVIDENCE)
        and len(evidence_by_id) == len(evidence_sources),
        "dependency evidence source set changed",
    )
    evidence_expressions: set[str] = set()
    for source_id, expected in EXPECTED_DEPENDENCY_EVIDENCE.items():
        source = evidence_by_id[source_id]
        for field, value in expected.items():
            _require(
                source.get(field) == value,
                f"dependency evidence {source_id} has stale {field}",
            )
        expressions = source.get("expressions")
        _require(
            isinstance(expressions, list)
            and expressions == sorted(expressions)
            and len(expressions) == len(set(expressions)),
            f"dependency evidence {source_id} expressions are malformed",
        )
        evidence_expressions.update(expressions)

    discovered = inventory.get("discoveredExpressions")
    _require(isinstance(discovered, list), "discovered dependency expressions must be a list")
    expression_records = {
        record.get("expression"): record
        for record in discovered
        if isinstance(record, dict)
    }
    _require(
        set(expression_records) == EXPECTED_DEPENDENCY_EXPRESSIONS
        == evidence_expressions
        and len(expression_records) == len(discovered),
        "dependency expressions must exactly equal the recorded lock and wheelhouse evidence",
    )
    classification_by_expression: dict[str, str] = {}
    for classification, expressions in (
        ("DEFAULT_ALLOWED", default_allowed),
        ("ALLOWED_EXCEPTION_EXPRESSION", exceptions),
        ("OPEN_CONTENT", open_content),
        ("OPTIONAL_EXPLICIT_REVIEW", optional_review),
        ("PLANNED_UNRESOLVED", unresolved),
        ("DENIED", denied),
    ):
        for expression in expressions:
            classification_by_expression[expression] = classification
    for expression, record in expression_records.items():
        _require(
            record.get("classification") == classification_by_expression.get(expression),
            f"dependency expression {expression!r} classification conflicts with policy",
        )
        if expression == "CC-BY-4.0":
            _require(
                record.get("useKind") == "CONTENT_DATASET"
                and record.get("components") == ["caniuse-lite@1.0.30001810"],
                "CC-BY-4.0 dependency evidence is not constrained to attributed content",
            )
        if record.get("classification") == "OPTIONAL_EXPLICIT_REVIEW":
            _require(
                record.get("releaseOutcome")
                == "DENY_RELEASE_WITHOUT_APPROVED_DECISION",
                f"review-gated dependency {expression!r} does not fail closed",
            )
    _require(
        inventory.get("approvedButNotObservedExpressions")
        == [
            {
                "expression": "LGPL-3.0-only",
                "classification": "OPTIONAL_EXPLICIT_REVIEW",
            }
        ],
        "approved but unobserved Phase-0 expression record changed",
    )

    providers = load_yaml(root / "architecture/providers.yaml")
    modules = providers.get("modules")
    _require(isinstance(modules, list), "provider catalog modules must be a list")
    expressions: set[str] = set()
    for module in modules:
        license_record = module.get("license", {})
        spdx = license_record.get("spdx")
        _require(
            isinstance(spdx, list)
            and spdx
            and all(isinstance(expression, str) and expression for expression in spdx),
            f"provider module {module.get('id')} has no license expressions",
        )
        expressions.update(spdx)
        _require(
            set(spdx) <= classified,
            f"provider module {module.get('id')} has an unclassified SPDX expression",
        )
        if "NOASSERTION" in spdx:
            _require(
                module.get("status") == "PLANNED"
                and license_record.get("custody")
                in {"COMPOSITE_REVIEW_REQUIRED", "TENANT_ATTESTED_PINNED"},
                f"provider module {module.get('id')} misuses NOASSERTION",
            )
    return len(expressions | evidence_expressions)


def _validate_phase_zero_audit(root: Path) -> None:
    audit = load_json(root / "docs/phase-0/phase-0-backtest.json")
    _require(
        audit.get("schemaVersion") == "harness.planeon.ai/phase-zero-backtest/v1alpha1"
        and audit.get("reportId") == "PHASE-0-BACKTEST-2026-09-04"
        and audit.get("packet") == "MET-P0-002"
        and audit.get("authorityCommitBeforePacket")
        == "2bf8819737149b847ee1ecd534ba472338afd1aa"
        and audit.get("disposition")
        == "READY_TO_COMPLETE_ON_GREEN_PR_AND_EXACT_MAIN_REPLAY",
        "Phase-0 audit identity or conditional completion boundary changed",
    )
    _require(
        audit.get("cardinality")
        == {
            "repositoriesPlanned": 13,
            "repositoriesPubliclyCreated": 10,
            "repositoriesPlannedNotCreated": 3,
            "planes": 4,
            "harnesses": 16,
            "services": 28,
            "providerModules": 87,
            "taskPackets": 107,
        },
        "Phase-0 audit cardinality is stale",
    )
    backlog = audit.get("backlog")
    _require(isinstance(backlog, list), "Phase-0 audit backlog must be a list")
    backlog_status = {
        item.get("id"): item.get("status")
        for item in backlog
        if isinstance(item, dict)
    }
    _require(
        backlog_status
        == {
            "P0-AUTHORITY": "DONE",
            "P0-WARM-OBSERVATIONS": "DONE",
            "P0-TRUST-BOUNDARY": "DONE",
            "P0-PUBLIC-FORK-ZERO-BILL": "DONE",
            "P0-TENANT-OVERVIEW": "DONE",
            "P0-FIVE-SOURCE-INDEX": "DONE",
            "P0-DEPENDENCY-LICENSE-CLOSURE": "DONE",
            "P0-FINAL-REPLAY": "WAITING",
            "ALPHA2-REMAINING-PLANE-BOOTSTRAPS": "WAITING",
        },
        "Phase-0 audit backlog is incomplete or overstates completion",
    )
    _require(
        audit.get("localAcceptance")
        == {
            "status": "PASS",
            "packetSha256": "6ffd3057b377f1d6c7fc47cae26472f010e83090b5c31d90cbb46c4e0a7d9611",
            "network": "OS_ENFORCED_DENY_ALL_OUTBOUND",
            "readiness": "PASS",
            "testsPassed": 179,
            "testsSkippedEnvironment": 5,
            "warmSourceAccess": "OS_DENIED",
        },
        "Phase-0 local acceptance evidence is missing or overstated",
    )
    warm_sources = audit.get("warmSources")
    _require(isinstance(warm_sources, list), "Phase-0 audit warm sources must be a list")
    warm_by_repository = {
        source.get("repository"): source
        for source in warm_sources
        if isinstance(source, dict)
    }
    _require(
        set(warm_by_repository) == set(EXPECTED_PUBLIC_SOURCES)
        and len(warm_by_repository) == len(warm_sources) == 5,
        "Phase-0 audit must name all five warm sources exactly once",
    )
    for repository, expected in EXPECTED_PUBLIC_SOURCES.items():
        source = warm_by_repository[repository]
        _require(
            source.get("commit") == expected["commit"]
            and source.get("copyAuthorization") == "NONE",
            f"Phase-0 audit overstates or mispins warm source {repository}",
        )
        observation = expected.get("observation")
        if isinstance(observation, dict):
            _require(
                source.get("authorityMode")
                == "SIGNED_METADATA_ONLY_FULL_TREE_OBSERVATION"
                and source.get("reportSha256") == observation["sha256"],
                f"Phase-0 audit observation evidence is stale for {repository}",
            )
    axes = audit.get("evidenceAxes")
    _require(isinstance(axes, list), "Phase-0 evidence axes must be a list")
    axis_status = {
        axis.get("axis"): axis.get("status")
        for axis in axes
        if isinstance(axis, dict)
    }
    _require(
        axis_status
        == {
            "SOURCE": "PASS_WITH_MET_P0_002_CANDIDATE_PENDING_MERGE",
            "CONTRACT_AND_UNIT": "PASS_SIGNED_LOCAL_CANDIDATE",
            "PR_CHECK": "NOT_RUN_PENDING_PR",
            "MERGE": "NOT_RUN_PENDING_PR",
            "ARTIFACT_AND_SBOM": "NOT_RUN_NOT_IN_PACKET",
            "SIGNATURE_AND_RELEASE": "NOT_RUN_NOT_IN_PACKET",
            "DEPLOYMENT": "NOT_RUN_ENV_UNAVAILABLE",
            "RUNTIME": "NOT_RUN_ENV_UNAVAILABLE",
            "SECURITY_AND_ASSURANCE": "NOT_RUN_ENV_UNAVAILABLE",
            "TENANT_ACCEPTANCE": "NOT_RUN_ENV_UNAVAILABLE",
        },
        "Phase-0 evidence axes are collapsed, missing, or overstated",
    )
    historical_debt = audit.get("historicalDebt")
    _require(
        isinstance(historical_debt, list)
        and {item.get("id") for item in historical_debt if isinstance(item, dict)}
        == {"HIST-MET-004-BRANCH-REUSE", "HIST-PRE-OBSERVATION-WORDING"},
        "Phase-0 historical debt must remain explicit",
    )
    markdown = (root / "docs/phase-0/PHASE_0_BACKTEST.md").read_text(
        encoding="utf-8"
    )
    for required in (
        "13 planned repositories",
        "16 harnesses",
        "28\nservices",
        "87 provider/module records",
        "107 task packets",
        "905 trees",
        "4,202 blobs",
        "zero copy authorization",
        "NOT_RUN_ENV_UNAVAILABLE",
    ):
        _require(required in markdown, f"Phase-0 human audit omits {required!r}")


@dataclass(frozen=True)
class ReuseReport:
    accounted_source_inputs: int
    public_sha_pins: int
    metadata_omitted_inputs: int
    task_packets: int
    tree_discovery_records: int
    blob_pending_records: int
    blob_copy_authorized_records: int
    porting_authorization_records: int
    classified_spdx_expressions: int
    authority_digests: dict[str, str]

    def render(self) -> str:
        lines = [
            (
                f"accounted_source_inputs={self.accounted_source_inputs} "
                f"public_sha_pins={self.public_sha_pins} "
                f"metadata_omitted_inputs={self.metadata_omitted_inputs}"
            ),
            f"task_packets={self.task_packets} source_path_closure=EXACT",
            (
                f"tree_discovery_records={self.tree_discovery_records} "
                f"blob_pending_records={self.blob_pending_records} "
                f"blob_copy_authorized_records={self.blob_copy_authorized_records}"
            ),
            (
                f"porting_admission=DISABLED_FAIL_CLOSED "
                f"porting_authorization_records={self.porting_authorization_records}"
            ),
            f"classified_spdx_expressions={self.classified_spdx_expressions} license_policy=FAIL_CLOSED",
        ]
        for path, digest in sorted(self.authority_digests.items()):
            lines.append(f"authority_sha256={digest} path={path}")
        lines.append("reuse validation passed")
        return "\n".join(lines)


def validate_reuse(root: Path = ROOT, *, check_toolchain: bool = True) -> ReuseReport:
    root = root.resolve()
    if check_toolchain:
        _validate_toolchain()
    source_by_repository, accounted_sources = _validate_reuse_map(root)
    indexed_paths = _validate_path_index(root, source_by_repository)
    task_packet_count = _validate_task_packet_closure(root, indexed_paths)
    _authorization, _porting_record_schema = _validate_authorization_protocol(root)
    classified_spdx = _validate_license_policy(root)
    _validate_phase_zero_audit(root)
    authority_digests = {
        relative: _sha256(root / relative)
        for relative in AUTHORITY_PATHS
    }
    return ReuseReport(
        accounted_source_inputs=accounted_sources,
        public_sha_pins=len(EXPECTED_PUBLIC_SOURCES),
        metadata_omitted_inputs=EXPECTED_SOURCE_INVENTORY["metadataOmittedCount"],
        task_packets=task_packet_count,
        tree_discovery_records=EXPECTED_CURRENT_INVENTORY["treeDiscoveryRecords"],
        blob_pending_records=EXPECTED_CURRENT_INVENTORY["blobPendingRecords"],
        blob_copy_authorized_records=EXPECTED_CURRENT_INVENTORY["blobCopyAuthorizedRecords"],
        porting_authorization_records=EXPECTED_CURRENT_INVENTORY["portingAuthorizationRecords"],
        classified_spdx_expressions=classified_spdx,
        authority_digests=authority_digests,
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root containing reuse, legal, schema, and packet authorities",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        report = validate_reuse(arguments.root)
    except ReuseValidationError as exc:
        print(f"reuse validation failed: {exc}", file=sys.stderr)
        return 2
    print(report.render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
