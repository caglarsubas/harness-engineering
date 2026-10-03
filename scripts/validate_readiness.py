#!/usr/bin/env python3
"""Validate the Harness Engineering implementation-readiness package."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import jsonschema
import yaml

try:
    from safe_yaml import SafeLoader as MetaSafeLoader, safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import SafeLoader as MetaSafeLoader, safe_load as safe_yaml_load

try:
    from validate_packet_ownership import validate_packet_ownership
    from validate_conformance_reference_measurement import validate_dispatch_ownership
    from validate_alpha2_readiness import validate_model_authority
    from validate_readiness_repairs import validate_repair_amendment, validate_repair_authority
    from validate_linux_readiness import validate_linux_readiness
    from validate_linux_repair import validate_linux_repair
    from validate_linux_test_ownership import validate_linux_test_ownership
    from validate_model_fixture_scope import load_scope_inputs, validate_model_fixture_scope
    from validate_live_backend_readiness import load_live_inputs, validate_live_backend_readiness
    from validate_packet_scalar_repair import load_scalar_inputs, validate_scalar_repair
    from validate_successor_inventory import load_successor_inputs, validate_successor_inventory
    from validate_proxy_contract import load_proxy_inputs, validate_proxy_contract
    from validate_policy_observation import load_observation_inputs, validate_observation_contract
    from validate_custody_handoff import load_custody_inputs, validate_custody_handoff
    from validate_ci_performance import load_performance_inputs, validate_ci_performance
    from validate_credential_lifecycle import load_credential_inputs, validate_credential_lifecycle
    from validate_model_api_inventory import load_inventory_inputs, validate_model_api_inventory
except ModuleNotFoundError:  # Imported as scripts.validate_readiness by unit tests.
    from scripts.validate_packet_ownership import validate_packet_ownership
    from scripts.validate_conformance_reference_measurement import validate_dispatch_ownership
    from scripts.validate_alpha2_readiness import validate_model_authority
    from scripts.validate_readiness_repairs import validate_repair_amendment, validate_repair_authority
    from scripts.validate_linux_readiness import validate_linux_readiness
    from scripts.validate_linux_repair import validate_linux_repair
    from scripts.validate_linux_test_ownership import validate_linux_test_ownership
    from scripts.validate_model_fixture_scope import load_scope_inputs, validate_model_fixture_scope
    from scripts.validate_live_backend_readiness import load_live_inputs, validate_live_backend_readiness
    from scripts.validate_packet_scalar_repair import load_scalar_inputs, validate_scalar_repair
    from scripts.validate_successor_inventory import load_successor_inputs, validate_successor_inventory
    from scripts.validate_proxy_contract import load_proxy_inputs, validate_proxy_contract
    from scripts.validate_policy_observation import load_observation_inputs, validate_observation_contract
    from scripts.validate_custody_handoff import load_custody_inputs, validate_custody_handoff
    from scripts.validate_ci_performance import load_performance_inputs, validate_ci_performance
    from scripts.validate_credential_lifecycle import load_credential_inputs, validate_credential_lifecycle
    from scripts.validate_model_api_inventory import load_inventory_inputs, validate_model_api_inventory


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_FORMAT_CHECKER = jsonschema.FormatChecker()


@SCHEMA_FORMAT_CHECKER.checks("date-time")
def is_canonical_rfc3339_date_time(value: object) -> bool:
    """Enforce date-time even when jsonschema's optional format extra is absent."""

    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ):
        return False
    try:
        dt.datetime.fromisoformat(
            value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else "")
        )
    except ValueError:
        return False
    return True

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

EXPECTED_HARNESSES = {
    "runtime.infrastructure",
    "runtime.model-inference",
    "runtime.ai-gateway",
    "runtime.experience",
    "knowledge.domain-semantic",
    "knowledge.data-integration",
    "knowledge.retrieval-context",
    "knowledge.memory-state",
    "execution.protocol-interoperability",
    "execution.orchestration",
    "execution.tool-skill-sandbox",
    "execution.ml-decision",
    "trust.security-safety",
    "trust.governance-agentops",
    "trust.observability-finops",
    "trust.evaluation-assurance",
}

EXPECTED_DEPLOYMENT_MODES = {
    "operator-hosted-saas",
    "tenant-public-cloud",
    "self-managed",
    "air-gapped",
}

EXPECTED_BASE_SOURCES = {
    "claude-harness-compass",
    "gemini-mas-composition",
    "chatgpt-deep-research",
    "enterprise-mas-presentation",
    "harness-onion-vector",
    "harness-onion-raster",
}

EXPECTED_PACKET_COUNT = 194
EXPECTED_REUSE_PATH_COUNT = 5107
LIVE_CAMPAIGN_PACKET_IDS = {
    "CONF-A1-001",
    "CONF-A2-001",
    "CONF-A3-001",
    "CONF-AIR-001",
    "CONF-K3S-001",
    "CONF-K8S-001",
    "CONF-LINUX-001",
    "CONF-LIVE-006",
    "CONF-OCP-001",
    "CONF-SEC-001",
    "CONF-UPG-001",
    "CONF-WG-001",
}
LIVE_CAMPAIGN_EXECUTION_BASE = {
    "launcherArgv": ["/opt/planeon/bin/harness-live-campaign-launch"],
    "commandTransport": "ARGV_ARRAY_V1",
    "executionPlacement": "PREINSTALLED_TARGET_LOCAL_EPHEMERAL_RUNNER",
    "executionEnvelopeEnvironment": "HARNESS_LIVE_EXECUTION_ENVELOPE",
    "executionEnvelopeMode": "DUAL_SIGNED_PACKET_COMMAND_CAMPAIGN_ENDPOINT_BINDING_V1",
    "releaseTrustStoreMount": "/etc/planeon/trust/release-trust-bundle.json",
    "tenantTrustStoreMount": "/etc/planeon/trust/tenant-trust-bundle.json",
    "trustStoreMode": "HASH_PINNED_LOCAL_PUBLIC_KEYS_VALIDITY_PURPOSE_AND_REVOCATION_V1",
    "revocationRequired": True,
    "networkIsolation": "OS_ENFORCED_DENY_ALL_EXCEPT_SIGNED_ENDPOINTS",
    "endpointAuthority": "TENANT_CONTROLLED_PREEXISTING_CAPACITY_ONLY",
    "dynamicEndpointTransport": "PREAUTHORIZED_API_OR_CAMPAIGN_PROXY_ONLY",
    "mutationAdmission": "SERVER_SIDE_SIGNED_ZERO_INCREMENTAL_COST_POLICY_AND_RBAC_REQUIRED",
    "capacityAuthorization": "INDEPENDENT_OPERATOR_SIGNED_FIXED_PREEXISTING_CAPACITY",
    "publicInternetDiscovery": "DENIED",
    "cloudManagementApis": "DENIED",
    "billingApis": "DENIED",
    "thirdPartyApiKeys": "DENIED",
    "credentialMode": "TENANT_LOCAL_SHORT_LIVED_FILE_REFERENCE",
    "unavailableResult": "NOT_RUN_ENV_UNAVAILABLE",
    "ciEvidenceUse": "FORBIDDEN",
}

DATA_HARNESS_V1_OBSERVATION_PATHS = [
    "schemas/v1/action-preview.schema.json",
    "schemas/v1/bounded-query-plan.schema.json",
    "schemas/v1/checkpoint-token.schema.json",
    "schemas/v1/connector-worker-profile.schema.json",
    "schemas/v1/coverage-statement.schema.json",
    "schemas/v1/cross-plane-evidence-set.schema.json",
    "schemas/v1/data-batch.schema.json",
    "schemas/v1/data-source-connector-profile.schema.json",
    "schemas/v1/deployment-profile.schema.json",
    "schemas/v1/disconnected-runtime-readiness.schema.json",
    "schemas/v1/durable-action-record.schema.json",
    "schemas/v1/entity-redirect.schema.json",
    "schemas/v1/freshness-observation.schema.json",
    "schemas/v1/industry-domain-pack-manifest.schema.json",
    "schemas/v1/live-acceptance-campaign.schema.json",
    "schemas/v1/local-cross-plane-evidence.schema.json",
    "schemas/v1/local-harness-runtime-evidence.schema.json",
    "schemas/v1/local-image-lock.schema.json",
    "schemas/v1/local-source-evidence.schema.json",
    "schemas/v1/northbound-tool-catalog.schema.json",
    "schemas/v1/promotion-readiness.schema.json",
    "schemas/v1/protocol-profile-conformance.schema.json",
    "schemas/v1/reference-lab-manifest.schema.json",
    "schemas/v1/route-decision.schema.json",
    "schemas/v1/semantic-assertion.schema.json",
    "schemas/v1/semantic-mapping-candidate.schema.json",
    "schemas/v1/source-action-capability-profile.schema.json",
    "schemas/v1/source-action-plan.schema.json",
    "schemas/v1/source-mutation-receipt.schema.json",
]

REFERENCE_OBSERVATION_EXECUTION_BASE = {
    "launcherArgv": ["/opt/planeon/bin/harness-reference-observe"],
    "executionPlacement": "PREINSTALLED_LOCAL_SEPARATE_OBSERVER_IDENTITY",
    "packetPathEnvironment": "HARNESS_TASK_PACKET",
    "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
    "sourceAuthorityEnvironment": "HARNESS_REFERENCE_SOURCE_AUTHORITY",
    "sourceAuthorityMode": "ROOT_OWNED_SIGNED_EXACT_COMMIT_AND_PATHS",
    "observerIdentity": "planeon-reference-observer",
    "networkIsolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
    "sourceFilesystem": "DECLARED_BLOBS_READ_METADATA_ONLY_ALL_WRITE_DENIED",
    "sourceCodeExecution": "DENIED",
    "outputMode": "DISTILLED_CONTRACT_FACTS_ONLY_NO_SOURCE_TEXT",
    "allowedFactKinds": [
        "SCHEMA_IDENTITY",
        "OBJECT_FIELD",
        "REQUIRED_FIELD",
        "VALUE_CONSTRAINT",
        "STATE_ENUM",
        "REFERENCE_EDGE",
        "SCHEMA_DIGEST",
    ],
    "copyAuthority": "NONE",
    "implementationIdentityAccess": "DENIED",
    "ciEvidenceUse": "FORBIDDEN",
}
TREE_OBSERVATION_EXECUTION_BASE = {
    "launcherArgv": ["/opt/planeon/bin/harness-reference-observe"],
    "executionPlacement": "PREINSTALLED_LOCAL_SEPARATE_OBSERVER_IDENTITY",
    "packetPathEnvironment": "HARNESS_TASK_PACKET",
    "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
    "sourceAuthorityEnvironment": "HARNESS_REFERENCE_SOURCE_AUTHORITY",
    "sourceAuthorityMode": "ROOT_OWNED_SIGNED_EXACT_COMMIT_FULL_TRACKED_TREE",
    "observerIdentity": "planeon-reference-observer",
    "observationMode": "FULL_TRACKED_TREE_METADATA",
    "sourceSelection": "FULL_TRACKED_TREE_AT_PINNED_COMMIT",
    "networkIsolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
    "sourceFilesystem": "FULL_TRACKED_TREE_METADATA_ONLY_ALL_CONTENT_READ_AND_WRITE_DENIED",
    "sourceCodeExecution": "DENIED",
    "outputMode": "DISTILLED_REPOSITORY_TREE_METADATA_ONLY_NO_SOURCE_TEXT",
    "allowedFactKinds": ["REPOSITORY_SUMMARY", "TREE_ENTRY"],
    "copyAuthority": "NONE",
    "implementationIdentityAccess": "DENIED",
    "ciEvidenceUse": "FORBIDDEN",
}
TREE_OBSERVATION_PACKETS = {
    "MET-OBS-AH-001": {
        "repository": "git@github.com:caglarsubas/agent-hook-v2.git",
        "commit": "2b521dc03a43b994bc52c76652306b1a77bf9572",
        "outputPath": "architecture/observations/agent-hook-v2-tree.json",
    },
    "MET-OBS-OCP-001": {
        "repository": "git@github.com:caglarsubas/orchestra-openshift-reference-lab.git",
        "commit": "ba615515af84760a0accb31c37b815f9820f06d2",
        "outputPath": "architecture/observations/orchestra-openshift-reference-lab-tree.json",
    },
    "MET-OBS-SDK-001": {
        "repository": "git@github.com:caglarsubas/planeon-orchestra-python-sdk.git",
        "commit": "3a4012d809e6ed00a3f05be940c5278eac20a166",
        "outputPath": "architecture/observations/planeon-orchestra-python-sdk-tree.json",
    },
}
LIVE_CAMPAIGN_EVIDENCE_AXES = {
    "CONF-A1-001": ["RUNTIME", "ASSURANCE"],
    "CONF-A2-001": ["RUNTIME", "ASSURANCE"],
    "CONF-A3-001": ["RUNTIME", "ASSURANCE"],
    "CONF-AIR-001": ["DEPLOYMENT", "RUNTIME", "ASSURANCE"],
    "CONF-K3S-001": ["DEPLOYMENT", "RUNTIME", "ASSURANCE"],
    "CONF-K8S-001": ["DEPLOYMENT", "RUNTIME", "ASSURANCE"],
    "CONF-LINUX-001": ["DEPLOYMENT", "RUNTIME", "SECURITY", "ASSURANCE"],
    "CONF-LIVE-006": ["DEPLOYMENT", "RUNTIME", "SECURITY", "ASSURANCE"],
    "CONF-OCP-001": ["DEPLOYMENT", "RUNTIME", "ASSURANCE"],
    "CONF-SEC-001": ["SECURITY", "ASSURANCE"],
    "CONF-UPG-001": ["DEPLOYMENT", "RUNTIME", "ASSURANCE"],
    "CONF-WG-001": ["ASSURANCE", "TENANT_ACCEPTANCE_CANDIDATE"],
}
LEGACY_PACKET_RESULT_PATTERN = re.compile(
    r"\b(?:LIVE_PASS|LIVE_FAIL|NOT_RUN)\b|\bLIVE\s+(?:or|result)",
    flags=re.IGNORECASE,
)
EXPECTED_MANAGEMENT_SERVICES = {
    "control-web": "mas-harness-control-plane",
    "profile-compiler-worker": "mas-harness-control-plane",
}

EXPECTED_WARM_SOURCES = {
    "git@github.com:caglarsubas/llm_inference_engine.git": "6815c21cb10a4d7dc0b4804f6bb223afb4321e97",
    "git@github.com:caglarsubas/data-source-harness.git": "858281f4b845ffacfe05cdb2c40a402c237d4c54",
    "git@github.com:caglarsubas/agent-hook-v2.git": "2b521dc03a43b994bc52c76652306b1a77bf9572",
    "git@github.com:caglarsubas/orchestra-openshift-reference-lab.git": "ba615515af84760a0accb31c37b815f9820f06d2",
    "git@github.com:caglarsubas/planeon-orchestra-python-sdk.git": "3a4012d809e6ed00a3f05be940c5278eac20a166",
}

EXPECTED_TREE_OBSERVATION_DIGESTS = {
    "MET-OBS-AH-001": "0c94377f0ae6bf7ec7d70d521c411ff6883614cb2cebca2a1243cea1ce775339",
    "MET-OBS-OCP-001": "c0cab3b3c294ab0db09f19215ad51f3ca5b09c71bb007fef2b894f7588d3f41b",
    "MET-OBS-SDK-001": "aa41c2d2b781e6776724367b3cf931d23b6812cc14ecb4a27c4f6c0b69ef61d7",
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

REQUIRED_REPOSITORY_TOPICS = {
    "purpose": ("purpose",),
    "non-goals": ("non-goals",),
    "repository structure": ("repository structure", "exact tree", "layout"),
    "dependencies": ("dependencies",),
    "testing": ("testing", "test strategy", "verification and acceptance"),
}

REQUIRED_HARNESS_TERMS = {
    "Dependencies",
    "Configuration",
    "State",
    "Failure",
    "Evidence",
    "Tests",
}

ALLOWED_PROVIDER_COST_DISPOSITIONS = {
    "SELF_HOSTED_OPEN_SOURCE_NON_METERED",
    "TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED",
}

REQUIRED_PROVIDER_FORBIDDEN_FIELDS = {
    "inlineSecret",
    "apiKey",
    "mutableTag",
    "runtimeDownload",
}

REQUIRED_FORBIDDEN_PROVIDER_TRAITS = {
    "metered-or-pay-per-use-service",
    "provider-owned-api-key-or-secret",
    "runtime-package-or-model-download",
    "mutable-artifact-reference",
    "undeclared-external-egress",
    "mandatory-public-cloud-control-plane",
    "hosted-ci-or-github-storage-requirement",
}

FORBIDDEN_PROVIDER_ID_FRAGMENTS = {
    "anthropic",
    "bedrock",
    "cloudflare",
    "gemini",
    "ghcr",
    "github-packages",
    "ngrok",
    "openai",
    "openrouter",
    "vertex",
}

MUTABLE_ARTIFACT_PATTERN = re.compile(
    r"(?:^|[/:@._-])(latest|main|master|head|nightly|edge)(?:$|[/:@._-])",
    re.IGNORECASE,
)


class Validation:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.error(message)


class DuplicateJsonKeyError(ValueError):
    """A JSON authority repeated a member name and is therefore ambiguous."""


class DuplicateYamlKeyError(yaml.YAMLError):
    """A YAML authority repeated a mapping key and is therefore ambiguous."""


class UniqueKeySafeLoader(MetaSafeLoader):
    """Safe YAML loader whose mappings reject duplicate keys."""


def construct_unique_yaml_mapping(
    loader: UniqueKeySafeLoader, node: yaml.MappingNode, deep: bool = False
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
    construct_unique_yaml_mapping,
)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_object
    )


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.load(handle, Loader=UniqueKeySafeLoader)


def validate_schema_instance(
    validation: Validation, schema_path: Path, instance: Any, label: str
) -> None:
    """Validate an authority against a closed Draft 2020-12 schema."""

    try:
        schema = load_json(schema_path)
        jsonschema.Draft202012Validator.check_schema(schema)
    except (
        OSError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
        jsonschema.SchemaError,
    ) as exc:
        validation.error(f"{label} schema is invalid or unreadable: {exc}")
        return
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=SCHEMA_FORMAT_CHECKER
    )
    for error in sorted(
        validator.iter_errors(instance),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    ):
        validation.error(
            f"{label} schema error at {list(error.absolute_path)}: {error.message}"
        )


def load_capability_registry(validation: Validation) -> set[str]:
    """Load the one canonical capability vocabulary used by all authorities."""

    catalog = load_yaml(ROOT / "architecture/providers.yaml")
    raw_registry = catalog.get("capabilityRegistry", []) if isinstance(catalog, dict) else []
    validation.require(
        isinstance(raw_registry, list)
        and all(isinstance(item, str) and item for item in raw_registry),
        "provider capabilityRegistry must be a non-empty string list",
    )
    capabilities = {
        item for item in raw_registry if isinstance(item, str) and item
    }
    validation.require(
        len(capabilities) == len(raw_registry) if isinstance(raw_registry, list) else False,
        "provider capabilityRegistry must not contain duplicates",
    )
    return capabilities


def validate_selection_predicate_references(
    validation: Validation,
    predicate: Any,
    label: str,
    capability_registry: set[str],
    harness_ids: set[str] | None = None,
) -> None:
    """Reject conditional references outside the canonical registries."""

    if not isinstance(predicate, dict):
        validation.error(f"{label} must use a typed selection predicate")
        return
    for capability in [
        *predicate.get("anyOfCapabilities", []),
        *predicate.get("anyOfSubjectCapabilities", []),
    ]:
        validation.require(
            capability in capability_registry,
            f"{label} references unregistered capability {capability!r}",
        )
    for harness_id in predicate.get("anyOfSubjectHarnesses", []):
        validation.require(
            harness_ids is not None and harness_id in harness_ids,
            f"{label} references unknown subject harness {harness_id!r}",
        )


def extract_packet_ids(text: str) -> list[str]:
    packet_ids: list[str] = []
    for token in re.findall(r"`([^`]+)`", text):
        match = re.fullmatch(
            r"([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)(?:-[a-z0-9][a-z0-9-]*)?",
            token,
        )
        if match:
            packet_ids.append(match.group(1))
    return packet_ids


def assert_acyclic(
    validation: Validation, nodes: set[str], edges: dict[str, list[str]], label: str
) -> None:
    indegree = {node: 0 for node in nodes}
    outgoing: dict[str, list[str]] = defaultdict(list)
    for node, dependencies in edges.items():
        for dependency in dependencies:
            if dependency not in nodes:
                validation.error(f"{label} {node!r} references unknown dependency {dependency!r}")
                continue
            indegree[node] += 1
            outgoing[dependency].append(node)

    queue = deque(sorted(node for node, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        current = queue.popleft()
        visited += 1
        for dependent in outgoing[current]:
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)
    if visited != len(nodes):
        cyclic = sorted(node for node, degree in indegree.items() if degree > 0)
        validation.error(f"{label} dependency cycle: {', '.join(cyclic)}")


def reduce_dependency_contributions(
    contributions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Apply the canonical order-independent full-snapshot dependency reducer."""

    severity_order = ["FAILED", "BLOCKED", "DEGRADED", "READY"]
    observed_order = ["FAILED", "BLOCKED", "DEGRADED", "NO_CHANGE"]
    readiness_order = ["NOT_READY", "POLICY_CONTROLLED", "NO_CHANGE"]
    desired_order = ["SET_SUSPENDED", "NO_CHANGE"]
    action_order = [
        "FAIL_WAVE_RETAIN_EVIDENCE",
        "REJECT_NEW_AND_COMPENSATE",
        "DO_NOT_APPLY",
        "BLOCK_START",
        "BLOCK_MUTATIONS",
        "PAUSE_ACK_RETAIN_CURSOR",
        "RETURN_RETRYABLE_503",
        "EXECUTE_ON_EXHAUSTION",
        "APPLY_DEGRADATION_POLICY",
        "RESET_DEGRADATION_BUDGET_AND_RECOMPUTE",
        "RESTORE_OPTIONAL_CAPABILITY_AND_RECOMPUTE",
        "RECOMPUTE_AND_UNBLOCK_IF_PERMITTED",
        "RECOMPUTE_AND_RESUME_IF_PERMITTED",
        "RECOMPUTE_FROM_DEPENDENCY_SNAPSHOT",
        "NO_CHANGE",
    ]

    def first_present(order: list[str], values: set[str]) -> str:
        return next((value for value in order if value in values), order[-1])

    normalized = [
        item
        for item in contributions
        if isinstance(item, dict)
        and isinstance(item.get("edgeContribution"), dict)
        and isinstance(item.get("edgeKey"), str)
    ]
    severities = {
        str(item["edgeContribution"].get("severity")) for item in normalized
    }
    winning_severity = first_present(severity_order, severities)
    winning_items = sorted(
        (
            item
            for item in normalized
            if item["edgeContribution"].get("severity") == winning_severity
        ),
        key=lambda item: item["edgeKey"],
    )
    actions = {str(item.get("workAction")) for item in normalized}
    if actions - {"NO_CHANGE"}:
        actions.discard("NO_CHANGE")
    return {
        "severity": winning_severity,
        "observedStateEffect": first_present(
            observed_order,
            {
                str(item["edgeContribution"].get("observedStateEffect"))
                for item in normalized
            },
        ),
        "readinessEffect": first_present(
            readiness_order,
            {
                str(item["edgeContribution"].get("readinessEffect"))
                for item in normalized
            },
        ),
        "desiredStateAction": first_present(
            desired_order,
            {
                str(item["edgeContribution"].get("desiredStateAction"))
                for item in normalized
            },
        ),
        "workActions": [action for action in action_order if action in actions],
        "reason": (
            winning_items[0].get("reason")
            if winning_items and winning_severity != "READY"
            else None
        ),
        "reasonEdgeKey": (
            winning_items[0]["edgeKey"]
            if winning_items and winning_severity != "READY"
            else None
        ),
    }


def validate_architecture(validation: Validation) -> tuple[set[str], set[str]]:
    capability_registry = load_capability_registry(validation)
    registry = load_yaml(ROOT / "architecture/repositories.yaml")
    validate_schema_instance(
        validation,
        ROOT / "schemas/repositories.schema.json",
        registry,
        "repository registry",
    )
    repositories = registry.get("repositories", [])
    names = {item.get("name") for item in repositories}
    ids = {item.get("id") for item in repositories}
    validation.require(names == EXPECTED_REPOSITORIES, "repository registry must contain exactly 13 approved repositories")
    validation.require(len(ids) == len(repositories), "repository IDs must be unique")

    dependency_semantics = registry.get("dependencySemantics", {})
    validation.require(
        dependency_semantics.get("everyUnconditionalRepositoryGraphAcyclic") is True,
        "repository registry must require every unconditional repository graph to be acyclic",
    )
    validation.require(
        dependency_semantics.get("acyclicityExclusions")
        == ["subjectUnderEvaluation"],
        "only subjectUnderEvaluation campaign callbacks may be excluded from repository acyclicity",
    )

    dependency_graphs = registry.get("dependencyGraphs", {})
    expected_graph_types = {
        "contractSource",
        "buildArtifact",
        "releaseSet",
        "runtimeIntegration",
    }
    validation.require(
        set(dependency_graphs) == expected_graph_types,
        "repository registry must define the four typed dependency graphs exactly once",
    )
    graph_edges: dict[str, list[dict[str, Any]]] = {}
    for graph_type in sorted(expected_graph_types):
        raw_edges = dependency_graphs.get(graph_type, {}).get("edges", [])
        validation.require(isinstance(raw_edges, list), f"repository {graph_type} edges must be a list")
        typed_edges: list[dict[str, Any]] = []
        seen_edges: set[tuple[str, str]] = set()
        for edge in raw_edges if isinstance(raw_edges, list) else []:
            validation.require(isinstance(edge, dict), f"repository {graph_type} edge must be a mapping")
            if not isinstance(edge, dict):
                continue
            consumer = edge.get("consumer")
            provider = edge.get("provider")
            validation.require(consumer in ids, f"repository {graph_type} edge has unknown consumer {consumer!r}")
            validation.require(provider in ids, f"repository {graph_type} edge has unknown provider {provider!r}")
            validation.require(consumer != provider, f"repository {graph_type} contains self-edge {consumer!r}")
            validation.require(
                (consumer, provider) not in seen_edges,
                f"repository {graph_type} repeats edge {consumer}->{provider}",
            )
            seen_edges.add((consumer, provider))
            if graph_type in {"buildArtifact", "releaseSet"}:
                validation.require(bool(edge.get("artifact")), f"repository {graph_type} edge {consumer}->{provider} lacks artifact")
            if graph_type == "runtimeIntegration":
                validation.require(bool(edge.get("interface")), f"runtime edge {consumer}->{provider} lacks interface")
                if "selectedWhen" in edge:
                    validate_selection_predicate_references(
                        validation,
                        edge.get("selectedWhen"),
                        f"repository runtime edge {consumer}->{provider}",
                        capability_registry,
                        EXPECTED_HARNESSES,
                    )
            typed_edges.append(edge)
        graph_edges[graph_type] = typed_edges
        acyclic_edges = []
        for edge in typed_edges:
            selection_type = edge.get("selectionType")
            validation.require(
                selection_type != "subjectUnderEvaluation" or graph_type == "runtimeIntegration",
                f"repository {graph_type} edge may not use the subjectUnderEvaluation exclusion",
            )
            if selection_type != "subjectUnderEvaluation":
                acyclic_edges.append(edge)
        assert_acyclic(
            validation,
            ids,
            {
                repository_id: [
                    edge["provider"]
                    for edge in acyclic_edges
                    if edge.get("consumer") == repository_id and edge.get("provider") in ids
                ]
                for repository_id in ids
            },
            f"repository {graph_type}",
        )

    contract_projection = {
        repository_id: sorted(
            edge["provider"]
            for edge in graph_edges.get("contractSource", [])
            if edge.get("consumer") == repository_id
        )
        for repository_id in ids
    }
    for repository in repositories:
        validation.require(
            sorted(repository.get("dependsOn", [])) == contract_projection.get(repository["id"], []),
            f"repository {repository['id']} legacy dependsOn is not the contractSource projection",
        )
    assert_acyclic(
        validation,
        ids,
        {item["id"]: item.get("dependsOn", []) for item in repositories},
        "repository",
    )

    bootstrap = registry.get("operatorBootstrap", {})
    validation.require(
        [phase.get("id") for phase in bootstrap.get("phases", [])]
        == ["build-operator", "assemble-release-set", "install-workloads"],
        "operator/distribution bootstrap phases must be explicit and ordered",
    )
    validation.require(
        any(
            item.get("releaseSet") == {"consumer": "distribution", "provider": "operator"}
            and item.get("runtimeIntegration") == {"consumer": "operator", "provider": "distribution"}
            for item in bootstrap.get("crossPhaseReciprocalEdges", [])
            if isinstance(item, dict)
        ),
        "operator/distribution reciprocal edges must be assigned to distinct bootstrap phases",
    )

    runtime_edges = graph_edges.get("runtimeIntegration", [])
    validation.require(
        any(
            edge.get("consumer") == "knowledge-plane"
            and edge.get("provider") == "trust-plane"
            for edge in runtime_edges
        )
        and any(
            edge.get("consumer") == "model-plane"
            and edge.get("provider") == "trust-plane"
            for edge in runtime_edges
        ),
        "knowledge and model runtime integrations must retain their trust-plane dependencies",
    )
    for subject_provider in ("knowledge-plane", "model-plane"):
        validation.require(
            any(
                edge.get("consumer") == "trust-plane"
                and edge.get("provider") == subject_provider
                and edge.get("selectionType") == "subjectUnderEvaluation"
                and isinstance(edge.get("selectedWhen"), dict)
                for edge in runtime_edges
            ),
            f"trust-plane lacks a typed subject-under-evaluation edge to {subject_provider}",
        )

    taxonomy = load_yaml(ROOT / "architecture/taxonomy.yaml")
    validate_schema_instance(
        validation,
        ROOT / "schemas/taxonomy.schema.json",
        taxonomy,
        "harness taxonomy",
    )
    deployment_modes = taxonomy.get("deploymentModes", {})
    mode_records = deployment_modes.get("modes", [])
    validation.require(
        isinstance(deployment_modes.get("billingBoundary"), str)
        and bool(deployment_modes.get("billingBoundary")),
        "taxonomy must state the deployment-mode billing boundary",
    )
    validation.require(
        isinstance(mode_records, list)
        and {mode.get("id") for mode in mode_records if isinstance(mode, dict)}
        == EXPECTED_DEPLOYMENT_MODES
        and len(mode_records) == len(EXPECTED_DEPLOYMENT_MODES),
        "taxonomy must define SaaS, tenant public-cloud, self-managed, and air-gapped modes exactly once",
    )
    for mode in mode_records if isinstance(mode_records, list) else []:
        if not isinstance(mode, dict):
            validation.error("deployment mode must be a mapping")
            continue
        mode_id = mode.get("id")
        validation.require(
            mode.get("billableProvisioning") == "FORBIDDEN",
            f"deployment mode {mode_id} permits billable provisioning",
        )
        validation.require(
            bool(mode.get("infrastructureCustody"))
            and bool(mode.get("tenancy"))
            and bool(mode.get("connectivity"))
            and bool(mode.get("certificationPackets")),
            f"deployment mode {mode_id} lacks custody, tenancy, connectivity, or certification mapping",
        )
    dependency_types = taxonomy.get("dependencyTypes", {})
    allowed_dependency_types = {
        "always",
        "whenCapability",
        "productionGate",
        "subjectUnderEvaluation",
    }
    validation.require(
        set(dependency_types) == allowed_dependency_types,
        "taxonomy must define all four typed harness dependency semantics",
    )
    harnesses = taxonomy.get("harnesses", [])
    harness_ids = {item.get("id") for item in harnesses}
    validation.require(harness_ids == EXPECTED_HARNESSES, "taxonomy must contain exactly the 16 canonical harnesses")
    gate_records = taxonomy.get("productionGates", [])
    gate_ids = {
        item.get("id") for item in gate_records if isinstance(item, dict)
    }
    expected_gate_ids = {
        "runtimeGatewayProductionAssurance",
        "decisionRouteProductionAssurance",
    }
    validation.require(
        gate_ids == expected_gate_ids and len(gate_records) == len(expected_gate_ids),
        "taxonomy must define both production gates exactly once",
    )
    required_controls_by_gate = {
        "runtimeGatewayProductionAssurance": [
            "gateway.contract-conformance",
            "gateway.route-integrity",
            "gateway.tenant-isolation",
            "gateway.security-safety",
            "gateway.zero-bill-offline",
            "gateway.supply-chain",
            "gateway.runtime-resilience",
            "gateway.tenant-acceptance",
        ],
        "decisionRouteProductionAssurance": [
            "decision.contract-conformance",
            "decision.route-integrity",
            "decision.data-provenance",
            "decision.tenant-isolation",
            "decision.security-safety",
            "decision.zero-bill-offline",
            "decision.supply-chain",
            "decision.runtime-resilience",
            "decision.tenant-acceptance",
        ],
    }
    digest_requirement = {"required": True, "algorithm": "sha256"}
    required_gate_scope = [
        "tenantId",
        "profileDigest",
        "bundleDigest",
        "routeId",
        "routeDigest",
        "subjectType",
        "subjectId",
        "subjectVersion",
        "subjectDigest",
    ]
    seen_gate_controls: set[str] = set()
    for gate in gate_records if isinstance(gate_records, list) else []:
        if not isinstance(gate, dict):
            continue
        gate_id = gate.get("id")
        validation.require(
            gate.get("requiredEvidenceStatus") == "PASS"
            and gate.get("maximumEvidenceAgeSeconds") == 86400,
            f"production gate {gate_id} must require fresh PASS evidence",
        )
        digest = gate.get("immutableSubjectDigest", {})
        validation.require(
            digest == digest_requirement,
            f"production gate {gate_id} must bind an immutable SHA-256 subject digest",
        )
        evidence_plan = gate.get("evidencePlanBinding", {})
        controls = evidence_plan.get("requiredControls", [])
        validation.require(
            evidence_plan.get("planIdRequired") is True
            and evidence_plan.get("planDigest") == digest_requirement
            and evidence_plan.get("controlSetDigest") == digest_requirement
            and controls == required_controls_by_gate.get(gate_id)
            and evidence_plan.get("aggregation") == "ALL_REQUIRED_CONTROLS",
            f"production gate {gate_id} must bind its complete immutable evidence plan and control set",
        )
        validation.require(
            not (seen_gate_controls & set(controls)),
            f"production gate {gate_id} reuses a control ID owned by another gate",
        )
        seen_gate_controls.update(controls)
        campaign = gate.get("campaignBinding", {})
        validation.require(
            campaign.get("purpose") == "PRODUCTION_PROMOTION"
            and campaign.get("campaignIdRequired") is True
            and campaign.get("campaignDigest") == digest_requirement,
            f"production gate {gate_id} must bind an immutable production-promotion campaign",
        )
        validation.require(
            gate.get("controlSatisfaction")
            == {
                "rule": "FRESH_PASS_FOR_EVERY_REQUIRED_CONTROL",
                "nonPassDisposition": "PROMOTION_BLOCKED",
                "waiverEffect": "DOCUMENT_EXCEPTION_ONLY_PROMOTION_REMAINS_BLOCKED",
                "waiverSatisfiesPromotion": False,
            },
            f"production gate {gate_id} must require fresh PASS for every control and keep waivers non-satisfying",
        )
        producer = gate.get("trustedProducer", {})
        validation.require(
            producer.get("policyId")
            == "production-assurance-trusted-producer-v1"
            and producer.get("policyDigest") == digest_requirement
            and producer.get("signatureRequired") is True
            and producer.get("signerIdentityRequired") is True
            and producer.get("producerReleaseDigest") == digest_requirement,
            f"production gate {gate_id} must bind a signed trusted producer release",
        )
        scope = gate.get("scopeBinding", {})
        validation.require(
            scope
            == {"matchPolicy": "EXACT_ALL", "requiredFields": required_gate_scope},
            f"production gate {gate_id} must exactly bind tenant/profile/bundle/route/subject scope",
        )
        waiver = gate.get("waiver", {})
        validation.require(
            waiver.get("allowed") is True
            and waiver.get("signatureRequired") is True
            and waiver.get("expiresAtRequired") is True
            and waiver.get("subjectDigestBindingRequired") is True
            and waiver.get("maximumDurationSeconds") == 14400
            and waiver.get("evidencePlanDigestBindingRequired") is True
            and waiver.get("controlSetDigestBindingRequired") is True
            and waiver.get("campaignDigestBindingRequired") is True
            and waiver.get("controlIdBinding") == "SAME_REQUIRED_CONTROL_ID"
            and waiver.get("scopeBinding") == "EXACT_GATE_SCOPE"
            and waiver.get("forbiddenEvidenceStatuses") == ["FAIL", "STALE"],
            f"production gate {gate_id} waiver must bind the same plan/control/campaign/scope and never override FAIL/STALE",
        )
    gate_consumers: dict[str, list[tuple[str, str]]] = defaultdict(list)
    harness_edges: dict[str, list[str]] = {}
    for harness in harnesses:
        validation.require(
            harness.get("ownerRepository") in ids,
            f"harness {harness.get('id')} has an unknown repository owner",
        )
        validation.require(bool(harness.get("deployables")), f"harness {harness.get('id')} has no deployable or platform unit")
        dependency_ids: list[str] = []
        for dependency in harness.get("requires", []):
            validation.require(
                isinstance(dependency, dict),
                f"harness {harness.get('id')} dependencies must be typed mappings",
            )
            if not isinstance(dependency, dict):
                continue
            dependency_id = dependency.get("id")
            dependency_type = dependency.get("type")
            validation.require(
                dependency_id in harness_ids,
                f"harness {harness.get('id')} references unknown dependency {dependency_id!r}",
            )
            validation.require(
                dependency_type in allowed_dependency_types,
                f"harness {harness.get('id')} dependency {dependency_id} has unknown type {dependency_type!r}",
            )
            if dependency_type in {"whenCapability", "subjectUnderEvaluation"}:
                selected_when = dependency.get("selectedWhen")
                validation.require(
                    isinstance(selected_when, dict) and bool(selected_when),
                    f"conditional dependency {harness.get('id')}->{dependency_id} lacks a typed selectedWhen predicate",
                )
                validate_selection_predicate_references(
                    validation,
                    selected_when,
                    f"harness dependency {harness.get('id')}->{dependency_id}",
                    capability_registry,
                    harness_ids,
                )
            if dependency_type == "productionGate":
                validation.require(
                    dependency.get("gate") in gate_ids,
                    f"harness {harness.get('id')} dependency {dependency_id} references unknown production gate {dependency.get('gate')!r}",
                )
                gate_consumers[str(dependency.get("gate"))].append(
                    (str(harness.get("id")), str(dependency_id))
                )
            if dependency_type == "always":
                validation.require(
                    set(dependency) == {"id", "type"},
                    f"always dependency {harness.get('id')}->{dependency_id} carries a conditional field",
                )
            dependency_ids.append(dependency_id)
        validation.require(
            len(dependency_ids) == len(set(dependency_ids)),
            f"harness {harness.get('id')} repeats a dependency",
        )
        harness_edges[harness["id"]] = dependency_ids
    validation.require(
        gate_consumers
        == {
            "runtimeGatewayProductionAssurance": [
                ("runtime.ai-gateway", "trust.evaluation-assurance")
            ],
            "decisionRouteProductionAssurance": [
                ("execution.ml-decision", "trust.evaluation-assurance")
            ],
        },
        "production gates must be referenced only by their designated runtime and decision consumers",
    )
    assert_acyclic(
        validation,
        harness_ids,
        harness_edges,
        "harness",
    )

    dependency_graph = load_yaml(ROOT / "architecture/dependency-graph.yaml")
    validate_schema_instance(
        validation,
        ROOT / "schemas/dependency-graph.schema.json",
        dependency_graph,
        "runtime dependency graph",
    )
    validation.require(
        dependency_graph.get("rules", {}).get("artifactReference") == "version-and-sha256-digest",
        "dependency graph must require immutable artifact versions and SHA-256 digests",
    )
    dependency_rules = dependency_graph.get("rules", {})
    validation.require(
        dependency_rules.get("everyUnconditionalRepositoryGraphAcyclic") is True
        and dependency_rules.get("repositoryGraphAcyclicityExclusions")
        == ["subjectUnderEvaluation"],
        "runtime dependency authority must exclude only subjectUnderEvaluation callbacks from repository acyclicity",
    )
    runtime_surface = dependency_graph.get("runtimeSurface", {}).get("services", {})
    validation.require(set(runtime_surface) == {"ai-gateway", "experience-gateway"}, "runtime surface must define both gateways")
    validation.require(runtime_surface.get("ai-gateway", {}).get("basePath") == "/gateway/v1", "AI gateway base path is not canonical")
    validation.require(
        runtime_surface.get("experience-gateway", {}).get("basePath") == "/experience/v1",
        "experience gateway base path is not canonical",
    )
    ai_endpoints = {
        (endpoint.get("method"), endpoint.get("path"))
        for endpoint in runtime_surface.get("ai-gateway", {}).get("endpoints", [])
    }
    validation.require(
        ("POST", "/gateway/v1/invoke") in ai_endpoints,
        "AI gateway canonical invoke endpoint is missing",
    )
    validation.require(
        runtime_surface.get("ai-gateway", {}).get("state", {}).get("behavior") == "STATEFUL"
        and runtime_surface.get("ai-gateway", {}).get("state", {}).get("durableContent") == "metadata-only",
        "AI gateway durable state must be metadata-only",
    )
    runtime_graph = dependency_graph.get("runtimeRequestGraph", {})
    branches = {branch.get("id"): branch for branch in runtime_graph.get("branches", [])}
    validation.require(
        set(branches) == {"direct-model", "task", "experience-task-control"},
        "runtime request graph must define the three canonical branches",
    )
    validation.require(
        branches.get("direct-model", {}).get("selectedWhen")
        == {"type": "routeKind", "routeKind": "DIRECT_MODEL"},
        "direct-model branch must use the closed DIRECT_MODEL route predicate",
    )
    validation.require(
        branches.get("task", {}).get("selectedWhen")
        == {"type": "routeKind", "routeKind": "TASK"},
        "task branch must use the closed TASK route predicate",
    )
    validation.require(
        branches.get("experience-task-control", {}).get("selectedWhen")
        == {
            "type": "taskEvent",
            "taskMustExist": True,
            "anyOfEvents": [
                "INPUT_SUBMITTED",
                "CANCELLATION_REQUESTED",
                "APPROVAL_DECIDED",
                "EVENT_REPLAY_REQUESTED",
            ],
        },
        "experience task-control branch must use the complete closed existing-task event predicate",
    )
    for branch_id, branch in branches.items():
        for edge in branch.get("edges", []):
            if "selectedWhen" in edge:
                validate_selection_predicate_references(
                    validation,
                    edge.get("selectedWhen"),
                    f"runtime branch edge {branch_id}:{edge.get('from')}->{edge.get('to')}",
                    capability_registry,
                )
    direct_edges = {
        (edge.get("from"), edge.get("to"))
        for edge in branches.get("direct-model", {}).get("edges", [])
    }
    task_edges = {
        (edge.get("from"), edge.get("to"))
        for edge in branches.get("task", {}).get("edges", [])
    }
    validation.require(
        ("ai-gateway", "inference-api") in direct_edges
        and not any(target in {"retrieval-service", "orchestration-api", "orchestration-worker", "tool-broker"} for _, target in direct_edges),
        "direct-model branch must call inference directly without task/retrieval/tool services",
    )
    validation.require(
        ("ai-gateway", "orchestration-api") in task_edges
        and ("orchestration-worker", "retrieval-service") in task_edges
        and not any(source == "ai-gateway" and target == "retrieval-service" for source, target in task_edges),
        "task branch must give orchestration-worker exclusive retrieval ownership",
    )
    validation.require(
        dependency_graph.get("controlPlaneOnRuntimePath") is False,
        "control plane must remain outside the runtime request path",
    )
    return names, ids


def validate_services(validation: Validation) -> None:
    capability_registry = load_capability_registry(validation)
    repositories = load_yaml(ROOT / "architecture/repositories.yaml").get("repositories", [])
    repository_name_by_id = {item["id"]: item["name"] for item in repositories}
    taxonomy = load_yaml(ROOT / "architecture/taxonomy.yaml").get("harnesses", [])
    canonical: dict[str, tuple[str, str]] = {}
    for harness in taxonomy:
        for deployable in harness["deployables"]:
            validation.require(deployable not in canonical, f"deployable {deployable} has more than one harness owner")
            canonical[deployable] = (
                harness["id"],
                repository_name_by_id[harness["ownerRepository"]],
            )

    catalog = load_yaml(ROOT / "architecture/services.yaml")
    validate_schema_instance(
        validation,
        ROOT / "schemas/services.schema.json",
        catalog,
        "service catalog",
    )
    services = catalog.get("services", [])
    service_ids = [service.get("id") for service in services]
    expected_ids = set(canonical) | set(EXPECTED_MANAGEMENT_SERVICES)
    validation.require(
        set(service_ids) == expected_ids and len(service_ids) == len(set(service_ids)),
        "service catalog must contain all 26 canonical and two management deployables exactly once",
    )
    counts = catalog.get("counts", {})
    validation.require(counts.get("canonicalDeployables") == len(canonical), "service catalog canonical count is stale")
    validation.require(
        counts.get("managementDeployables") == len(EXPECTED_MANAGEMENT_SERVICES),
        "service catalog management count is stale",
    )
    validation.require(counts.get("total") == len(expected_ids), "service catalog total count is stale")

    implementation_ownership = catalog.get("implementationOwnership", {})
    validation.require(
        set(implementation_ownership) == expected_ids,
        "service implementation ownership must cover every service exactly once",
    )
    packet_by_id = {
        packet["id"]: packet
        for packet_path in (ROOT / "task-packets").glob("*.yaml")
        if isinstance((packet := load_yaml(packet_path)), dict)
        and isinstance(packet.get("id"), str)
    }
    for service_id, ownership in implementation_ownership.items():
        packet_id = ownership.get("packetId") if isinstance(ownership, dict) else None
        implementation_path = ownership.get("path") if isinstance(ownership, dict) else None
        packet = packet_by_id.get(packet_id, {})
        service = next(
            (item for item in services if item.get("id") == service_id), {}
        )
        validation.require(
            packet_id in packet_by_id,
            f"service {service_id} references unknown implementation packet {packet_id!r}",
        )
        validation.require(
            packet.get("repository") == service.get("ownerRepository"),
            f"service {service_id} implementation packet has the wrong repository owner",
        )
        validation.require(
            implementation_path in packet.get("allowedPaths", []),
            f"service {service_id} implementation path {implementation_path!r} is not an exact allowedPath of packet {packet_id}",
        )

    enums = catalog.get("enums", {})
    dependency_modes = set(enums.get("dependencyModes", []))
    failure_modes = set(enums.get("failureModes", []))
    degradation_policy_types = set(enums.get("degradationPolicyTypes", []))
    degradation_budget_dimensions = set(enums.get("degradationBudgetDimensions", []))
    degradation_exhaustion_modes = set(enums.get("degradationBudgetExhaustionModes", []))
    degradation_exhaustion_actions = set(enums.get("degradationExhaustionActions", []))
    behavior_modes = set(enums.get("behaviorModes", []))
    implementation_statuses = set(enums.get("implementationStatuses", []))
    evidence_statuses = set(enums.get("evidenceStatuses", []))
    external_ids = set(catalog.get("externalDependencies", {}))

    waves: dict[str, int] = {}
    for wave in catalog.get("startupWaves", []):
        wave_number = wave.get("wave")
        for service_id in wave.get("services", []):
            validation.require(service_id not in waves, f"service {service_id} appears in more than one startup wave")
            waves[service_id] = wave_number
    validation.require(set(waves) == expected_ids, "startup waves must cover every service exactly once")

    graph: dict[str, list[str]] = {}
    service_by_id = {service["id"]: service for service in services if service.get("id")}
    for service in services:
        service_id = service.get("id")
        if service_id not in expected_ids:
            continue
        if service_id in canonical:
            expected_harness, expected_repository = canonical[service_id]
            validation.require(service.get("harness") == expected_harness, f"service {service_id} has wrong harness owner")
            validation.require(
                service.get("ownerRepository") == expected_repository,
                f"service {service_id} has wrong repository owner",
            )
        else:
            validation.require(service.get("harness") == "management-plane", f"service {service_id} must be management-plane")
            validation.require(
                service.get("ownerRepository") == EXPECTED_MANAGEMENT_SERVICES[service_id],
                f"service {service_id} has wrong management repository owner",
            )
        state_behavior = service.get("stateBehavior", {})
        validation.require(
            state_behavior.get("mode") in behavior_modes,
            f"service {service_id} has unknown state behavior",
        )
        validation.require(
            isinstance(state_behavior.get("durableState"), bool),
            f"service {service_id} must declare durableState",
        )
        validation.require(bool(state_behavior.get("restartSemantics")), f"service {service_id} has no restart semantics")
        validation.require(bool(service.get("readinessCriteria")), f"service {service_id} has no readiness criteria")
        validation.require(
            service.get("implementationStatus") == "PLANNED"
            and service.get("implementationStatus") in implementation_statuses,
            f"service {service_id} implementation status must truthfully remain PLANNED",
        )
        validation.require(
            service.get("evidenceStatus") == "NOT_STARTED"
            and service.get("evidenceStatus") in evidence_statuses,
            f"service {service_id} evidence status must truthfully remain NOT_STARTED",
        )
        validation.require(service.get("startupWave") == waves.get(service_id), f"service {service_id} startup wave is inconsistent")

        internal_dependencies: list[str] = []
        dependency_ids: list[str] = []
        for dependency in service.get("dependencies", []):
            dependency_id = dependency.get("id")
            dependency_ids.append(dependency_id)
            validation.require(
                dependency_id in expected_ids | external_ids,
                f"service {service_id} references unknown dependency {dependency_id}",
            )
            validation.require(
                dependency.get("mode") in dependency_modes,
                f"service {service_id} dependency {dependency_id} has unknown mode",
            )
            validation.require(
                dependency.get("failureMode") in failure_modes,
                f"service {service_id} dependency {dependency_id} has unknown failure mode",
            )
            validation.require(isinstance(dependency.get("required"), bool), f"service {service_id} dependency {dependency_id} lacks required flag")
            validation.require(bool(dependency.get("behavior")), f"service {service_id} dependency {dependency_id} lacks failure behavior")
            if "selectedWhen" in dependency:
                validate_selection_predicate_references(
                    validation,
                    dependency.get("selectedWhen"),
                    f"service dependency {service_id}->{dependency_id}",
                    capability_registry,
                    EXPECTED_HARNESSES,
                )
            if dependency.get("required") is False:
                validation.require(
                    dependency.get("failureMode") == "FAIL_OPEN",
                    f"optional dependency {service_id}->{dependency_id} must fail open",
                )
                degradation_policy = dependency.get("degradationPolicy", {})
                policy_type = degradation_policy.get("type") if isinstance(degradation_policy, dict) else None
                validation.require(
                    policy_type in degradation_policy_types,
                    f"optional dependency {service_id}->{dependency_id} lacks a typed degradation policy",
                )
                if policy_type == "disableImmediately":
                    validation.require(
                        bool(degradation_policy.get("capability")),
                        f"disableImmediately policy {service_id}->{dependency_id} lacks a capability",
                    )
                    validation.require(
                        degradation_policy.get("capability") in capability_registry,
                        f"disableImmediately policy {service_id}->{dependency_id} references unregistered capability {degradation_policy.get('capability')!r}",
                    )
                if policy_type == "bounded":
                    budget = degradation_policy.get("budget", {})
                    validation.require(
                        isinstance(budget, dict) and bool(budget),
                        f"bounded policy {service_id}->{dependency_id} has no budget",
                    )
                    if isinstance(budget, dict):
                        validation.require(
                            set(budget) <= degradation_budget_dimensions,
                            f"bounded policy {service_id}->{dependency_id} has an unknown budget dimension",
                        )
                        validation.require(
                            all(isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in budget.values()),
                            f"bounded policy {service_id}->{dependency_id} budget must contain positive integers",
                        )
                    validation.require(
                        degradation_policy.get("exhaustWhen") in degradation_exhaustion_modes,
                        f"bounded policy {service_id}->{dependency_id} has no typed ANY/ALL exhaustion rule",
                    )
                    validation.require(
                        degradation_policy.get("onExhaustion") in degradation_exhaustion_actions,
                        f"bounded policy {service_id}->{dependency_id} has no typed exhaustion action",
                    )
            if dependency.get("required") is True:
                validation.require(
                    dependency.get("failureMode") == "FAIL_CLOSED",
                    f"required dependency {service_id}->{dependency_id} must fail closed",
                )
                validation.require(
                    "degradationPolicy" not in dependency,
                    f"required dependency {service_id}->{dependency_id} must not declare fail-open degradation",
                )
            if dependency_id in expected_ids:
                internal_dependencies.append(dependency_id)
                if dependency.get("required") is True:
                    validation.require(
                        waves.get(dependency_id, 10**9) <= waves.get(service_id, -1),
                        f"required dependency {service_id}->{dependency_id} starts in a later wave",
                    )
        validation.require(
            len(dependency_ids) == len(set(dependency_ids)),
            f"service {service_id} repeats a dependency edge",
        )
        external_stores = {
            store.get("name")
            for store in service.get("stores", [])
            if isinstance(store, dict) and store.get("name") in external_ids
        }
        validation.require(
            external_stores <= set(dependency_ids),
            f"service {service_id} uses external stores without dependency edges: {sorted(external_stores - set(dependency_ids))}",
        )
        graph[service_id] = internal_dependencies

    assert_acyclic(validation, expected_ids, graph, "service")

    reachable_by_machine: dict[str, set[str]] = {}
    for machine_name, machine in catalog.get("stateMachines", {}).items():
        states = set(machine.get("states", []))
        validation.require(bool(states), f"{machine_name} state machine has no states")
        validation.require(machine.get("initial") in states, f"{machine_name} initial state is unknown")
        transitions = machine.get("transitions", {})
        validation.require(set(transitions) == states, f"{machine_name} transitions must define every state")
        for source, destinations in transitions.items():
            for destination in destinations:
                validation.require(destination in states, f"{machine_name} transition {source}->{destination} is invalid")
        initial = machine.get("initial")
        reachable: set[str] = set()
        pending = [initial] if initial in states else []
        while pending:
            current = pending.pop()
            if current in reachable:
                continue
            reachable.add(current)
            pending.extend(transitions.get(current, []))
        reachable_by_machine[machine_name] = reachable
        validation.require(
            reachable == states,
            f"{machine_name} state machine has unreachable states: {sorted(states - reachable)}",
        )

    expected_aggregation = {
        "evaluationModel": "FULL_SNAPSHOT_RECOMPUTE",
        "edgeKey": "consumerServiceId+dependencyId",
        "snapshotRevisionRule": "LATEST_MONOTONIC_SNAPSHOT_ONLY",
        "conditionNormalization": "ONE_CANONICAL_CONDITION_PER_EDGE_REVISION",
        "ruleApplication": "AT_MOST_ONE_EXPLICIT_RULE_ELSE_DEFAULT_CONTRIBUTION",
        "triggerMatrix": "EXACT_DECLARED_TRIGGERS_ONLY",
        "unmatchedSelectedFailureDisposition": "FAIL_CLOSED_INVALID_TRIGGER",
        "unmatchedSelectedFailureContribution": {
            "severity": "FAILED",
            "observedStateEffect": "FAILED",
            "readinessEffect": "NOT_READY",
            "desiredStateAction": "NO_CHANGE",
        },
        "unmatchedSelectedFailureWorkAction": "REJECT_NEW_AND_COMPENSATE",
        "unmatchedSelectedFailureReason": "DependencyTriggerInvalid",
        "defaultContributionEligibility": "HEALTHY_CONDITION_ONLY",
        "modeAggregates": {"RUNTIME_DATA_PATH": ["SYNC", "ASYNC"]},
        "defaultContribution": {
            "severity": "READY",
            "observedStateEffect": "NO_CHANGE",
            "readinessEffect": "NO_CHANGE",
            "desiredStateAction": "NO_CHANGE",
        },
        "contributionUpdate": "REPLACE_BY_EDGE_KEY",
        "recomputeOnAnyEdgeRevision": True,
        "orderIndependent": True,
        "severityPrecedence": ["FAILED", "BLOCKED", "DEGRADED", "READY"],
        "readinessPrecedence": ["NOT_READY", "POLICY_CONTROLLED", "NO_CHANGE"],
        "desiredStateActionPrecedence": ["SET_SUSPENDED", "NO_CHANGE"],
        "workActionAggregation": "ORDERED_UNIQUE_SET",
        "noChangeActionHandling": "OMIT_WHEN_ANY_NON_NEUTRAL_ACTION_EXISTS",
        "workActionPrecedence": [
            "FAIL_WAVE_RETAIN_EVIDENCE",
            "REJECT_NEW_AND_COMPENSATE",
            "DO_NOT_APPLY",
            "BLOCK_START",
            "BLOCK_MUTATIONS",
            "PAUSE_ACK_RETAIN_CURSOR",
            "RETURN_RETRYABLE_503",
            "EXECUTE_ON_EXHAUSTION",
            "APPLY_DEGRADATION_POLICY",
            "RESET_DEGRADATION_BUDGET_AND_RECOMPUTE",
            "RESTORE_OPTIONAL_CAPABILITY_AND_RECOMPUTE",
            "RECOMPUTE_AND_UNBLOCK_IF_PERMITTED",
            "RECOMPUTE_AND_RESUME_IF_PERMITTED",
            "RECOMPUTE_FROM_DEPENDENCY_SNAPSHOT",
            "NO_CHANGE",
        ],
        "reasonTieBreak": "HIGHEST_SEVERITY_THEN_LEXICOGRAPHIC_EDGE_KEY",
        "neutralReasonHandling": "EXCLUDE_FROM_PRIMARY_REASON",
        "projection": {
            "observedState": "FAILED_ELSE_BLOCKED_ELSE_DEGRADED_ELSE_LOCAL_STATE",
            "readiness": "NOT_READY_ELSE_POLICY_CONTROLLED_ELSE_LOCAL_READINESS",
            "desiredState": "SET_SUSPENDED_ELSE_NO_CHANGE",
        },
        "selectionHandling": "UNSELECTED_EDGE_REPLACES_PRIOR_CONTRIBUTION_WITH_NO_CHANGE",
        "recoveryActionGate": "EXECUTE_ONLY_IF_AGGREGATED_RESULT_PERMITS",
        "revokedReleaseRecovery": "FORBIDDEN_TERMINAL",
    }
    validation.require(
        catalog.get("dependencyStateAggregation") == expected_aggregation,
        "service catalog must define the exact order-independent full-snapshot dependency reducer",
    )
    validation.require(
        bool(catalog.get("dependencyStatePropagation")),
        "service catalog must define dependency-state propagation rules",
    )
    propagation_records = catalog.get("dependencyStatePropagation", [])
    propagation_rules = {
        rule.get("id")
        for rule in propagation_records
        if isinstance(rule, dict)
    }
    expected_propagation_triggers = {
        "required-artifact-unverified": {"mode": "ARTIFACT", "requirement": "REQUIRED", "event": "UNVERIFIED", "phase": "BEFORE_START", "degradationBudget": "NOT_APPLICABLE"},
        "required-control-not-ready-before-start": {"mode": "CONTROL", "requirement": "REQUIRED", "event": "NOT_READY", "phase": "BEFORE_START", "degradationBudget": "NOT_APPLICABLE"},
        "required-control-lost-after-ready": {"mode": "CONTROL", "requirement": "REQUIRED", "event": "LOST", "phase": "AFTER_READY", "degradationBudget": "NOT_APPLICABLE"},
        "required-sync-lost": {"mode": "SYNC", "requirement": "REQUIRED", "event": "LOST", "phase": "ANY", "degradationBudget": "NOT_APPLICABLE"},
        "required-async-lost": {"mode": "ASYNC", "requirement": "REQUIRED", "event": "LOST", "phase": "ANY", "degradationBudget": "NOT_APPLICABLE"},
        "fail-open-lost": {"mode": "ANY", "requirement": "OPTIONAL", "event": "LOST", "phase": "ANY", "degradationBudget": "AVAILABLE"},
        "fail-open-budget-exhausted": {"mode": "ANY", "requirement": "OPTIONAL", "event": "LOST", "phase": "ANY", "degradationBudget": "EXHAUSTED"},
        "optional-disable-immediately-lost": {"mode": "ANY", "requirement": "OPTIONAL", "event": "LOST", "phase": "ANY", "degradationBudget": "NOT_APPLICABLE"},
        "optional-or-unselected": {"mode": "ANY", "requirement": "UNSELECTED", "event": "UNSELECTED", "phase": "ANY", "degradationBudget": "NOT_APPLICABLE"},
        "dependency-release-revoked": {"mode": "ANY", "requirement": "ANY", "event": "RELEASE_REVOKED", "phase": "ANY", "degradationBudget": "NOT_APPLICABLE"},
        "ephemeral-dependency-failed": {"mode": "ARTIFACT", "requirement": "REQUIRED", "event": "EXECUTION_FAILED", "phase": "BEFORE_START", "degradationBudget": "NOT_APPLICABLE"},
        "required-artifact-invalidated-after-ready": {"mode": "ARTIFACT", "requirement": "REQUIRED", "event": "UNVERIFIED", "phase": "AFTER_READY", "degradationBudget": "NOT_APPLICABLE"},
        "required-artifact-restored": {"mode": "ARTIFACT", "requirement": "REQUIRED", "event": "VERIFIED_OR_RESTORED", "phase": "ANY", "degradationBudget": "NOT_APPLICABLE"},
        "required-control-restored": {"mode": "CONTROL", "requirement": "REQUIRED", "event": "RESTORED", "phase": "ANY", "degradationBudget": "NOT_APPLICABLE"},
        "required-runtime-dependency-restored": {"mode": "RUNTIME_DATA_PATH", "requirement": "REQUIRED", "event": "RESTORED", "phase": "ANY", "degradationBudget": "NOT_APPLICABLE"},
        "optional-dependency-recovered": {"mode": "ANY", "requirement": "OPTIONAL", "event": "RESTORED", "phase": "ANY", "degradationBudget": "RECOVERED"},
        "optional-disable-immediately-restored": {"mode": "ANY", "requirement": "OPTIONAL", "event": "RESTORED", "phase": "ANY", "degradationBudget": "NOT_APPLICABLE"},
    }
    validation.require(
        propagation_rules == set(expected_propagation_triggers)
        and len(propagation_records) == len(expected_propagation_triggers),
        "dependency propagation truth table must cover each canonical trigger exactly once",
    )
    expected_outcomes = {
        "required-artifact-unverified": ({"severity": "BLOCKED", "observedStateEffect": "BLOCKED", "readinessEffect": "NOT_READY", "desiredStateAction": "NO_CHANGE"}, "DO_NOT_APPLY", "DependencyArtifactUnverified"),
        "required-control-not-ready-before-start": ({"severity": "BLOCKED", "observedStateEffect": "BLOCKED", "readinessEffect": "NOT_READY", "desiredStateAction": "NO_CHANGE"}, "BLOCK_START", "DependencyControlNotReady"),
        "required-control-lost-after-ready": ({"severity": "DEGRADED", "observedStateEffect": "DEGRADED", "readinessEffect": "NOT_READY", "desiredStateAction": "NO_CHANGE"}, "BLOCK_MUTATIONS", "DependencyControlLost"),
        "required-sync-lost": ({"severity": "DEGRADED", "observedStateEffect": "DEGRADED", "readinessEffect": "NOT_READY", "desiredStateAction": "NO_CHANGE"}, "RETURN_RETRYABLE_503", "DependencySyncLost"),
        "required-async-lost": ({"severity": "DEGRADED", "observedStateEffect": "DEGRADED", "readinessEffect": "NOT_READY", "desiredStateAction": "NO_CHANGE"}, "PAUSE_ACK_RETAIN_CURSOR", "DependencyAsyncLost"),
        "fail-open-lost": ({"severity": "DEGRADED", "observedStateEffect": "DEGRADED", "readinessEffect": "POLICY_CONTROLLED", "desiredStateAction": "NO_CHANGE"}, "APPLY_DEGRADATION_POLICY", "DependencyDegraded"),
        "fail-open-budget-exhausted": ({"severity": "DEGRADED", "observedStateEffect": "DEGRADED", "readinessEffect": "NOT_READY", "desiredStateAction": "NO_CHANGE"}, "EXECUTE_ON_EXHAUSTION", "DependencyBudgetExhausted"),
        "optional-disable-immediately-lost": ({"severity": "DEGRADED", "observedStateEffect": "DEGRADED", "readinessEffect": "POLICY_CONTROLLED", "desiredStateAction": "NO_CHANGE"}, "APPLY_DEGRADATION_POLICY", "DependencyCapabilityDisabled"),
        "optional-or-unselected": ({"severity": "READY", "observedStateEffect": "NO_CHANGE", "readinessEffect": "NO_CHANGE", "desiredStateAction": "NO_CHANGE"}, "NO_CHANGE", "DependencyNotSelected"),
        "dependency-release-revoked": ({"severity": "DEGRADED", "observedStateEffect": "DEGRADED", "readinessEffect": "NOT_READY", "desiredStateAction": "SET_SUSPENDED"}, "REJECT_NEW_AND_COMPENSATE", "DependencyReleaseRevoked"),
        "ephemeral-dependency-failed": ({"severity": "FAILED", "observedStateEffect": "FAILED", "readinessEffect": "NOT_READY", "desiredStateAction": "NO_CHANGE"}, "FAIL_WAVE_RETAIN_EVIDENCE", "DependencyExecutionFailed"),
        "required-artifact-invalidated-after-ready": ({"severity": "DEGRADED", "observedStateEffect": "DEGRADED", "readinessEffect": "NOT_READY", "desiredStateAction": "NO_CHANGE"}, "REJECT_NEW_AND_COMPENSATE", "DependencyArtifactInvalidated"),
        "required-artifact-restored": ({"severity": "READY", "observedStateEffect": "NO_CHANGE", "readinessEffect": "NO_CHANGE", "desiredStateAction": "NO_CHANGE"}, "RECOMPUTE_FROM_DEPENDENCY_SNAPSHOT", "DependencyArtifactRestored"),
        "required-control-restored": ({"severity": "READY", "observedStateEffect": "NO_CHANGE", "readinessEffect": "NO_CHANGE", "desiredStateAction": "NO_CHANGE"}, "RECOMPUTE_AND_UNBLOCK_IF_PERMITTED", "DependencyControlRestored"),
        "required-runtime-dependency-restored": ({"severity": "READY", "observedStateEffect": "NO_CHANGE", "readinessEffect": "NO_CHANGE", "desiredStateAction": "NO_CHANGE"}, "RECOMPUTE_AND_RESUME_IF_PERMITTED", "DependencyRuntimeRestored"),
        "optional-dependency-recovered": ({"severity": "READY", "observedStateEffect": "NO_CHANGE", "readinessEffect": "NO_CHANGE", "desiredStateAction": "NO_CHANGE"}, "RESET_DEGRADATION_BUDGET_AND_RECOMPUTE", "OptionalDependencyRecovered"),
        "optional-disable-immediately-restored": ({"severity": "READY", "observedStateEffect": "NO_CHANGE", "readinessEffect": "NO_CHANGE", "desiredStateAction": "NO_CHANGE"}, "RESTORE_OPTIONAL_CAPABILITY_AND_RECOMPUTE", "OptionalCapabilityRestored"),
    }
    seen_triggers: set[tuple[tuple[str, Any], ...]] = set()
    expanded_triggers: set[tuple[tuple[str, Any], ...]] = set()
    for rule in propagation_records if isinstance(propagation_records, list) else []:
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id")
        trigger = rule.get("trigger", {})
        outcome = rule.get("outcome", {})
        validation.require(
            trigger == expected_propagation_triggers.get(rule_id),
            f"dependency propagation rule {rule_id} has a non-canonical trigger",
        )
        if isinstance(trigger, dict):
            trigger_key = tuple(sorted(trigger.items()))
            validation.require(
                trigger_key not in seen_triggers,
                f"dependency propagation trigger is ambiguous or duplicated for {rule_id}",
            )
            seen_triggers.add(trigger_key)
            expanded_modes = expected_aggregation["modeAggregates"].get(
                trigger.get("mode"), [trigger.get("mode")]
            )
            for expanded_mode in expanded_modes:
                expanded = dict(trigger)
                expanded["mode"] = expanded_mode
                expanded_key = tuple(sorted(expanded.items()))
                validation.require(
                    expanded_key not in expanded_triggers,
                    f"dependency propagation trigger overlaps after mode expansion for {rule_id}",
                )
                expanded_triggers.add(expanded_key)
        expected_contribution, expected_action, expected_reason = expected_outcomes.get(
            rule_id, ({}, None, None)
        )
        validation.require(
            outcome.get("edgeContribution") == expected_contribution
            and outcome.get("workAction") == expected_action
            and outcome.get("reason") == expected_reason,
            f"dependency propagation rule {rule_id} has a non-canonical contribution/action/reason",
        )
        contribution = outcome.get("edgeContribution", {}) if isinstance(outcome, dict) else {}
        observed_state = contribution.get("observedStateEffect")
        validation.require(
            observed_state == "NO_CHANGE"
            or observed_state in reachable_by_machine.get("observed", set()),
            f"dependency propagation rule {rule_id} targets unreachable observed state {observed_state!r}",
        )
        readiness = contribution.get("readinessEffect")
        validation.require(
            readiness != "POLICY_CONTROLLED" or observed_state == "DEGRADED",
            f"dependency propagation rule {rule_id} may use POLICY_CONTROLLED only while DEGRADED",
        )
        if contribution.get("desiredStateAction") == "SET_SUSPENDED":
            validation.require(
                rule_id == "dependency-release-revoked"
                and catalog.get("dependencyStateAggregation", {}).get(
                    "revokedReleaseRecovery"
                )
                == "FORBIDDEN_TERMINAL"
                and
                "SUSPENDED" in reachable_by_machine.get("desired", set()),
                f"dependency propagation rule {rule_id} targets unreachable desired SUSPENDED state",
            )

    runtime_surface = load_yaml(ROOT / "architecture/dependency-graph.yaml").get("runtimeSurface", {}).get("services", {})
    for gateway_id in ("ai-gateway", "experience-gateway"):
        service = service_by_id.get(gateway_id, {})
        surface_state = runtime_surface.get(gateway_id, {}).get("state", {})
        validation.require(
            service.get("stateBehavior", {}).get("mode") == surface_state.get("behavior") == "STATEFUL",
            f"{gateway_id} state behavior contradicts the canonical runtime surface",
        )
        validation.require(
            service.get("stateBehavior", {}).get("durableState") is True,
            f"{gateway_id} must declare its bounded durable metadata/projection state",
        )


def dependency_closure(
    module_by_id: dict[str, dict[str, Any]],
    roots: set[str],
    subject_harnesses: set[str] | None = None,
    subject_capabilities: set[str] | None = None,
) -> set[str]:
    """Return roots plus every active, transitively required catalog dependency."""

    closure: set[str] = set()
    pending = list(roots)
    explicit_subjects = subject_harnesses or set()
    explicit_subject_capabilities = subject_capabilities or set()
    while pending:
        module_id = pending.pop()
        if module_id in closure or module_id not in module_by_id:
            continue
        closure.add(module_id)
        module = module_by_id[module_id]
        pending.extend(module.get("dependencies", []))
        for conditional in module.get("conditionalDependencies", []):
            if selection_predicate_active(
                conditional.get("selectedWhen", {}),
                explicit_subjects,
                set(),
                explicit_subject_capabilities,
            ):
                pending.append(conditional.get("moduleId"))
    return closure


def capability_fixed_point(catalog: dict[str, Any], seeds: set[str]) -> set[str]:
    """Resolve declared capability implications to a deterministic fixed point."""

    resolved = set(seeds)
    changed = True
    while changed:
        changed = False
        for implication in catalog.get("capabilityImplications", []):
            if not isinstance(implication, dict):
                continue
            required = set(implication.get("whenAll", []))
            additions = set(implication.get("addCapabilities", []))
            if required <= resolved and not additions <= resolved:
                resolved.update(additions)
                changed = True
    return resolved


def selection_predicate_active(
    predicate: Any,
    subject_harnesses: set[str],
    capabilities: set[str],
    subject_capabilities: set[str] | None = None,
) -> bool:
    """Evaluate the closed OR predicate used by conditional service edges."""

    if not isinstance(predicate, dict):
        return False
    harness_match = bool(
        subject_harnesses & set(predicate.get("anyOfSubjectHarnesses", []))
    )
    capability_match = bool(
        capabilities & set(predicate.get("anyOfCapabilities", []))
    )
    subject_capability_match = bool(
        (subject_capabilities or set())
        & set(predicate.get("anyOfSubjectCapabilities", []))
    )
    return harness_match or capability_match or subject_capability_match


def validate_module_license_policy(
    validation: Validation, modules: list[dict[str, Any]]
) -> None:
    """Apply the fail-closed license classifier to every provider module."""

    policy = load_yaml(ROOT / "legal/third-party-license-policy.yaml")
    validation.require(
        policy.get("evaluation", {}).get("failClosed") is True,
        "third-party license policy must fail closed",
    )
    validation.require(
        policy.get("evaluation", {}).get("expressionMatching")
        == "EXACT_SPDX_EXPRESSION",
        "third-party license policy must use exact SPDX-expression matching",
    )
    validation.require(
        policy.get("deniedRule", {}).get("overrideAllowed") is False,
        "denied license expressions must be non-overridable",
    )

    classifications: dict[str, set[str]] = {
        "DEFAULT_ALLOWED": set(policy.get("defaultAllowedSpdx", [])),
        "ALLOWED_EXCEPTION_EXPRESSION": {
            item.get("expression")
            for item in policy.get("allowedExceptionExpressions", [])
            if isinstance(item, dict)
        },
        "OPEN_CONTENT": {
            item.get("expression")
            for item in policy.get("openContentSpdx", [])
            if isinstance(item, dict)
        },
        "OPTIONAL_EXPLICIT_REVIEW": set(
            policy.get("optionalExplicitReview", [])
        ),
        "PLANNED_UNRESOLVED": set(policy.get("plannedUnresolvedSpdx", [])),
        "DENIED": set(policy.get("deniedForDefaultDistribution", [])),
    }
    expression_classes: dict[str, set[str]] = defaultdict(set)
    for classification, expressions in classifications.items():
        for expression in expressions:
            if isinstance(expression, str):
                expression_classes[expression].add(classification)
    for expression, assigned in expression_classes.items():
        validation.require(
            len(assigned) == 1,
            f"license expression {expression!r} is multiply classified: {sorted(assigned)}",
        )

    exception_by_expression = {
        item["expression"]: item
        for item in policy.get("allowedExceptionExpressions", [])
        if isinstance(item, dict) and isinstance(item.get("expression"), str)
    }
    open_content_by_expression = {
        item["expression"]: item
        for item in policy.get("openContentSpdx", [])
        if isinstance(item, dict) and isinstance(item.get("expression"), str)
    }
    unresolved_rule = policy.get("plannedUnresolvedRule", {})
    custody_rules = policy.get("custodyRules", {})

    for module in modules:
        if not isinstance(module, dict):
            continue
        module_id = module.get("id", "<unknown>")
        license_record = module.get("license", {})
        expressions = license_record.get("spdx", [])
        custody = license_record.get("custody")
        validation.require(
            custody in custody_rules,
            f"provider module {module_id} has no custody policy for {custody!r}",
        )
        for expression in expressions:
            assigned = expression_classes.get(expression, set())
            validation.require(
                len(assigned) == 1,
                f"provider module {module_id} has unknown or ambiguous license expression {expression!r}",
            )
            if "DENIED" in assigned:
                validation.error(
                    f"provider module {module_id} uses denied license expression {expression!r}"
                )
            if "PLANNED_UNRESOLVED" in assigned:
                validation.require(
                    module.get("status")
                    in set(unresolved_rule.get("allowedModuleStatus", []))
                    and custody in set(unresolved_rule.get("allowedCustody", [])),
                    f"provider module {module_id} may use {expression!r} only as a planned "
                    "placeholder under approved unresolved custody",
                )
            if "ALLOWED_EXCEPTION_EXPRESSION" in assigned:
                allowed_custody = set(
                    exception_by_expression.get(expression, {}).get(
                        "allowedCustody", []
                    )
                )
                validation.require(
                    custody in allowed_custody,
                    f"provider module {module_id} uses exception expression {expression!r} "
                    f"under disallowed custody {custody!r}",
                )
            if "OPEN_CONTENT" in assigned:
                rule = open_content_by_expression.get(expression, {})
                validation.require(
                    module.get("kind") in set(rule.get("allowedKinds", []))
                    and module.get("scope") in set(rule.get("allowedScopes", [])),
                    f"provider module {module_id} uses open-content expression {expression!r} "
                    "outside the allowed kind/scope",
                )

    inventory = load_json(ROOT / "docs/phase-0/dependency-license-inventory.json")
    validation.require(
        inventory.get("schemaVersion")
        == "harness.planeon.ai/phase-zero-dependency-license-inventory/v1alpha1"
        and inventory.get("policy") == "legal/third-party-license-policy.yaml",
        "Phase-0 dependency license inventory identity is not exact",
    )
    repository_records = inventory.get("repositories", [])
    repository_names = [
        record.get("repository")
        for record in repository_records
        if isinstance(record, dict)
    ]
    validation.require(
        set(repository_names) == EXPECTED_REPOSITORIES
        and len(repository_names) == len(repository_records) == 13,
        "Phase-0 dependency inventory must account for all thirteen planned repositories exactly once",
    )
    planned_repositories = {
        record.get("repository")
        for record in repository_records
        if isinstance(record, dict)
        and record.get("sourceState") == "PLANNED_NOT_CREATED"
    }
    validation.require(
        planned_repositories
        == {
            "mas-harness-runtime-plane",
            "mas-harness-model-plane",
            "mas-harness-execution-plane",
        },
        "only the three not-yet-created plane repositories may be marked planned",
    )
    evidence_sources = inventory.get("evidenceSources", [])
    validation.require(
        isinstance(evidence_sources, list)
        and len(evidence_sources) == 4
        and len({source.get("id") for source in evidence_sources}) == 4,
        "Phase-0 dependency inventory must retain four exact lock/inventory evidence sources",
    )
    evidence_expressions = {
        expression
        for source in evidence_sources
        if isinstance(source, dict)
        for expression in source.get("expressions", [])
    }
    discovered_records = inventory.get("discoveredExpressions", [])
    discovered_by_expression = {
        record.get("expression"): record
        for record in discovered_records
        if isinstance(record, dict)
    }
    validation.require(
        set(discovered_by_expression) == EXPECTED_DEPENDENCY_EXPRESSIONS
        == evidence_expressions
        and len(discovered_by_expression) == len(discovered_records),
        "Phase-0 dependency expressions must exactly match the lock and wheelhouse evidence",
    )
    for expression, record in discovered_by_expression.items():
        assigned = expression_classes.get(expression, set())
        validation.require(
            len(assigned) == 1 and record.get("classification") in assigned,
            f"Phase-0 dependency {expression!r} is unknown, ambiguous, or misclassified",
        )
        if expression == "CC-BY-4.0":
            validation.require(
                record.get("useKind") == "CONTENT_DATASET"
                and record.get("components") == ["caniuse-lite@1.0.30001810"],
                "CC-BY-4.0 must remain attributed non-runtime content only",
            )
        if "OPTIONAL_EXPLICIT_REVIEW" in assigned:
            validation.require(
                record.get("releaseOutcome")
                == "DENY_RELEASE_WITHOUT_APPROVED_DECISION",
                f"review-gated dependency {expression!r} must deny release without approval",
            )
    validation.require(
        inventory.get("approvedButNotObservedExpressions")
        == [
            {
                "expression": "LGPL-3.0-only",
                "classification": "OPTIONAL_EXPLICIT_REVIEW",
            }
        ],
        "approved but unobserved LGPL classification changed",
    )


def validate_provider_catalog_data(
    validation: Validation,
    catalog: Any,
    schema: Any,
    repository_names: set[str],
    canonical_service_ids: set[str],
) -> None:
    """Validate provider catalog schema, closure, custody, and zero-bill invariants."""

    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        validation.error(
            f"provider-module schema is invalid at {list(exc.absolute_schema_path)}: {exc.message}"
        )
        return

    if not isinstance(catalog, dict):
        validation.error("provider catalog must be a mapping")
        return

    schema_validator = jsonschema.Draft202012Validator(
        schema, format_checker=SCHEMA_FORMAT_CHECKER
    )
    for error in sorted(
        schema_validator.iter_errors(catalog),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    ):
        validation.error(
            "provider catalog schema error at "
            f"{list(error.absolute_path)}: {error.message}"
        )

    modules = catalog.get("modules", [])
    if not isinstance(modules, list):
        validation.error("provider catalog modules must be a list")
        return

    module_ids = [
        module.get("id")
        for module in modules
        if isinstance(module, dict) and isinstance(module.get("id"), str)
    ]
    validation.require(
        len(module_ids) == len(modules),
        "every provider catalog module must have a string ID",
    )
    validation.require(
        len(module_ids) == len(set(module_ids)),
        "provider catalog module IDs must be unique",
    )
    module_by_id = {
        module["id"]: module
        for module in modules
        if isinstance(module, dict) and isinstance(module.get("id"), str)
    }
    module_id_set = set(module_by_id)

    implementation_ownership = catalog.get("implementationOwnership", {})
    validation.require(
        isinstance(implementation_ownership, dict)
        and set(implementation_ownership) == module_id_set,
        "provider implementation ownership must cover every module exactly once",
    )
    packet_by_id = {
        packet["id"]: packet
        for packet_path in (ROOT / "task-packets").glob("*.yaml")
        if isinstance((packet := load_yaml(packet_path)), dict)
        and isinstance(packet.get("id"), str)
    }
    service_bound_modules = {
        binding.get("moduleId")
        for binding in catalog.get("serviceModuleBindings", [])
        if isinstance(binding, dict)
    }
    profile_implementation_modules = {
        module_id
        for profile in catalog.get("profileExamples", [])
        if isinstance(profile, dict)
        for field in ("selectedModules", "expectedClosure")
        for module_id in profile.get(field, [])
        if isinstance(module_id, str)
    }
    implementation_disposition_counts: dict[str, int] = defaultdict(int)
    for module_id, module in module_by_id.items():
        ownership = (
            implementation_ownership.get(module_id, {})
            if isinstance(implementation_ownership, dict)
            else {}
        )
        disposition = ownership.get("disposition")
        if isinstance(disposition, str):
            implementation_disposition_counts[disposition] += 1
        owner = module.get("owner", {})
        owner_type = owner.get("type") if isinstance(owner, dict) else None
        owner_name = owner.get("name") if isinstance(owner, dict) else None

        if disposition == "REPOSITORY_PACKET":
            packet_id = ownership.get("packetId")
            implementation_path = ownership.get("path")
            deliverable_index = ownership.get("deliverableIndex")
            packet = packet_by_id.get(packet_id, {})
            validation.require(
                owner_type == "REPOSITORY",
                f"provider module {module_id} assigns a repository packet to a non-repository owner",
            )
            validation.require(
                packet_id in packet_by_id,
                f"provider module {module_id} references unknown implementation packet {packet_id!r}",
            )
            validation.require(
                packet.get("repository") == owner_name,
                f"provider module {module_id} implementation packet has the wrong repository owner",
            )
            validation.require(
                isinstance(implementation_path, str)
                and any(
                    implementation_path == allowed_path
                    or (
                        isinstance(allowed_path, str)
                        and allowed_path.endswith("/")
                        and implementation_path.startswith(allowed_path)
                    )
                    for allowed_path in packet.get("allowedPaths", [])
                ),
                f"provider module {module_id} implementation path {implementation_path!r} "
                f"is not covered by packet {packet_id} allowedPaths",
            )
            deliverables = packet.get("deliverables", [])
            validation.require(
                isinstance(deliverable_index, int)
                and not isinstance(deliverable_index, bool)
                and 0 <= deliverable_index < len(deliverables),
                f"provider module {module_id} implementation packet {packet_id} "
                f"does not contain deliverable index {deliverable_index!r}",
            )
        elif disposition == "EXTERNAL_PREREQUISITE":
            validation.require(
                owner_type == "TENANT_SUPPLIED_EXTERNAL"
                and module.get("scope") == "EXTERNAL",
                f"provider module {module_id} external disposition requires a tenant-supplied external owner and scope",
            )
        elif disposition == "CONTRACT_ONLY":
            validation.require(
                owner_type == "REPOSITORY",
                f"provider module {module_id} contract-only disposition requires a repository contract owner",
            )
            validation.require(
                module_id not in service_bound_modules,
                f"provider module {module_id} cannot be contract-only while bound to a runtime service",
            )
            validation.require(
                module_id not in profile_implementation_modules,
                f"provider module {module_id} cannot be contract-only while selected by a profile fixture",
            )
            validation.require(
                all(
                    install_unit.get("digestStatus") == "MISSING_PLANNED"
                    and install_unit.get("digest") is None
                    for install_unit in module.get("installUnits", [])
                    if isinstance(install_unit, dict)
                ),
                f"provider module {module_id} contract-only disposition cannot carry a locked install unit",
            )
        else:
            validation.error(
                f"provider module {module_id} has invalid implementation disposition {disposition!r}"
            )

    validation.require(
        set(implementation_disposition_counts)
        <= {"REPOSITORY_PACKET", "EXTERNAL_PREREQUISITE", "CONTRACT_ONLY"},
        "provider implementation ownership contains an unknown disposition",
    )

    graph: dict[str, list[str]] = {}
    provider_owner: dict[str, str] = {}
    install_unit_names: set[str] = set()
    module_tail_ids: set[str] = set()
    represented_harnesses: set[str] = set()
    network_usage: dict[str, set[str]] = defaultdict(set)
    allowed_costs = set(catalog.get("policy", {}).get("validCostDispositions", []))
    validation.require(
        allowed_costs == ALLOWED_PROVIDER_COST_DISPOSITIONS,
        "provider catalog policy must allow exactly the two zero-bill cost dispositions",
    )
    validation.require(
        REQUIRED_FORBIDDEN_PROVIDER_TRAITS
        <= set(catalog.get("policy", {}).get("forbiddenProviderTraits", [])),
        "provider catalog policy is missing a required forbidden provider trait",
    )
    validation.require(
        catalog.get("policy", {}).get("runtimeDownloadAllowed") is False,
        "provider catalog must prohibit runtime downloads",
    )
    forbidden_demand_list = catalog.get("policy", {}).get(
        "forbiddenDemandCapabilities", []
    )
    forbidden_demands = set(forbidden_demand_list)
    validation.require(
        isinstance(forbidden_demand_list, list)
        and len(forbidden_demand_list) == len(forbidden_demands),
        "forbidden demand capabilities must be a unique list",
    )

    for module in modules:
        if not isinstance(module, dict) or not isinstance(module.get("id"), str):
            continue
        module_id = module["id"]
        dependencies = module.get("dependencies", [])
        graph[module_id] = dependencies if isinstance(dependencies, list) else []
        represented_harnesses.add(str(module.get("harness", "")))
        module_tail_ids.add(module_id.rsplit(".", 1)[-1])

        owner = module.get("owner", {})
        owner_type = owner.get("type") if isinstance(owner, dict) else None
        owner_name = owner.get("name") if isinstance(owner, dict) else None
        if owner_type == "REPOSITORY":
            validation.require(
                owner_name in repository_names,
                f"provider module {module_id} has unknown repository owner {owner_name!r}",
            )
            validation.require(
                module.get("costDisposition")
                == "SELF_HOSTED_OPEN_SOURCE_NON_METERED",
                f"repository-owned provider module {module_id} has an unsafe cost disposition",
            )
        elif owner_type == "TENANT_SUPPLIED_EXTERNAL":
            validation.require(
                module.get("scope") == "EXTERNAL",
                f"tenant-supplied provider module {module_id} must have EXTERNAL scope",
            )
            validation.require(
                module.get("costDisposition")
                == "TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED",
                f"tenant-supplied provider module {module_id} has an unsafe cost disposition",
            )
        else:
            validation.error(
                f"provider module {module_id} has unknown owner type {owner_type!r}"
            )

        validation.require(
            module.get("costDisposition") in ALLOWED_PROVIDER_COST_DISPOSITIONS,
            f"provider module {module_id} has an unknown cost disposition",
        )
        validation.require(
            module.get("immutableDigestRequired") is True,
            f"provider module {module_id} does not require immutable digests",
        )
        validation.require(
            module.get("status") == "PLANNED",
            f"provider module {module_id} must truthfully remain PLANNED",
        )

        configuration = module.get("configuration", {})
        forbidden_fields = set(
            configuration.get("forbiddenFields", [])
            if isinstance(configuration, dict)
            else []
        )
        validation.require(
            REQUIRED_PROVIDER_FORBIDDEN_FIELDS <= forbidden_fields,
            f"provider module {module_id} does not forbid inline secrets, API keys, mutable tags, and runtime downloads",
        )

        secrets = module.get("secrets", {})
        validation.require(
            isinstance(secrets, dict)
            and secrets.get("inlineValuesAllowed") is False,
            f"provider module {module_id} permits inline secret values",
        )
        secret_mode = secrets.get("mode") if isinstance(secrets, dict) else None
        secret_references = secrets.get("references", []) if isinstance(secrets, dict) else []
        if secret_mode == "NONE":
            validation.require(
                secret_references == [],
                f"provider module {module_id} declares secret references in NONE mode",
            )
        else:
            validation.require(
                all(
                    isinstance(reference, str)
                    and "ref" in reference.casefold()
                    for reference in secret_references
                ),
                f"provider module {module_id} contains a non-reference secret declaration",
            )

        network = module.get("network", {})
        validation.require(
            isinstance(network, dict)
            and network.get("undeclaredExternalEgressAllowed") is False,
            f"provider module {module_id} permits undeclared external egress",
        )
        if isinstance(network, dict):
            for target_id in network.get("ingressFrom", []):
                network_usage[str(target_id)].add("INGRESS")
            for target_id in network.get("egressTo", []):
                network_usage[str(target_id)].add("EGRESS")

        providers = module.get("providers", [])
        for provider_id in providers if isinstance(providers, list) else []:
            validation.require(
                provider_id not in provider_owner,
                f"provider ID {provider_id!r} is owned by more than one module",
            )
            provider_owner[provider_id] = module_id
            folded_provider = str(provider_id).casefold()
            validation.require(
                not any(
                    fragment in folded_provider
                    for fragment in FORBIDDEN_PROVIDER_ID_FRAGMENTS
                ),
                f"provider module {module_id} exposes prohibited provider ID {provider_id!r}",
            )

        for unit in module.get("installUnits", []):
            if not isinstance(unit, dict):
                continue
            unit_name = unit.get("name")
            if isinstance(unit_name, str):
                install_unit_names.add(unit_name)
            artifact = str(unit.get("artifact", ""))
            validation.require(
                bool(artifact)
                and "://" not in artifact
                and not artifact.casefold().startswith("git@")
                and MUTABLE_ARTIFACT_PATTERN.search(artifact) is None,
                f"provider module {module_id} has a URL or mutable artifact reference {artifact!r}",
            )
            folded_artifact = artifact.casefold()
            validation.require(
                not any(
                    fragment in folded_artifact
                    for fragment in FORBIDDEN_PROVIDER_ID_FRAGMENTS
                ),
                f"provider module {module_id} has prohibited provider artifact {artifact!r}",
            )
            digest_status = unit.get("digestStatus")
            digest = unit.get("digest")
            if digest_status == "MISSING_PLANNED":
                validation.require(
                    digest is None and module.get("status") == "PLANNED",
                    f"provider module {module_id} planned artifact must have a null digest",
                )
            elif digest_status == "LOCKED":
                validation.require(
                    isinstance(digest, str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None,
                    f"provider module {module_id} locked artifact has no SHA-256 digest",
                )
            else:
                validation.error(
                    f"provider module {module_id} has unknown digest status {digest_status!r}"
                )

    validate_module_license_policy(validation, modules)
    assert_acyclic(validation, module_id_set, graph, "provider module")

    network_target_by_id: dict[str, dict[str, Any]] = {}
    valid_target_authorities = {
        "MODULE_SERVICE": {"MODULE_ID"},
        "EXTERNAL_PREREQUISITE": {"CATALOG_EXTERNAL_ID"},
        "TENANT_INGRESS": {"PROFILE_ALLOWLIST"},
        "TENANT_PRIVATE_ENDPOINT": {"PROFILE_ALLOWLIST"},
        "LOCAL_SELECTOR": {"PROFILE_ALLOWLIST", "STATIC_LOCAL_SELECTOR"},
        "CLUSTER_API": {"CATALOG_EXTERNAL_ID"},
        "LOCAL_ARTIFACT_SOURCE": {"CATALOG_EXTERNAL_ID"},
        "OFFLINE_PREFETCH_SOURCE": {"OPERATOR_ALLOWLIST"},
    }
    for target in catalog.get("networkTargetRegistry", []):
        target_id = target.get("id") if isinstance(target, dict) else None
        validation.require(
            isinstance(target_id, str) and target_id not in network_target_by_id,
            f"network target registry has missing or duplicate ID {target_id!r}",
        )
        if not isinstance(target_id, str):
            continue
        network_target_by_id[target_id] = target
        target_class = target.get("targetClass")
        authority = target.get("resolutionAuthority")
        validation.require(
            authority in valid_target_authorities.get(str(target_class), set()),
            f"network target {target_id!r} has an authority/type mismatch",
        )
        if target_class == "MODULE_SERVICE":
            validation.require(
                target_id.startswith("module.") and target_id in module_id_set,
                f"module-service network target {target_id!r} does not resolve to a catalog module",
            )
        elif target_class in {
            "EXTERNAL_PREREQUISITE",
            "CLUSTER_API",
            "LOCAL_ARTIFACT_SOURCE",
        }:
            validation.require(
                target_id.startswith("external.") and target_id in module_id_set,
                f"external network target {target_id!r} does not resolve to a catalog prerequisite",
            )
        validation.require(
            target.get("addressPolicy") == "LOCAL_OR_SIGNED_TENANT_PRIVATE_ONLY",
            f"network target {target_id!r} permits a non-local or unsigned address",
        )
        validation.require(
            target.get("urlLiteralAllowed") is False,
            f"URL literals are forbidden for network target {target_id!r}",
        )
        validation.require(
            target.get("publicHostAllowed") is False,
            f"public-host network targets are forbidden: {target_id!r}",
        )
        validation.require(
            "://" not in target_id
            and "@" not in target_id
            and not target_id.casefold().startswith("www."),
            f"network target registry contains URL or public-host syntax {target_id!r}",
        )

    registered_network_targets = set(network_target_by_id)
    used_network_targets = set(network_usage)
    for target_id in sorted(used_network_targets - registered_network_targets):
        validation.error(f"unknown network target {target_id!r}")
    validation.require(
        not (registered_network_targets - used_network_targets),
        "network target registry contains unused entries: "
        f"{sorted(registered_network_targets - used_network_targets)}",
    )
    for target_id in sorted(registered_network_targets & used_network_targets):
        allowed_directions = set(
            network_target_by_id[target_id].get("allowedDirections", [])
        )
        validation.require(
            allowed_directions == network_usage[target_id],
            f"network target {target_id!r} direction projection differs from module use; "
            f"declared={sorted(allowed_directions)}, used={sorted(network_usage[target_id])}",
        )

    compatibility_by_module: dict[str, dict[str, Any]] = {}
    for compatibility in catalog.get("moduleCompatibility", []):
        module_id = (
            compatibility.get("moduleId")
            if isinstance(compatibility, dict)
            else None
        )
        validation.require(
            isinstance(module_id, str) and module_id not in compatibility_by_module,
            f"module compatibility has missing or duplicate module ID {module_id!r}",
        )
        if isinstance(module_id, str):
            compatibility_by_module[module_id] = compatibility
    validation.require(
        set(compatibility_by_module) == module_id_set,
        "moduleCompatibility must exactly cover every module; "
        f"missing={sorted(module_id_set - set(compatibility_by_module))}, "
        f"extra={sorted(set(compatibility_by_module) - module_id_set)}",
    )
    for module_id, compatibility in compatibility_by_module.items():
        module = module_by_id.get(module_id)
        if not module:
            continue
        validation.require(
            set(compatibility.get("operatingSystems", []))
            == set(module.get("platforms", {}).get("os", [])),
            f"module compatibility {module_id} operating-system projection is inconsistent",
        )
        validation.require(
            compatibility.get("kubernetesApiGrant")
            == module.get("rbac", {}).get("kubernetesApiAccess"),
            f"module compatibility {module_id} Kubernetes API/RBAC projection is inconsistent",
        )
        validation.require(
            compatibility.get("storageMode") == module.get("storage", {}).get("mode"),
            f"module compatibility {module_id} storage projection is inconsistent",
        )
        resource_requirement = compatibility.get("resourceRequirement", {})
        validation.require(
            set(resource_requirement.get("availableClasses", []))
            == {module.get("resources", {}).get("class")},
            f"module compatibility {module_id} resource-class projection is inconsistent",
        )
        validation.require(
            resource_requirement.get("capacityStatus") == "MISSING_PLANNED"
            and resource_requirement.get("cpuMillicores") is None
            and resource_requirement.get("memoryMiB") is None
            and resource_requirement.get("ephemeralStorageMiB") is None,
            f"planned module compatibility {module_id} must not claim measured capacity",
        )
        module_network_targets = set(module.get("network", {}).get("ingressFrom", [])) | set(
            module.get("network", {}).get("egressTo", [])
        )
        projected_localities = {
            network_target_by_id[target_id].get("locality")
            for target_id in module_network_targets
            if target_id in network_target_by_id
        }
        validation.require(
            set(compatibility.get("networkLocalities", [])) == projected_localities,
            f"module compatibility {module_id} network-locality projection is inconsistent",
        )

    capability_registry_list = catalog.get("capabilityRegistry", [])
    capability_registry = set(capability_registry_list)
    validation.require(
        len(capability_registry_list) == len(capability_registry),
        "provider capability registry contains duplicate IDs",
    )
    validation.require(
        forbidden_demands <= capability_registry,
        "forbidden demand policy references unregistered capabilities: "
        f"{sorted(forbidden_demands - capability_registry)}",
    )

    admission = catalog.get("capabilityAdmission", {})
    public_demand_capabilities = set(
        admission.get("publicDemandCapabilities", [])
    )
    environment_fact_capabilities = set(
        admission.get("environmentFactCapabilities", [])
    )
    provider_selector_capabilities = set(
        admission.get("providerSelectorCapabilities", [])
    )
    admission_sets = [
        public_demand_capabilities,
        environment_fact_capabilities,
        provider_selector_capabilities,
    ]
    validation.require(
        all(admission_set <= capability_registry for admission_set in admission_sets),
        "capability admission classifications must be subsets of capabilityRegistry",
    )
    validation.require(
        all(
            left.isdisjoint(right)
            for index, left in enumerate(admission_sets)
            for right in admission_sets[index + 1 :]
        ),
        "public demand, environment fact, and provider selector classifications must be pairwise disjoint",
    )
    validation.require(
        admission.get("defaultClassification") == "INTERNAL_ONLY"
        and admission.get("requestAdmission")
        == {
            "allowedClassifications": ["PUBLIC_DEMAND", "PROVIDER_SELECTOR"],
            "inactiveSelectorDisposition": "INVALID_COMBINATION",
            "missingSelectorDisposition": "NEEDS_INPUT",
            "multipleSelectorDisposition": "AMBIGUOUS_PROVIDER",
            "internalCapabilityDisposition": "INVALID_CAPABILITY_ROLE",
        }
        and admission.get("environmentAdmission")
        == {
            "allowedClassification": "ENVIRONMENT_FACT",
            "releaseRequiresSignedAttestation": True,
        }
        and admission.get("recommendationPolicy")
        == {
            "rankingOutput": "PROPOSED_SELECTOR_ONLY",
            "tenantAcceptanceRequired": True,
            "acceptedSelectorField": "requestedCapabilities",
            "implicitSelectionAllowed": False,
            "compatibleFallbackAllowed": False,
        }
        and admission.get("assuranceSubjectAdmission")
        == {
            "allowedClassification": "PUBLIC_DEMAND",
            "capabilitiesMustBeSubsetOfAcceptedResolvedDemand": True,
            "inferenceSource": "EXPLICIT_SUBJECT_SET_ONLY",
        },
        "capability admission must fail closed and keep recommendations non-selecting",
    )
    validation.require(
        admission.get("conditionalRequirements")
        == [
            {
                "whenCapability": "assurance.local-model-judge",
                "requiresAnyCapabilities": ["model.local-cpu", "model.local-gpu"],
                "requiresSelectorGroup": "group.model-backend",
                "missingDisposition": "NEEDS_INPUT",
            }
        ],
        "local-model judge demand must require an explicit local model class and backend selector",
    )
    validation.require(
        forbidden_demands.isdisjoint(
            public_demand_capabilities
            | environment_fact_capabilities
            | provider_selector_capabilities
        ),
        "forbidden capabilities must not be admitted as demand, facts, or selectors",
    )

    implication_ids: set[str] = set()
    implication_additions: dict[str, set[str]] = {}
    for implication in catalog.get("capabilityImplications", []):
        implication_id = implication.get("id") if isinstance(implication, dict) else None
        validation.require(
            isinstance(implication_id, str) and implication_id not in implication_ids,
            f"provider capability implication has missing or duplicate ID {implication_id!r}",
        )
        if isinstance(implication_id, str):
            implication_ids.add(implication_id)
            implication_additions[implication_id] = set(
                implication.get("addCapabilities", [])
            )
        referenced = set(implication.get("whenAll", [])) | set(
            implication.get("addCapabilities", [])
        )
        validation.require(
            referenced <= capability_registry,
            f"provider capability implication {implication_id} references unregistered capabilities: "
            f"{sorted(referenced - capability_registry)}",
        )
        validation.require(
            not (set(implication.get("addCapabilities", [])) & forbidden_demands),
            f"provider capability implication {implication_id} introduces forbidden demand capabilities: "
            f"{sorted(set(implication.get('addCapabilities', [])) & forbidden_demands)}",
        )

    capability_bindings: dict[str, dict[str, Any]] = {}
    for binding in catalog.get("capabilityProviders", []):
        capability = binding.get("capability") if isinstance(binding, dict) else None
        validation.require(
            isinstance(capability, str) and capability not in capability_bindings,
            f"provider capability binding has missing or duplicate capability {capability!r}",
        )
        if not isinstance(capability, str):
            continue
        capability_bindings[capability] = binding
        validation.require(
            binding.get("resolution") == "ALL",
            f"provider capability {capability} capabilityProviders resolution must be ALL",
        )
        validation.require(
            capability in capability_registry,
            f"provider capability binding references unregistered capability {capability!r}",
        )
        referenced_modules = set(binding.get("modules", []))
        validation.require(
            referenced_modules <= module_id_set,
            f"provider capability {capability} references unknown modules: "
            f"{sorted(referenced_modules - module_id_set)}",
        )
        owning_module = provider_owner.get(capability)
        validation.require(
            owning_module is not None and referenced_modules == {owning_module},
            f"provider capability {capability} does not map to its owning module; "
            f"expected={owning_module!r}, actual={sorted(referenced_modules)}",
        )
    validation.require(
        set(capability_bindings) == set(provider_owner),
        "capabilityProviders must exactly bind every module provider capability; "
        f"missing={sorted(set(provider_owner) - set(capability_bindings))}, "
        f"extra={sorted(set(capability_bindings) - set(provider_owner))}",
    )

    group_by_id: dict[str, dict[str, Any]] = {}
    group_selector_map: dict[str, dict[str, str]] = {}
    group_member_owner: dict[str, str] = {}
    selector_group_owner: dict[str, str] = {}
    for group in catalog.get("providerExclusivityGroups", []):
        group_id = group.get("id") if isinstance(group, dict) else None
        validation.require(
            isinstance(group_id, str) and group_id not in group_by_id,
            f"provider exclusivity group has missing or duplicate ID {group_id!r}",
        )
        if not isinstance(group_id, str):
            continue
        group_by_id[group_id] = group
        activation = set(group.get("activatedByCapabilities", []))
        members = set(group.get("members", []))
        validation.require(
            activation <= capability_registry,
            f"provider exclusivity group {group_id} has unregistered activators: "
            f"{sorted(activation - capability_registry)}",
        )
        validation.require(
            activation
            <= public_demand_capabilities | environment_fact_capabilities,
            f"provider exclusivity group {group_id} activators must be admitted demand or environment facts: "
            f"{sorted(activation - public_demand_capabilities - environment_fact_capabilities)}",
        )
        validation.require(
            members <= module_id_set,
            f"provider exclusivity group {group_id} has unknown members: "
            f"{sorted(members - module_id_set)}",
        )
        selectors_by_capability: dict[str, set[str]] = defaultdict(set)
        selector_members: set[str] = set()
        for selector in group.get("selectors", []):
            if not isinstance(selector, dict):
                continue
            selector_capability = selector.get("selectorCapability")
            selector_member = selector.get("memberId")
            validation.require(
                selector_capability in capability_registry,
                f"provider exclusivity group {group_id} has unregistered selector capability {selector_capability!r}",
            )
            validation.require(
                selector_member in members,
                f"provider exclusivity group {group_id} selector {selector_capability!r} has unknown member {selector_member!r}",
            )
            if isinstance(selector_capability, str) and isinstance(selector_member, str):
                validation.require(
                    selector_capability not in selector_group_owner,
                    f"selector capability {selector_capability!r} belongs to multiple exclusivity groups",
                )
                selector_group_owner[selector_capability] = group_id
                selectors_by_capability[selector_capability].add(selector_member)
                selector_members.add(selector_member)
        for selector_capability, mapped_members in selectors_by_capability.items():
            occurrences = sum(
                1
                for selector in group.get("selectors", [])
                if selector.get("selectorCapability") == selector_capability
            )
            validation.require(
                len(mapped_members) == 1 and occurrences == 1,
                f"selector capability {selector_capability!r} maps to multiple members in {group_id}",
            )
        validation.require(
            selector_members == members
            and len(selectors_by_capability) == len(members),
            f"provider exclusivity group {group_id} selectors must map uniquely and completely to its members",
        )
        group_selector_map[group_id] = {
            selector_capability: next(iter(mapped_members))
            for selector_capability, mapped_members in selectors_by_capability.items()
            if len(mapped_members) == 1
        }
        for member in members:
            validation.require(
                member not in group_member_owner,
                f"provider module {member} belongs to multiple exclusivity groups",
            )
            group_member_owner[member] = group_id

    validation.require(
        set(selector_group_owner) == provider_selector_capabilities,
        "capabilityAdmission provider selectors must exactly equal the exclusivity-group selector projection; "
        f"admission-only={sorted(provider_selector_capabilities - set(selector_group_owner))}, "
        f"group-only={sorted(set(selector_group_owner) - provider_selector_capabilities)}",
    )
    exclusive_member_provider_tokens = {
        provider
        for member_id in group_member_owner
        for provider in module_by_id.get(member_id, {}).get("providers", [])
    }
    for implication_id, additions in implication_additions.items():
        prohibited_additions = additions & (
            provider_selector_capabilities | exclusive_member_provider_tokens
        )
        validation.require(
            not prohibited_additions,
            f"provider capability implication {implication_id} silently selects an exclusive provider: "
            f"{sorted(prohibited_additions)}",
        )

    for module_id, module in module_by_id.items():
        condition = module.get("capabilityCondition", {})
        condition_capabilities = (
            set(condition.get("allOf", []))
            | set(condition.get("anyOf", []))
            | set(condition.get("not", []))
        )
        validation.require(
            condition_capabilities <= capability_registry,
            f"provider module {module_id} condition references unregistered capabilities: "
            f"{sorted(condition_capabilities - capability_registry)}",
        )
        required_groups = set(module.get("requiredProviderGroups", []))
        validation.require(
            required_groups <= set(group_by_id),
            f"provider module {module_id} references unknown required groups: "
            f"{sorted(required_groups - set(group_by_id))}",
        )
        for conditional in module.get("conditionalDependencies", []):
            target = conditional.get("moduleId")
            validation.require(
                target in module_id_set,
                f"provider module {module_id} has unknown conditional dependency {target!r}",
            )
            validate_selection_predicate_references(
                validation,
                conditional.get("selectedWhen"),
                f"provider module {module_id} conditional dependency {target}",
                capability_registry,
                EXPECTED_HARNESSES,
            )

    service_bindings: dict[str, str] = {}
    for binding in catalog.get("serviceModuleBindings", []):
        service_id = binding.get("serviceId") if isinstance(binding, dict) else None
        module_id = binding.get("moduleId") if isinstance(binding, dict) else None
        validation.require(
            isinstance(service_id, str) and service_id not in service_bindings,
            f"service-module binding has missing or duplicate service {service_id!r}",
        )
        if not isinstance(service_id, str):
            continue
        service_bindings[service_id] = str(module_id)
        validation.require(
            module_id in module_id_set,
            f"service-module binding {service_id} references unknown module {module_id!r}",
        )
    validation.require(
        set(service_bindings) == canonical_service_ids,
        "serviceModuleBindings must exactly cover the canonical service catalog; "
        f"missing={sorted(canonical_service_ids - set(service_bindings))}, "
        f"extra={sorted(set(service_bindings) - canonical_service_ids)}",
    )

    services_catalog = load_yaml(ROOT / "architecture/services.yaml")
    services = services_catalog.get("services", [])
    service_by_id = {
        service["id"]: service
        for service in services
        if isinstance(service, dict) and isinstance(service.get("id"), str)
    }
    external_dependency_ids = set(services_catalog.get("externalDependencies", {}))
    satisfaction_by_dependency: dict[str, dict[str, Any]] = {}
    for satisfaction in catalog.get("dependencySatisfaction", []):
        dependency_id = (
            satisfaction.get("serviceDependencyId")
            if isinstance(satisfaction, dict)
            else None
        )
        validation.require(
            isinstance(dependency_id, str)
            and dependency_id not in satisfaction_by_dependency,
            f"dependency satisfaction has missing or duplicate ID {dependency_id!r}",
        )
        if not isinstance(dependency_id, str):
            continue
        satisfaction_by_dependency[dependency_id] = satisfaction
        validation.require(
            dependency_id in external_dependency_ids,
            f"dependency satisfaction references unknown external service dependency {dependency_id!r}",
        )
        mode = satisfaction.get("mode")
        target = satisfaction.get("targetId")
        if mode == "MODULE_ALIAS":
            validation.require(
                target in module_id_set,
                f"dependency satisfaction {dependency_id} has unknown module target {target!r}",
            )
        elif mode == "EXCLUSIVE_GROUP":
            validation.require(
                target in group_by_id,
                f"dependency satisfaction {dependency_id} has unknown group target {target!r}",
            )

    # Every hard service edge must have an equivalent module-level install edge.
    for service_id, service in service_by_id.items():
        module_id = service_bindings.get(service_id)
        module = module_by_id.get(module_id, {})
        module_dependencies = set(module.get("dependencies", []))
        module_conditionals = module.get("conditionalDependencies", [])
        required_groups = set(module.get("requiredProviderGroups", []))
        for dependency in service.get("dependencies", []):
            dependency_id = dependency.get("id")
            selection_type = dependency.get("selectionType")
            if selection_type == "subjectUnderEvaluation":
                target_module = service_bindings.get(str(dependency_id))
                service_predicate = dependency.get("selectedWhen", {})
                equivalent = any(
                    conditional.get("moduleId") == target_module
                    and conditional.get("selectionType")
                    == "subjectUnderEvaluation"
                    and conditional.get("selectedWhen") == service_predicate
                    for conditional in module_conditionals
                )
                validation.require(
                    target_module is not None and equivalent,
                    f"service {service_id} conditional dependency {dependency_id} has no exact provider-module subject predicate",
                )
                continue
            if dependency.get("required") is not True:
                continue
            if dependency_id in service_bindings:
                target_module = service_bindings[dependency_id]
                validation.require(
                    target_module in module_dependencies,
                    f"service {service_id} hard dependency {dependency_id} is absent "
                    f"from provider module {module_id}",
                )
                continue
            satisfaction = satisfaction_by_dependency.get(str(dependency_id))
            if satisfaction and satisfaction.get("mode") == "MODULE_ALIAS":
                validation.require(
                    satisfaction.get("targetId") in module_dependencies,
                    f"service {service_id} hard dependency {dependency_id} alias is absent "
                    f"from provider module {module_id}",
                )
            elif satisfaction and satisfaction.get("mode") == "EXCLUSIVE_GROUP":
                validation.require(
                    satisfaction.get("targetId") in required_groups,
                    f"service {service_id} hard dependency {dependency_id} group is absent "
                    f"from provider module {module_id}",
                )
            else:
                validation.require(
                    dependency_id in module_dependencies,
                    f"service {service_id} hard dependency {dependency_id} is absent "
                    f"from provider module {module_id}",
                )

    validation.require(
        EXPECTED_HARNESSES <= represented_harnesses,
        "provider catalog does not represent every canonical harness: "
        f"{sorted(EXPECTED_HARNESSES - represented_harnesses)}",
    )

    represented_services = install_unit_names | module_tail_ids
    missing_services = canonical_service_ids - represented_services
    if "operator" in missing_services and "mas-harness-operator" in install_unit_names:
        missing_services.remove("operator")
    validation.require(
        not missing_services,
        f"provider catalog does not represent canonical services: {sorted(missing_services)}",
    )

    profiles = catalog.get("profileExamples", [])
    if not isinstance(profiles, list):
        validation.error("provider catalog profileExamples must be a list")
        return
    profile_ids = [
        profile.get("id")
        for profile in profiles
        if isinstance(profile, dict) and isinstance(profile.get("id"), str)
    ]
    validation.require(
        len(profile_ids) == len(profiles)
        and len(profile_ids) == len(set(profile_ids)),
        "provider catalog profile IDs must be present and unique",
    )
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get("id"), str):
            continue
        profile_id = profile["id"]
        selected = set(profile.get("selectedModules", []))
        external = set(profile.get("externalPrerequisites", []))
        excluded = set(profile.get("excludedModules", []))
        expected = set(profile.get("expectedClosure", []))
        all_references = selected | external | excluded | expected
        validation.require(
            all_references <= module_id_set,
            f"provider profile {profile_id} references unknown module IDs: {sorted(all_references - module_id_set)}",
        )
        validation.require(
            selected.isdisjoint(external)
            and selected.isdisjoint(excluded)
            and external.isdisjoint(excluded),
            f"provider profile {profile_id} selected, external, and excluded sets must be disjoint",
        )
        validation.require(
            all(
                not module_id.startswith("external.")
                for module_id in selected
            ),
            f"provider profile {profile_id} places an external prerequisite in selectedModules",
        )

        requested_capabilities = set(profile.get("requestedCapabilities", []))
        environment_facts = profile.get("environmentFacts", {})
        assurance_subjects = profile.get("assuranceSubjects", {})
        subject_harnesses = set(assurance_subjects.get("harnesses", []))
        subject_capabilities = set(assurance_subjects.get("capabilities", []))
        validation.require(
            subject_harnesses <= EXPECTED_HARNESSES,
            f"provider profile {profile_id} assurance subjects reference unknown harnesses: "
            f"{sorted(subject_harnesses - EXPECTED_HARNESSES)}",
        )
        validation.require(
            subject_capabilities <= public_demand_capabilities,
            f"provider profile {profile_id} assurance subjects must be PUBLIC_DEMAND capabilities: "
            f"{sorted(subject_capabilities - public_demand_capabilities)}",
        )
        validation.require(
            assurance_subjects.get("selectionMode")
            == "EXPLICIT_IMMUTABLE_SUBJECT_SET",
            f"provider profile {profile_id} assurance subjects are not explicitly selected",
        )
        validation.require(
            assurance_subjects.get("subjectSetDigest") is None
            and assurance_subjects.get("digestStatus") == "MISSING_PLANNED"
            and assurance_subjects.get("signatureStatus") == "MISSING_PLANNED",
            f"provider profile fixture {profile_id} must not claim signed assurance subject evidence before implementation",
        )
        fact_attestation = environment_facts.get("attestation", {})
        validation.require(
            fact_attestation.get("digest") is None
            and fact_attestation.get("digestStatus") == "MISSING_PLANNED"
            and fact_attestation.get("signatureStatus") == "MISSING_PLANNED",
            f"provider profile fixture {profile_id} must not claim signed environment evidence before implementation",
        )
        environment_capabilities = set(environment_facts.get("capabilities", []))
        validation.require(
            requested_capabilities
            <= public_demand_capabilities | provider_selector_capabilities,
            f"provider profile {profile_id} requestedCapabilities contains an internal or environment-only capability: "
            f"{sorted(requested_capabilities - public_demand_capabilities - provider_selector_capabilities)}",
        )
        validation.require(
            environment_capabilities <= environment_fact_capabilities,
            f"provider profile {profile_id} environmentFacts.capabilities contains a demand, selector, or internal capability: "
            f"{sorted(environment_capabilities - environment_fact_capabilities)}",
        )
        seed_capabilities = requested_capabilities | environment_capabilities
        for forbidden_capability in sorted(seed_capabilities & forbidden_demands):
            validation.error(
                f"provider profile {profile_id} requests forbidden demand capability {forbidden_capability!r}"
            )
        validation.require(
            seed_capabilities <= capability_registry,
            f"provider profile {profile_id} references unregistered requested/environment capabilities: "
            f"{sorted(seed_capabilities - capability_registry)}",
        )
        resolved_capabilities = capability_fixed_point(catalog, seed_capabilities)
        for forbidden_capability in sorted(
            (resolved_capabilities - seed_capabilities) & forbidden_demands
        ):
            validation.error(
                f"provider profile {profile_id} implication introduces forbidden demand capability {forbidden_capability!r}"
            )
        validation.require(
            subject_capabilities <= resolved_capabilities,
            f"provider profile {profile_id} assurance subjects are not a subset of accepted resolved demand: "
            f"{sorted(subject_capabilities - resolved_capabilities)}",
        )

        accepted_selectors = requested_capabilities & provider_selector_capabilities
        active_groups = {
            group_id
            for group_id, group in group_by_id.items()
            if set(group.get("activatedByCapabilities", []))
            & resolved_capabilities
        }
        for selector_capability in sorted(accepted_selectors):
            selector_group = selector_group_owner.get(selector_capability)
            validation.require(
                selector_group in active_groups,
                f"provider profile {profile_id} accepts inactive selector {selector_capability!r}",
            )
        selected_group_members: set[str] = set()
        for group_id in sorted(active_groups):
            selector_map = group_selector_map.get(group_id, {})
            chosen_selectors = accepted_selectors & set(selector_map)
            validation.require(
                len(chosen_selectors) == 1,
                f"provider profile {profile_id} active group {group_id} requires exactly one explicitly accepted selector; "
                f"chosen={sorted(chosen_selectors)}",
            )
            if len(chosen_selectors) == 1:
                selected_group_members.add(
                    selector_map[next(iter(chosen_selectors))]
                )

        for requirement in admission.get("conditionalRequirements", []):
            capability = requirement.get("whenCapability")
            if capability not in resolved_capabilities:
                continue
            validation.require(
                bool(
                    set(requirement.get("requiresAnyCapabilities", []))
                    & resolved_capabilities
                ),
                f"provider profile {profile_id} capability {capability} is missing its required local model class",
            )
            required_group = requirement.get("requiresSelectorGroup")
            validation.require(
                required_group in active_groups
                and len(
                    accepted_selectors
                    & set(group_selector_map.get(str(required_group), {}))
                )
                == 1,
                f"provider profile {profile_id} capability {capability} is missing its required explicit backend selector",
            )

        derived_selected: set[str] = set()
        for capability, binding in capability_bindings.items():
            if capability not in resolved_capabilities or capability in (
                provider_selector_capabilities | exclusive_member_provider_tokens
            ):
                continue
            candidates = set(binding.get("modules", []))
            if binding.get("resolution") == "ALL":
                derived_selected.update(candidates)
            else:
                chosen = candidates & selected
                validation.require(
                    len(chosen) == 1,
                    f"provider profile {profile_id} must choose exactly one module for capability {capability}; "
                    f"chosen={sorted(chosen)}",
                )
                derived_selected.update(chosen)
        derived_selected.update(selected_group_members)
        validation.require(
            selected == derived_selected,
            f"provider profile {profile_id} selectedModules do not equal deterministic capability derivation; "
            f"missing={sorted(derived_selected - selected)}, extra={sorted(selected - derived_selected)}",
        )

        computed_without_subject_dependencies = dependency_closure(
            module_by_id, selected
        )
        computed = dependency_closure(
            module_by_id,
            selected,
            subject_harnesses,
            subject_capabilities,
        )
        for activated_dependency in sorted(
            computed - computed_without_subject_dependencies
        ):
            if activated_dependency not in expected:
                validation.error(
                    f"provider profile {profile_id} assurance subject selection activates conditional dependency "
                    f"{activated_dependency!r}, but expectedClosure omits it"
                )
        computed_external = {
            module_id
            for module_id in computed
            if module_id.startswith("external.")
        }
        validation.require(
            external == computed_external,
            f"provider profile {profile_id} externalPrerequisites do not equal closure external nodes; "
            f"missing={sorted(computed_external - external)}, extra={sorted(external - computed_external)}",
        )
        validation.require(
            expected == computed,
            f"provider profile {profile_id} expectedClosure does not equal computed closure; "
            f"missing={sorted(computed - expected)}, extra={sorted(expected - computed)}",
        )
        validation.require(
            computed.isdisjoint(excluded),
            f"provider profile {profile_id} excludes modules required by its closure: {sorted(computed & excluded)}",
        )

        profile_kubernetes = environment_facts.get("kubernetes")
        profile_architecture = environment_facts.get("architecture")
        kubernetes_facts = environment_facts.get("kubernetesApi", {})
        capacity_facts = environment_facts.get("resourceCapacity", {})
        validation.require(
            kubernetes_facts.get("version") is None
            and kubernetes_facts.get("versionStatus") == "MISSING_PLANNED",
            f"provider profile fixture {profile_id} must not claim a verified Kubernetes version before implementation",
        )
        validation.require(
            capacity_facts.get("capacityStatus") == "MISSING_PLANNED"
            and capacity_facts.get("cpuMillicores") is None
            and capacity_facts.get("memoryMiB") is None
            and capacity_facts.get("ephemeralStorageMiB") is None,
            f"provider profile fixture {profile_id} must not claim measured resource capacity before implementation",
        )
        expected_fact_capabilities = {
            f"architecture.{profile_architecture}-available",
            f"connectivity.{environment_facts.get('connectivity')}",
        }
        validation.require(
            expected_fact_capabilities <= environment_capabilities,
            f"provider profile {profile_id} environmentFacts omit coherent platform facts: "
            f"{sorted(expected_fact_capabilities - environment_capabilities)}",
        )
        platform_selector = {
            "upstream": "platform.provider.kubernetes-upstream",
            "k3s": "platform.provider.k3s",
            "openshift": "platform.provider.openshift",
        }.get(str(profile_kubernetes))
        validation.require(
            platform_selector in accepted_selectors,
            f"provider profile {profile_id} Kubernetes fact {profile_kubernetes!r} does not match an explicitly accepted platform selector",
        )
        platform_demands = requested_capabilities & {"platform.k3s", "platform.openshift"}
        expected_platform_demands = {
            "upstream": set(),
            "k3s": {"platform.k3s"},
            "openshift": {"platform.openshift"},
        }.get(str(profile_kubernetes), set())
        validation.require(
            platform_demands == expected_platform_demands,
            f"provider profile {profile_id} platform demand contradicts typed Kubernetes facts",
        )
        isolation_demand = "isolation.dedicated-cluster"
        validation.require(
            (isolation_demand in requested_capabilities)
            == (environment_facts.get("isolation") == "dedicated-cluster"),
            f"provider profile {profile_id} isolation demand contradicts typed isolation facts",
        )
        requested_architectures = requested_capabilities & {
            "architecture.amd64",
            "architecture.arm64",
        }
        validation.require(
            not requested_architectures
            or requested_architectures == {f"architecture.{profile_architecture}"},
            f"provider profile {profile_id} requested architecture contradicts typed architecture facts",
        )
        if environment_facts.get("accelerators"):
            validation.require(
                "accelerator.nvidia-available" in environment_capabilities,
                f"provider profile {profile_id} declares an accelerator without its availability capability",
            )

        explicitly_selected_provider_members = {
            member_id
            for selector_map in group_selector_map.values()
            for selector_capability, member_id in selector_map.items()
            if selector_capability in accepted_selectors
        }
        for module_id in computed:
            module = module_by_id.get(module_id)
            if not module:
                continue
            condition = module.get("capabilityCondition", {})
            all_of = set(condition.get("allOf", []))
            any_of = set(condition.get("anyOf", []))
            prohibited = set(condition.get("not", []))
            validation.require(
                all_of <= resolved_capabilities,
                f"provider profile {profile_id} selects {module_id} without required capabilities: "
                f"{sorted(all_of - resolved_capabilities)}",
            )
            validation.require(
                not any_of or bool(any_of & resolved_capabilities),
                f"provider profile {profile_id} selects {module_id} without any compatible capability from "
                f"{sorted(any_of)}",
            )
            validation.require(
                prohibited.isdisjoint(resolved_capabilities),
                f"provider profile {profile_id} selects {module_id} despite prohibited capabilities: "
                f"{sorted(prohibited & resolved_capabilities)}",
            )

            supported_kubernetes = set(
                module.get("platforms", {}).get("kubernetes", [])
            )
            validation.require(
                profile_kubernetes in supported_kubernetes
                or "none" in supported_kubernetes,
                f"provider profile {profile_id} selects {module_id} on incompatible Kubernetes "
                f"platform {profile_kubernetes!r}",
            )
            supported_architectures = set(module.get("architectures", []))
            external_obligation = module_id in external and module.get("scope") == "EXTERNAL"
            explicit_platform_obligation = external_obligation or (
                module_id in explicitly_selected_provider_members
                and "platform-supplied"
                in set(environment_facts.get("runtimeClasses", []))
            )
            validation.require(
                profile_architecture in supported_architectures
                or (
                    "platform-supplied" in supported_architectures
                    and explicit_platform_obligation
                ),
                f"provider profile {profile_id} selects {module_id} on incompatible architecture "
                f"{profile_architecture!r}",
            )
            if module.get("resources", {}).get("accelerator") == "REQUIRED":
                validation.require(
                    "nvidia" in set(environment_facts.get("accelerators", [])),
                    f"provider profile {profile_id} selects accelerator-required module {module_id} "
                    "without a compatible accelerator fact",
                )

            compatibility = compatibility_by_module.get(module_id, {})
            operating_system = environment_facts.get("operatingSystem")
            supported_operating_systems = set(
                compatibility.get("operatingSystems", [])
            )
            validation.require(
                operating_system in supported_operating_systems
                or (
                    "platform-supplied" in supported_operating_systems
                    and explicit_platform_obligation
                ),
                f"provider profile {profile_id} selects {module_id} with incompatible operating system {operating_system!r}",
            )
            isolation_fact = environment_facts.get("isolation")
            supported_isolation = set(compatibility.get("isolationModes", []))
            validation.require(
                isolation_fact in supported_isolation
                or (
                    "platform-supplied" in supported_isolation
                    and external_obligation
                ),
                f"provider profile {profile_id} selects {module_id} with incompatible isolation fact {isolation_fact!r}",
            )
            required_grant = compatibility.get("kubernetesApiGrant")
            available_grants = set(kubernetes_facts.get("grants", []))
            validation.require(
                required_grant in available_grants,
                f"provider profile {profile_id} selects {module_id} but is missing Kubernetes API/RBAC grant {required_grant!r}",
            )
            required_storage_mode = compatibility.get("storageMode")
            validation.require(
                required_storage_mode
                in set(environment_facts.get("storageModes", [])),
                f"provider profile {profile_id} selects {module_id} but is missing storage mode {required_storage_mode!r}",
            )
            required_resource_classes = set(
                compatibility.get("resourceRequirement", {}).get(
                    "availableClasses", []
                )
            )
            available_resource_classes = set(
                capacity_facts.get("availableClasses", [])
            )
            validation.require(
                required_resource_classes <= available_resource_classes,
                f"provider profile {profile_id} selects {module_id} but is missing resource class "
                f"{sorted(required_resource_classes - available_resource_classes)}",
            )
            required_localities = set(
                compatibility.get("networkLocalities", [])
            )
            available_localities = set(
                environment_facts.get("networkLocalities", [])
            )
            validation.require(
                required_localities <= available_localities,
                f"provider profile {profile_id} selects {module_id} but is missing network locality "
                f"{sorted(required_localities - available_localities)}",
            )
            required_runtime_classes = set(
                compatibility.get("requiredRuntimeClasses", [])
            )
            available_runtime_classes = set(
                environment_facts.get("runtimeClasses", [])
            )
            unresolved_runtime_classes = required_runtime_classes - available_runtime_classes
            validation.require(
                not unresolved_runtime_classes
                or (
                    unresolved_runtime_classes == {"platform-supplied"}
                    and explicit_platform_obligation
                ),
                f"provider profile {profile_id} selects {module_id} but is missing runtime class "
                f"{sorted(unresolved_runtime_classes)}",
            )
            validation.require(
                "platform-supplied" not in required_runtime_classes
                or explicit_platform_obligation,
                f"provider profile {profile_id} treats platform-supplied runtime as an undeclared external obligation for {module_id}",
            )

            for conditional in module.get("conditionalDependencies", []):
                if selection_predicate_active(
                    conditional.get("selectedWhen"),
                    subject_harnesses,
                    set(),
                    subject_capabilities,
                ):
                    validation.require(
                        conditional.get("moduleId") in computed,
                        f"provider profile {profile_id} omits active conditional dependency "
                        f"{conditional.get('moduleId')} for {module_id}",
                    )

        for group_id, group in group_by_id.items():
            members = set(group.get("members", []))
            chosen = members & computed
            validation.require(
                len(chosen) <= 1,
                f"provider profile {profile_id} selects multiple members of {group_id}: {sorted(chosen)}",
            )
            if set(group.get("activatedByCapabilities", [])) & resolved_capabilities:
                active_selectors = {
                    selector_capability: selector_member
                    for selector_capability, selector_member in group_selector_map.get(
                        group_id, {}
                    ).items()
                    if selector_capability in accepted_selectors
                }
                validation.require(
                    len(active_selectors) == 1,
                    f"provider profile {profile_id} must activate exactly one explicit selector for {group_id}; "
                    f"active={sorted(active_selectors)}",
                )
                validation.require(
                    len(chosen) == 1,
                    f"provider profile {profile_id} must select exactly one compatible member of {group_id}",
                )
                if len(active_selectors) == 1:
                    selected_by_selector = next(iter(active_selectors.values()))
                    validation.require(
                        chosen == {selected_by_selector},
                        f"provider profile {profile_id} selected member for {group_id} does not match its explicit selector",
                    )
        for module_id in computed:
            for group_id in module_by_id.get(module_id, {}).get(
                "requiredProviderGroups", []
            ):
                chosen = set(group_by_id[group_id].get("members", [])) & computed
                validation.require(
                    len(chosen) == 1,
                    f"provider profile {profile_id} does not satisfy {module_id} required group {group_id}",
                )

        # Prove that each selected deployable's active hard service dependencies
        # are present in the same minimal module closure.
        for service_id, service in service_by_id.items():
            service_module = service_bindings.get(service_id)
            if service_module not in computed:
                continue
            for dependency in service.get("dependencies", []):
                if dependency.get("required") is not True:
                    continue
                if dependency.get("selectedWhen") and not selection_predicate_active(
                    dependency.get("selectedWhen"),
                    subject_harnesses,
                    resolved_capabilities,
                    subject_capabilities,
                ):
                    continue
                dependency_id = dependency.get("id")
                if dependency_id in service_bindings:
                    target_module = service_bindings[dependency_id]
                    validation.require(
                        target_module in computed,
                        f"provider profile {profile_id} omits hard service dependency {dependency_id} "
                        f"required by {service_id}",
                    )
                    continue
                satisfaction = satisfaction_by_dependency.get(str(dependency_id))
                if satisfaction and satisfaction.get("mode") == "MODULE_ALIAS":
                    target_module = satisfaction.get("targetId")
                    validation.require(
                        target_module in computed,
                        f"provider profile {profile_id} omits dependency alias {target_module} "
                        f"required by {service_id}",
                    )
                elif satisfaction and satisfaction.get("mode") == "EXCLUSIVE_GROUP":
                    target_group = group_by_id.get(satisfaction.get("targetId"), {})
                    validation.require(
                        len(set(target_group.get("members", [])) & computed) == 1,
                        f"provider profile {profile_id} does not satisfy dependency group "
                        f"{satisfaction.get('targetId')} required by {service_id}",
                    )
                else:
                    validation.require(
                        dependency_id in computed,
                        f"provider profile {profile_id} omits external dependency {dependency_id} "
                        f"required by {service_id}",
                    )


def validate_provider_catalog(
    validation: Validation, repository_names: set[str]
) -> None:
    schema_path = ROOT / "schemas/provider-module.schema.json"
    catalog_path = ROOT / "architecture/providers.yaml"
    documentation_path = ROOT / "docs/PROVIDER_MODULE_CATALOG.md"
    validation.require(schema_path.is_file(), "provider-module JSON Schema is missing")
    validation.require(catalog_path.is_file(), "provider module catalog is missing")
    validation.require(
        documentation_path.is_file(),
        "provider module catalog documentation is missing",
    )
    documentation_text = ""
    if documentation_path.is_file():
        documentation_text = documentation_path.read_text(encoding="utf-8")
        documentation = documentation_text.casefold()
        validation.require(
            "architecture/providers.yaml" in documentation
            and "schemas/provider-module.schema.json" in documentation
            and "closure" in documentation,
            "provider module catalog documentation must identify the catalog, schema, and closure semantics",
        )
    if not schema_path.is_file() or not catalog_path.is_file():
        return
    try:
        schema = load_json(schema_path)
    except (json.JSONDecodeError, DuplicateJsonKeyError, OSError) as exc:
        validation.error(f"provider-module JSON Schema cannot be read: {exc}")
        return
    try:
        catalog = load_yaml(catalog_path)
    except (OSError, yaml.YAMLError) as exc:
        validation.error(f"provider module catalog cannot be read: {exc}")
        return
    for label, field in (
        ("Module/provider records", "modules"),
        ("Registered capability/fact IDs", "capabilityRegistry"),
        ("Capability implication rules", "capabilityImplications"),
        ("Capability-to-module bindings", "capabilityProviders"),
        ("Exclusive provider groups", "providerExclusivityGroups"),
        ("Closed network targets", "networkTargetRegistry"),
        ("Typed module compatibility records", "moduleCompatibility"),
        ("Service-to-module identities", "serviceModuleBindings"),
        ("Deterministic profile fixtures", "profileExamples"),
    ):
        validation.require(
            f"| {label} | {len(catalog.get(field, []))} |" in documentation_text,
            f"provider module documentation count is stale for {field}",
        )
    implementation_ownership = catalog.get("implementationOwnership", {})
    for label, disposition in (
        ("Repository packet implementations", "REPOSITORY_PACKET"),
        ("Tenant external prerequisites", "EXTERNAL_PREREQUISITE"),
        ("Contract-only non-installables", "CONTRACT_ONLY"),
    ):
        disposition_count = sum(
            1
            for ownership in implementation_ownership.values()
            if isinstance(ownership, dict)
            and ownership.get("disposition") == disposition
        ) if isinstance(implementation_ownership, dict) else 0
        validation.require(
            f"| {label} | {disposition_count} |" in documentation_text,
            f"provider module documentation count is stale for {disposition}",
        )
    services = load_yaml(ROOT / "architecture/services.yaml").get("services", [])
    canonical_service_ids = {
        service.get("id")
        for service in services
        if isinstance(service, dict) and isinstance(service.get("id"), str)
    }
    validate_provider_catalog_data(
        validation,
        catalog,
        schema,
        repository_names,
        canonical_service_ids,
    )


def validate_reuse(
    validation: Validation,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[tuple[str, str], dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    reuse = load_yaml(ROOT / "architecture/reuse-map.yaml")
    sources = reuse.get("sources", [])
    source_by_repository = {source.get("repository"): source for source in sources}
    validation.require(
        set(source_by_repository) == set(EXPECTED_WARM_SOURCES)
        and len(source_by_repository) == len(sources),
        "reuse map must contain each publicly disclosed warm-start repository exactly once",
    )
    validation.require(
        reuse.get("sourceInventory")
        == {
            "approvedRepositoryCount": 5,
            "publiclyRecordedCount": 5,
            "metadataOmittedCount": 0,
            "copyAuthorization": "NONE",
        },
        "reuse map source inventory must account for five public repositories and authorize no copying",
    )
    for source in sources:
        commit = str(source.get("commit", ""))
        validation.require(bool(re.fullmatch(r"[0-9a-f]{40}", commit)), f"invalid source commit: {commit}")
        validation.require(
            commit == EXPECTED_WARM_SOURCES.get(source.get("repository")),
            f"warm source {source.get('repository')} is not pinned to the approved commit",
        )
        validation.require(bool(source.get("destinations")), f"source {source.get('repository')} has no destination")
        validation.require(bool(source.get("excluded")), f"source {source.get('repository')} has no exclusions")
        validation.require(
            bool(source.get("excludedPathPatterns")),
            f"source {source.get('repository')} has no enforceable excluded path pattern",
        )

    authorization = load_yaml(ROOT / "legal/source-reuse-authorization.yaml")
    validation.require(
        authorization.get("status") == "recorded-repository-scope-authorization",
        "source authorization must truthfully record repository-scope consent only",
    )
    acquisition = authorization.get("acquisition", {})
    validation.require(acquisition.get("checkout") == "detached-read-only-snapshot", "source checkout must be detached/read-only")
    validation.require(
        acquisition.get("lockTool") == "ci/lock_warm_snapshot.py"
        and acquisition.get("directArgvOnly") is True
        and acquisition.get("sourceCommitVerification")
        == "required-before-and-after-reference-session"
        and acquisition.get("objectInventoryVerification")
        == "required-before-and-after-reference-session-with-lazy-fetch-disabled"
        and acquisition.get("workingTreeCleanVerification")
        == "required-before-and-after-reference-session"
        and acquisition.get("filesystemEnforcement")
        == "REMOVE_ALL_WRITE_BITS_AND_REQUIRE_OS_READ_ONLY_MOUNT_OR_SEPARATE_UNPRIVILEGED_OBSERVER"
        and acquisition.get("implementationIdentityAccess") == "forbidden"
        and acquisition.get("observationIdentity")
        == "separate-unprivileged-source-observer"
        and acquisition.get("fetchRemoteAfterMaterialization") == "disabled",
        "warm-source acquisition must be executable, exact-object verified, and separated from implementation identity",
    )
    validation.require(acquisition.get("pushRemote") == "forbidden", "warm source push remotes must be forbidden")
    validation.require(acquisition.get("pushCredentials") == "forbidden", "warm source push credentials must be forbidden")
    validation.require(acquisition.get("sourceFilesystemWrites") == "forbidden", "warm source filesystem writes must be forbidden")
    validation.require(
        acquisition.get("pathAuthority") == "architecture/reuse-path-index.yaml",
        "source authorization must cite the path index",
    )
    validation.require(
        acquisition.get("authorizationAuthority")
        == "architecture/porting-authorization-index.yaml"
        and acquisition.get("authorizationSchema")
        == "schemas/porting-authorization.schema.json"
        and acquisition.get("destinationRecordSchema")
        == "schemas/porting-record.schema.json",
        "source authorization must cite both sides of the porting transaction",
    )

    path_index = load_yaml(ROOT / "architecture/reuse-path-index.yaml")
    validate_schema_instance(
        validation,
        ROOT / "schemas/reuse-path-index.schema.json",
        path_index,
        "reuse path index",
    )
    authorization_index = load_yaml(
        ROOT / "architecture/porting-authorization-index.yaml"
    )
    validate_schema_instance(
        validation,
        ROOT / "schemas/porting-authorization.schema.json",
        authorization_index,
        "porting authorization index",
    )
    validation.require(
        authorization_index.get("status") == "DISABLED_FAIL_CLOSED"
        and authorization_index.get("admissionEnabled") is False
        and authorization_index.get("authorizations") == [],
        "porting authorization admission must remain disabled and empty until an offline verifier exists",
    )
    try:
        porting_record_schema = load_json(
            ROOT / "schemas/porting-record.schema.json"
        )
        jsonschema.Draft202012Validator.check_schema(porting_record_schema)
    except (
        OSError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
        jsonschema.SchemaError,
    ) as exc:
        validation.error(f"destination porting-record schema is invalid: {exc}")
    authorizations = authorization_index.get("authorizations", [])
    authorization_by_id = {
        authorization.get("authorizationId"): authorization
        for authorization in authorizations
        if isinstance(authorization, dict)
        and isinstance(authorization.get("authorizationId"), str)
    }
    validation.require(
        len(authorization_by_id) == len(authorizations),
        "porting authorization IDs must be present and unique",
    )
    state_machine = authorization.get("authorizationStateMachine", {})
    validation.require(
        state_machine.get("admissionEnabled") is False
        and state_machine.get("admissionDisabledReason")
        == "NO_OFFLINE_SIGNATURE_AND_EVIDENCE_VERIFIER_IMPLEMENTED"
        and set(state_machine.get("futureAdmissionEnablementRequires", []))
        == {
            "canonicalAuthorizationSignatureVerifier",
            "pinnedOfflineApproverKeyFingerprint",
            "trackedEvidencePathDigestVerification",
            "exactPathIndexAuthorizationPacketDestinationJoin",
            "destinationPreparedAndAppliedRecordVerification",
        },
        "source authorization must fail closed until signed evidence and both destination phases are verified",
    )
    transaction = authorization.get("twoRepositoryTransaction", {})
    validation.require(
        transaction.get("phases")
        == ["SOURCE_APPROVED", "DESTINATION_PREPARED", "APPLIED"]
        and "source-material commit" in str(transaction.get("applyRule", ""))
        and "never self-referential" in str(transaction.get("mergeRule", "")),
        "porting transaction must use a non-circular prepared/apply/merge protocol",
    )
    validation.require(
        path_index.get("defaultReuseDisposition")
        == "REFERENCE_ONLY_PENDING_PATH_REVIEW",
        "reuse path index must fail closed to reference-only pending review",
    )
    validation.require(
        path_index.get("copyAuthorizationDisposition") == "COPY_AUTHORIZED",
        "reuse path index has no explicit per-blob copy-authorization state",
    )
    indexed_sources = path_index.get("sources", [])
    indexed_source_by_repository = {source.get("repository"): source for source in indexed_sources}
    validation.require(
        set(indexed_source_by_repository) == set(EXPECTED_WARM_SOURCES)
        and len(indexed_source_by_repository) == len(indexed_sources),
        "reuse path index must contain each warm source exactly once",
    )
    indexed_paths: dict[tuple[str, str], dict[str, Any]] = {}
    for source in indexed_sources:
        repository = source.get("repository")
        validation.require(
            source.get("commit") == EXPECTED_WARM_SOURCES.get(repository),
            f"reuse path index has wrong commit for {repository}",
        )
        validation.require(
            source.get("licenseDisposition")
            == source_by_repository.get(repository, {}).get("licenseDisposition")
            == "path-review-required-before-copy",
            f"reuse path index has wrong license disposition for {repository}",
        )
        validation.require(
            source.get("authorization") == authorization.get("status"),
            f"reuse path index has no authorization for {repository}",
        )
        for entry in source.get("paths", []):
            key = (repository, entry.get("path"))
            validation.require(key not in indexed_paths, f"duplicate reuse path index entry {key}")
            validation.require(
                bool(re.fullmatch(r"[0-9a-f]{40}", str(entry.get("gitObject", "")))),
                f"reuse path {key} has no immutable Git object hash",
            )
            validation.require(entry.get("kind") in {"blob", "tree"}, f"reuse path {key} has unknown Git object kind")
            use_modes = entry.get("useModes", [])
            validation.require(
                isinstance(use_modes, list)
                and len(use_modes) == len(set(use_modes))
                and set(use_modes)
                <= {"DISCOVERY_ONLY", "REFERENCE_ONLY", "PORT_CANDIDATE"},
                f"reuse path {key} has invalid or duplicate use modes",
            )
            ownership = entry.get("ownershipEvidence", {})
            validation.require(
                ownership.get("status")
                in {
                    "REPOSITORY_SCOPE_CONSENT_ONLY",
                    "PATH_LEVEL_RIGHTS_VERIFIED",
                }
                and ownership.get("authorshipClaim")
                in {"NONE", "VERIFIED", "NOT_REQUIRED_BY_LICENSE_GRANT"},
                f"reuse path {key} overstates or omits ownership evidence",
            )
            license_evidence = entry.get("licenseEvidence", {})
            validation.require(
                license_evidence.get("authority")
                in {
                    "legal/third-party-license-policy.yaml",
                    "architecture/porting-authorization-index.yaml",
                }
                and license_evidence.get("inferredFromRepositoryOwnership") is False,
                f"reuse path {key} infers license rights from repository ownership",
            )
            if entry.get("kind") == "tree":
                validation.require(
                    entry.get("recordType") == "TREE_DISCOVERY"
                    and set(use_modes) == {"DISCOVERY_ONLY"}
                    and entry.get("reuseDisposition") == "DISCOVERY_ONLY"
                    and entry.get("eligibleForCopyAuthorization") is False
                    and entry.get("requiredBeforeCopy")
                    == ["replaceWithExactIndexedBlobs"],
                    f"reuse tree {key} is not strictly discovery-only",
                )
            elif entry.get("kind") == "blob":
                validation.require(
                    "DISCOVERY_ONLY" not in set(use_modes),
                    f"reuse blob {key} incorrectly uses discovery-tree semantics",
                )
                validation.require(
                    entry.get("reuseDisposition")
                    in {
                        "REFERENCE_ONLY_PENDING_PATH_REVIEW",
                        "COPY_AUTHORIZED",
                    },
                    f"reuse blob {key} has an unknown copy disposition",
                )
                if entry.get("reuseDisposition") == "COPY_AUTHORIZED":
                    validation.require(
                        entry.get("recordType") == "BLOB_COPY_AUTHORIZED"
                        and set(use_modes) == {"PORT_CANDIDATE"}
                        and license_evidence.get("status")
                        == "PATH_LEVEL_LICENSE_APPROVED"
                        and ownership.get("status") == "PATH_LEVEL_RIGHTS_VERIFIED"
                        and bool(entry.get("authorizationIds"))
                        and bool(entry.get("approvedDestinations")),
                        f"reuse blob {key} claims COPY_AUTHORIZED without path-level license/ownership evidence",
                    )
                else:
                    validation.require(
                        entry.get("recordType") == "BLOB_PENDING"
                        and set(use_modes) == {"REFERENCE_ONLY"}
                        and entry.get("eligibleForCopyAuthorization") is True
                        and license_evidence.get("status") == "NOT_YET_VERIFIED",
                        f"reuse blob {key} pending review has inconsistent evidence state",
                    )
                    validation.require(
                        {
                            "ownerOrLicenseGrantEvidenceRecorded",
                            "spdxDispositionRecorded",
                            "thirdPartyAndGeneratedContentReviewed",
                            "excludedFeatureScanPassed",
                            "portingRecordPrepared",
                        }
                        <= set(entry.get("requiredBeforeCopy", [])),
                        f"reuse blob {key} omits a required COPY_AUTHORIZED promotion gate",
                    )
            indexed_paths[key] = entry

            for pattern in source_by_repository.get(repository, {}).get(
                "excludedPathPatterns", []
            ):
                validation.require(
                    re.search(pattern, str(entry.get("path"))) is None,
                    f"reuse path index includes excluded path {key} matching {pattern}",
                )

    validation.require(
        len(indexed_paths) == EXPECTED_REUSE_PATH_COUNT,
        f"reuse path index must freeze exactly {EXPECTED_REUSE_PATH_COUNT} approved baseline paths, "
        f"found {len(indexed_paths)}",
    )

    referenced_paths: set[tuple[str, str]] = set()
    for packet_path in (ROOT / "task-packets").glob("*.yaml"):
        packet = load_yaml(packet_path)
        for source in packet.get("sourceReuse", []):
            referenced_paths.update((source["repository"], path) for path in source.get("paths", []))
    observed_paths: set[tuple[str, str]] = set()
    for packet_id, observation in TREE_OBSERVATION_PACKETS.items():
        report_path = ROOT / observation["outputPath"]
        try:
            report = load_json(report_path)
        except (OSError, json.JSONDecodeError, DuplicateJsonKeyError) as exc:
            validation.error(f"tree observation {packet_id} cannot be read: {exc}")
            continue
        validation.require(
            hashlib.sha256(report_path.read_bytes()).hexdigest()
            == EXPECTED_TREE_OBSERVATION_DIGESTS[packet_id],
            f"tree observation {packet_id} digest changed",
        )
        authority_record = report.get("authority", {})
        validation.require(
            authority_record.get("packetId") == packet_id
            and authority_record.get("repository") == observation["repository"]
            and authority_record.get("commit") == observation["commit"]
            and authority_record.get("packetObservation", {}).get("copyAuthority")
            == "NONE"
            and report.get("isolationEvidence", {}).get("copyAuthority") == "NONE",
            f"tree observation {packet_id} authority is not exact or overstates copying",
        )
        sources = report.get("sources", [])
        source_paths = [
            source.get("path") for source in sources if isinstance(source, dict)
        ]
        validation.require(
            len(source_paths) == len(sources) == len(set(source_paths))
            and source_paths == sorted(source_paths),
            f"tree observation {packet_id} paths are malformed, duplicated, or unordered",
        )
        for source in sources:
            object_type = source.get("objectType")
            validation.require(
                object_type in {"blob", "tree"},
                f"tree observation {packet_id} contains an unknown object type",
            )
            observed_path = (
                f"{source.get('path')}/" if object_type == "tree" else source.get("path")
            )
            key = (observation["repository"], observed_path)
            validation.require(key not in observed_paths, f"duplicate observed path {key}")
            validation.require(key in indexed_paths, f"tree observation path is unindexed: {key}")
            indexed_entry = indexed_paths.get(key, {})
            validation.require(
                indexed_entry.get("kind") == object_type
                and indexed_entry.get("gitObject") == source.get("gitObject")
                and indexed_entry.get("recordType")
                == ("TREE_DISCOVERY" if object_type == "tree" else "BLOB_PENDING"),
                f"tree observation metadata conflicts with indexed path {key}",
            )
            observed_paths.add(key)
    validation.require(
        not referenced_paths & observed_paths,
        "task packet source references and full-tree observations must not overlap",
    )
    validation.require(
        set(indexed_paths) == referenced_paths | observed_paths,
        "reuse path index must exactly match packet references plus signed tree observations",
    )
    authorized_index_ids: set[str] = set()
    for (repository, source_path), entry in indexed_paths.items():
        if entry.get("reuseDisposition") != "COPY_AUTHORIZED":
            continue
        entry_authorization_ids = set(entry.get("authorizationIds", []))
        authorized_index_ids.update(entry_authorization_ids)
        for authorization_id in entry_authorization_ids:
            authorization_record = authorization_by_id.get(authorization_id, {})
            validation.require(
                authorization_id in authorization_by_id,
                f"copy-authorized reuse blob {(repository, source_path)} cites missing authorization {authorization_id!r}",
            )
            validation.require(
                authorization_record.get("state") == "APPROVED"
                and authorization_record.get("sourceRepository") == repository
                and authorization_record.get("sourceCommit")
                == EXPECTED_WARM_SOURCES.get(repository)
                and authorization_record.get("sourcePath") == source_path
                and authorization_record.get("sourceGitObject")
                == entry.get("gitObject"),
                f"porting authorization {authorization_id!r} does not exactly identify its indexed source blob",
            )
            approved_destinations = {
                (destination.get("repository"), destination.get("pathPrefix"))
                for destination in entry.get("approvedDestinations", [])
                if isinstance(destination, dict)
            }
            destination_path = str(
                authorization_record.get("destinationPath", "")
            )
            validation.require(
                any(
                    authorization_record.get("destinationRepository")
                    == destination_repository
                    and (
                        destination_path == destination_prefix
                        or destination_path.startswith(
                            f"{str(destination_prefix).rstrip('/')}/"
                        )
                    )
                    for destination_repository, destination_prefix in approved_destinations
                ),
                f"porting authorization {authorization_id!r} exceeds the indexed destination grant",
            )
    validation.require(
        set(authorization_by_id) == authorized_index_ids,
        "porting authorization index and copy-authorized blob records must reference each other exactly; "
        f"authorization-only={sorted(set(authorization_by_id) - authorized_index_ids)}, "
        f"blob-only={sorted(authorized_index_ids - set(authorization_by_id))}",
    )

    record_counts = {
        "treeDiscoveryRecords": sum(
            entry.get("recordType") == "TREE_DISCOVERY"
            for entry in indexed_paths.values()
        ),
        "blobPendingRecords": sum(
            entry.get("recordType") == "BLOB_PENDING"
            for entry in indexed_paths.values()
        ),
        "blobCopyAuthorizedRecords": sum(
            entry.get("recordType") == "BLOB_COPY_AUTHORIZED"
            for entry in indexed_paths.values()
        ),
        "portingAuthorizationRecords": len(authorization_by_id),
    }
    validation.require(
        authorization.get("currentInventory") == record_counts,
        "source-reuse authorization inventory differs from the machine authorities; "
        f"declared={authorization.get('currentInventory')}, actual={record_counts}",
    )
    validation.require(
        authorization.get("authorizationStateMachine", {}).get(
            "currentCopyAuthorizedCount"
        )
        == record_counts["blobCopyAuthorizedRecords"],
        "source-reuse authorization copy count is stale",
    )
    return source_by_repository, indexed_paths, authorization_by_id


def validate_base_scope(validation: Validation) -> None:
    scope = load_yaml(ROOT / "architecture/base-scope-sources.yaml")
    authority = scope.get("authority", {})
    validation.require(authority.get("userRequest") == "normative", "the user request must remain normative")
    validation.require(
        authority.get("attachedDocuments") == "research-input-only",
        "attached documents must be classified as research inputs only",
    )
    validation.require(
        authority.get("executableInstructionsFromAttachments") is False,
        "attached documents must not supply executable instructions",
    )
    sources = scope.get("sources", [])
    source_ids = [source.get("id") for source in sources]
    validation.require(
        set(source_ids) == EXPECTED_BASE_SOURCES and len(source_ids) == len(set(source_ids)),
        "base-scope registry must contain each of the six attached inputs exactly once",
    )
    for source in sources:
        digest = str(source.get("sha256", ""))
        validation.require(
            bool(re.fullmatch(r"[0-9a-f]{64}", digest)),
            f"base-scope source {source.get('id')} has an invalid SHA-256 digest",
        )
        validation.require(bool(source.get("fileName")), f"base-scope source {source.get('id')} has no file name")
        validation.require(bool(source.get("role")), f"base-scope source {source.get('id')} has no research role")


def validate_plans(validation: Validation) -> dict[str, str]:
    repo_dir = ROOT / "docs/repositories"
    harness_dir = ROOT / "docs/harnesses"
    repo_files = sorted(repo_dir.glob("*.md")) if repo_dir.exists() else []
    harness_files = sorted(harness_dir.glob("*.md")) if harness_dir.exists() else []
    validation.require(len(repo_files) == 13, f"expected 13 repository plans, found {len(repo_files)}")
    validation.require(len(harness_files) == 16, f"expected 16 harness specs, found {len(harness_files)}")

    repo_texts = {path: path.read_text(encoding="utf-8") for path in repo_files}
    repository_title_pattern = re.compile(r"^# Repository Plan: `([^`]+)`\s*$", re.MULTILINE)
    documented_repositories: list[str] = []
    declared_packet_owners: dict[str, str] = {}
    for path, text in repo_texts.items():
        title_matches = repository_title_pattern.findall(text)
        validation.require(len(title_matches) == 1, f"{path} must have exactly one canonical repository-plan title")
        documented_repositories.extend(title_matches)
        repository = title_matches[0] if len(title_matches) == 1 else ""
        folded = text.casefold()
        for topic, alternatives in REQUIRED_REPOSITORY_TOPICS.items():
            validation.require(
                any(alternative in folded for alternative in alternatives),
                f"{path} is missing repository-plan topic {topic}",
            )
        validation.require(
            "prefetchCommands" in text
            and "offlineAcceptanceCommands" in text
            and "ci/verify-offline.sh" in text,
            f"{path} lacks the direct-argv offline execution contract",
        )
        packet_section = re.search(r"^## PR packets\s*$([\s\S]*?)(?=^## |\Z)", text, re.MULTILINE)
        validation.require(packet_section is not None, f"{path} has no PR packet section")
        if packet_section:
            for packet_id in extract_packet_ids(packet_section.group(1)):
                validation.require(
                    packet_id not in declared_packet_owners,
                    f"task packet {packet_id} is declared by more than one repository plan",
                )
                declared_packet_owners[packet_id] = repository
    validation.require(
        set(documented_repositories) == EXPECTED_REPOSITORIES
        and len(documented_repositories) == len(set(documented_repositories)),
        "repository-plan titles must cover each approved repository exactly once",
    )
    validation.require(
        len(declared_packet_owners) == EXPECTED_PACKET_COUNT,
        f"repository plans must declare exactly {EXPECTED_PACKET_COUNT} PR packets, found {len(declared_packet_owners)}",
    )

    harness_texts = {path: path.read_text(encoding="utf-8") for path in harness_files}
    harness_title_pattern = re.compile(r"^# Harness Specification: `([^`]+)`\s*$", re.MULTILINE)
    documented_harnesses: list[str] = []
    repository_name_by_id = {
        repository["id"]: repository["name"]
        for repository in load_yaml(ROOT / "architecture/repositories.yaml").get("repositories", [])
    }
    harness_owner_by_id = {
        harness["id"]: repository_name_by_id.get(harness["ownerRepository"], "")
        for harness in load_yaml(ROOT / "architecture/taxonomy.yaml").get("harnesses", [])
    }
    for path, text in harness_texts.items():
        title_matches = harness_title_pattern.findall(text)
        validation.require(len(title_matches) == 1, f"{path} must have exactly one canonical harness-spec title")
        documented_harnesses.extend(title_matches)
        harness_id = title_matches[0] if len(title_matches) == 1 else ""
        for term in REQUIRED_HARNESS_TERMS:
            validation.require(term.casefold() in text.casefold(), f"{path} is missing harness-spec topic {term}")
        packet_section = re.search(
            r"^## Sol-high implementation packets\s*$([\s\S]*?)(?=^## |\Z)",
            text,
            re.MULTILINE | re.IGNORECASE,
        )
        validation.require(packet_section is not None, f"{path} has no Sol-high implementation packet section")
        if packet_section:
            packet_ids = extract_packet_ids(packet_section.group(1))
            validation.require(bool(packet_ids), f"{path} maps to no executable task packet")
            for packet_id in packet_ids:
                validation.require(
                    packet_id in declared_packet_owners,
                    f"{path} references undeclared task packet {packet_id}",
                )
            expected_owner = harness_owner_by_id.get(harness_id)
            validation.require(
                any(declared_packet_owners.get(packet_id) == expected_owner for packet_id in packet_ids),
                f"{path} maps to no packet owned by {expected_owner}",
            )
    validation.require(
        set(documented_harnesses) == EXPECTED_HARNESSES
        and len(documented_harnesses) == len(set(documented_harnesses)),
        "harness-spec titles must cover each canonical harness exactly once",
    )
    return declared_packet_owners


def validate_packets(
    validation: Validation,
    repository_names: set[str],
    repository_ids: set[str],
    declared_packet_owners: dict[str, str],
    reuse_sources: dict[str, dict[str, Any]],
    indexed_reuse_paths: dict[tuple[str, str], dict[str, Any]],
    porting_authorizations: dict[str, dict[str, Any]],
) -> None:
    packet_dir = ROOT / "task-packets"
    packet_files = sorted(packet_dir.glob("*.yaml")) if packet_dir.exists() else []
    validation.require(bool(packet_files), "no task packets found")
    live_envelope_schema = load_json(
        ROOT / "schemas/live-campaign-execution-envelope.schema.json"
    )
    jsonschema.Draft202012Validator.check_schema(live_envelope_schema)
    validation.require(
        live_envelope_schema.get("$schema")
        == "https://json-schema.org/draft/2020-12/schema"
        and live_envelope_schema.get("$id")
        == "https://harness.planeon.ai/schemas/live-campaign-execution-envelope.v1alpha1.json"
        and live_envelope_schema.get("additionalProperties") is False,
        "live campaign execution envelope must be the closed Draft 2020-12 v1alpha1 schema",
    )
    schema = load_json(ROOT / "schemas/task-packet.schema.json")
    packets: dict[str, dict[str, Any]] = {}
    branches: set[str] = set()
    covered_repositories: set[str] = set()
    pinned_sources = {repository: source["commit"] for repository, source in reuse_sources.items()}
    repository_id_by_name = {
        repository["name"]: repository["id"]
        for repository in load_yaml(ROOT / "architecture/repositories.yaml").get("repositories", [])
    }
    schema_validator = None

    for path in packet_files:
        packet = load_yaml(path)
        try:
            if schema_validator is None:
                validator_class = jsonschema.validators.validator_for(schema)
                validator_class.check_schema(schema)
                schema_validator = validator_class(
                    schema, format_checker=SCHEMA_FORMAT_CHECKER
                )
            error = jsonschema.exceptions.best_match(
                schema_validator.iter_errors(packet)
            )
            if error is not None:
                raise error
        except jsonschema.ValidationError as exc:
            validation.error(f"{path}: schema error at {list(exc.absolute_path)}: {exc.message}")
            continue
        packet_id = packet["id"]
        validation.require(path.stem == packet_id, f"task packet file {path.name} must be named {packet_id}.yaml")
        validation.require(packet_id not in packets, f"duplicate task packet ID {packet_id}")
        packets[packet_id] = packet
        validation.require(packet["branch"] not in branches, f"duplicate task branch {packet['branch']}")
        branches.add(packet["branch"])
        validation.require(
            packet["repository"] in repository_names | repository_ids,
            f"packet {packet_id} references unknown repository {packet['repository']}",
        )
        validation.require(
            packet["repository"] == declared_packet_owners.get(packet_id),
            f"packet {packet_id} must target its declaring repository {declared_packet_owners.get(packet_id)!r}",
        )
        validation.require(
            packet["branch"].startswith(f"codex/{packet_id.casefold()}"),
            f"packet {packet_id} branch must start with codex/{packet_id.casefold()}",
        )
        covered_repositories.add(packet["repository"])
        reference_observation = packet.get("referenceObservationExecution")
        if packet_id in {"MET-002", "MET-OBS-MODEL-001"}:
            expected_reference_observation = {
                **REFERENCE_OBSERVATION_EXECUTION_BASE,
                "repository": "git@github.com:caglarsubas/data-source-harness.git",
                "commit": "858281f4b845ffacfe05cdb2c40a402c237d4c54",
                "sourcePaths": DATA_HARNESS_V1_OBSERVATION_PATHS,
                "outputPath": "architecture/observations/data-harness-v1.json",
            }
            if packet_id == "MET-OBS-MODEL-001":
                expected_reference_observation.update({
                    "repository": "git@github.com:caglarsubas/llm_inference_engine.git",
                    "commit": "6815c21cb10a4d7dc0b4804f6bb223afb4321e97",
                    "sourcePaths": ["contracts/prometa-model-usage-v2.schema.json"],
                    "outputPath": "architecture/observations/model-usage-v2.json",
                })
            validation.require(
                packet.get("warmSourceAccess")
                == "AUTHORIZED_READ_ONLY_OBSERVATION",
                f"packet {packet_id} must declare the separately launched read-only observation boundary",
            )
            validation.require(
                reference_observation == expected_reference_observation,
                f"packet {packet_id} reference observation must exactly bind the pinned schema blobs and distilled output",
            )
            reference_only_paths = {
                source_path
                for source in packet.get("sourceReuse", [])
                if source.get("repository")
                == expected_reference_observation["repository"]
                and source.get("commit") == expected_reference_observation["commit"]
                and source.get("reuseMode") == "REFERENCE_ONLY"
                for source_path in source.get("paths", [])
            }
            validation.require(
                set(expected_reference_observation["sourcePaths"]) <= reference_only_paths,
                f"packet {packet_id} observation paths must all be exact REFERENCE_ONLY indexed blobs",
            )
            validation.require(
                expected_reference_observation["outputPath"]
                in packet.get("allowedPaths", []),
                f"packet {packet_id} must own its exact distilled observation output",
            )
        elif packet_id in TREE_OBSERVATION_PACKETS:
            expected_reference_observation = {
                **TREE_OBSERVATION_EXECUTION_BASE,
                **TREE_OBSERVATION_PACKETS[packet_id],
            }
            validation.require(
                packet.get("warmSourceAccess") == "AUTHORIZED_READ_ONLY_OBSERVATION",
                f"packet {packet_id} must declare the separate full-tree observer boundary",
            )
            validation.require(
                reference_observation == expected_reference_observation,
                f"packet {packet_id} full-tree observation binding is not exact",
            )
            validation.require(
                expected_reference_observation["outputPath"]
                in packet.get("allowedPaths", []),
                f"packet {packet_id} must own only its distilled observation output",
            )
            validation.require(
                packet.get("sourceReuse") == [],
                f"packet {packet_id} metadata observation cannot grant source reuse",
            )
        else:
            validation.require(
                packet.get("warmSourceAccess")
                == "PROHIBITED_DURING_IMPLEMENTATION",
                f"packet {packet_id} must deny warm-source filesystem access to the implementation run",
            )
            validation.require(
                reference_observation is None,
                f"packet {packet_id} may not declare reference-observation authority",
            )
        prefetch_commands = packet["prefetchCommands"]
        offline_commands = packet["offlineAcceptanceCommands"]
        offline_execution = packet["offlineExecution"]
        live_campaign_execution = packet.get("liveCampaignExecution")
        live_commands = (
            live_campaign_execution.get("commands", [])
            if isinstance(live_campaign_execution, dict)
            else []
        )
        validation.require(
            offline_execution
            == {
                "wrapperArgv": ["./ci/verify-offline.sh"],
                "packetPathEnvironment": "HARNESS_TASK_PACKET",
                "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
                "commandTransport": "ARGV_ARRAY_V1",
                "isolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
                "sessionScope": "SINGLE_PROCESS_TREE",
                "prefetchOutsideSession": False,
                "offlineEnvironment": {
                    "UV_OFFLINE": "1",
                    "UV_FROZEN": "1",
                    "UV_NO_SYNC": "1",
                },
            },
            f"packet {packet_id} must use the hash-pinned ARGV_ARRAY_V1 OS-isolated execution contract",
        )
        if packet_id in LIVE_CAMPAIGN_PACKET_IDS:
            validation.require(
                live_campaign_execution
                == {
                    **LIVE_CAMPAIGN_EXECUTION_BASE,
                    "allowedEvidenceAxes": LIVE_CAMPAIGN_EVIDENCE_AXES[packet_id],
                    "commands": offline_commands,
                },
                f"packet {packet_id} must declare the closed preinstalled live-campaign execution contract",
            )
            validation.require(
                any(command[:2] == ["make", "campaign"] for command in offline_commands),
                f"packet {packet_id} live campaign must expose the canonical make campaign argv",
            )
        else:
            validation.require(
                live_campaign_execution is None,
                f"packet {packet_id} may not declare live-campaign endpoint access",
            )
        expected_evidence_text = "\n".join(packet["expectedEvidence"])
        validation.require(
            LEGACY_PACKET_RESULT_PATTERN.search(expected_evidence_text) is None,
            f"packet {packet_id} expected evidence uses a non-canonical result token",
        )
        if packet_id == "CONF-001":
            validation.require(
                ["make", "acceptance-package-contract"] in offline_commands,
                "packet CONF-001 must own and test the generic acceptance-package dispatch contract",
            )
        if packet_id == "CONF-WG-001":
            folded_evidence = expected_evidence_text.casefold()
            validation.require(
                "unsigned acceptance candidate" in folded_evidence
                and "separate tenant-authorized signature" in folded_evidence
                and "signed acceptance record" not in folded_evidence,
                "packet CONF-WG-001 must separate its unsigned candidate from tenant acceptance",
            )
        validation.require(
            all(command == ["make", "prefetch"] for command in prefetch_commands),
            f"packet {packet_id} has an undeclared prefetch entry point",
        )
        forbidden_offline_tokens = {
            "curl",
            "wget",
            "npx",
            "prefetch",
            "fetch",
            "download",
            "install",
            "sync",
            "add",
            "pull",
        }
        forbidden_executables = {"sh", "bash", "zsh", "dash", "env"}
        for command in prefetch_commands + offline_commands + live_commands:
            validation.require(
                isinstance(command, list)
                and bool(command)
                and all(
                    isinstance(argument, str)
                    and bool(argument)
                    and "\x00" not in argument
                    for argument in command
                ),
                f"packet {packet_id} contains a malformed direct argv command",
            )
            if not isinstance(command, list) or not command:
                continue
            executable = Path(str(command[0])).name.casefold()
            validation.require(
                executable not in forbidden_executables,
                f"packet {packet_id} invokes forbidden shell/environment executable {command[0]!r}",
            )
            folded_command = [str(argument).casefold() for argument in command]
            forbidden_sequences = (
                ["terraform", "apply"],
                ["tofu", "apply"],
                ["pulumi", "up"],
                ["aws", "cloudformation"],
                ["az", "deployment"],
            )
            validation.require(
                executable != "gcloud"
                and not any(
                    folded_command[: len(sequence)] == sequence
                    for sequence in forbidden_sequences
                ),
                f"packet {packet_id} contains prohibited billable/provisioning argv {command!r}",
            )
        for command in offline_commands:
            folded_command = [str(argument).casefold() for argument in command]
            validation.require(
                not (set(folded_command) & forbidden_offline_tokens),
                f"packet {packet_id} performs package/artifact prefetch inside its offline process tree: {command!r}",
            )
            validation.require(
                folded_command[:2] != ["make", "verify-offline"],
                f"packet {packet_id} recursively invokes make verify-offline",
            )
            if folded_command and Path(folded_command[0]).name == "uv":
                validation.require(
                    {"--offline", "--frozen", "--no-sync"}
                    <= set(folded_command),
                    f"packet {packet_id} has uv argv without --offline, --frozen, and --no-sync: {command!r}",
                )
        for allowed_path in packet["allowedPaths"]:
            parts = Path(allowed_path).parts
            validation.require(not Path(allowed_path).is_absolute(), f"packet {packet_id} has absolute allowed path {allowed_path}")
            validation.require(".." not in parts, f"packet {packet_id} allowed path escapes its repository: {allowed_path}")
            validation.require(
                allowed_path not in {".", "*", "**", "/"},
                f"packet {packet_id} has an unbounded allowed path {allowed_path}",
            )
        for source in packet["sourceReuse"]:
            repository = source["repository"]
            validation.require(
                repository in pinned_sources,
                f"packet {packet_id} references an unapproved warm source {repository}",
            )
            validation.require(
                source["commit"] == pinned_sources.get(repository),
                f"packet {packet_id} does not use the pinned source commit for {repository}",
            )
            reuse_mode = source["reuseMode"]
            for source_path in source["paths"]:
                indexed_entry = indexed_reuse_paths.get((repository, source_path), {})
                validation.require(
                    (repository, source_path) in indexed_reuse_paths,
                    f"packet {packet_id} source path is not in the immutable reuse index: {repository}:{source_path}",
                )
                validation.require(
                    reuse_mode in set(indexed_entry.get("useModes", [])),
                    f"packet {packet_id} reuse mode {reuse_mode} is not authorized by the path index: "
                    f"{repository}:{source_path}",
                )
                if reuse_mode == "DISCOVERY_ONLY":
                    validation.require(
                        indexed_entry.get("kind") == "tree"
                        and indexed_entry.get("recordType") == "TREE_DISCOVERY"
                        and indexed_entry.get("reuseDisposition") == "DISCOVERY_ONLY"
                        and indexed_entry.get("eligibleForCopyAuthorization") is False,
                        f"packet {packet_id} discovery path can be copied or is not an indexed tree: "
                        f"{repository}:{source_path}",
                    )
                elif reuse_mode == "REFERENCE_ONLY":
                    validation.require(
                        indexed_entry.get("kind") == "blob"
                        and indexed_entry.get("recordType") == "BLOB_PENDING"
                        and indexed_entry.get("reuseDisposition")
                        == "REFERENCE_ONLY_PENDING_PATH_REVIEW",
                        f"packet {packet_id} reference-only path must be an exact pending indexed blob: "
                        f"{repository}:{source_path}",
                    )
                elif reuse_mode == "PORT_CANDIDATE":
                    validation.require(
                        indexed_entry.get("kind") == "blob"
                        and indexed_entry.get("recordType")
                        == "BLOB_COPY_AUTHORIZED"
                        and indexed_entry.get("reuseDisposition")
                        == "COPY_AUTHORIZED",
                        f"packet {packet_id} port candidate lacks an exact copy-authorized indexed blob: "
                        f"{repository}:{source_path}",
                    )
                for pattern in reuse_sources.get(repository, {}).get("excludedPathPatterns", []):
                    validation.require(
                        re.search(pattern, source_path) is None,
                        f"packet {packet_id} source path matches excluded pattern {pattern}: {source_path}",
                    )
            if reuse_mode == "PORT_CANDIDATE":
                validation.require(
                    False,
                    f"packet {packet_id} is a PORT_CANDIDATE while porting admission is disabled",
                )
                destination = repository_id_by_name.get(packet["repository"])
                validation.require(
                    destination in reuse_sources.get(repository, {}).get("destinations", []),
                    f"packet {packet_id} targets unauthorized destination {destination} for {repository}",
                )
                validation.require(
                    "COPY_AUTHORIZED" in source["strategy"],
                    f"packet {packet_id} port-candidate strategy does not cite the exact COPY_AUTHORIZED gate",
                )
                authorization_id = source.get("authorizationId")
                authorization_record = porting_authorizations.get(
                    authorization_id, {}
                )
                mappings = source.get("mappings", [])
                validation.require(
                    authorization_id in porting_authorizations
                    and len(source.get("paths", [])) == 1
                    and len(mappings) == 1,
                    f"packet {packet_id} port candidate lacks one approved authorization and one exact mapping",
                )
                if len(source.get("paths", [])) == 1 and len(mappings) == 1:
                    source_path = source["paths"][0]
                    mapping = mappings[0]
                    indexed_entry = indexed_reuse_paths.get(
                        (repository, source_path), {}
                    )
                    validation.require(
                        mapping.get("sourcePath") == source_path
                        and authorization_record.get("sourceRepository")
                        == repository
                        and authorization_record.get("sourceCommit")
                        == source.get("commit")
                        and authorization_record.get("sourcePath") == source_path
                        and authorization_record.get("sourceGitObject")
                        == indexed_entry.get("gitObject")
                        and authorization_record.get("destinationRepository")
                        == packet["repository"]
                        and authorization_record.get("destinationPath")
                        == mapping.get("destinationPath")
                        and authorization_record.get("transformationIntent")
                        == mapping.get("transformationIntent")
                        and authorization_record.get("parityIntent")
                        == mapping.get("parityIntent"),
                        f"packet {packet_id} port mapping does not exactly match authorization {authorization_id!r}",
                    )
                    destination_path = str(mapping.get("destinationPath", ""))
                    validation.require(
                        any(
                            allowed_path == destination_path
                            or (
                                allowed_path.endswith("/")
                                and destination_path.startswith(allowed_path)
                            )
                            for allowed_path in packet["allowedPaths"]
                        ),
                        f"packet {packet_id} destination mapping is outside allowedPaths: {destination_path!r}",
                    )
            else:
                validation.require(
                    "authorizationId" not in source
                    and "mappings" not in source,
                    f"packet {packet_id} non-port reuse entry must not carry copy authority",
                )
        if packet["sourceReuse"] and any(
            source["reuseMode"] == "PORT_CANDIDATE"
            for source in packet["sourceReuse"]
        ):
            validation.require(
                any(path == "PORTING.yaml" or path.startswith("porting/") for path in packet["allowedPaths"]),
                f"packet {packet_id} reuses source without an allowed PORTING manifest path",
            )

    for packet_id, packet in packets.items():
        for predecessor in packet["predecessors"]:
            validation.require(predecessor in packets, f"packet {packet_id} has unknown predecessor {predecessor}")
    assert_acyclic(
        validation,
        set(packets),
        {packet_id: packet["predecessors"] for packet_id, packet in packets.items()},
        "task packet",
    )
    ancestor_cache: dict[str, set[str]] = {}

    def ancestors(packet_id: str, visiting: set[str] | None = None) -> set[str]:
        if packet_id in ancestor_cache:
            return ancestor_cache[packet_id]
        visiting = set() if visiting is None else set(visiting)
        if packet_id in visiting:
            return set()
        visiting.add(packet_id)
        result: set[str] = set()
        for predecessor in packets.get(packet_id, {}).get("predecessors", []):
            result.add(predecessor)
            result.update(ancestors(predecessor, visiting))
        ancestor_cache[packet_id] = result
        return result

    for packet_id, packet in packets.items():
        if packet_id != "MET-002" and packet.get("sourceReuse"):
            validation.require(
                "MET-002" in ancestors(packet_id),
                f"packet {packet_id} may inspect or port warm source before the MET-002 authorization gate",
            )
    for authority_error in validate_model_authority(
        packets, load_json(ROOT / "architecture/model-evidence-boundary.json")
    ):
        validation.error(authority_error)
    for ownership_error in validate_dispatch_ownership(packets):
        validation.error(ownership_error)
    for linux_error in validate_linux_readiness(
        packets, load_json(ROOT / "architecture/linux-readiness.json")
    ):
        validation.error(linux_error)
    for repair_error in validate_repair_authority(
        packets, load_json(ROOT / "architecture/readiness-repairs.json")
    ):
        validation.error(repair_error)
    for linux_repair_error in validate_linux_repair(
        packets, load_json(ROOT / "architecture/linux-readiness-amendment.json"),
        (ROOT / "architecture/linux-readiness.json").read_bytes(),
    ):
        validation.error(linux_repair_error)
    for test_ownership_error in validate_linux_test_ownership(
        packets, load_json(ROOT / "architecture/linux-test-ownership-amendment.json"),
        (ROOT / "architecture/linux-readiness-amendment.json").read_bytes(),
    ):
        validation.error(test_ownership_error)
    for fixture_scope_error in validate_model_fixture_scope(
        packets, load_json(ROOT / "architecture/model-fixture-scope-amendment.json"),
        load_scope_inputs(ROOT),
    ):
        validation.error(fixture_scope_error)
    for inventory_error in validate_model_api_inventory(
        packets, load_json(ROOT / "architecture/model-api-inventory-amendment.json"),
        load_inventory_inputs(ROOT),
    ):
        validation.error(inventory_error)
    for live_error in validate_live_backend_readiness(packets, *load_live_inputs(ROOT)):
        validation.error(live_error)
    for scalar_error in validate_scalar_repair(packets, *load_scalar_inputs(ROOT)):
        validation.error(scalar_error)
    for successor_error in validate_successor_inventory(packets, *load_successor_inputs(ROOT)):
        validation.error(successor_error)
    for proxy_error in validate_proxy_contract(packets, *load_proxy_inputs(ROOT)):
        validation.error(proxy_error)
    for observation_error in validate_observation_contract(packets, *load_observation_inputs(ROOT)):
        validation.error(observation_error)
    for custody_error in validate_custody_handoff(packets, *load_custody_inputs(ROOT)):
        validation.error(custody_error)
    for performance_error in validate_ci_performance(packets, *load_performance_inputs(ROOT)):
        validation.error(performance_error)
    for credential_error in validate_credential_lifecycle(packets, *load_credential_inputs(ROOT)):
        validation.error(credential_error)
    try:
        from validate_credential_ordering import load_ordering_inputs, validate_credential_ordering
    except ImportError:
        from scripts.validate_credential_ordering import load_ordering_inputs, validate_credential_ordering
    for ordering_error in validate_credential_ordering(packets, *load_ordering_inputs(ROOT)):
        validation.error(ordering_error)
    try:
        from validate_broker_handoff import load_handoff_inputs, validate_handoff
    except ImportError:
        from scripts.validate_broker_handoff import load_handoff_inputs, validate_handoff
    for handoff_error in validate_handoff(packets, *load_handoff_inputs(ROOT)):
        validation.error(handoff_error)
    for amendment_error in validate_repair_amendment(
        packets, load_json(ROOT / "architecture/readiness-repair-amendment.json"),
        (ROOT / "architecture/readiness-repairs.json").read_bytes(),
    ):
        validation.error(amendment_error)
    validation.require(
        set(packets) == set(declared_packet_owners),
        f"task packet files must exactly match the {EXPECTED_PACKET_COUNT} packets declared by repository plans",
    )

    authority_owner: dict[str, str] = {
        **{
            path: "MET-001"
            for path in (
                "architecture/base-scope-sources.yaml",
                "architecture/taxonomy.yaml",
                "architecture/repositories.yaml",
                "architecture/services.yaml",
                "architecture/dependency-graph.yaml",
                "architecture/providers.yaml",
                "schemas/taxonomy.schema.json",
                "schemas/repositories.schema.json",
                "schemas/services.schema.json",
                "schemas/dependency-graph.schema.json",
                "schemas/provider-module.schema.json",
            )
        },
        **{
            path: "MET-002"
            for path in (
                "architecture/reuse-map.yaml",
                "architecture/reuse-path-index.yaml",
                "architecture/porting-authorization-index.yaml",
                "legal/source-reuse-authorization.yaml",
                "legal/third-party-license-policy.yaml",
                "ci/lock_warm_snapshot.py",
                "ci/test_warm_snapshot.py",
                "schemas/reuse-path-index.schema.json",
                "schemas/porting-authorization.schema.json",
                "schemas/porting-record.schema.json",
            )
        },
        "policies/zero-bill-policy.yaml": "MET-003",
        "schemas/trusted-runner-manifest.schema.json": "MET-003",
        "schemas/task-packet.schema.json": "MET-A2-001",
        "architecture/model-evidence-boundary.json": "MET-A2-001",
        "scripts/validate_alpha2_readiness.py": "MET-REPAIR-006",
        "scripts/validate_readiness_repairs.py": "MET-REPAIR-012",
        "scripts/validate_linux_readiness.py": "MET-REPAIR-012",
        "scripts/validate_linux_repair.py": "MET-REPAIR-012",
        "scripts/validate_linux_test_ownership.py": "MET-REPAIR-012",
        "scripts/validate_model_fixture_scope.py": "MET-REPAIR-012",
        "scripts/validate_model_api_inventory.py": "MET-REPAIR-012",
        "architecture/live-backend-roadmap.json": "MET-LIVE-001",
        "scripts/validate_live_backend_readiness.py": "MET-REPAIR-012",
        "architecture/packet-scalar-amendment.json": "MET-REPAIR-007",
        "architecture/packet-scalar-inputs/baseline.json": "MET-REPAIR-007",
        "architecture/packet-scalar-inputs/run_packet.before.txt": "MET-REPAIR-007",
        "architecture/packet-scalar-inputs/test_linux_inventory.before.txt": "MET-REPAIR-007",
        "scripts/validate_packet_scalar_repair.py": "MET-REPAIR-012",
        "architecture/model-api-inventory-amendment.json": "MET-REPAIR-006",
        "architecture/successor-inventory-amendment.json": "MET-REPAIR-008",
        "architecture/successor-inventory-inputs/baseline.json": "MET-REPAIR-008",
        "architecture/successor-inventory-inputs/test_packet_scalars.before.txt": "MET-REPAIR-008",
        "architecture/successor-inventory-inputs/live_launcher.before.txt": "MET-REPAIR-008",
        "scripts/validate_successor_inventory.py": "MET-REPAIR-012",
        "architecture/proxy-contract-amendment.json": "MET-REPAIR-009",
        "architecture/proxy-contract-inputs/baseline.json": "MET-REPAIR-009",
        "architecture/proxy-contract-inputs/profile.schema.json": "MET-REPAIR-009",
        "architecture/proxy-contract-inputs/vectors.json": "MET-REPAIR-009",
        "scripts/validate_proxy_contract.py": "MET-REPAIR-012",
        "architecture/credential-lifecycle-amendment.json": "MET-REPAIR-012",
        "architecture/credential-lifecycle-inputs/before.json": "MET-REPAIR-012",
        "architecture/credential-lifecycle-inputs/checkpoint.json": "MET-REPAIR-012",
        "scripts/validate_credential_lifecycle.py": "MET-REPAIR-012",
        "architecture/custody-handoff-amendment.json": "MET-REPAIR-011",
        "architecture/custody-handoff-inputs/baseline.json": "MET-REPAIR-011",
        "scripts/validate_custody_handoff.py": "MET-REPAIR-012",
        "architecture/policy-observation-amendment.json": "MET-REPAIR-010",
        "architecture/policy-observation-inputs/channel.schema.json": "MET-REPAIR-010",
        "architecture/policy-observation-inputs/vectors.json": "MET-REPAIR-010",
        "scripts/validate_policy_observation.py": "MET-REPAIR-012",
        "architecture/model-fixture-scope-amendment.json": "MET-REPAIR-005",
        "architecture/linux-test-ownership-amendment.json": "MET-REPAIR-004",
        "architecture/linux-readiness-amendment.json": "MET-REPAIR-003",
        "architecture/linux-readiness.json": "MET-LINUX-001",
        "architecture/readiness-repairs.json": "MET-REPAIR-001",
        "architecture/readiness-repair-amendment.json": "MET-REPAIR-002",
        "schemas/live-campaign-execution-envelope.schema.json": "MET-004",
        "scripts/validate_packet_ownership.py": "MET-004",
        "tests/test_validator_units.py": "MET-P0-002",
        **{
            f"task-packets/{packet_path.name}": (
                "MET-REPAIR-012"
                if packet_path.stem in {"MET-REPAIR-012", "CONF-FIX-005"}
                else "MET-PERF-001"
                if packet_path.stem == "MET-PERF-001"
                else "MET-REPAIR-011"
                if packet_path.stem in {"MET-REPAIR-011", "CONF-FIX-004"}
                else "MET-REPAIR-010"
                if packet_path.stem == "MET-REPAIR-010"
                else "MET-REPAIR-009"
                if packet_path.stem == "MET-REPAIR-009"
                else "MET-REPAIR-008"
                if packet_path.stem in {"MET-REPAIR-008", "CONF-FIX-003"}
                else "MET-REPAIR-007"
                if packet_path.stem in {"MET-REPAIR-007", "CONF-FIX-002"}
                else "MET-LIVE-001"
                if packet_path.stem in {"MET-LIVE-001", "CONF-LIVE-001", "CONF-LIVE-002", "CONF-LIVE-003", "CONF-LIVE-004", "CONF-LIVE-005", "CONF-LIVE-006"}
                else "MET-REPAIR-006"
                if packet_path.stem in {"MET-REPAIR-006", "CON-MODEL-001"}
                else "MET-REPAIR-005"
                if packet_path.stem == "MET-REPAIR-005"
                else
                "MET-REPAIR-004"
                if packet_path.stem in {"MET-REPAIR-004", "CONF-LINUX-001"}
                else
                "MET-REPAIR-003"
                if packet_path.stem in {"MET-REPAIR-003", "CONF-FIX-001", "CONF-LINUX-001"}
                else "MET-LINUX-001"
                if packet_path.stem in {"MET-LINUX-001", "MET-LINUX-002", "CONF-LINUX-001", "MODEL-001", "RUN-001", "EXEC-001", "CTRL-INTEGRATE-001"}
                else "MET-REPAIR-002"
                if packet_path.stem in {"MET-REPAIR-002", "CON-FIX-001"}
                else "MET-REPAIR-001"
                if packet_path.stem in {"MET-REPAIR-001", "CON-FIX-001", "CTRL-FIX-003", "CTRL-INTEGRATE-001", "CON-MODEL-001", "CONF-A2-001"}
                else "MET-A2-001"
                if packet_path.stem in {"MET-A2-001", "MET-OBS-MODEL-001", "CON-MODEL-001", "MODEL-001"}
                else "MET-P0-FIX-004"
                if packet_path.stem
                in {"MET-P0-FIX-004", "MET-P0-002"}
                else "MET-P0-FIX-003"
                if packet_path.stem
                in {
                    "MET-P0-FIX-003", "CTRL-FIX-002",
                }
                else "MET-P0-FIX-002"
                if packet_path.stem
                in {
                    "MET-P0-FIX-002", "TRUST-001",
                }
                else "MET-P0-FIX-001"
                if packet_path.stem
                in {
                    "MET-P0-FIX-001", "MET-OBS-AH-001",
                    "MET-OBS-OCP-001", "MET-OBS-SDK-001",
                }
                else "MET-P0-001"
                if packet_path.stem in {
                    "MET-P0-001", "TRUST-FIX-002",
                    "IND-FIX-001", "TRUST-003",
                }
                else "MET-004"
            )
            for packet_path in packet_files
        },
    }
    authority_owner.update(
        {
            "architecture/base-scope-sources.yaml": "MET-P0-002",
            "architecture/reuse-map.yaml": "MET-P0-002",
            "architecture/reuse-path-index.yaml": "MET-P0-002",
            "legal/source-reuse-authorization.yaml": "MET-P0-002",
            "legal/third-party-license-policy.yaml": "MET-P0-002",
            "schemas/reuse-path-index.schema.json": "MET-P0-002",
            "schemas/porting-authorization.schema.json": "MET-P0-002",
        }
    )
    authority_owner.update({path: "MET-PERF-001" for path in ["architecture/ci-performance-amendment.json","architecture/ci-performance-inputs/tests.before.json","scripts/safe_yaml.py","scripts/validate_alpha2_readiness.py","scripts/validate_architecture.py","scripts/validate_ci_performance.py","scripts/validate_custody_handoff.py","scripts/validate_data_harness_v1_observation.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_model_usage_observation.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_proxy_contract.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_repository_tree_observation.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","tests/test_validator_units.py"]})
    authority_owner.update({path: "MET-REPAIR-012"
                            for path in packets["MET-REPAIR-012"]["allowedPaths"]
                            if path in authority_owner})
    authority_owner["architecture/credential-lifecycle-inputs/meta-tests.before.json"] = "MET-REPAIR-012"
    authority_owner.update({path: "MET-REPAIR-013"
                            for path in packets["MET-REPAIR-013"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-REPAIR-013.yaml"] = "MET-REPAIR-013"
    authority_owner.update({path: "MET-REPAIR-014"
                            for path in packets["MET-REPAIR-014"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-REPAIR-014.yaml"] = "MET-REPAIR-014"
    authority_owner.update({path: "MET-REPAIR-015"
                            for path in packets["MET-REPAIR-015"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-REPAIR-015.yaml"] = "MET-REPAIR-015"
    authority_owner.update({path: "MET-PERF-002"
                            for path in packets["MET-PERF-002"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-002.yaml"] = "MET-PERF-002"
    authority_owner["task-packets/CONF-PERF-001.yaml"] = "MET-PERF-002"
    authority_owner.update({path: "MET-PERF-003"
                            for path in packets["MET-PERF-003"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-003.yaml"] = "MET-PERF-003"
    authority_owner["task-packets/CONF-PERF-002.yaml"] = "MET-PERF-003"
    authority_owner.update({path: "MET-PERF-004"
                            for path in packets["MET-PERF-004"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-004.yaml"] = "MET-PERF-004"
    authority_owner["task-packets/CONF-PERF-003.yaml"] = "MET-PERF-004"
    authority_owner.update({path: "MET-PERF-005"
                            for path in packets["MET-PERF-005"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-005.yaml"] = "MET-PERF-005"
    authority_owner["task-packets/CONF-PERF-004.yaml"] = "MET-PERF-005"
    authority_owner["task-packets/CONF-BENCH-001.yaml"] = "MET-PERF-005"
    authority_owner.update({path: "MET-REPAIR-016"
                            for path in packets["MET-REPAIR-016"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-REPAIR-016.yaml"] = "MET-REPAIR-016"
    authority_owner["task-packets/CONF-FIX-006.yaml"] = "MET-REPAIR-016"
    authority_owner.update({path: "MET-ADOPT-001"
                            for path in packets["MET-ADOPT-001"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-ADOPT-001.yaml"] = "MET-ADOPT-001"
    authority_owner.update({path: "MET-PERF-006"
                            for path in packets["MET-PERF-006"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-006.yaml"] = "MET-PERF-006"
    authority_owner["task-packets/CONF-DIAG-001.yaml"] = "MET-PERF-006"
    authority_owner.update({path: "MET-PERF-007"
                            for path in packets["MET-PERF-007"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-007.yaml"] = "MET-PERF-007"
    authority_owner.update({path: "MET-PERF-008"
                            for path in packets["MET-PERF-008"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-008.yaml"] = "MET-PERF-008"
    authority_owner["task-packets/CONF-DIAG-002.yaml"] = "MET-PERF-008"
    authority_owner.update({path: "MET-ACCEPT-001"
                            for path in packets["MET-ACCEPT-001"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-ACCEPT-001.yaml"] = "MET-ACCEPT-001"
    authority_owner.update({path: "MET-PUBLISH-001"
                            for path in packets["MET-PUBLISH-001"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PUBLISH-001.yaml"] = "MET-PUBLISH-001"
    authority_owner.update({path: "MET-REPAIR-017"
                            for path in packets["MET-REPAIR-017"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-REPAIR-017.yaml"] = "MET-REPAIR-017"
    authority_owner["task-packets/CONF-FIX-007.yaml"] = "MET-REPAIR-017"
    authority_owner.update({path: "MET-ADOPT-002"
                            for path in packets["MET-ADOPT-002"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-ADOPT-002.yaml"] = "MET-ADOPT-002"
    authority_owner.update({path: "MET-PERF-010"
                            for path in packets["MET-PERF-010"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-010.yaml"] = "MET-PERF-010"
    authority_owner.update({path: "MET-PERF-009"
                            for path in packets["MET-PERF-009"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-009.yaml"] = "MET-PERF-009"
    authority_owner["task-packets/CONF-DIAG-003.yaml"] = "MET-PERF-009"
    authority_owner.update({path: "MET-PERF-011"
                            for path in packets["MET-PERF-011"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-011.yaml"] = "MET-PERF-011"
    authority_owner.update({path: "MET-PERF-012"
                            for path in packets["MET-PERF-012"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    for packet_id in ("MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002"):
        authority_owner["task-packets/" + packet_id + ".yaml"] = "MET-PERF-012"
    authority_owner.update({path: "MET-PERF-013"
                            for path in packets["MET-PERF-013"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    for packet_id in ("MET-PERF-013", "CONF-BENCH-003"):
        authority_owner["task-packets/" + packet_id + ".yaml"] = "MET-PERF-013"
    authority_owner.update({path: "MET-REPAIR-018"
                            for path in packets["MET-REPAIR-018"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    for packet_id in ("MET-REPAIR-018", "CONF-FIX-008"):
        authority_owner["task-packets/" + packet_id + ".yaml"] = "MET-REPAIR-018"
    authority_owner.update({path: "MET-PERF-014"
                            for path in packets["MET-PERF-014"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    for packet_id in ("MET-PERF-014", "CONF-DIAG-004"):
        authority_owner["task-packets/" + packet_id + ".yaml"] = "MET-PERF-014"
    authority_owner.update({path: "MET-PERF-015"
                            for path in packets["MET-PERF-015"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    for packet_id in ("MET-PERF-015", "CONF-FIX-009"):
        authority_owner["task-packets/" + packet_id + ".yaml"] = "MET-PERF-015"
    authority_owner.update({path: "MET-PERF-016"
                            for path in packets["MET-PERF-016"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    for packet_id in ("MET-PERF-016", "CONF-FIX-009"):
        authority_owner["task-packets/" + packet_id + ".yaml"] = "MET-PERF-016"
    authority_owner.update({path: "MET-PERF-017"
                            for path in packets["MET-PERF-017"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    for packet_id in ("MET-PERF-017", "CONF-FIX-010"):
        authority_owner["task-packets/" + packet_id + ".yaml"] = "MET-PERF-017"
    authority_owner.update({path: "MET-REPAIR-019"
                            for path in packets["MET-REPAIR-019"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-REPAIR-019.yaml"] = "MET-REPAIR-019"
    authority_owner.update({path: "MET-ENFORCE-001"
                            for path in packets["MET-ENFORCE-001"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-ENFORCE-001.yaml"] = "MET-ENFORCE-001"
    authority_owner.update({path: "MET-PERF-018"
                            for path in packets["MET-PERF-018"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-018.yaml"] = "MET-PERF-018"
    authority_owner.update({path: "MET-ENFORCE-003"
                            for path in packets["MET-ENFORCE-003"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-ENFORCE-003.yaml"] = "MET-ENFORCE-003"
    authority_owner.update({path: "MET-UNIFY-005"
                            for path in packets["MET-UNIFY-005"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-UNIFY-005.yaml"] = "MET-UNIFY-005"
    authority_owner.update({path: "MET-RUNNER-001"
                            for path in packets["MET-RUNNER-001"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-RUNNER-001.yaml"] = "MET-RUNNER-001"
    authority_owner.update({path: "MET-PERF-028"
                            for path in packets["MET-PERF-028"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-028.yaml"] = "MET-PERF-028"
    authority_owner.update({path: "MET-LINUX-005"
                            for path in packets["MET-LINUX-005"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-LINUX-005.yaml"] = "MET-LINUX-005"
    authority_owner.update({path: "MET-VERIFY-001"
                            for path in packets["MET-VERIFY-001"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-VERIFY-001.yaml"] = "MET-VERIFY-001"
    authority_owner.update({path: "MET-PERF-029"
                            for path in packets["MET-PERF-029"]["allowedPaths"]
                            if path in authority_owner or path.startswith(("architecture/", "scripts/"))})
    authority_owner["task-packets/MET-PERF-029.yaml"] = "MET-PERF-029"
    observation_authority_path = "architecture/observations/data-harness-v1.json"
    if (ROOT / observation_authority_path).is_file():
        authority_owner[observation_authority_path] = "MET-002"

    def packet_owns_path(packet: dict[str, Any], authority_path: str) -> bool:
        if packet.get("repository") != "Harness-Engineering":
            return False
        return any(
            allowed_path == authority_path
            or (
                allowed_path.endswith("/")
                and authority_path.startswith(allowed_path)
            )
            for allowed_path in packet.get("allowedPaths", [])
        )

    for authority_path, expected_owner in authority_owner.items():
        validation.require(
            (ROOT / authority_path).is_file(),
            f"canonical machine authority is missing: {authority_path}",
        )
        owners = {
            packet_id
            for packet_id, packet in packets.items()
            if packet_owns_path(packet, authority_path)
        }
        superseded_owners = owners - {expected_owner}
        validation.require(
            expected_owner in owners
            and superseded_owners <= ancestors(expected_owner),
            f"machine authority {authority_path} must be currently owned by {expected_owner} "
            f"with only ordered predecessor owners; found={sorted(owners)}",
        )

    authorized_roots_by_repository: dict[str, set[str]] = defaultdict(set)
    for packet in packets.values():
        for allowed_path in packet["allowedPaths"]:
            authorized_roots_by_repository[packet["repository"]].add(
                Path(allowed_path).parts[0]
            )
    plan_by_repository: dict[str, tuple[Path, str]] = {}
    for plan_path in (ROOT / "docs/repositories").glob("*.md"):
        plan_text = plan_path.read_text(encoding="utf-8")
        title = re.search(r"^# Repository Plan: `([^`]+)`\s*$", plan_text, re.MULTILINE)
        if title:
            plan_by_repository[title.group(1)] = (plan_path, plan_text)
    for repository in sorted(repository_names):
        plan_path, plan_text = plan_by_repository.get(repository, (Path("<missing>"), ""))
        tree_match = re.search(
            r"^## Repository structure[^\n]*\n[\s\S]*?```text\n(.*?)\n```",
            plan_text,
            re.MULTILINE | re.DOTALL,
        )
        validation.require(tree_match is not None, f"{plan_path} has no exact fenced repository tree")
        if not tree_match:
            continue
        declared_roots: set[str] = set()
        for line in tree_match.group(1).splitlines()[1:]:
            root_match = re.match(r"[├└]── ([^/]+?)(?:/|$)", line)
            if root_match:
                declared_roots.add(root_match.group(1))
        validation.require(
            declared_roots == authorized_roots_by_repository.get(repository, set()),
            f"{plan_path} exact-tree roots differ from packet-authorized roots; "
            f"tree-only={sorted(declared_roots - authorized_roots_by_repository.get(repository, set()))}, "
            f"packet-only={sorted(authorized_roots_by_repository.get(repository, set()) - declared_roots)}",
        )
    packet_readme = (packet_dir / "README.md").read_text(encoding="utf-8")
    ordered_packet_ids = re.findall(
        r"^\|\s*\d+\s*\|\s*`([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)`\s*\|",
        packet_readme,
        re.MULTILINE,
    )
    validation.require(
        len(ordered_packet_ids) == EXPECTED_PACKET_COUNT
        and len(ordered_packet_ids) == len(set(ordered_packet_ids))
        and set(ordered_packet_ids) == set(declared_packet_owners),
        f"task-packets README must index each of the {EXPECTED_PACKET_COUNT} individual packet files exactly once",
    )
    order_by_id = {packet_id: index for index, packet_id in enumerate(ordered_packet_ids)}
    for packet_id, packet in packets.items():
        for predecessor in packet["predecessors"]:
            if packet_id in order_by_id and predecessor in order_by_id:
                validation.require(
                    order_by_id[predecessor] < order_by_id[packet_id],
                    f"task-packets README orders {packet_id} before predecessor {predecessor}",
                )
    validation.require("alpha-1.yaml" not in packet_readme, "task-packets README still references obsolete wrapper files")
    validation.require(
        "one yaml file per packet" in packet_readme.casefold(),
        "task-packets README must state the one-file-per-packet execution rule",
    )
    for repository in repository_names:
        registry_id = next(
            (
                item["id"]
                for item in load_yaml(ROOT / "architecture/repositories.yaml")["repositories"]
                if item["name"] == repository
            ),
            None,
        )
        validation.require(
            repository in covered_repositories or registry_id in covered_repositories,
            f"repository {repository} has no task packet",
        )


def validate_workflow(validation: Validation, path: Path) -> None:
    original_text = path.read_text(encoding="utf-8")
    text = original_text.casefold()
    workflow = load_yaml(path) or {}
    validation.require(
        "${{ secrets." not in text,
        f"{path} references a GitHub or provider secret",
    )
    for forbidden in (
        "ubuntu-latest",
        "ubuntu-24.04",
        "windows-latest",
        "macos-latest",
        "actions/upload-artifact",
        "actions/cache",
        "schedule:",
        "packages: write",
        "pull_request_target:",
    ):
        validation.require(forbidden not in text, f"{path} contains zero-bill violation {forbidden}")

    def validate_permissions(permissions: Any, owner: str) -> None:
        if permissions is None:
            return
        validation.require(isinstance(permissions, dict), f"{owner} permissions must be an explicit mapping")
        if isinstance(permissions, dict):
            for scope, access in permissions.items():
                validation.require(access in {"read", "none"}, f"{owner} grants prohibited {scope}: {access}")

    validate_permissions(workflow.get("permissions"), str(path))
    jobs = workflow.get("jobs", {})
    validation.require(bool(jobs) and isinstance(jobs, dict), f"{path} defines no jobs")
    for job_id, job in jobs.items() if isinstance(jobs, dict) else []:
        validation.require(isinstance(job, dict), f"{path} job {job_id} must be a mapping")
        if not isinstance(job, dict):
            continue
        runs_on = job.get("runs-on")
        labels = [runs_on] if isinstance(runs_on, str) else runs_on
        validation.require(isinstance(labels, list), f"{path} job {job_id} must use explicit runner labels")
        normalized_labels = {str(label).casefold() for label in labels or []}
        validation.require(
            len(labels or []) == 4
            and normalized_labels
            == {"self-hosted", "harness-engineering", "ephemeral", "credential-free"},
            f"{path} job {job_id} must use only the closed ephemeral credential-free runner labels",
        )
        validation.require(
            not any("${{" in label for label in normalized_labels),
            f"{path} job {job_id} computes runner labels dynamically",
        )
        validation.require("services" not in job, f"{path} job {job_id} declares downloadable service containers")
        validation.require("container" not in job, f"{path} job {job_id} declares a downloadable job container")
        validate_permissions(job.get("permissions"), f"{path} job {job_id}")
        for environment_owner, environment in (
            (f"{path} job {job_id}", job.get("env", {})),
            *(
                (
                    f"{path} job {job_id} step {index}",
                    step.get("env", {}),
                )
                for index, step in enumerate(job.get("steps", []))
                if isinstance(step, dict)
            ),
        ):
            if not isinstance(environment, dict):
                continue
            for name in environment:
                validation.require(
                    re.search(
                        r"(?:api[_-]?key|secret|credential|access[_-]?token|cloud[_-]?token)",
                        str(name),
                        re.IGNORECASE,
                    )
                    is None,
                    f"{environment_owner} declares prohibited credential environment {name!r}",
                )
        if "pull_request:" in text:
            condition = str(job.get("if", ""))
            validation.require(
                "head.repo.fork == false" in condition,
                f"{path} job {job_id} does not block untrusted fork execution",
            )
        steps = job.get("steps", [])
        validation.require(
            isinstance(steps, list),
            f"{path} job {job_id} steps must be an explicit list",
        )
        run_steps = [
            step
            for step in steps
            if isinstance(step, dict) and "run" in step
        ] if isinstance(steps, list) else []
        validation.require(
            len(run_steps) == 1
            and run_steps[0].get("run")
            == "/opt/planeon/bin/harness-offline-launch"
            and set(run_steps[0]) <= {"name", "run"},
            f"{path} job {job_id} must execute only the preinstalled absolute host launcher before repository code",
        )
        validation.require(
            len(steps) == 2
            and isinstance(steps[0], dict)
            and str(steps[0].get("uses", "")).startswith("actions/checkout@")
            and steps[1] is run_steps[0],
            f"{path} job {job_id} must contain only pinned checkout followed by the preinstalled host launcher",
        )

    validation.require(
        re.search(r"^\s*[a-z-]+:\s*write\s*$", text, re.MULTILINE) is None,
        f"{path} grants a write permission",
    )
    action_references = [
        str(step.get("uses"))
        for job in jobs.values()
        if isinstance(job, dict)
        for step in job.get("steps", [])
        if isinstance(step, dict) and isinstance(step.get("uses"), str)
    ] if isinstance(jobs, dict) else []
    for action in action_references:
        if action.startswith("./"):
            validation.error(
                f"{path} uses unvalidated local action {action}; inline the read-only step or add closed recursive action validation"
            )
            continue
        if action.startswith("docker://"):
            validation.require(
                bool(re.search(r"@sha256:[0-9a-f]{64}$", action)),
                f"{path} uses an unpinned Docker action {action}",
            )
            continue
        validation.require(
            bool(re.search(r"@[0-9a-f]{40}$", action)),
            f"{path} uses an action not pinned to a full commit SHA: {action}",
        )
        validation.require(
            action
            == "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            f"{path} uses non-allowlisted external action {action}",
        )
    checkout_steps = [
        step
        for job in jobs.values()
        if isinstance(job, dict)
        for step in job.get("steps", [])
        if isinstance(step, dict)
        and str(step.get("uses", "")).startswith("actions/checkout@")
    ] if isinstance(jobs, dict) else []
    validation.require(
        len(checkout_steps) == 1
        and checkout_steps[0].get("with", {}).get("persist-credentials") is False
        and checkout_steps[0].get("with", {}).get("fetch-depth") == 1,
        f"{path} must use one credential-free shallow checkout",
    )
    trusted_launcher = ROOT / "scripts/verify_offline.sh"
    launcher_text = trusted_launcher.read_text(encoding="utf-8")
    validation.require(
        "source \"$repo_root/ci/warm-source-isolation.sh\"" in launcher_text
        and "/usr/bin/sandbox-exec" in launcher_text
        and "--blacklist=${warm_root}" in launcher_text
        and "unshare --user" not in launcher_text
        and "exec make verify-offline-inner" in launcher_text,
        f"{path} trusted launcher does not establish the closed macOS/Linux isolation boundary",
    )
    toolchain_verifier = (ROOT / "scripts/verify_toolchain.py").read_text(
        encoding="utf-8"
    )
    validation.require(
        'EXPECTED = {"jsonschema": "4.24.0", "PyYAML": "6.0.2"}'
        in toolchain_verifier
        and "sys.version_info[:2] != (3, 12)" in toolchain_verifier,
        f"{path} does not verify the preprovisioned locked toolchain inside isolation",
    )
    runner_manifest_schema = load_json(
        ROOT / "schemas/trusted-runner-manifest.schema.json"
    )
    try:
        jsonschema.Draft202012Validator.check_schema(runner_manifest_schema)
    except jsonschema.SchemaError as exc:
        validation.error(f"trusted runner manifest schema is invalid: {exc}")
    runner_contract = (ROOT / "docs/TRUSTED_RUNNER_CONTRACT.md").read_text(
        encoding="utf-8"
    )
    validation.require(
        "/etc/planeon/harness-runner-manifest.json" in runner_contract
        and "/etc/planeon/harness-runner-manifest.json.sig" in runner_contract
        and "/etc/planeon/harness-runner-manifest.pub" in runner_contract
        and "explicit external prerequisite for CI" in runner_contract
        and "must not fabricate" in runner_contract,
        f"{path} does not bind the host launcher to exact external signed custody",
    )


def validate_zero_bill(validation: Validation) -> None:
    policy = load_yaml(ROOT / "policies/zero-bill-policy.yaml")
    defaults = policy.get("defaults", {})
    validation.require(defaults.get("deploymentMode") == "offline", "default mode must be offline")
    validation.require(defaults.get("allowedHosts") == [], "default allowedHosts must be empty")
    for field in (
        "runtimeDownloads",
        "externalTelemetry",
        "paidOrMeteredProviders",
        "thirdPartyApiKeys",
    ):
        validation.require(defaults.get(field) is False, f"zero-bill default {field} must be false")
    forbidden_implementation = set(policy.get("forbiddenImplementation", []))
    validation.require(
        {
            "cloud-resource-provisioning",
            "paid-or-metered-providers",
            "third-party-api-key-providers",
            "unknown-provider-cost-disposition",
            "hosted-model-providers",
            "cloud-billing-apis",
            "runtime-model-downloads",
            "runtime-package-downloads",
            "runtime-image-downloads-outside-locked-bundle",
            "external-telemetry-exporters",
            "implicit-network-package-execution",
        }
        <= forbidden_implementation,
        "zero-bill forbiddenImplementation is incomplete",
    )
    provider_admission = policy.get("providerAdmission", {})
    validation.require(
        set(provider_admission.get("allowedCostDispositions", []))
        == {
            "SELF_HOSTED_OPEN_SOURCE_NON_METERED",
            "TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED",
        },
        "provider admission has an unsafe cost disposition",
    )
    for field in ("unknownCostDisposition", "paidOrMetered", "thirdPartyApiKey", "externalTelemetry"):
        validation.require(provider_admission.get(field) == "reject", f"provider admission must reject {field}")
    offline = policy.get("offlineVerification", {})
    validation.require(offline.get("osNetworkIsolationRequired") is True, "offline verification must require OS isolation")
    validation.require(offline.get("outboundCanaryRequired") is True, "offline verification must require a canary")
    validation.require(offline.get("unsupportedIsolationBackend") == "fail", "unknown isolation backends must fail")

    ci_policy = policy.get("ci", {})
    validation.require(
        ci_policy.get("requiredRunnerLabels")
        == ["self-hosted", "harness-engineering", "ephemeral", "credential-free"]
        and ci_policy.get("ephemeralRunnerRequired") is True
        and ci_policy.get("credentialAndBrokerFreeRequired") is True
        and ci_policy.get("trustedHostLauncher")
        == "/opt/planeon/bin/harness-offline-launch"
        and ci_policy.get("trustedRunnerManifest")
        == "/etc/planeon/harness-runner-manifest.json"
        and ci_policy.get("trustedHostLauncherState")
        == "EXTERNAL_PREREQUISITE_NOT_PROVEN"
        and ci_policy.get("repositoryCodeBeforeHostIsolation") is False,
        "CI policy must bind the closed labels and preinstalled host isolation boundary",
    )

    workflow_dir = ROOT / ".github/workflows"
    if workflow_dir.exists():
        for path in workflow_dir.glob("*.y*ml"):
            validate_workflow(validation, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zero-bill-only", action="store_true")
    args = parser.parse_args()
    validation = Validation()

    try:
        validate_zero_bill(validation)
        validate_provider_catalog(validation, EXPECTED_REPOSITORIES)
        if not args.zero_bill_only:
            repository_names, repository_ids = validate_architecture(validation)
            validate_services(validation)
            validate_base_scope(validation)
            (
                reuse_sources,
                indexed_reuse_paths,
                porting_authorizations,
            ) = validate_reuse(validation)
            declared_packet_owners = validate_plans(validation)
            validate_packets(
                validation,
                repository_names,
                repository_ids,
                declared_packet_owners,
                reuse_sources,
                indexed_reuse_paths,
                porting_authorizations,
            )
    except (
        OSError,
        yaml.YAMLError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
        jsonschema.SchemaError,
    ) as exc:
        validation.error(f"machine authority is unreadable or ambiguous: {exc}")

    if validation.errors:
        for error in validation.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"readiness validation failed with {len(validation.errors)} error(s)", file=sys.stderr)
        return 1
    print("readiness validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
