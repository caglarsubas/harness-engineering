#!/usr/bin/env python3
"""Validate the immutable Linux roadmap publication, not live Linux readiness."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

try:
    from safe_yaml import safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import safe_load as safe_yaml_load

try:
    from validate_linux_repair import amend_linux_packet
    from validate_linux_test_ownership import amend_linux_test_packet
except ModuleNotFoundError:
    from scripts.validate_linux_repair import amend_linux_packet
    from scripts.validate_linux_test_ownership import amend_linux_test_packet

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_POLICY = json.loads(r'''{
  "schemaVersion": "harness.planeon.ai/linux-readiness/v1",
  "authorityPacket": "MET-LINUX-001",
  "currentPacketCount": 118,
  "publicationEvidence": "ROADMAP_AUTHORITY_ONLY",
  "developmentHosts": [
    "macOS",
    "Linux"
  ],
  "productionKernel": "Linux",
  "runnerKitOwner": "MET-LINUX-002",
  "earlyCampaignOwner": "CONF-LINUX-001",
  "gate": {
    "status": "WAITING",
    "runtimeCodingRequires": "FRESH_NATIVE_LINUX_AMD64_PASS",
    "blockedPackets": [
      "CTRL-INTEGRATE-001",
      "MODEL-001",
      "EXEC-001",
      "RUN-001"
    ],
    "sourceOnlyExceptions": [
      "CTRL-FIX-003",
      "CON-MODEL-001"
    ],
    "unavailableResult": "NOT_RUN_ENV_UNAVAILABLE",
    "unavailableUnblocksRuntimeCoding": false,
    "maximumEvidenceAgeHours": 168,
    "invalidateOn": [
      "SOURCE_OR_IMAGE_CHANGE",
      "TOOLCHAIN_OR_CACHE_CHANGE",
      "HOST_OR_ISOLATION_CHANGE",
      "TRUST_REVOCATION_OR_EXPIRY",
      "FAILED_REQUIRED_CASE"
    ]
  },
  "targets": [
    {
      "os": "linux",
      "architecture": "amd64",
      "execution": "NATIVE",
      "requiredFor": "EARLY_RUNTIME_CODING_GATE",
      "status": "NOT_RUN_ENV_UNAVAILABLE"
    },
    {
      "os": "linux",
      "architecture": "arm64",
      "execution": "NATIVE",
      "requiredFor": "ARM64_RELEASE_OR_SUPPORT_CLAIM",
      "status": "NOT_RUN_ENV_UNAVAILABLE"
    }
  ],
  "build": {
    "targetNativeDependencies": true,
    "hostOutputReuse": "DENIED",
    "mutableInputs": "DENIED",
    "downloads": "DENIED",
    "sourceScope": "PINNED_OWN_PRODUCT_TREES_ONLY",
    "cacheScope": "PINNED_OS_ARCH_LIBC_TOOLCHAIN",
    "requiredBindings": [
      "SOURCE_COMMIT",
      "IMAGE_DIGEST",
      "BUILD_RECIPE_DIGEST",
      "OS_ARCH_LIBC",
      "TOOLCHAIN_INVENTORY",
      "CACHE_INVENTORY",
      "SBOM_DIGEST",
      "BUILD_LOG_DIGEST"
    ]
  },
  "requiredCases": [
    "HOST_ISOLATION_NEGATIVES",
    "LINUX_TARGET_BUILD",
    "FULL_PREDECESSOR_REGRESSION",
    "CONTROL_CONTAINER_STARTUP",
    "POSTGRES_MIGRATION_AND_RLS",
    "DURABLE_RESTART",
    "ARBITRARY_NON_ROOT_UID",
    "READ_ONLY_ROOT_FILESYSTEM",
    "KUBERNETES_SMOKE",
    "DEFAULT_DENY_NETWORK"
  ],
  "evidence": {
    "axes": [
      "DEPLOYMENT",
      "RUNTIME",
      "SECURITY",
      "ASSURANCE"
    ],
    "sourceOrFixtureCanPass": false,
    "emulationCanQualifyNative": false,
    "missingMandatoryCaseCanPass": false,
    "acceptCallerVerificationBoolean": false,
    "requiredBindings": [
      "PACKET_DIGEST",
      "ENVELOPE_DIGEST",
      "CAPACITY_AUTHORIZATION_DIGEST",
      "TENANT_AND_ENVIRONMENT",
      "HOST_KERNEL_ARCH_LIBC",
      "SOURCE_AND_IMAGE_DIGESTS",
      "RUN_NONCE",
      "OBSERVED_AT",
      "VALID_UNTIL",
      "PROBE_DIGESTS",
      "OUTPUT_DIGESTS",
      "INDEPENDENT_SIGNATURES"
    ],
    "signingAuthority": "EXISTING_PLATFORM_RELEASE_TENANT_LIVE_EXECUTION_AND_CAPACITY_OPERATOR",
    "runtimeTransport": "SIGNED_PREEXISTING_PROXY_ONLY"
  },
  "billing": {
    "newProvisioning": false,
    "hostedRunners": false,
    "paidApis": false,
    "thirdPartyKeys": false,
    "rawContainerSockets": false,
    "capacity": "LOCAL_OR_PREEXISTING_TENANT_AUTHORIZED_ZERO_INCREMENTAL_COST"
  },
  "laterCertificationOwners": [
    "CONF-K8S-001",
    "CONF-OCP-001",
    "CONF-K3S-001",
    "CONF-AIR-001",
    "CONF-SEC-001",
    "CONF-UPG-001",
    "CONF-WG-001"
  ],
  "completedCorrection": {
    "packet": "CON-FIX-001",
    "repository": "mas-harness-contracts",
    "mergeCommit": "fb365aabfd8c5560e064be5d97ff9f2bcc69c57c",
    "pr": 8,
    "requiredCiRun": 33982852363,
    "exactMain": {
      "kind": "LOCAL_SIGNED_OFFLINE",
      "passed": 758,
      "failed": 0,
      "skipped": 0,
      "logSha256": "c4fc420019527382d41ec72d06e4de91e00ebb401e9c38c78d1b40056f95429a"
    },
    "linuxProof": false
  }
}''')
EXPECTED_PACKETS = json.loads(r'''{
  "MET-LINUX-001": {
    "id": "MET-LINUX-001",
    "repository": "Harness-Engineering",
    "branch": "codex/met-linux-001-early-linux-readiness",
    "objective": "Publish the approved early Linux build, isolated verification and minimal-runtime gates before new runtime implementation; retain completed corrections and Alpha-4 certification boundaries.",
    "predecessors": [
      "MET-REPAIR-002",
      "CON-FIX-001"
    ],
    "allowedPaths": [
      "task-packets/MET-LINUX-001.yaml",
      "task-packets/MET-LINUX-002.yaml",
      "task-packets/CONF-LINUX-001.yaml",
      "task-packets/MODEL-001.yaml",
      "task-packets/RUN-001.yaml",
      "task-packets/EXEC-001.yaml",
      "task-packets/CTRL-INTEGRATE-001.yaml",
      "task-packets/README.md",
      "architecture/linux-readiness.json",
      "scripts/validate_linux_readiness.py",
      "tests/test_linux_readiness.py",
      "scripts/validate_readiness.py",
      "scripts/validate_reuse.py",
      "scripts/validate_alpha2_readiness.py",
      "scripts/validate_readiness_repairs.py",
      "tests/test_task_packets.py",
      "tests/test_reuse.py",
      "tests/test_alpha2_readiness.py",
      "tests/test_readiness_repairs.py",
      "docs/DEVELOPMENT_STATUS.md",
      "docs/MASTER_DEVELOPMENT_PLAN.md",
      "docs/READINESS_INDEX.md",
      "docs/TRUSTED_RUNNER_CONTRACT.md",
      "docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md",
      "docs/adr/0004-sol-high-packet-boundary.md",
      "docs/alpha-2/LINUX_READINESS.md",
      "docs/alpha-2/READINESS_REPAIRS.md",
      "docs/alpha-2/MODEL_PREREQUISITES.md",
      "docs/repositories/00-harness-engineering.md",
      "docs/repositories/04-mas-harness-control-plane.md",
      "docs/repositories/05-mas-harness-runtime-plane.md",
      "docs/repositories/06-mas-harness-model-plane.md",
      "docs/repositories/08-mas-harness-execution-plane.md",
      "docs/repositories/12-mas-harness-conformance-labs.md"
    ],
    "warmSourceAccess": "PROHIBITED_DURING_IMPLEMENTATION",
    "sourceReuse": [],
    "contracts": [
      "Produces a 118-packet roadmap with Linux-first release acceptance and macOS as a development host only.",
      "Preserves historical 107, 110, 114 and 115 packet snapshots and every source lock; records verified CON-FIX-001 closure separately.",
      "Produces narrowly owned MET-LINUX-002 runner-kit and CONF-LINUX-001 early Linux campaign packets; no current Linux PASS claim."
    ],
    "deliverables": [
      "Add the early Linux gate after CTRL-FIX-003 and before CTRL-INTEGRATE-001 or new MODEL-001, EXEC-001 and RUN-001 runtime implementation. Existing pure status corrections and contract work may proceed without claiming Linux acceptance.",
      "Publish an exact Linux AMD64 baseline and separately qualified Linux ARM64 matrix, with native versus emulated execution recorded independently and unavailable architectures never inferred as passing.",
      "Require Linux-target builds from clean pinned sources and preprovisioned OS/architecture-specific caches, independent regression, startup, database/migration, restricted-user and Kubernetes smoke evidence.",
      "Keep Linux host bootstrap and signed installation external to product CI, prevent raw host/container socket access in campaigns, and preserve all signed zero-cost, source-denial and live-acceptance boundaries.",
      "Update phase-labelled roadmap, repository plans, ownership/count validators and negative tests; preserve immutable historical review records and the CON-FIX-001 pre-fix and exact-main evidence."
    ],
    "excluded": [
      "Product code edits, root-owned host changes, new credentials/keys, dependency or runtime downloads, cloud provisioning, hosted runners, billable API calls, warm-source access, public wire-contract changes and actual deployment or Linux certification."
    ],
    "prefetchCommands": [],
    "offlineAcceptanceCommands": [
      [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/validate_readiness.py"
      ],
      [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/validate_reuse.py"
      ],
      [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/validate_alpha2_readiness.py"
      ],
      [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/validate_readiness_repairs.py"
      ],
      [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/validate_linux_readiness.py"
      ],
      [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "-m",
        "pytest",
        "tests",
        "ci/test_offline_runner.py",
        "ci/test_warm_snapshot.py"
      ],
      [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "scripts/zero_bill_scan.py",
        "."
      ]
    ],
    "offlineExecution": {
      "wrapperArgv": [
        "./ci/verify-offline.sh"
      ],
      "packetPathEnvironment": "HARNESS_TASK_PACKET",
      "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
      "commandTransport": "ARGV_ARRAY_V1",
      "isolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
      "sessionScope": "SINGLE_PROCESS_TREE",
      "prefetchOutsideSession": false,
      "offlineEnvironment": {
        "UV_OFFLINE": "1",
        "UV_FROZEN": "1",
        "UV_NO_SYNC": "1"
      }
    },
    "expectedEvidence": [
      "118 unique topologically ordered packets with closed path/command ownership; exactly eleven live-campaign packet declarations preserve independent release, tenant and capacity authority.",
      "Negative tests reject omitted Linux prerequisites, weakened architecture/native-execution/build provenance, passing unavailable targets, macOS output admitted as Linux, public/metered endpoints, widened packet paths and erased predecessor evidence.",
      "Publication source, offline, PR, merge and exact-main evidence remain separate from future Linux host/build/runtime PASS; CON-FIX-001 closure is retained at fb365aabfd8c5560e064be5d97ff9f2bcc69c57c."
    ],
    "rollback": "Revert this unconsumed roadmap publication as a unit; after consumption supersede through a new reviewed authority, retaining prior packet and evidence snapshots."
  },
  "MET-LINUX-002": {
    "id": "MET-LINUX-002",
    "repository": "Harness-Engineering",
    "branch": "codex/met-linux-002-linux-runner-kit",
    "objective": "Implement a portable, root-custodied Linux trusted-offline launcher candidate and reproducible operator kit without installing or claiming a Linux host pass.",
    "predecessors": [
      "MET-LINUX-001"
    ],
    "allowedPaths": [
      "ci/linux-runner/",
      "tests/linux_runner/",
      "docs/linux-runner/"
    ],
    "warmSourceAccess": "PROHIBITED_DURING_IMPLEMENTATION",
    "sourceReuse": [],
    "prefetchCommands": [],
    "offlineExecution": {
      "wrapperArgv": [
        "./ci/verify-offline.sh"
      ],
      "packetPathEnvironment": "HARNESS_TASK_PACKET",
      "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
      "commandTransport": "ARGV_ARRAY_V1",
      "isolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
      "sessionScope": "SINGLE_PROCESS_TREE",
      "prefetchOutsideSession": false,
      "offlineEnvironment": {
        "UV_OFFLINE": "1",
        "UV_FROZEN": "1",
        "UV_NO_SYNC": "1"
      }
    },
    "contracts": [
      "Consumes docs/alpha-2/LINUX_READINESS.md and the unchanged trusted-runner manifest, offline argv and live-runner contracts.",
      "Produces a source-tested Linux launcher candidate, fixed direct-argv build recipes and operator preflight; installation remains separately signed external host maintenance."
    ],
    "deliverables": [
      "Implement ci/linux-runner/launcher.py and deterministic build.py using only already locked Python standard-library tooling; produce candidate launcher and SHA-256 inventory, never install root files from repository code.",
      "Implement ci/linux-runner/preflight.py and tests/linux_runner/ against Linux Firejail deny-all networking, exhaustive warm-root read/metadata/write denial, hidden credential homes/control sockets, packet/manifest tamper rejection, process descendants and environment scrubbing. Missing kernel/backend/privilege reports NOT_RUN_ENV_UNAVAILABLE; never fall back to unisolated execution.",
      "Preserve the exact signed manifest and packet digest, root ownership, command order, local cache inventories and per-command digest checks. Do not re-use a Darwin preflight, command result, sandbox profile or native binary as Linux proof.",
      "Publish docs/linux-runner/OPERATOR.md and closed build-input specification for operator-supplied pinned Linux AMD64/ARM64 toolchains, source trees and local caches. Linux-native dependencies and standalone Next.js output must be built in the declared Linux target, independently of macOS build folders.",
      "Test malformed manifests, altered packets, unsafe paths, shell argv, wrong architecture/libc/toolchain, unpinned or missing caches, writable trust, runner credentials, child network/socket/source access, and byte-identical deterministic packaging. Run the real integration subset only when the trusted Linux backend exists; synthetic adapter tests are explicitly source-only."
    ],
    "excluded": [
      "Root installation, workflow edits, product code, cloud or VM provisioning, package downloads, new keys, raw Docker/CRI socket grants, source observation, Linux runtime PASS and tenant acceptance."
    ],
    "offlineAcceptanceCommands": [
      [
        "uv",
        "run",
        "--offline",
        "--frozen",
        "--no-sync",
        "python",
        "-m",
        "pytest",
        "tests/linux_runner"
      ]
    ],
    "expectedEvidence": [
      "Candidate source/tests/package digests and negative-test results are separate from fresh operator-installed Linux isolation evidence; macOS unit results cannot close the Linux gate.",
      "An external operator must review the candidate, install signed hash-pinned bytes with rollback and execute every required negative probe on the named Linux host before CONF-LINUX-001 live execution."
    ],
    "rollback": "Revert the unconsumed candidate; installed host rollback is an independent operator transaction to the previously verified signed launcher and trust bundle."
  },
  "CONF-LINUX-001": {
    "id": "CONF-LINUX-001",
    "repository": "mas-harness-conformance-labs",
    "branch": "codex/conf-linux-001-early-linux-baseline",
    "objective": "Implement and independently run the early Linux foundation acceptance campaign, keeping offline source tests separate from signed Linux build/isolation/runtime evidence.",
    "predecessors": [
      "CONF-A1-001",
      "MET-LINUX-002",
      "CTRL-FIX-003"
    ],
    "allowedPaths": [
      "campaigns/platform/linux-baseline/",
      "tests/platform/linux_baseline/",
      "fixtures/platform/linux-baseline/",
      "docs/reports/linux-baseline.md",
      "tests/meta/test_registry_dispatch.py",
      "src/harness_conformance/linux_readiness.py",
      "src/harness_conformance/campaign.py",
      "src/harness_conformance/cli.py",
      "src/harness_conformance/schema.py",
      "src/harness_conformance/live.py",
      "src/harness_conformance/live_launcher.py",
      "schemas/v1alpha1/conformance-campaign.schema.json",
      "schemas/v1alpha1/linux-readiness-evidence.schema.json"
    ],
    "warmSourceAccess": "PROHIBITED_DURING_IMPLEMENTATION",
    "sourceReuse": [],
    "contracts": [
      "Consumes the MET-LINUX-001 Linux readiness policy and MET-LINUX-002 reviewed runner candidate, CONF-001 evidence/trust/dispatch contracts, and completed foundation plus CTRL-FIX-003 exact-main artifacts.",
      "Produces a closed Linux readiness evidence record and a fixed LINUX_READINESS campaign handler; generic ENVIRONMENT_CAPABILITY=true and checked-in fixtures never satisfy real Linux acceptance."
    ],
    "deliverables": [
      "Add the linux-baseline campaign and closed evidence schema with independent cases for native AMD64 and ARM64, Linux-target build provenance, offline full regression, standalone control container startup, PostgreSQL migrations/RLS/restart, arbitrary non-root UID/read-only filesystem and default-deny Kubernetes smoke.",
      "Implement a fixed evidence verifier in src/harness_conformance/linux_readiness.py and additive campaign/CLI/schema/live-context integration. Verify exact source/image/OS/architecture/libc/toolchain/cache/probe/result digests, independent signer purpose and validity, observation freshness, envelope tenant/environment/release binding and every required case; do not trust caller-supplied verified booleans or capability fixtures.",
      "Use the existing external dual-signed launcher only. Live probe operations are a closed set against the envelope-authorized pre-existing CAMPAIGN_PROXY or KUBERNETES_API_PROXY, with namespace/quota/zero-incremental-cost admission and per-operation evidence bound to the run nonce; no arbitrary executable, URL, command, plugin import, raw socket, root or provisioning authority.",
      "Keep CI fully offline: fake transports are labelled unit evidence, unavailable signed runtime context yields NOT_RUN_ENV_UNAVAILABLE, real target failure yields FAIL, and malformed/expired/replayed or digest-mismatched records fail closed. Source-kit merge cannot satisfy the Linux gate.",
      "Run all predecessor conformance tests plus new Linux negative cases. Preserve existing campaign output bytes and handlers for unaffected inputs; no synthetic fixture replacement of the full baseline.",
      "Publish docs/reports/linux-baseline.md with exact packet/source/build/CI/merge versus operator-install/Linux evidence axes, native/emulated matrix, missing capacity blockers and reusable pre-existing resource cleanup/rollback. Operator-installed fixed probe/build helpers must be reviewed and hash-bound; absence is NOT_RUN_ENV_UNAVAILABLE, not permission to install or download them."
    ],
    "excluded": [
      "Product service modifications, Makefile/dispatcher changes, root-owned launcher installation from CI, dependency downloads, cloud resources, new capacity, node-wide mutations, raw Docker/CRI sockets, warm sources, new tenant acceptance signatures, model/GPU performance or Alpha-4 platform certification."
    ],
    "prefetchCommands": [],
    "offlineAcceptanceCommands": [
      [
        "python3",
        "-m",
        "unittest",
        "discover",
        "-s",
        "tests",
        "-p",
        "test_*.py"
      ],
      [
        "make",
        "campaign",
        "CAMPAIGN=linux-baseline"
      ],
      [
        "make",
        "evidence-verify",
        "CAMPAIGN=linux-baseline"
      ]
    ],
    "offlineExecution": {
      "wrapperArgv": [
        "./ci/verify-offline.sh"
      ],
      "packetPathEnvironment": "HARNESS_TASK_PACKET",
      "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
      "commandTransport": "ARGV_ARRAY_V1",
      "isolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
      "sessionScope": "SINGLE_PROCESS_TREE",
      "prefetchOutsideSession": false,
      "offlineEnvironment": {
        "UV_OFFLINE": "1",
        "UV_FROZEN": "1",
        "UV_NO_SYNC": "1"
      }
    },
    "liveCampaignExecution": {
      "launcherArgv": [
        "/opt/planeon/bin/harness-live-campaign-launch"
      ],
      "commandTransport": "ARGV_ARRAY_V1",
      "executionPlacement": "PREINSTALLED_TARGET_LOCAL_EPHEMERAL_RUNNER",
      "executionEnvelopeEnvironment": "HARNESS_LIVE_EXECUTION_ENVELOPE",
      "executionEnvelopeMode": "DUAL_SIGNED_PACKET_COMMAND_CAMPAIGN_ENDPOINT_BINDING_V1",
      "releaseTrustStoreMount": "/etc/planeon/trust/release-trust-bundle.json",
      "tenantTrustStoreMount": "/etc/planeon/trust/tenant-trust-bundle.json",
      "trustStoreMode": "HASH_PINNED_LOCAL_PUBLIC_KEYS_VALIDITY_PURPOSE_AND_REVOCATION_V1",
      "revocationRequired": true,
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
      "allowedEvidenceAxes": [
        "DEPLOYMENT",
        "RUNTIME",
        "SECURITY",
        "ASSURANCE"
      ],
      "commands": [
        [
          "python3",
          "-m",
          "unittest",
          "discover",
          "-s",
          "tests",
          "-p",
          "test_*.py"
        ],
        [
          "make",
          "campaign",
          "CAMPAIGN=linux-baseline"
        ],
        [
          "make",
          "evidence-verify",
          "CAMPAIGN=linux-baseline"
        ]
      ]
    },
    "expectedEvidence": [
      "Fresh native Linux AMD64 PASS is mandatory before CTRL-INTEGRATE-001, MODEL-001, EXEC-001 or RUN-001 runtime coding; missing Linux capacity or authority is NOT_RUN_ENV_UNAVAILABLE and keeps this stricter gate closed even after the kit source merges.",
      "Linux ARM64 is separately required before advertising or releasing that target. Emulated execution never satisfies native qualification; macOS development artifacts cannot be accepted as Linux release outputs.",
      "Real Linux-target build, full regression, startup, migration/RLS, restart, restricted UID and Kubernetes deny-all probes are digest-bound and independently verified; every missing or skipped mandatory case prevents PASS.",
      "Full enterprise K8s/K3s/OCP/air-gap, upgrade, GPU and tenant acceptance remain later independently executed gates."
    ],
    "rollback": "Remove only run-labelled resources inside the preauthorized namespace through the signed proxy; preserve tenant data and evidence. Do not destroy capacity or automatically reverse destructive migrations; restore a verified checkpoint only with separate data-owner authority."
  }
}''')
RUNTIME_PREDECESSORS = json.loads(r'''{"MODEL-001":["SDK-003","CON-006","MET-002","MET-003","CON-MODEL-001","CONF-LINUX-001"],"RUN-001":["SDK-004","TRUST-001","MET-003","CONF-LINUX-001"],"EXEC-001":["SDK-004","TRUST-001","KN-001","MET-003","CONF-LINUX-001"],"CTRL-INTEGRATE-001":["CTRL-FIX-003","CONF-LINUX-001"]}''')
GATE_REQUIREMENT = "Fresh CONF-LINUX-001 native Linux AMD64 PASS is required before runtime coding; merged source or NOT_RUN_ENV_UNAVAILABLE does not open this gate. Revalidate exact source/image/toolchain/host/trust bindings and freshness under docs/alpha-2/LINUX_READINESS.md."


def _same(actual: Any, expected: Any) -> bool:
    """Compare closed JSON with exact types (True must not equal 1)."""
    try:
        return json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(
            expected, sort_keys=True, allow_nan=False
        )
    except (TypeError, ValueError):
        return False


def validate_linux_readiness(packets: Any, policy: Any) -> list[str]:
    errors: list[str] = []
    if not _same(policy, EXPECTED_POLICY):
        errors.append("Linux publication policy changed or claims unverified readiness")
    if not isinstance(packets, dict):
        return [*errors, "Linux packet catalog must be an object"]
    if len(packets) != 194:
        errors.append("Current catalog requires 194 packets; original Linux policy remains 118")
    for packet_id, expected in EXPECTED_PACKETS.items():
        if packet_id == "CONF-LINUX-001":
            expected = amend_linux_test_packet(amend_linux_packet(expected))
        if not _same(packets.get(packet_id), expected):
            errors.append(f"{packet_id} closed Linux authority changed")
    for packet_id, predecessors in RUNTIME_PREDECESSORS.items():
        packet = packets.get(packet_id)
        if not isinstance(packet, dict):
            errors.append(f"{packet_id} runtime packet missing")
            continue
        if not _same(packet.get("predecessors"), predecessors):
            errors.append(f"{packet_id} Linux predecessors changed")
        evidence = packet.get("expectedEvidence")
        if not isinstance(evidence, list) or GATE_REQUIREMENT not in evidence:
            errors.append(f"{packet_id} must retain the fresh native Linux coding gate")
    return errors


def main() -> int:
    packets = {
        path.stem: safe_yaml_load(path.read_text(encoding="utf-8"))
        for path in sorted((ROOT / "task-packets").glob("*.yaml"))
    }
    errors = validate_linux_readiness(
        packets, json.loads((ROOT / "architecture/linux-readiness.json").read_text(encoding="utf-8"))
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Linux roadmap authority valid: 194 packets; historical 118/120/121-packet authorities preserved; live Linux acceptance remains unproven.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
