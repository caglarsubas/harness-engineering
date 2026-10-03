#!/usr/bin/env python3
"""Pinned source-only performance authority. No product imports or execution."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import stat
from types import MappingProxyType

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

try:
    from validate_proxy_diagnostics import historical_bytes as diagnostic_history, current_test_bytes as diagnostic_current, validate_additions as diagnostic_additions
except ImportError:
    from scripts.validate_proxy_diagnostics import historical_bytes as diagnostic_history, current_test_bytes as diagnostic_current, validate_additions as diagnostic_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/provider-adoption-authority.json"
RECORD_SHA256 = "040f02f7ce6aeb54a2d5469804a0b293149d97a66ac7ccdf43d7f41c6fa48284"
NEW_IDS = ("MET-ADOPT-001",)
RECORD_FILE_SHA256 = "9b143600b0885d8a010814720e1dd98b775faa971c27a903c8fce36f97493a56"
HISTORY_PATHS = frozenset(["README.md","docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/PROVIDER_MODULE_CATALOG.md","docs/READINESS_INDEX.md","docs/harnesses/execution.ml-decision.md","docs/harnesses/execution.orchestration.md","docs/harnesses/execution.protocol-interoperability.md","docs/harnesses/execution.tool-skill-sandbox.md","docs/harnesses/knowledge.data-integration.md","docs/harnesses/knowledge.domain-semantic.md","docs/harnesses/knowledge.memory-state.md","docs/harnesses/knowledge.retrieval-context.md","docs/harnesses/runtime.ai-gateway.md","docs/harnesses/runtime.experience.md","docs/harnesses/runtime.infrastructure.md","docs/harnesses/runtime.model-inference.md","docs/harnesses/trust.evaluation-assurance.md","docs/harnesses/trust.governance-agentops.md","docs/harnesses/trust.observability-finops.md","docs/harnesses/trust.security-safety.md","docs/repositories/00-harness-engineering.md","docs/repositories/01-mas-harness-contracts.md","docs/repositories/02-mas-harness-sdks.md","docs/repositories/03-mas-harness-industry-packs.md","docs/repositories/04-mas-harness-control-plane.md","docs/repositories/05-mas-harness-runtime-plane.md","docs/repositories/06-mas-harness-model-plane.md","docs/repositories/07-mas-harness-knowledge-plane.md","docs/repositories/08-mas-harness-execution-plane.md","docs/repositories/09-mas-harness-trust-plane.md","docs/repositories/10-mas-harness-operator.md","docs/repositories/11-mas-harness-distribution.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_broker_handoff.py","scripts/validate_ci_performance.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_proxy_contract.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_broker_handoff.py","tests/test_ci_performance.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_proxy_contract.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, "duplicate JSON member")
            value[key] = item
        return value
    def nonfinite(_):
        raise ValueError("nonfinite JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def regular_bytes(root, path):
    require(type(path) is str and path and not path.startswith("/")
            and all(x not in ("", ".", "..") for x in path.split("/")), "relative path")
    current = Path(root)
    for part in path.split("/")[:-1]:
        current /= part
        require(stat.S_ISDIR(current.lstat().st_mode), "linked ancestor")
    target = current / path.split("/")[-1]
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= 16777216, "bounded unlinked regular file")
    raw = target.read_bytes()
    after = target.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size, "file changed")
    return raw


def pinned(record):
    require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256, "exact performance authority")


def _record():
    # Fresh read and byte digest every invocation; never cache parsed authority.
    raw = regular_bytes(ROOT, RECORD_PATH)
    require(digest(raw) == RECORD_FILE_SHA256, "exact fresh authority bytes")
    return parse(raw)


def _freeze_projection_rules():
    """Freeze only inverse recipes; current authority bytes are never cached."""
    record = _record()
    require(set(record["metaRecipes"]) == HISTORY_PATHS, "exact historical routing")
    return MappingProxyType({
        path: (
            rule["beforeSha256"],
            rule["afterSha256"],
            tuple((row["before"], row["after"], row["count"])
                  for row in rule["replacements"]),
        )
        for path, rule in record["metaRecipes"].items()
    })


_PROJECTION_RULES = _freeze_projection_rules()


def _checked_projection_rule(path):
    # Preserve a complete fresh regular-file read and SHA on every projection.
    raw = regular_bytes(ROOT, RECORD_PATH)
    require(digest(raw) == RECORD_FILE_SHA256, "exact fresh authority bytes")
    frozen = _PROJECTION_RULES.get(path)
    if frozen is None:
        return None
    before_sha, after_sha, replacements = frozen
    return {
        "beforeSha256": before_sha,
        "afterSha256": after_sha,
        "replacements": [
            {"before": before, "after": after, "count": count}
            for before, after, count in replacements
        ],
    }


def apply_recipe(before, rule):
    require(type(before) is bytes and type(rule) is dict
            and set(rule) == {"beforeSha256", "afterSha256", "replacements"}
            and digest(before) == rule["beforeSha256"], "exact before bytes")
    current = before
    for item in rule["replacements"]:
        require(type(item) is dict and set(item) == {"before", "after", "count"}
                and type(item["before"]) is type(item["after"]) is str
                and item["before"] and item["before"] != item["after"]
                and type(item["count"]) is int and item["count"] > 0, "closed effective replacement")
        old, new = item["before"].encode(), item["after"].encode()
        require(current.count(old) == item["count"], "replacement cardinality")
        current = current.replace(old, new)
    require(digest(current) == rule["afterSha256"], "exact current source")
    return current


def historical_bytes(path, raw):
    raw = diagnostic_history(path, raw)
    # A closed code-pinned routing table, not an acceptance/result cache.
    # Unchanged inputs still receive the predecessor caller's exact hash check.
    if path not in HISTORY_PATHS:
        return raw
    rule = _checked_projection_rule(path)
    if rule is None:
        return raw
    require(type(raw) is bytes and digest(raw) == rule["afterSha256"], "current bytes changed: " + path)
    before = raw
    for row in reversed(rule["replacements"]):
        new, old = row["after"].encode(), row["before"].encode()
        require(before.count(new) == row["count"], "inverse cardinality")
        before = before.replace(new, old)
    require(apply_recipe(before, rule) == raw, "unreviewed inverse")
    return before


def current_test_bytes(before):
    require(type(before) is bytes, "test bytes")
    record = _record()
    input_digest = digest(before)
    matches = [r for p, r in record["metaRecipes"].items()
               if p.startswith("tests/") and r["beforeSha256"] == input_digest]
    if not matches:
        require(input_digest in record["unchangedTests"].values(), "unreviewed unchanged test")
        return diagnostic_current(before)
    require(len(matches) == 1, "unique predecessor")
    return diagnostic_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return diagnostic_additions(packets)
    except (ValueError, TypeError, RecursionError):
        return ["missing or changed performance packets"]


def test_ids(raw):
    result = []
    def visit(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                result.append(prefix + node.name)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
    visit(ast.parse(raw).body)
    require(len(result) == len(set(result)), "duplicate test identity")
    return result


PLAN_PATH = "architecture/provider-adoption.json"
GUIDE_PATH = "docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md"
POLICY = parse("{\"billableProvisioning\":false,\"coreCatalogMutation\":false,\"customAdapterIsolation\":\"SEPARATE_WORKER_OR_SERVICE\",\"customAdapterMaySelfAuthorize\":false,\"distributedSoftware\":\"OPEN_SOURCE_EXISTING_LICENSE_POLICY\",\"existingExternalServiceLifecycleOwner\":\"TENANT\",\"externalTelemetryDefault\":false,\"hostedRunners\":false,\"macOS\":\"DEVELOPMENT_NOT_QUALIFICATION\",\"onlineLicenseCheck\":false,\"paidApis\":false,\"productionFoundation\":\"LINUX_KUBERNETES_OPENSHIFT\",\"proprietaryTargetAllowed\":\"AUTHORIZED_ALREADY_LICENSED_ON_PREM_ZERO_INCREMENTAL_CHARGES_ONLY\",\"proprietaryTargetMayBeDistributed\":false,\"registryOwner\":\"trust-plane\",\"runtimeDownloads\":false,\"selectionUiOwner\":\"control-plane\",\"unknownIncrementalCharges\":\"BLOCK\",\"warmSourceAccess\":\"PROHIBITED_DURING_IMPLEMENTATION\"}")
EXTENSIONS = parse("{\"CON-EXT-001\":[\"contracts\",[\"MET-ADOPT-001\"]],\"CONF-EXT-001\":[\"conformance-labs\",[\"CON-EXT-001\",\"SDK-EXT-001\"]],\"CTRL-EXT-001\":[\"control-plane\",[\"SDK-EXT-001\",\"TRUST-EXT-001\"]],\"DIST-EXT-001\":[\"distribution\",[\"CON-EXT-001\",\"TRUST-EXT-001\"]],\"OP-EXT-001\":[\"operator\",[\"CON-EXT-001\",\"DIST-EXT-001\"]],\"SDK-EXT-001\":[\"sdks\",[\"CON-EXT-001\"]],\"TRUST-EXT-001\":[\"trust-plane\",[\"CON-EXT-001\",\"CONF-EXT-001\"]]}")
EXPANSION = parse("[{\"id\":\"ollama-existing-and-managed\",\"order\":[\"QUALIFY_EXTERNAL_ENDPOINT\",\"QUALIFY_MANAGED_DEPLOYMENT\"],\"owner\":\"model-plane\",\"packet\":\"MODEL-OLLAMA-001\",\"phase\":\"ALPHA_2\",\"status\":\"WAITING_QUALIFICATION\"},{\"id\":\"llamacpp-vllm-alternatives\",\"owner\":\"model-plane\",\"packets\":[\"MODEL-LLAMACPP-001\",\"MODEL-VLLM-001\"],\"phase\":\"ALPHA_2\",\"status\":\"WAITING_QUALIFICATION\"},{\"id\":\"retrieval-pgvector\",\"owner\":\"knowledge-plane\",\"packet\":\"KN-RET-001\",\"phase\":\"ALPHA_2\",\"status\":\"WAITING_QUALIFICATION\"},{\"id\":\"milvus\",\"order\":[\"EXTERNAL_ATTACHMENT\",\"MANAGED_DEPLOYMENT\"],\"owner\":\"knowledge-plane\",\"packet\":null,\"phase\":\"POST_RELEASE_WAVE_1\",\"status\":\"WAITING_PACKET_PUBLICATION\"},{\"candidate\":\"Temporal\",\"id\":\"durable-execution-adoption\",\"implementationAuthorized\":false,\"owner\":\"execution-plane\",\"packet\":\"EXEC-ORCH-001\",\"phase\":\"BEFORE_FURTHER_BESPOKE_EXECUTION\",\"status\":\"ADOPTION_DECISION_REQUIRED\"},{\"fakeSurfaceIsQualification\":false,\"id\":\"framework-real-package-qualification\",\"owner\":\"sdks\",\"packet\":null,\"phase\":\"ALPHA_2_AND_EXPANSION\",\"status\":\"WAITING_PACKET_PUBLICATION\"}]")
CHECKPOINT = parse("{\"conformanceDraft\":\"6dcd8e72859037839915c2f928e0fb55641e458a\",\"conformanceMain\":\"f988c78e93b28257810ed99e7f0c072e9b76bae5\",\"evidenceClass\":\"RECORDED_LOCAL_AND_CI_NOT_PACKET_COMPLETION\",\"metaBase\":\"9010ef0280d301eb18071266bda17e4c1ad5ebcc\",\"modelEffortTransition\":\"NOT_DUE\",\"nativeQualification\":\"NOT_RUN_ENV_UNAVAILABLE\",\"packet\":\"CONF-LIVE-003\",\"phase\":\"ALPHA_2\",\"recordedSkips\":0,\"recordedTests\":509,\"status\":\"IMPLEMENTATION_INCOMPLETE\",\"tenantAcceptance\":false}")


def validate_plan(plan, taxonomy, repositories, catalog):
    require(type(plan) is dict and set(plan) == {'schemaVersion', 'evidenceClass', 'releaseRequirement', 'minimumQualifiedBaselines', 'selectionRule', 'policies', 'repositoryMap', 'harnessCoverage', 'relationships', 'extensionBacklog', 'expansionBacklog', 'currentCheckpoint'}, 'closed adoption plan')
    require(plan['schemaVersion'] == 'planeon.internal.provider-adoption/v1' and plan['evidenceClass'] == 'PLANNING_ONLY', 'planning evidence only')
    require(plan['releaseRequirement'] == 'Require **at least one qualified baseline for every released harness capability** at the first enterprise release.' and type(plan['minimumQualifiedBaselines']) is int and plan['minimumQualifiedBaselines'] == 1, 'at least one release floor')
    require(plan['selectionRule'] == 'EXACTLY_ONE_EXPLICIT_ACCEPTED_SELECTOR_PER_ACTIVE_EXCLUSIVE_GROUP', 'unchanged exclusive selection')
    require(plan['policies'] == POLICY, 'closed non-billable extension boundaries')
    repos = {r['id']: r['name'] for r in repositories['repositories']}
    harnesses = {r['id']: r for r in taxonomy['harnesses']}
    require(len(repos) == 13 and len(harnesses) == 16, '13 repositories and16 harnesses')
    mapping = plan['repositoryMap']
    require(type(mapping) is list and len(mapping) == 13 and len({r['repositoryId'] for r in mapping}) == 13, 'unique repository mapping')
    for index, row in enumerate(mapping):
        require(set(row) == {'label', 'repositoryId', 'name', 'harnessIds'} and row['label'] == f'R{index:02d}' and repos.get(row['repositoryId']) == row['name'], 'canonical repository identity')
        require(row['harnessIds'] == [h['id'] for h in taxonomy['harnesses'] if h['ownerRepository'] == row['repositoryId']], 'exact single harness ownership')
    coverage = plan['harnessCoverage']
    require(type(coverage) is list and len(coverage) == 16 and {r['harnessId'] for r in coverage} == set(harnesses), 'complete unique harness coverage')
    records = {r['id']: r for r in catalog['modules']}
    for row in coverage:
        h = harnesses[row['harnessId']]
        require(set(row) == {'harnessId', 'ownerRepository', 'phase', 'minimumQualifiedBaselines', 'expansionTarget', 'catalogCandidateIds', 'qualificationStatus', 'evidenceRefs'} and row['ownerRepository'] == h['ownerRepository'], 'coverage owner and fields')
        require(type(row['minimumQualifiedBaselines']) is int and row['minimumQualifiedBaselines'] == 1 and row['phase'] == 'ALPHA_4_RELEASE_GATE' and row['expansionTarget'] == [3, 4], 'coverage phased floor')
        require(row['qualificationStatus'] == 'NOT_CLAIMED' and row['evidenceRefs'] == [], 'catalog is not qualification')
        require(row['catalogCandidateIds'] == sorted(k for k,v in records.items() if v['harness'] == row['harnessId']), 'exact catalog relationship projection')
    rows = plan['relationships']
    expected = {k for k,v in records.items() if v['harness'] in harnesses}
    require(len(rows) == len(expected) and {r['catalogId'] for r in rows} == expected, 'complete unique provider/module relationships')
    for row in rows:
        require(set(row) == {'catalogId','harnessId','ownerRepository','originatingPacket','technologyOptions','capabilityScope','integrationModes','version','environment','qualificationStatus','supportOwner','countsTowardQualifiedOptions','remainingWork'}, 'closed relationship fields')
        c = records[row['catalogId']]
        owner = catalog['implementationOwnership'][row['catalogId']]
        require(row['harnessId'] == c['harness'] and row['ownerRepository'] == harnesses[c['harness']]['ownerRepository'] and row['originatingPacket'] == owner.get('packetId'), 'catalog/packet owner parity')
        require(row['technologyOptions'] == c['providers'] and row['capabilityScope'] == 'CATALOG_RECORD_ONLY_NOT_PER_CAPABILITY_QUALIFICATION', 'technology projection not invented capability proof')
        mode = 'BUILT_IN_EXTERNAL' if c['scope'] == 'EXTERNAL' else 'BUILT_IN_MANAGED'
        require(row['integrationModes'] == ([mode] if owner['disposition'] != 'CONTRACT_ONLY' else []), 'contract-only not installable')
        require(row['version'] is None and row['environment'] is None and row['qualificationStatus'] == 'NOT_CLAIMED' and row['countsTowardQualifiedOptions'] is False, 'no fabricated pins or qualification')
        require(row['supportOwner'] == harnesses[c['harness']]['ownerRepository'] and row['remainingWork'] == 'PIN_VERSION_ENVIRONMENT_AND_PER_CAPABILITY_EVIDENCE_BEFORE_RELEASE', 'explicit remaining qualification')
    backlog = plan['extensionBacklog']
    require(type(backlog) is list and len(backlog) == len(EXTENSIONS) and {x['id'] for x in backlog} == set(EXTENSIONS), 'exact extension backlog')
    by_id = {x['id']: x for x in backlog}
    for row in backlog:
        require(set(row) == {'id','repositoryId','phase','status','dispatchable','predecessors','requiredInterfaces','acceptance','publicationGate'}, 'closed extension specification')
        owner, predecessors = EXTENSIONS[row['id']]
        require(row['repositoryId'] == owner and row['predecessors'] == predecessors and row['phase'] == 'ALPHA_2', 'exact owner and dependency order')
        require(row['status'] == 'WAITING_PACKET_PUBLICATION' and row['dispatchable'] is False, 'not an executable packet')
        require(row['publicationGate'] == ['EXACT_ALLOWED_PATHS','ACCEPTED_PREDECESSOR_RELEASE_DIGESTS','DECLARED_OFFLINE_ARGV','REQUIRED_SELF_HOSTED_CI','ONE_PACKET_BRANCH_PR'], 'closed publication gate')
        require(row['requiredInterfaces'] and row['acceptance'] and all(type(v) is str and v for v in row['requiredInterfaces'] + row['acceptance']), 'implementation obligations required')
    def visit(key, stack):
        require(key not in stack, 'cyclic extension backlog')
        for predecessor in by_id[key]['predecessors']:
            if predecessor in by_id:
                visit(predecessor, stack | {key})
            else:
                require(predecessor == 'MET-ADOPT-001', 'unknown extension predecessor')
    for key in by_id:
        visit(key, set())
    require(plan['expansionBacklog'] == EXPANSION, 'closed phased adoption decisions')
    require(plan['currentCheckpoint'] == CHECKPOINT, 'source-only incomplete checkpoint')


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record, {p: regular_bytes(root, p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact history routing')
        require(not validate_additions(packets), 'new packet binding')
        pins = {**record['protectedFiles'], **record['inputFiles'], **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(set(inputs) == set(pins), 'exact fresh input inventory')
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(diagnostic_history(path, inputs[path])) == checksum, 'changed current source: ' + path)
        old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old) == 155 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {'MET-PERF-006', 'CONF-DIAG-001', 'MET-PERF-007', 'MET-PERF-008', 'CONF-DIAG-002', 'MET-ACCEPT-001', 'MET-PUBLISH-001', 'MET-REPAIR-017', 'CONF-FIX-007', 'MET-ADOPT-002', 'MET-PERF-010', 'MET-PERF-009', 'CONF-DIAG-003', 'MET-PERF-011', 'MET-PERF-012', 'CONF-PERF-006', 'CONF-BENCH-002', 'MET-PERF-013', 'CONF-BENCH-003', 'MET-REPAIR-018', 'CONF-FIX-008', 'MET-PERF-014', 'CONF-DIAG-004', 'MET-PERF-015', 'CONF-FIX-009', 'MET-PERF-016', 'MET-PERF-017', 'MET-REPAIR-019', 'MET-ENFORCE-001', 'MET-PERF-018', 'MET-ENFORCE-003', 'CONF-FIX-010', 'MET-UNIFY-005', 'MET-RUNNER-001', 'MET-PERF-028', 'MET-LINUX-005', 'MET-VERIFY-001', 'MET-PERF-029'}, 'exact158 catalog with155 immutable predecessors')
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'raw semantic packet binding')
        packet = packets['MET-ADOPT-001']
        require(packet['allowedPaths'] == record['ownedPaths'] and packet['sourceReuse'] == [] and packet['predecessors'] == ['MET-REPAIR-016'], 'meta-only scope')
        commands = packet['offlineAcceptanceCommands']
        require(len(commands) == 29 and commands[:-3] == packets['MET-REPAIR-016']['offlineAcceptanceCommands'][:-2] and commands[-2:] == packets['MET-REPAIR-016']['offlineAcceptanceCommands'][-2:] and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_provider_adoption.py'], 'all28 prior commands plus new validator')
        for path, rule in record['metaRecipes'].items():
            before = historical_bytes(path, inputs[path])
            require(apply_recipe(before, rule) == diagnostic_history(path, inputs[path]), 'exact reversible amendment')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'all historical test identities preserved')
        plan = parse(inputs[PLAN_PATH])
        validate_plan(plan, safe_load(inputs['architecture/taxonomy.yaml']), safe_load(inputs['architecture/repositories.yaml']), safe_load(inputs['architecture/providers.yaml']))
        guide = inputs[GUIDE_PATH].decode()
        require(plan['releaseRequirement'] in guide and all(x['name'] in guide for x in plan['repositoryMap']) and all(x in guide for x in EXTENSIONS), 'complete readable plan')
        for path in record['navigationPaths']:
            require(b'PROVIDER_ADOPTION_ROADMAP.md' in inputs[path] and b'MET-ADOPT-001' in inputs[path], 'missing current navigation: '+path)
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError) as exc:
        return ['invalid provider adoption authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem: safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets, *load_inputs(ROOT))
    if errors:
        print('\n'.join(errors))
        raise SystemExit(1)
    print('Provider adoption authority valid:194 packets;155 immutable predecessors;16 harnesses/13 repositories; planning only, no product qualification.')
