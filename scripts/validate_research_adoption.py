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
    from validate_validation_performance import historical_bytes as repair_history, current_test_bytes as repair_current, validate_additions as repair_additions
except ImportError:
    from scripts.validate_validation_performance import historical_bytes as repair_history, current_test_bytes as repair_current, validate_additions as repair_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/research-adoption-authority.json"
RECORD_SHA256 = "483920e5ca7ab37d1ab92997b828d98f8a5543e3ba5438af5ebe81e4cdcad351"
NEW_IDS = ("MET-ADOPT-002",)
RECORD_FILE_SHA256 = "37fd33e216e5ec7513f3af751bf5590399f918d4cfde4eea8c7bbbc4587d752b"
HISTORY_PATHS = frozenset(["README.md","docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/CANONICAL_REPAIR_PLAN.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md","docs/harnesses/execution.ml-decision.md","docs/harnesses/execution.orchestration.md","docs/harnesses/execution.protocol-interoperability.md","docs/harnesses/execution.tool-skill-sandbox.md","docs/harnesses/knowledge.data-integration.md","docs/harnesses/knowledge.domain-semantic.md","docs/harnesses/knowledge.memory-state.md","docs/harnesses/knowledge.retrieval-context.md","docs/harnesses/runtime.ai-gateway.md","docs/harnesses/runtime.experience.md","docs/harnesses/runtime.infrastructure.md","docs/harnesses/runtime.model-inference.md","docs/harnesses/trust.evaluation-assurance.md","docs/harnesses/trust.governance-agentops.md","docs/harnesses/trust.observability-finops.md","docs/harnesses/trust.security-safety.md","docs/repositories/00-harness-engineering.md","docs/repositories/01-mas-harness-contracts.md","docs/repositories/02-mas-harness-sdks.md","docs/repositories/03-mas-harness-industry-packs.md","docs/repositories/04-mas-harness-control-plane.md","docs/repositories/05-mas-harness-runtime-plane.md","docs/repositories/06-mas-harness-model-plane.md","docs/repositories/07-mas-harness-knowledge-plane.md","docs/repositories/08-mas-harness-execution-plane.md","docs/repositories/09-mas-harness-trust-plane.md","docs/repositories/10-mas-harness-operator.md","docs/repositories/11-mas-harness-distribution.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_backend_timing.py","scripts/validate_broker_handoff.py","scripts/validate_canonical_repair_plan.py","scripts/validate_ci_performance.py","scripts/validate_conformance_completion.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_publication.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_local_acceptance.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_provider_adoption.py","scripts/validate_proxy_contract.py","scripts/validate_proxy_diagnostics.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_backend_timing.py","tests/test_broker_handoff.py","tests/test_canonical_repair_plan.py","tests/test_ci_performance.py","tests/test_conformance_completion.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_publication.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_local_acceptance.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_provider_adoption.py","tests/test_proxy_contract.py","tests/test_proxy_diagnostics.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


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
    raw = repair_history(path, raw)
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
        return repair_current(before)
    require(len(matches) == 1, "unique predecessor")
    return repair_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return repair_additions(packets)
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


SPEC_PATH = "architecture/research-adoption.json"
EXPECTED_SPEC_SHA256 = "4eda342af1d9e3d93c0106a76360d705fa9c2dd60740aea7518b396ba9e4ef5e"


EXPECTED_KEYS = {'schemaVersion','metaPacketId','metaBase','evidenceClass','checkedAt',
                 'releaseRequirement','minimumQualifiedBaselines','ownershipAuthority',
                 'repositoryAuthority','historicalProviderLedger','policies','sources',
                 'papers','upstreams','mappings','commonGates','workflow','adoptionDelivery',
                 'migration','researchCaveats','preservedGate'}
TRUE_POLICIES = {'reuseFirst','newGeneralPurposeEngineRequiresSeparateADR',
                 'internalModuleAloneDoesNotSatisfyOSSAdoption','capabilityScopedQualification',
                 'multipleQualifiedOptionsAllowed','exclusiveSelectionRequiresExplicitAcceptance',
                 'linuxProduction','macOSDevelopmentOnly','controlIsNotSeventeenthHarness'}
FALSE_POLICIES = {'publicContractChangesThisPacket','providerCatalogActivationThisPacket',
                  'productExecutionThisPacket','warmSourceAccess','copyAuthorization',
                  'hostedRunner','paidAPI','cloudProvisioning','runtimeDownloads',
                  'defaultExternalTelemetry','licenseChecksOnline',
                  'externalServiceLifecycleMutation','customAdapterCoreInjection',
                  'mandatorySuiteFiltering'}
RELEASE_REQUIREMENT = 'Require **at least one qualified baseline for every released harness capability** at the first enterprise release.'


def nonempty(value):
    return type(value) is str and bool(value.strip())


def unique_rows(rows, key):
    require(type(rows) is list and rows, 'nonempty rows')
    require(all(type(row) is dict and nonempty(row.get(key)) for row in rows), 'row identities')
    result = {row[key]:row for row in rows}
    require(len(result) == len(rows), 'duplicate '+key)
    return result


def validate_plan(plan, taxonomy, prior, packet_ids, *, bind=True):
    """Planning integrity only: never returns qualification or execution authority."""
    require(type(plan) is dict and set(plan) == EXPECTED_KEYS, 'closed research plan')
    if bind:
        require(digest(canonical(plan)) == EXPECTED_SPEC_SHA256, 'exact research plan')
    require(plan['schemaVersion'] == 'planeon.internal.research-adoption/v1'
            and plan['metaPacketId'] == 'MET-ADOPT-002'
            and plan['metaBase'] == 'a92b78f9bca51bed4836f5100e58caebadf4b3fb'
            and plan['evidenceClass'] == 'META_PLANNING_ONLY', 'planning boundary')
    require(plan['releaseRequirement'] == RELEASE_REQUIREMENT
            and type(plan['minimumQualifiedBaselines']) is int
            and plan['minimumQualifiedBaselines'] == 1, 'at least one per released capability')
    require(plan['ownershipAuthority'] == 'architecture/taxonomy.yaml'
            and plan['repositoryAuthority'] == 'architecture/repositories.yaml'
            and plan['historicalProviderLedger'] == 'architecture/provider-adoption.json', 'unchanged authorities')
    require(type(plan['policies']) is dict and set(plan['policies']) == TRUE_POLICIES | FALSE_POLICIES,
            'closed policy boundary')
    require(all(plan['policies'][key] is True for key in TRUE_POLICIES)
            and all(plan['policies'][key] is False for key in FALSE_POLICIES), 'unsafe policy drift')
    sources = unique_rows(plan['sources'],'id')
    require(set(sources) == {'A','B','C'}, 'three user research inputs')
    for row in sources.values():
        require(nonempty(row['name']) and '/' not in row['name']
                and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None
                and row['role'] == 'USER_RESEARCH_INPUT_NOT_EXECUTION_AUTHORITY', 'research not authority')
    papers = unique_rows(plan['papers'],'id')
    require(len(papers) == 18, 'curated paper inventory')
    for pid,row in papers.items():
        require(re.fullmatch(r'[0-9]{4}\.[0-9]{4,5}',pid) is not None
                and row['url'] == 'https://arxiv.org/abs/'+pid and nonempty(row['title']), 'primary paper URL')
        require(type(row['firstPublicationYear']) is int
                and row['firstPublicationYear'] == 2000+int(pid[:2]), 'first publication not revision year')
        require(type(row['sourceInputs']) is list and row['sourceInputs']
                and set(row['sourceInputs']) <= {'A','B','C','SUPPLEMENT'}, 'research attribution')
        require(row['verification'] == 'PRIMARY_ABSTRACT_REVIEWED'
                and row['fullTextImplementationLinkVerified'] is False, 'no invented implementation link')
    upstreams = unique_rows(plan['upstreams'],'repository')
    require(len(upstreams) == 32, 'metadata snapshot inventory')
    for name,row in upstreams.items():
        require(re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',name) is not None
                and row['url'] == 'https://github.com/'+name
                and row['sourceUrl'] == 'https://api.github.com/repos/'+name, 'primary upstream source')
        require(row['evidenceClass'] == 'GITHUB_METADATA_NOT_ARTIFACT_QUALIFICATION'
                and row['licenseReview'] == 'PINNED_ARTIFACT_REVIEW_REQUIRED'
                and row['qualificationStatus'] == 'NOT_CLAIMED'
                and row['releaseVersion'] is None and row['artifactDigest'] is None, 'metadata not qualification')
    owners = {r['id']:r['ownerRepository'] for r in taxonomy['harnesses']}
    rows = unique_rows(plan['mappings'],'harnessId')
    require(len(owners) == len(rows) == 16 and set(rows) == set(owners), 'all16 canonical harnesses')
    require([r['harnessId'] for r in plan['mappings']] == [r['id'] for r in taxonomy['harnesses']]
            and [r['number'] for r in plan['mappings']] == list(range(1,17)), 'canonical onion numbering')
    repository_ids = {r['repositoryId'] for r in prior['repositoryMap']}
    require(len(repository_ids) == 13, '13 repositories')
    coverage = {r['harnessId']:r for r in prior['harnessCoverage']}
    extension_ids = {r['id'] for r in prior['extensionBacklog']}
    proposed = [r['proposedPacketId'] for r in rows.values()]
    require(len(set(proposed)) == 16 and not set(proposed) & set(packet_ids), 'proposed not executable packets')
    gate_ids = [g['id'] for g in plan['commonGates']]
    require(gate_ids == ['G'+str(i) for i in range(1,9)]
            and all(nonempty(g['description']) for g in plan['commonGates']), 'all adoption gates')
    edges = {r['id']:r['predecessors'] for r in prior['extensionBacklog']}
    for hid,row in rows.items():
        require(row['ownerRepository'] == owners[hid] == coverage[hid]['ownerRepository']
                and row['supportOwner'] == owners[hid] and owners[hid] in repository_ids, 'unique accountable owner')
        require(row['adoptionStatus'] == 'PLANNED_BASELINE_TARGET'
                and row['qualificationStatus'] == 'NOT_CLAIMED'
                and row['installable'] is False and row['packetPublished'] is False
                and row['countsTowardQualifiedOptions'] is False
                and row['releaseVersion'] is row['artifactDigest'] is None
                and row['qualificationEvidence'] == [], 'no false implementation or qualification')
        require(type(row['preferredUpstreams']) is list and row['preferredUpstreams']
                and len(set(row['preferredUpstreams'])) == len(row['preferredUpstreams'])
                and set(row['preferredUpstreams']) <= set(upstreams), 'actual OSS implementation required')
        require(row['catalogCandidateIds'] == coverage[hid]['catalogCandidateIds'], 'historical catalog retained')
        require(row['phase'] in {'ALPHA_2','ALPHA_3'}
                and row['acceptanceGateIds'] == gate_ids
                and row['technologyRolesAreNotExclusiveOptions'] is True, 'scoped phased acceptance')
        for key in ('reuseResponsibility','platformResponsibility','acceptance'):
            require(nonempty(row[key]), 'separate build reuse and acceptance')
        require(type(row['relatedExistingPackets']) is list and row['relatedExistingPackets']
                and set(row['relatedExistingPackets']) <= set(packet_ids), 'existing packet traceability')
        require(type(row['researchLinks']) is list and row['researchLinks'], 'paper traceability')
        for link in row['researchLinks']:
            require(link['paperId'] in papers and link['basis'] == papers[link['paperId']]['url']
                    and nonempty(link['scope']), 'paper source and relationship rationale')
            require(type(link['upstreams']) is list and link['upstreams']
                    and set(link['upstreams']) <= set(row['preferredUpstreams']), 'mapped upstream owner scope')
            if link['relationship'] == 'EVALUATED_COMPONENT':
                require(link['paperId'] == '2608.20481' and link['upstreams'] == ['open-policy-agent/opa'],
                        'only explicitly supported component relationship')
            else:
                require(link['relationship'] == 'CONCEPTUAL_ALIGNMENT', 'no invented official code link')
        require(type(row['predecessors']) is list and 'MET-ADOPT-002' in row['predecessors']
                and 'CON-EXT-001' in row['predecessors']
                and set(row['predecessors']) <= set(packet_ids) | extension_ids | set(proposed), 'contract-first dependencies')
        require(set(row['publicationRequirements']) == {'EXACT_ALLOWED_PATHS','ACCEPTED_PREDECESSOR_RELEASE_DIGESTS',
                'PINNED_OSS_COMPONENT_LICENSE_AND_OFFLINE_CLOSURE','PUBLIC_CONTRACT_COMPATIBILITY_VECTORS',
                'DECLARED_ISOLATED_OFFLINE_ARGV','REQUIRED_SELF_HOSTED_CI','MIGRATION_AND_ROLLBACK_PLAN'}, 'publication gates')
        edges[row['proposedPacketId']] = row['predecessors']
    def visit(key, stack, done):
        require(key not in stack, 'proposed dependency cycle')
        if key in done or key not in edges:
            return
        for parent in edges[key]:
            visit(parent,stack | {key},done)
        done.add(key)
    done = set()
    for key in edges:
        visit(key,set(),done)
    delivery = plan['adoptionDelivery']
    require(delivery['futurePacketsDispatchable'] is False
            and delivery['stateSequenceIsNotAutomaticPromotion'] is True
            and delivery['futureHarnessPacketIds'] == proposed
            and set(delivery['extensionPacketIds']) == extension_ids, 'future backlog not authority')
    require(plan['migration']['keepExistingSourceAndEvidence'] is True
            and all(plan['migration'][k] is False for k in ('rewriteOldPacketYAML','changeRuntimeSelectors','changeSourceReusePolicy')),
            'no destructive migration or authority drift')
    gate = plan['preservedGate']
    require(gate == {'specification':'architecture/conformance-completion.json','packet':'CONF-FIX-007',
                    'status':'PAUSED_RESEARCH_AMENDMENT','nativeSuccessor':'CONF-LIVE-004',
                    'nativeSuccessorStatus':'WAITING_PREDECESSOR_CORRECTION','budgetsReset':False,
                    'productDraftEdited':False,'phaseCompletion':False,'modelEffortTransition':'NOT_DUE'}, 'retained completion gate')
    # All checks are data checks; no imports, installation, authority or network actions.


def load_inputs(root):
    record = parse(regular_bytes(root,RECORD_PATH)); pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record,{p:regular_bytes(root,p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact history routing')
        require(validate_additions(packets) == [], 'new packet bound')
        pins = {**record['protectedFiles'], **record['inputFiles'], **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'exact fresh inputs')
        for path,checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(repair_history(path, inputs[path])) == checksum, 'changed source: '+path)
        old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old) == 165 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {'MET-PERF-010', 'MET-PERF-009', 'CONF-DIAG-003', 'MET-PERF-011', 'MET-PERF-012', 'CONF-PERF-006', 'CONF-BENCH-002', 'MET-PERF-013', 'CONF-BENCH-003', 'MET-REPAIR-018', 'CONF-FIX-008', 'MET-PERF-014', 'CONF-DIAG-004', 'MET-PERF-015', 'CONF-FIX-009', 'MET-PERF-016', 'MET-PERF-017', 'MET-REPAIR-019', 'MET-ENFORCE-001', 'MET-PERF-018', 'MET-ENFORCE-003', 'CONF-FIX-010', 'MET-UNIFY-005', 'MET-RUNNER-001', 'MET-PERF-028', 'MET-LINUX-005', 'MET-VERIFY-001', 'MET-PERF-029'}, '165 immutable plus one META')
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'packet source parity')
        meta = packets['MET-ADOPT-002']
        require(meta['allowedPaths'] == record['ownedPaths'] and meta['predecessors'] == ['MET-REPAIR-017']
                and meta['repository'] == 'Harness-Engineering', 'META-only scope')
        commands,prior_commands = meta['offlineAcceptanceCommands'],packets['MET-REPAIR-017']['offlineAcceptanceCommands']
        require(len(commands) == 36 and commands[:-3] == prior_commands[:-2] and commands[-2:] == prior_commands[-2:]
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_research_adoption.py']
                and meta['offlineExecution'] == packets['MET-REPAIR-017']['offlineExecution'], 'whole35-command predecessor recipe')
        require(meta['sourceReuse'] == [] and meta['prefetchCommands'] == []
                and meta['warmSourceAccess'] == 'PROHIBITED_DURING_IMPLEMENTATION'
                and 'liveCampaignExecution' not in meta, 'no source or live authority')
        plan = parse(inputs[SPEC_PATH])
        validate_plan(plan,safe_load(inputs['architecture/taxonomy.yaml']),parse(inputs['architecture/provider-adoption.json']),set(packets))
        for path,rule in record['metaRecipes'].items():
            before = historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule) == repair_history(path, inputs[path]), 'exact reversible amendment')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'all inherited test identities')
        for path in record['navigationPaths']:
            require(b'HARNESS_PAPER_REPOSITORY_MAP.md' in inputs[path]
                    and b'MET-ADOPT-002' in inputs[path]
                    and b'WAITING_PREDECESSOR_CORRECTION' in inputs[path]
                    and b'NOT_DUE' in inputs[path], 'consistent current navigation')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid research adoption authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Research adoption authority valid:194 specifications;165 unchanged packets;16 harnesses/13 repositories; no provider qualification or product execution.')
