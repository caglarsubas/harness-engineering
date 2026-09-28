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
    from validate_enforcement_integration import historical_bytes as integration_history, current_test_bytes as integration_current, historical_catalog as integration_catalog
except ImportError:
    from scripts.validate_enforcement_integration import historical_bytes as integration_history, current_test_bytes as integration_current, historical_catalog as integration_catalog

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = 'architecture/observation-enforcement-authority.json'
RECORD_SHA256 = 'fcfb83eaa9f799dca50160567559df08aba13725341d1fb3acbd022f49753573'
NEW_IDS = ('MET-REPAIR-019',)
RECORD_FILE_SHA256 = 'dc1a3745a2bc16dbf3f82753c12f25e3aeebc43c6bd4f85ca67d4f79449bda92'
HISTORY_PATHS = frozenset(['README.md', 'docs/DEVELOPMENT_STATUS.md', 'docs/MASTER_DEVELOPMENT_PLAN.md', 'docs/READINESS_INDEX.md', 'docs/alpha-2/ACCOUNTING_SCOPE_AMENDMENT.md', 'docs/alpha-2/BENCHMARK_TRANSPORT.md', 'docs/alpha-2/CANONICAL_REPAIR_PLAN.md', 'docs/alpha-2/COMPLETION_INTEGRATION.md', 'docs/alpha-2/CONFORMANCE_COMPLETION.md', 'docs/alpha-2/DOCUMENT_REPAIR_AUTHORITY.md', 'docs/alpha-2/DOCUMENT_REPAIR_PLAN.md', 'docs/alpha-2/FACTORY_DIAGNOSTICS.md', 'docs/alpha-2/GUARD_COST_REPAIR.md', 'docs/alpha-2/GUARD_TRAVERSAL_REPAIR.md', 'docs/alpha-2/LIVE_BACKEND_READINESS.md', 'docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md', 'docs/repositories/00-harness-engineering.md', 'docs/repositories/12-mas-harness-conformance-labs.md', 'scripts/validate_backend_timing.py', 'scripts/validate_benchmark_transport.py', 'scripts/validate_broker_handoff.py', 'scripts/validate_canonical_repair_plan.py', 'scripts/validate_ci_performance.py', 'scripts/validate_completion_profiling.py', 'scripts/validate_conformance_completion.py', 'scripts/validate_conformance_consumer_closure.py', 'scripts/validate_conformance_performance.py', 'scripts/validate_conformance_performance_followup.py', 'scripts/validate_conformance_publication.py', 'scripts/validate_conformance_reference_measurement.py', 'scripts/validate_conformance_successor_checkpoint.py', 'scripts/validate_credential_lifecycle.py', 'scripts/validate_credential_ordering.py', 'scripts/validate_custody_handoff.py', 'scripts/validate_document_repair_execution.py', 'scripts/validate_guard_traversal.py', 'scripts/validate_linux_readiness.py', 'scripts/validate_linux_repair.py', 'scripts/validate_linux_test_ownership.py', 'scripts/validate_live_backend_readiness.py', 'scripts/validate_local_acceptance.py', 'scripts/validate_model_api_inventory.py', 'scripts/validate_model_fixture_scope.py', 'scripts/validate_native_qualification.py', 'scripts/validate_packet_scalar_repair.py', 'scripts/validate_policy_observation.py', 'scripts/validate_provider_adoption.py', 'scripts/validate_proxy_contract.py', 'scripts/validate_proxy_diagnostics.py', 'scripts/validate_readiness.py', 'scripts/validate_readiness_repairs.py', 'scripts/validate_research_adoption.py', 'scripts/validate_reuse.py', 'scripts/validate_successor_inventory.py', 'scripts/validate_validation_performance.py', 'task-packets/README.md', 'tests/test_accounting_scope.py', 'tests/test_alpha2_readiness.py', 'tests/test_backend_timing.py', 'tests/test_benchmark_transport.py', 'tests/test_broker_handoff.py', 'tests/test_canonical_repair_plan.py', 'tests/test_ci_performance.py', 'tests/test_completion_integration.py', 'tests/test_completion_profiling.py', 'tests/test_conformance_completion.py', 'tests/test_conformance_consumer_closure.py', 'tests/test_conformance_performance.py', 'tests/test_conformance_performance_followup.py', 'tests/test_conformance_publication.py', 'tests/test_conformance_reference_measurement.py', 'tests/test_conformance_successor_checkpoint.py', 'tests/test_credential_lifecycle.py', 'tests/test_credential_ordering.py', 'tests/test_custody_handoff.py', 'tests/test_document_repair_execution.py', 'tests/test_document_repair_plan.py', 'tests/test_factory_diagnostics.py', 'tests/test_guard_cost_repair.py', 'tests/test_guard_traversal.py', 'tests/test_linux_readiness.py', 'tests/test_linux_repair.py', 'tests/test_linux_test_ownership.py', 'tests/test_live_backend_readiness.py', 'tests/test_local_acceptance.py', 'tests/test_model_api_inventory.py', 'tests/test_model_fixture_scope.py', 'tests/test_native_qualification.py', 'tests/test_packet_scalar_repair.py', 'tests/test_policy_observation.py', 'tests/test_provider_adoption.py', 'tests/test_proxy_contract.py', 'tests/test_proxy_diagnostics.py', 'tests/test_research_adoption.py', 'tests/test_reuse.py', 'tests/test_successor_inventory.py', 'tests/test_task_packets.py', 'tests/test_validation_performance.py'])


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
    raw = integration_history(path, raw)
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
        return integration_current(before)
    require(len(matches) == 1, "unique predecessor")
    return integration_current(apply_recipe(before, matches[0]))


def _validate_local_additions(packets, record):
    """Private digest check only; public entry points own successor validation."""
    pinned(record)
    require(type(packets) is dict, "packet mapping")
    for name in NEW_IDS:
        require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
    return []


def validate_additions(packets):
    try:
        packets = integration_catalog(packets)
        return _validate_local_additions(packets, _record())
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


SPEC_PATH = 'architecture/observation-enforcement-plan.json'
SPEC_SHA256 = 'b283e545436c3825b0cb5f195b982217395d47b7a770e33d3aa1a95dbe33ace9'
MEMBER_DIGESTS = {'schemaVersion': '0838266211a758e0ae2db4404616b7931812296cb33bd616af1ac15b1b9e1e8c', 'packetId': 'a49bbdacc86da54de8ba63789474f42496edbc1aab139b046eb01b7388a499ea', 'metaBase': '58ec4d871b7d21306f5f5f14c6ca4bedddaa52ea5990e355de5f55361d876e03', 'status': 'f933e24a5f0fe0d4772d6720f6f0597111ac2fcd5b823c0d4260743ab0b8bee0', 'reviewProvenance': 'fc9f5e195447a12c263fca300e2bc0ec4e7ff73993822dee1c5e47303c5e7db1', 'sourceStates': '87caa6dfded677fd050a0610b4d2ed68c7bf55e9be1d20fb4c9c8d72bbc364cf', 'budgets': 'abde74ea04c216c12e972eb60444081896608f44d0d0103fcded0f3c329e3e16', 'limits': '55c877ff2cfdeb3570006b31f6a0bc121923356c6912855cccf6b8e7fa5cce47', 'oldAttemptsReset': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'productPacketAdded': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'productExecution': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'runtimeAdoptionAuthorized': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'nativeAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'tenantAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'phaseComplete': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'modelEffortTransition': '1a52549010eb8759f3859b045dc178992c125c9ae322fad189484fd023aa4020', 'harnesses': 'b17ef6d19c7a5b1ee83b907c595526dcb1eb06db8227d650d5dda0a9f4ce8cd9', 'planes': '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a', 'repositories': '3fdba35f04dc8c462986c992bcf875546257113072a909c162f7e470e581e278', 'testAccounting': '6d50fcc1413dbd43026da0c95571cc331be22361278144d86be863f4afe73c81'}
MATRIX = 'architecture/observation-enforcement-inputs/enforcement-matrix.json'
DELTAS = 'architecture/observation-enforcement-inputs/observation-deltas.json'
REVIEW = 'architecture/observation-enforcement-inputs/design-review.json'
E_IDS = tuple('E%02d' % n for n in range(1, 13))
D_IDS = tuple('D%02d' % n for n in range(1, 9))
W_IDS = tuple('W%02d' % n for n in range(1, 9))


def historical_catalog(packets):
    record = _record(); pinned(record)
    try:
        packets = integration_catalog(packets)
        errors = _validate_local_additions(packets, _record())
    except (ValueError, TypeError, RecursionError):
        errors = ["missing or changed performance packets"]
    require(errors == [], 'exact new META packet')
    old = {Path(p).stem for p in record['protectedFiles']
           if p.startswith('task-packets/') and p.endswith('.yaml')}
    require(len(old) == 184 and set(packets) == old | set(NEW_IDS), 'closed 185-packet catalog')
    return {name: packets[name] for name in old}


def validate_spec(value, *, bind=True):
    require(type(value) is dict and set(value) == set(MEMBER_DIGESTS), 'closed observation plan')
    if bind:
        require(digest(canonical(value)) == SPEC_SHA256, 'exact observation plan')
    for name, checksum in MEMBER_DIGESTS.items():
        require(digest(canonical(value[name])) == checksum, 'changed plan member: ' + name)
    require(all(value[k] is False for k in ('productExecution', 'runtimeAdoptionAuthorized',
            'nativeAcceptance', 'tenantAcceptance', 'phaseComplete')), 'no authority promotion')


def validate_matrix(value, owner_ids):
    require(type(value) is dict and set(value) == {'schemaVersion', 'rows', 'selectedEnforcer',
            'nativeQualified', 'runtimeAdoptionAuthorized'}, 'closed enforcement matrix')
    require(value['schemaVersion'] == 'planeon.internal.observation-enforcement-matrix/v1'
            and value['selectedEnforcer'] is None and value['nativeQualified'] is False
            and value['runtimeAdoptionAuthorized'] is False, 'unselected unqualified enforcement')
    require(type(value['rows']) is list and len(value['rows']) == 12, 'twelve enforcement rows')
    keys = {'id', 'state', 'actorAndBypassRoutes', 'mediatorAndRetainedObservations',
            'invalidationEvidenceAndCleanup', 'ownerIds', 'externalMaintainerSelected', 'proofEvidence'}
    for expected, row in zip(E_IDS, value['rows']):
        require(type(row) is dict and set(row) == keys and row['id'] == expected,
                'unique ordered closed enforcement row')
        require(row['state'] == 'OPEN_UNPROVEN' and row['externalMaintainerSelected'] is None
                and type(row['proofEvidence']) is list and not row['proofEvidence'], 'no assumed proof')
        require(all(type(row[k]) is str and 0 < len(row[k]) <= 4096 for k in
                ('actorAndBypassRoutes', 'mediatorAndRetainedObservations', 'invalidationEvidenceAndCleanup')),
                'bounded nonempty obligation')
        owners = row['ownerIds']
        require(type(owners) is list and owners and all(type(x) is str for x in owners)
                and len(owners) == len(set(owners)) and set(owners) <= owner_ids
                and owners == (['conformance-labs'] if expected in ('E02', 'E09')
                               else ['operator', 'conformance-labs']), 'accountable existing owners')


def validate_deltas(value):
    require(type(value) is dict and set(value) == {'schemaVersion', 'deltas', 'windows',
            'exhaustive', 'approvedForRuntime', 'indirectRemovalsIncluded',
            'autonomousEventTimingRequired', 'preservedLeafTests'}, 'closed delta register')
    require(value['schemaVersion'] == 'planeon.internal.observation-deltas/v1'
            and value['exhaustive'] is False and value['approvedForRuntime'] is False
            and value['indirectRemovalsIncluded'] is True and value['autonomousEventTimingRequired'] is True
            and type(value['preservedLeafTests']) is int and value['preservedLeafTests'] == 14,
            'no schedule-equivalence claim')
    for field, ids, keys in (('deltas', D_IDS, {'id', 'existingBoundary', 'proposedTreatment', 'lostWindowProof'}),
                             ('windows', W_IDS, {'id', 'oldDetectionOpportunity', 'requiredClosure'})):
        require(type(value[field]) is list and len(value[field]) == len(ids), 'complete delta rows')
        for expected, row in zip(ids, value[field]):
            require(type(row) is dict and set(row) == keys and row['id'] == expected
                    and all(type(x) is str and 0 < len(x) <= 8192 for x in row.values()),
                    'ordered bounded unique delta row')
    d03 = value['deltas'][2]['lostWindowProof']
    require(all(x in d03 for x in ('E01', 'E02', 'E07', 'nested', 'cadence')), 'indirect guards not erased')


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH)); pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record, {p: regular_bytes(root, p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record); old = historical_catalog(packets)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'closed history routing')
        pins = {**record['protectedFiles'], **record['inputFiles'],
                **{p: r['afterSha256'] for p, r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'complete fresh current inputs')
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(integration_history(path, inputs[path])) == checksum, 'current source drift: ' + path)
        packets = integration_catalog(packets)
        for name in packets:
            require(canonical(packets[name]) == canonical(safe_load(integration_history('task-packets/' + name + '.yaml', inputs['task-packets/' + name + '.yaml']))),
                    'packet bytes and parsed data agree')
        value = parse(inputs[SPEC_PATH]); validate_spec(value)
        meta, prior = packets['MET-REPAIR-019'], old['MET-PERF-017']
        require(meta['repository'] == 'Harness-Engineering' and meta['predecessors'] == ['MET-PERF-017']
                and meta['allowedPaths'] == record['ownedPaths'], 'exact source-only owner')
        commands = meta['offlineAcceptanceCommands']
        require(len(commands) == 47 and commands[:-3] + commands[-2:] == prior['offlineAcceptanceCommands']
                and commands[-3] == ['uv', 'run', '--offline', '--frozen', '--no-sync', 'python',
                                     'scripts/validate_observation_enforcement.py'], 'all46 inherited commands')
        require(meta['sourceReuse'] == meta['prefetchCommands'] == [] and 'liveCampaignExecution' not in meta
                and meta['warmSourceAccess'] == 'PROHIBITED_DURING_IMPLEMENTATION'
                and meta['offlineExecution'] == prior['offlineExecution'], 'unchanged isolated offline recipe')
        registry = safe_load(inputs['architecture/repositories.yaml'])
        owner_ids = {r['id'] for r in registry['repositories']}
        require(len(owner_ids) == 13, 'thirteen existing repositories')
        validate_matrix(parse(inputs[MATRIX]), owner_ids)
        validate_deltas(parse(inputs[DELTAS]))
        review = parse(inputs[REVIEW])
        require(review == value['reviewProvenance'] and review['verdict'] == 'APPROVABLE_AS_DESIGN_DIRECTION_ONLY'
                and review['repositoryRenderingIndependentlyReviewed'] is False, 'review is not runtime proof')
        require(value['budgets'] == dict(LOCAL=2, CI=2, LOCAL_EXACT_MAIN=1, product=0, diagnostics=0, benchmarks=0)
                and value['oldAttemptsReset'] is False and value['productPacketAdded'] is False,
                'finite distinct META allowance')
        require(value['sourceStates']['CONF-FIX-009'] == 'BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED'
                and value['sourceStates']['CONF-FIX-010'] == 'BLOCKED_SAFE_DESIGN', 'stopped product remains stopped')
        for path, rule in record['metaRecipes'].items():
            before = historical_bytes(path, inputs[path])
            require(apply_recipe(before, rule) == integration_history(path, inputs[path]), 'exact reversible current-first history')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'inherited test identities')
        for path in record['navigationPaths']:
            require(all(s in inputs[path] for s in (b'OBSERVATION_ENFORCEMENT_PUBLICATION.md', b'MET-REPAIR-019',
                    b'BLOCKED_SAFE_DESIGN', b'HARNESS_PAPER_REPOSITORY_MAP.md', b'NOT_DUE')), 'truthful roadmap navigation')
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError) as exc:
        return ['invalid observation/enforcement publication: ' + str(exc)]


if __name__ == '__main__':
    packets = {p.stem: safe_load(p.read_bytes()) for p in (ROOT / 'task-packets').glob('*.yaml')}
    errors = validate_authority(packets, *load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Observation design valid:185 specifications;184 immutable packets;12 unproven obligations; no runtime adoption.')
