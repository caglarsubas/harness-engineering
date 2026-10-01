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
    from validate_guard_traversal import historical_bytes as traversal_history, current_test_bytes as traversal_current, historical_catalog as traversal_catalog
except ImportError:
    from scripts.validate_guard_traversal import historical_bytes as traversal_history, current_test_bytes as traversal_current, historical_catalog as traversal_catalog

try:
    from validate_ci_runner_admission import historical_bytes as runner_history
except ImportError:
    from scripts.validate_ci_runner_admission import historical_bytes as runner_history

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = 'architecture/accounting-scope-authority.json'
RECORD_SHA256 = '6eed585bb6be867531b88c93c564618242d9d7807aba20cbeac4a9d43e1d4117'
NEW_IDS = ('MET-PERF-016', 'CONF-FIX-009')
RECORD_FILE_SHA256 = 'ad277badb5732a0073c6a93c9b1a71fabe5865c48567524ffc4dfb1af31c96cd'
HISTORY_PATHS = frozenset(['README.md', 'docs/DEVELOPMENT_STATUS.md', 'docs/MASTER_DEVELOPMENT_PLAN.md', 'docs/READINESS_INDEX.md', 'docs/alpha-2/BENCHMARK_TRANSPORT.md', 'docs/alpha-2/CANONICAL_REPAIR_PLAN.md', 'docs/alpha-2/COMPLETION_INTEGRATION.md', 'docs/alpha-2/CONFORMANCE_COMPLETION.md', 'docs/alpha-2/DOCUMENT_REPAIR_AUTHORITY.md', 'docs/alpha-2/DOCUMENT_REPAIR_PLAN.md', 'docs/alpha-2/FACTORY_DIAGNOSTICS.md', 'docs/alpha-2/GUARD_COST_REPAIR.md', 'docs/alpha-2/LIVE_BACKEND_READINESS.md', 'docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md', 'docs/repositories/00-harness-engineering.md', 'docs/repositories/12-mas-harness-conformance-labs.md', 'scripts/validate_backend_timing.py', 'scripts/validate_benchmark_transport.py', 'scripts/validate_broker_handoff.py', 'scripts/validate_canonical_repair_plan.py', 'scripts/validate_ci_performance.py', 'scripts/validate_completion_profiling.py', 'scripts/validate_conformance_completion.py', 'scripts/validate_conformance_consumer_closure.py', 'scripts/validate_conformance_performance.py', 'scripts/validate_conformance_performance_followup.py', 'scripts/validate_conformance_publication.py', 'scripts/validate_conformance_reference_measurement.py', 'scripts/validate_conformance_successor_checkpoint.py', 'scripts/validate_credential_lifecycle.py', 'scripts/validate_credential_ordering.py', 'scripts/validate_custody_handoff.py', 'scripts/validate_document_repair_execution.py', 'scripts/validate_guard_cost_repair.py', 'scripts/validate_linux_readiness.py', 'scripts/validate_linux_repair.py', 'scripts/validate_linux_test_ownership.py', 'scripts/validate_live_backend_readiness.py', 'scripts/validate_local_acceptance.py', 'scripts/validate_model_api_inventory.py', 'scripts/validate_model_fixture_scope.py', 'scripts/validate_native_qualification.py', 'scripts/validate_packet_scalar_repair.py', 'scripts/validate_policy_observation.py', 'scripts/validate_provider_adoption.py', 'scripts/validate_proxy_contract.py', 'scripts/validate_proxy_diagnostics.py', 'scripts/validate_readiness.py', 'scripts/validate_readiness_repairs.py', 'scripts/validate_research_adoption.py', 'scripts/validate_reuse.py', 'scripts/validate_successor_inventory.py', 'scripts/validate_validation_performance.py', 'task-packets/CONF-FIX-009.yaml', 'task-packets/README.md', 'tests/test_alpha2_readiness.py', 'tests/test_backend_timing.py', 'tests/test_benchmark_transport.py', 'tests/test_broker_handoff.py', 'tests/test_canonical_repair_plan.py', 'tests/test_ci_performance.py', 'tests/test_completion_integration.py', 'tests/test_completion_profiling.py', 'tests/test_conformance_completion.py', 'tests/test_conformance_consumer_closure.py', 'tests/test_conformance_performance.py', 'tests/test_conformance_performance_followup.py', 'tests/test_conformance_publication.py', 'tests/test_conformance_reference_measurement.py', 'tests/test_conformance_successor_checkpoint.py', 'tests/test_credential_lifecycle.py', 'tests/test_credential_ordering.py', 'tests/test_custody_handoff.py', 'tests/test_document_repair_execution.py', 'tests/test_document_repair_plan.py', 'tests/test_factory_diagnostics.py', 'tests/test_guard_cost_repair.py', 'tests/test_linux_readiness.py', 'tests/test_linux_repair.py', 'tests/test_linux_test_ownership.py', 'tests/test_live_backend_readiness.py', 'tests/test_local_acceptance.py', 'tests/test_model_api_inventory.py', 'tests/test_model_fixture_scope.py', 'tests/test_native_qualification.py', 'tests/test_packet_scalar_repair.py', 'tests/test_policy_observation.py', 'tests/test_provider_adoption.py', 'tests/test_proxy_contract.py', 'tests/test_proxy_diagnostics.py', 'tests/test_research_adoption.py', 'tests/test_reuse.py', 'tests/test_successor_inventory.py', 'tests/test_task_packets.py', 'tests/test_validation_performance.py'])


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
    raw = traversal_history(path, raw)
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
        return traversal_current(before)
    require(len(matches) == 1, "unique predecessor")
    return traversal_current(apply_recipe(before, matches[0]))


def _validate_local_additions(packets, record):
    """Private digest check only; public entry points own successor validation."""
    pinned(record)
    require(type(packets) is dict, "packet mapping")
    for name in NEW_IDS:
        require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
    return []


def validate_additions(packets):
    try:
        packets = traversal_catalog(packets)
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


SPEC_PATH = 'architecture/accounting-scope-amendment.json'
SPEC_SHA256 = '106543d490bf9a4a8d28dd9947d0897b72f3eddedbc981e1bbd5853b4414d711'
MEMBER_DIGESTS = {'schemaVersion': '81b06c519b2b0cebec942d75ae8127c7623d574c493c54ca5d62b63550e2b274', 'packetId': '11d59fb3dfd9328732b634bbc5becc48792d4efe8a0e59f72acd2def83db737f', 'metaBase': 'fbf99861e8c71fda5e3349ec27c13c974418ad114a0bb705382f5335b97d74cf', 'status': '0da9365f401908507ca93b0b0a3016a6beaadd8af1310b652f540dc34b73a11f', 'subject': '443a34275784fb6ffdd554ecfde60aed28d7deb12af7698e2dc49d9be9d8ff57', 'accountingException': '6a5ca9b0569814dee95d627e4dcec3a908bb20157f3c8805038e7c93f2d87868', 'budgets': 'b05141e71ee989b719e668212e73d59891f5bcd17817dbf367da0a657c41b900', 'limits': '55c877ff2cfdeb3570006b31f6a0bc121923356c6912855cccf6b8e7fa5cce47', 'gates': '91856b614e26f75c60e63a56ee1cda43b41da16466fdfbc1b9196b4d7a5cfb69', 'preservedArtifacts': '4b1343bf181f58af087ef4e0e741e41eb7c3e60bcb8e2439d64a90caf63c2287', 'productExecutionInMetaRun': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'productAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'nativeAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'tenantAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'phaseComplete': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'testAccounting': '45dbb63a2a09ba3bd6a23104f84cf4846b6ad43e51510b6eea7c35896c338cbb'}
SOURCE = 'architecture/accounting-scope-inputs/readiness.json'
PRODUCT_PATH = 'task-packets/CONF-FIX-009.yaml'


def historical_catalog(packets):
    record = _record(); pinned(record)
    try:
        packets = traversal_catalog(packets)
        errors = _validate_local_additions(packets, _record())
    except (ValueError, TypeError, RecursionError):
        errors = ["missing or changed performance packets"]
    require(errors == [], 'exact accounting amendment packets')
    old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
    require(len(old) == 180 and set(packets) == old | set(NEW_IDS), 'closed 182-packet catalog')
    # The amended product packet is current-first validated, then projected as
    # data for the predecessor's historical policy checks. No stored code runs.
    raw = regular_bytes(ROOT, PRODUCT_PATH)
    require(canonical(safe_load(raw)) == canonical(packets['CONF-FIX-009']), 'fresh product packet parity')
    result = {name: packets[name] for name in old}
    result['CONF-FIX-009'] = safe_load(historical_bytes(PRODUCT_PATH, raw))
    return result


def validate_spec(value, *, bind=True):
    require(type(value) is dict and set(value) == set(MEMBER_DIGESTS), 'closed accounting amendment')
    if bind: require(digest(canonical(value)) == SPEC_SHA256, 'exact accounting amendment')
    for key, checksum in MEMBER_DIGESTS.items():
        require(digest(canonical(value[key])) == checksum, 'changed accounting boundary: '+key)
    require(value['productExecutionInMetaRun'] is value['productAcceptance'] is value['nativeAcceptance']
            is value['tenantAcceptance'] is value['phaseComplete'] is False, 'no execution or promotion')


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH)); pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record, {p: regular_bytes(root, p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record); old = historical_catalog(packets)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'closed history routing')
        pins = {**record['protectedFiles'], **record['inputFiles'],
                **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'complete fresh inputs')
        for p, checksum in pins.items():
            require(type(inputs[p]) is bytes and digest(traversal_history(p,inputs[p])) == checksum, 'source drift: '+p)
        packets = traversal_catalog(packets)
        for name in packets:
            require(canonical(packets[name]) == canonical(safe_load(traversal_history('task-packets/'+name+'.yaml',inputs['task-packets/'+name+'.yaml']))), 'packet byte parity')
        value = parse(inputs[SPEC_PATH]); validate_spec(value)
        meta, product, prior = packets['MET-PERF-016'], packets['CONF-FIX-009'], old['MET-PERF-015']
        require(meta['repository'] == 'Harness-Engineering' and meta['predecessors'] == ['MET-PERF-015']
                and meta['allowedPaths'] == record['ownedPaths'], 'exact META owner')
        commands = meta['offlineAcceptanceCommands']
        require(len(commands) == 45 and commands[:-3]+commands[-2:] == prior['offlineAcceptanceCommands']
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_accounting_scope.py'], 'all44 inherited commands')
        baseline = old['CONF-FIX-009']
        require(set(product) == set(baseline) and all(product[k] == baseline[k]
                for k in product if k not in ('contracts','predecessors','excluded')), 'closed product packet amendment')
        require(product['predecessors'] == ['MET-PERF-016', *baseline['predecessors']], 'new META gate without loss')
        require(len(product['allowedPaths']) == 5 and len(product['offlineAcceptanceCommands']) == 8, 'same five paths and eight commands')
        for p in (meta,product):
            require(p['sourceReuse'] == p['prefetchCommands'] == [] and 'liveCampaignExecution' not in p
                    and p['warmSourceAccess'] == 'PROHIBITED_DURING_IMPLEMENTATION'
                    and p['offlineExecution'] == prior['offlineExecution'], 'unchanged isolation')
        source = parse(inputs[SOURCE])
        require(source['status'] == 'STATIC_SCOPE_CONFLICT_NOT_TEST_RESULT'
                and source['trackedFiles'] == 135 and source['immutableNonOwned'] == 130
                and source['totalTestIds'] == 1617 and source['backendTestIds'] == 1447
                and source['attemptsConsumed'] == 0
                and source['legacyFixture']['name'] == 'CompletionIntegrationSourceTests.setUp', 'bounded static diagnosis')
        require(not any(source[k] for k in ('productImported','testsCollected','productExecuted','behavioralEdits')), 'static is not acceptance')
        require(value['accountingException']['additionalInheritedSymbol'] == 'CompletionIntegrationSourceTests.setUp'
                and value['accountingException']['preserveOldTestBodies'] == 18
                and value['accountingException']['otherInheritedMigration'] is False, 'one additional fixture only')
        for path, checksum in value['preservedArtifacts'].items():
            require(digest(runner_history(path, inputs[path])) == checksum, 'preserved contracts and locks')
        for path, rule in record['metaRecipes'].items():
            before = historical_bytes(path, inputs[path])
            require(apply_recipe(before, rule) == traversal_history(path,inputs[path]), 'exact reversible metadata')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'inherited test identities')
        for path in record['navigationPaths']:
            require(all(s in inputs[path] for s in (b'ACCOUNTING_SCOPE_AMENDMENT.md',b'MET-PERF-016',b'CONF-FIX-009',b'HARNESS_PAPER_REPOSITORY_MAP.md',b'NOT_DUE')), 'consistent navigation')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid accounting scope authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets, *load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Accounting scope amendment valid:182 specifications;180 immutable packets; one fixture exception; product not executed or accepted.')
