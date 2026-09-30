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
    from validate_factory_diagnostics import historical_bytes as factory_history, current_test_bytes as factory_current, validate_additions as factory_additions, historical_catalog as factory_catalog
except ImportError:
    from scripts.validate_factory_diagnostics import historical_bytes as factory_history, current_test_bytes as factory_current, validate_additions as factory_additions, historical_catalog as factory_catalog

try:
    from validate_ci_runner_admission import historical_bytes as runner_history
except ImportError:
    from scripts.validate_ci_runner_admission import historical_bytes as runner_history

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = 'architecture/completion-integration-authority.json'
RECORD_SHA256 = '61419d001ed05ab04f23f6e7d1dbc402c655023c71cccb1df6f6e936eafaf747'
NEW_IDS = ('MET-REPAIR-018', 'CONF-FIX-008')
RECORD_FILE_SHA256 = '7c6f2cd5a2c0c76487df897c853f1de577e8fc8bc1e1f5c3698b118621035793'
HISTORY_PATHS = frozenset(['README.md', 'docs/DEVELOPMENT_STATUS.md', 'docs/MASTER_DEVELOPMENT_PLAN.md', 'docs/READINESS_INDEX.md', 'docs/alpha-2/BENCHMARK_TRANSPORT.md', 'docs/alpha-2/CANONICAL_REPAIR_PLAN.md', 'docs/alpha-2/CONFORMANCE_COMPLETION.md', 'docs/alpha-2/DOCUMENT_REPAIR_AUTHORITY.md', 'docs/alpha-2/DOCUMENT_REPAIR_PLAN.md', 'docs/alpha-2/LIVE_BACKEND_READINESS.md', 'docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md', 'docs/repositories/00-harness-engineering.md', 'docs/repositories/12-mas-harness-conformance-labs.md', 'scripts/validate_backend_timing.py', 'scripts/validate_benchmark_transport.py', 'scripts/validate_broker_handoff.py', 'scripts/validate_canonical_repair_plan.py', 'scripts/validate_ci_performance.py', 'scripts/validate_completion_profiling.py', 'scripts/validate_conformance_completion.py', 'scripts/validate_conformance_consumer_closure.py', 'scripts/validate_conformance_performance.py', 'scripts/validate_conformance_performance_followup.py', 'scripts/validate_conformance_publication.py', 'scripts/validate_conformance_reference_measurement.py', 'scripts/validate_conformance_successor_checkpoint.py', 'scripts/validate_credential_lifecycle.py', 'scripts/validate_credential_ordering.py', 'scripts/validate_custody_handoff.py', 'scripts/validate_document_repair_execution.py', 'scripts/validate_linux_readiness.py', 'scripts/validate_linux_repair.py', 'scripts/validate_linux_test_ownership.py', 'scripts/validate_live_backend_readiness.py', 'scripts/validate_local_acceptance.py', 'scripts/validate_model_api_inventory.py', 'scripts/validate_model_fixture_scope.py', 'scripts/validate_native_qualification.py', 'scripts/validate_packet_scalar_repair.py', 'scripts/validate_policy_observation.py', 'scripts/validate_provider_adoption.py', 'scripts/validate_proxy_contract.py', 'scripts/validate_proxy_diagnostics.py', 'scripts/validate_readiness.py', 'scripts/validate_readiness_repairs.py', 'scripts/validate_research_adoption.py', 'scripts/validate_reuse.py', 'scripts/validate_successor_inventory.py', 'scripts/validate_validation_performance.py', 'task-packets/README.md', 'tests/test_alpha2_readiness.py', 'tests/test_backend_timing.py', 'tests/test_benchmark_transport.py', 'tests/test_broker_handoff.py', 'tests/test_canonical_repair_plan.py', 'tests/test_ci_performance.py', 'tests/test_completion_profiling.py', 'tests/test_conformance_completion.py', 'tests/test_conformance_consumer_closure.py', 'tests/test_conformance_performance.py', 'tests/test_conformance_performance_followup.py', 'tests/test_conformance_publication.py', 'tests/test_conformance_reference_measurement.py', 'tests/test_conformance_successor_checkpoint.py', 'tests/test_credential_lifecycle.py', 'tests/test_credential_ordering.py', 'tests/test_custody_handoff.py', 'tests/test_document_repair_execution.py', 'tests/test_document_repair_plan.py', 'tests/test_linux_readiness.py', 'tests/test_linux_repair.py', 'tests/test_linux_test_ownership.py', 'tests/test_live_backend_readiness.py', 'tests/test_local_acceptance.py', 'tests/test_model_api_inventory.py', 'tests/test_model_fixture_scope.py', 'tests/test_native_qualification.py', 'tests/test_packet_scalar_repair.py', 'tests/test_policy_observation.py', 'tests/test_provider_adoption.py', 'tests/test_proxy_contract.py', 'tests/test_proxy_diagnostics.py', 'tests/test_research_adoption.py', 'tests/test_reuse.py', 'tests/test_successor_inventory.py', 'tests/test_task_packets.py', 'tests/test_validation_performance.py'])


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
    raw = factory_history(path, raw)
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
        return factory_current(before)
    require(len(matches) == 1, "unique predecessor")
    return factory_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return factory_additions(packets)
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


SPEC_PATH = 'architecture/completion-integration.json'
SPEC_SHA256 = 'f14c14fdb22c74bac8f8c53afdb0714ebde6fd93ec891d4d4dc6eed58e58cd19'
MEMBER_DIGESTS = {'schemaVersion': '3023552d306f5029158db0d36d15733b165e928eea220caa4215a4fb97e4c2f8', 'packetId': '07bd2958cf5685481fb2a96062dac3cbe9a43ba7a1f6284bc69ac9fc70761841', 'metaBase': '0a746fff7b28c58cc5cf1ee365f19694bbb93efda88a3b737beec1d002f52abc', 'status': '0da9365f401908507ca93b0b0a3016a6beaadd8af1310b652f540dc34b73a11f', 'proposalSha256': 'd245efca5964e1bcb45fef51612f963f61e144daa31e4dda119e82395eefe7c7', 'sourceAccountingSha256': '65bd2ff4019f45637edbb7d38328c860d8c8d3ead7e74e2a6e972dfbe33db9c9', 'predecessorSourceGates': '95985f681003137bd5ca900b6ccdebadb47d55d2e4b8f3ae37cd261c3b761634', 'product': 'ba6b3583aa298adfc19ba301e51c9097cbb6ad9b9f943a086040a9e345861277', 'retiredPacket': 'a6574d81b74b5abc3f6bfd5b68bce7eeb5e0d7ec2483be4735ebfcffebfc61d1', 'effectivePredecessors': 'da09c719051dfd9d678fd7005e9836083e8449294a76d8efb9a0b327f17f4116', 'completionRequirements': 'ed87df00a623214a67cb5b3a1e3cbe9ea15c3eb80a6948f9b01fcaeadb79b250', 'budgets': '484f9abf2aa61d39f184f963b33b760b29d06bd2e3df4c6ad91428963ced860e', 'limits': '55c877ff2cfdeb3570006b31f6a0bc121923356c6912855cccf6b8e7fa5cce47', 'preservedArtifacts': 'b26b529c7c78cc62bc6c6592f7b6a8e602ff24c4a68471c0674f761a0925e1af', 'dispatchOverlaps': '382b5a05035ca787e9941dc8d3429e51a49bca9dfe5e94aa37a028ad763b85ed', 'productExecutionInMetaRun': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'productAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'nativeAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'tenantAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'phaseComplete': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'testAccounting': '36eea1cde197a4f37a84734b5b24185ef21f45e7b9c5b9b3548cd1075633aa30'}
AUDIT = 'architecture/completion-integration-inputs/source-audit.json'
CLOSEOUT = 'architecture/completion-integration-inputs/product-closeout.json'
ACCOUNTING = 'architecture/completion-integration-inputs/source-accounting.json'


def historical_catalog(packets):
    record = _record(); pinned(record)
    require(validate_additions(packets) == [], 'exact integration packets')
    packets = factory_catalog(packets)
    old = {Path(p).stem for p in record['protectedFiles']
           if p.startswith('task-packets/') and p.endswith('.yaml')}
    require(len(old) == 175 and set(packets) == old | set(NEW_IDS), 'closed 177-packet catalog')
    return {name: packets[name] for name in old}


def validate_spec(value, *, bind=True):
    require(type(value) is dict and set(value) == set(MEMBER_DIGESTS), 'closed integration specification')
    if bind:
        require(digest(canonical(value)) == SPEC_SHA256, 'exact integration specification')
    for key, checksum in MEMBER_DIGESTS.items():
        require(digest(canonical(value[key])) == checksum, 'changed integration boundary: ' + key)
    require(value['effectivePredecessors'] == {'CONF-LIVE-004': ['CONF-LIVE-003','CONF-FIX-008']}, 'mandatory separate completion')
    require(value['retiredPacket']['id'] == 'CONF-FIX-007'
            and value['retiredPacket']['dispatchable'] is False, 'exhausted draft preserved')
    require(value['productExecutionInMetaRun'] is value['productAcceptance'] is value['nativeAcceptance']
            is value['tenantAcceptance'] is value['phaseComplete'] is False, 'no execution or promotion')


def completion_evidence(value):
    """Shape check only: never authenticates signatures, grants execution or readiness."""
    keys = {'packetId','baseline','tree','reviewedTree','localTree','ciTree','mainTree',
            'localPassed','requiredCIPassed','protectedMerge','exactMainPassed','remainingWork',
            'reviewEvidenceSha256','completion','evidenceClass'}
    require(type(value) is dict and set(value) == keys, 'closed source evidence')
    require(value['packetId'] == 'CONF-FIX-008' and value['baseline'] == '3a81c8ffb17be9e288c4368d443c57361d5a4fc8', 'successor and accepted base')
    require(value['evidenceClass'] == 'SOURCE_ONLY_REQUIRES_INDEPENDENT_AUTHENTICATION', 'source-only evidence')
    tree = value['tree']
    require(type(tree) is str and re.fullmatch('[0-9a-f]{40}', tree) is not None
            and tree not in ('0'*40,'0627100bafa06443bfec1b4ab4ae17c86891186a','6f38052fb9a31e9fe8b9abb6b055ddd96f06854f'), 'new integrated tree')
    require(all(value[k] == tree for k in ('reviewedTree','localTree','ciTree','mainTree')), 'exact source parity')
    require(all(value[k] is True for k in ('localPassed','requiredCIPassed','protectedMerge','exactMainPassed')), 'four separate source gates')
    require(type(value['remainingWork']) is list and value['remainingWork'] == [], 'incomplete implementation')
    checksum = value['reviewEvidenceSha256']
    require(type(checksum) is str and re.fullmatch('[0-9a-f]{64}', checksum) is not None and checksum != '0'*64, 'independent review reference')
    rows = value['completion']
    require(type(rows) is list and len(rows) == 7, 'seven obligations')
    for i, row in enumerate(rows, 1):
        require(type(row) is dict and set(row) == {'id','sourceSymbols','testIds','reviewed'}
                and row['id'] == 'C'+str(i) and row['reviewed'] is True, 'ordered reviewed obligation')
        for key in ('sourceSymbols','testIds'):
            items = row[key]
            require(type(items) is list and 0 < len(items) <= 128
                    and all(type(x) is str and 0 < len(x) <= 256 for x in items)
                    and len(set(items)) == len(items), 'nonempty unique mappings')


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH)); pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record, {p: regular_bytes(root,p) for p in paths}


def close_integration_dispatch(packets, errors):
    """Close only exact retired-source/read-only overlaps, not execution authority."""
    try:
        record = _record(); pinned(record); historical_catalog(packets)
        value = parse(regular_bytes(ROOT,SPEC_PATH)); validate_spec(value)
        exact = []
        for item in value['dispatchOverlaps']:
            a,b,path = item['left'],item['right'],item['path']
            for name in (a,b):
                raw = regular_bytes(ROOT,'task-packets/'+name+'.yaml')
                expected = record['inputFiles'].get('task-packets/'+name+'.yaml',record['protectedFiles'].get('task-packets/'+name+'.yaml'))
                require(digest(raw) == expected and canonical(safe_load(raw)) == canonical(packets[name]), 'exact overlap neighbors')
            require(path in packets[a]['allowedPaths'] and path in packets[b]['allowedPaths'], 'exact owned overlap')
            exact.append('unordered same-repository packets '+a+' and '+b+' overlap at '+repr(path)+' and '+repr(path))
        require(len(exact) == len(set(exact)) == 8 and all(errors.count(e) == 1 for e in exact), 'eight exact diagnostics')
        return [e for e in errors if e not in exact]
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        return errors + ['missing or changed completion integration dispatch']


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact history routing')
        old = historical_catalog(packets)
        pins = {**record['protectedFiles'], **record['inputFiles'], **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'complete fresh inputs')
        for path,checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(factory_history(path,inputs[path])) == checksum, 'source drift: '+path)
        for name in factory_catalog(packets):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'packet byte parity')
        value = parse(inputs[SPEC_PATH]); validate_spec(value)
        meta, product, prior = packets['MET-REPAIR-018'], packets['CONF-FIX-008'], old['MET-PERF-013']
        require(meta['repository'] == 'Harness-Engineering' and meta['predecessors'] == ['MET-PERF-013','CONF-PERF-006']
                and meta['allowedPaths'] == record['ownedPaths'], 'exact META owner')
        commands = meta['offlineAcceptanceCommands']
        require(len(commands) == 42 and commands[:-3]+commands[-2:] == prior['offlineAcceptanceCommands']
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_completion_integration.py'], 'all41 predecessor commands')
        require(product['repository'] == 'mas-harness-conformance-labs'
                and product['predecessors'] == ['MET-REPAIR-018','CONF-PERF-006','CONF-LIVE-003','CONF-DIAG-002']
                and product['allowedPaths'] == value['product']['allowedPaths']
                and product['offlineAcceptanceCommands'] == old['CONF-FIX-007']['offlineAcceptanceCommands'], 'five-path full-recipe successor')
        for p in (meta,product):
            require(p['sourceReuse'] == p['prefetchCommands'] == [] and 'liveCampaignExecution' not in p
                    and p['warmSourceAccess'] == 'PROHIBITED_DURING_IMPLEMENTATION'
                    and p['offlineExecution'] == prior['offlineExecution'], 'unchanged offline boundary')
        require(inputs[CLOSEOUT].endswith(b'\n') and digest(inputs[CLOSEOUT][:-1]) == value['predecessorSourceGates']['product']['closeoutSha256'], 'exact retained closeout plus one text LF')
        audit, closeout, accounting = parse(inputs[AUDIT]), parse(inputs[CLOSEOUT]), parse(inputs[ACCOUNTING])
        require(audit['status'] == 'STATIC_SOURCE_REVIEW_ONLY_NOT_ACCEPTANCE'
                and audit['subjects']['ACCEPTED']['commit'] == value['product']['base']
                and audit['subjects']['DRAFT']['commit'] == value['retiredPacket']['head']
                and audit['integrationInheritedTests'] == 1599 and audit['integrationInheritedBackendTests'] == 1429
                and audit['productImported'] is audit['collectionExecuted'] is audit['testsExecuted'] is False, 'source inventory not acceptance')
        counts = {'BASE':1277,'ACCEPTED':1309,'DRAFT':1567}
        for label, count in counts.items():
            subject = audit['subjects'][label]
            require(len(subject['files']) == 135 and sum(map(len,subject['testIds'].values())) == count, 'complete source subjects')
        combined = {p: sorted(set(audit['subjects']['ACCEPTED']['testIds'][p]) | set(audit['subjects']['DRAFT']['testIds'][p]))
                    for p in audit['subjects']['BASE']['testIds']}
        require(combined == audit['combinedTestIds'] and sum(map(len,combined.values())) == 1599, 'identity union, no dropped tests')
        require(closeout['status'] == 'DONE_SOURCE_GATES' and closeout['main'] == value['product']['base']
                and closeout['tree'] == value['product']['baseTree'] and closeout['testsPerAcceptance'] == 1309
                and closeout['ci']['status'] == 'PASS' and closeout['local']['status'] == closeout['exactMain']['status'] == 'FULL_LOCAL_ACCEPTANCE_VERIFIED'
                and closeout['nativeAcceptance'] is closeout['tenantAcceptance'] is closeout['phaseComplete'] is False, 'separate accepted helper evidence')
        require(accounting['inheritedTotal'] == 1599 and accounting['otherAcceptedRepairMethodBodiesImmutable'] == 31
                and accounting['methodException']['id'] == 'DocumentRepairTests.test_consumer_history_preserved'
                and accounting['currentBeforeHistorical'] is True and accounting['additionalConsumerMigrationAuthorized'] is False, 'named migration only')
        for path,checksum in value['preservedArtifacts'].items():
            require(digest(runner_history(path, inputs[path])) == checksum, 'immutable contract/lock')
        for path,rule in record['metaRecipes'].items():
            before = historical_bytes(path, inputs[path])
            require(apply_recipe(before,rule) == factory_history(path,inputs[path]), 'exact reversible metadata')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'all inherited test identities')
        for path in record['navigationPaths']:
            require(all(s in inputs[path] for s in (b'COMPLETION_INTEGRATION.md',b'MET-REPAIR-018',b'CONF-FIX-008',b'DONE_SOURCE_GATES',b'HARNESS_PAPER_REPOSITORY_MAP.md',b'NOT_DUE')), 'consistent roadmap')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid completion integration authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Completion integration authority valid:177 specifications;175 immutable packets; no product/native execution; independent C1-C7 required.')
