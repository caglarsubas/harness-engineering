#!/usr/bin/env python3
"""Pinned source-only performance authority. No product imports or execution."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import stat

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

try:
    from validate_document_repair_execution import historical_bytes as execution_history, current_test_bytes as execution_current, validate_additions as execution_additions, historical_catalog
except ImportError:
    from scripts.validate_document_repair_execution import historical_bytes as execution_history, current_test_bytes as execution_current, validate_additions as execution_additions, historical_catalog

try:
    from validate_ci_runner_admission import historical_bytes as runner_history
except ImportError:
    from scripts.validate_ci_runner_admission import historical_bytes as runner_history

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = 'architecture/document-repair-authority.json'
RECORD_SHA256 = '26713d4ee1ad0d7a35ecacb9d321f16355fc537b05bdf95f1485f9d35285bc63'
NEW_IDS = ("MET-PERF-011",)
RECORD_FILE_SHA256 = 'ecd0b37b2959add14b681a646f1291e7d119f328eaf730bd850ceec761d47d2b'
HISTORY_PATHS = frozenset(['README.md', 'docs/DEVELOPMENT_STATUS.md', 'docs/MASTER_DEVELOPMENT_PLAN.md', 'docs/READINESS_INDEX.md', 'docs/alpha-2/CANONICAL_REPAIR_PLAN.md', 'docs/alpha-2/LIVE_BACKEND_READINESS.md', 'docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md', 'docs/repositories/00-harness-engineering.md', 'docs/repositories/12-mas-harness-conformance-labs.md', 'scripts/validate_backend_timing.py', 'scripts/validate_broker_handoff.py', 'scripts/validate_canonical_repair_plan.py', 'scripts/validate_ci_performance.py', 'scripts/validate_completion_profiling.py', 'scripts/validate_conformance_completion.py', 'scripts/validate_conformance_consumer_closure.py', 'scripts/validate_conformance_performance.py', 'scripts/validate_conformance_performance_followup.py', 'scripts/validate_conformance_publication.py', 'scripts/validate_conformance_reference_measurement.py', 'scripts/validate_conformance_successor_checkpoint.py', 'scripts/validate_credential_lifecycle.py', 'scripts/validate_credential_ordering.py', 'scripts/validate_custody_handoff.py', 'scripts/validate_linux_readiness.py', 'scripts/validate_linux_repair.py', 'scripts/validate_linux_test_ownership.py', 'scripts/validate_live_backend_readiness.py', 'scripts/validate_local_acceptance.py', 'scripts/validate_model_api_inventory.py', 'scripts/validate_model_fixture_scope.py', 'scripts/validate_native_qualification.py', 'scripts/validate_packet_scalar_repair.py', 'scripts/validate_policy_observation.py', 'scripts/validate_provider_adoption.py', 'scripts/validate_proxy_contract.py', 'scripts/validate_proxy_diagnostics.py', 'scripts/validate_readiness.py', 'scripts/validate_readiness_repairs.py', 'scripts/validate_research_adoption.py', 'scripts/validate_reuse.py', 'scripts/validate_successor_inventory.py', 'scripts/validate_validation_performance.py', 'task-packets/README.md', 'tests/test_alpha2_readiness.py', 'tests/test_backend_timing.py', 'tests/test_broker_handoff.py', 'tests/test_canonical_repair_plan.py', 'tests/test_ci_performance.py', 'tests/test_completion_profiling.py', 'tests/test_conformance_completion.py', 'tests/test_conformance_consumer_closure.py', 'tests/test_conformance_performance.py', 'tests/test_conformance_performance_followup.py', 'tests/test_conformance_publication.py', 'tests/test_conformance_reference_measurement.py', 'tests/test_conformance_successor_checkpoint.py', 'tests/test_credential_lifecycle.py', 'tests/test_credential_ordering.py', 'tests/test_custody_handoff.py', 'tests/test_linux_readiness.py', 'tests/test_linux_repair.py', 'tests/test_linux_test_ownership.py', 'tests/test_live_backend_readiness.py', 'tests/test_local_acceptance.py', 'tests/test_model_api_inventory.py', 'tests/test_model_fixture_scope.py', 'tests/test_native_qualification.py', 'tests/test_packet_scalar_repair.py', 'tests/test_policy_observation.py', 'tests/test_provider_adoption.py', 'tests/test_proxy_contract.py', 'tests/test_proxy_diagnostics.py', 'tests/test_research_adoption.py', 'tests/test_reuse.py', 'tests/test_successor_inventory.py', 'tests/test_task_packets.py', 'tests/test_validation_performance.py'])


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
    raw = execution_history(path, runner_history(path, raw))
    # A closed code-pinned routing table, not an acceptance/result cache.
    # Unchanged inputs still receive the predecessor caller's exact hash check.
    if path not in HISTORY_PATHS:
        return raw
    record = _record()
    rule = record["metaRecipes"].get(path)
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
        return execution_current(before)
    require(len(matches) == 1, "unique predecessor")
    return execution_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return execution_additions(packets)
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


SPEC_PATH = "architecture/document-repair-plan.json"
SPEC_SHA256 = "f5c8343d0999b2de95711ddf79bb48198b89b6b6164ba5cfe832f8f8513a1525"
MEMBER_DIGESTS = {'schemaVersion': '91db93655d1ceb8125ae42354abcf970572a135108b80b70a0e9d92f7aed1ddc', 'packetId': 'a0d0db2857d717106075e49706b434c69372b5a20d86caee659a05a6cd8b2985', 'metaBase': 'fa8dc175222ad86524d1750ded0e9d2acf9f9335dc0c0dfd562cfef2719dbd33', 'evidenceClass': '316d2b070c7e3d5909fd68d5064fcb2fb7d995ab6e209ca679ec3aac2e395263', 'productGrant': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'proposedPacketId': '5c15bc9bdaeb6d3674ab3fd5725273e66b68f182216fcc5984e95f8f795dac3b', 'readiness': 'ea2207583b04f19ad4a8ac0b7366a5bdfc1fc845288365aed39cb21727cc40df', 'diagnostic': 'd66449a18e741b9cb425e4cb11748ce1f761df90323e3db1722f6d663396f4c0', 'evidenceDigests': '413bc3de500011f9a5fd0a9a705778f0dba2dfd029d80cb41cd3c729122f522e', 'subject': '002ecbf8836403e94e0fa24d489d404d656bd4d2e1fd8b9993d7d75a50af4be8', 'candidate': 'bf1614ccd0e31cb8ef971f17097aa976229c310641bc286c95969789a34b5a09', 'consumers': 'dbaf689d25b7d509826c2991be9e0777138e0c7506ae5f029e3f0b0ebc04258b', 'consumerMigration': '2b698c0657c220121193934646c0a2293ef78ab970e3a6ca97a847de9444067e', 'proposedOwnerPaths': '9fcdc0801f97bb71f9aef07452a39d27f3e7ba2b5e565100075a9c677a8c6463', 'sequencing': 'c3896b230ec3c92a58c9428d5cf8bd60dc292ea6b61a1b7f817ad6a53f1fa52d', 'budgets': '8e3ff95c2e2e3b702bee6ded71e506955b3804d866015034a11100df0ecec130', 'limits': '94e8e9c93513d4d9021ed48da7360a950736b949d138556940edcd226ca1012a', 'gates': '95e275775b61574ae2f311386c7ae6635e21ba704aded19cd53b7698660379f2', 'contractPins': 'b2bb2e5c26eef5d1692c07de58bb2aa8da55a6656da0dd5d6cc0f0022a19254a', 'localBudgetExtension': '053dfd964fdea13ca83fd54755b118d491afd1bf3986c5d882df40b0b23390bf', 'testAccounting': '1adbf281543c5168d943d50fde4e5139b5e6ac75e283f0b61b40a0100877840c'}


def validate_plan(value, *, bind=True):
    """Data-shape/source checks only; cannot authenticate retained run evidence."""
    require(type(value) is dict and set(value)==set(MEMBER_DIGESTS), 'closed document repair plan')
    if bind: require(digest(canonical(value))==SPEC_SHA256, 'exact document repair plan')
    for key, expected in MEMBER_DIGESTS.items():
        require(digest(canonical(value[key]))==expected, 'changed planning boundary: '+key)
    require(value['productGrant'] is False and value['candidate']['implemented'] is False,
            'planning is not product authority')
    d=value['diagnostic']
    require(d['status']=='INCOMPLETE_DIAGNOSTIC_RETAINED'
            and d['completedTestCount']==426 and d['announcedTestCount']==427
            and d['expectedTestCount']==1397 and d['remainingAttempts']==0
            and d['pendingTestCost']=='NOT_MEASURED', 'incomplete exhausted diagnostic')
    require(all(d[key] is False for key in ('sourceAcceptance','nativeAcceptance','tenantAcceptance')),
            'no evidence promotion')
    require(value['candidate']['crossCallCache'] is value['candidate']['guardRemoval']
            is value['candidate']['cryptoChange'] is value['candidate']['sharedCanonicalChange'] is False,
            'bounded private helper only')
    require(value['budgets']==dict(metaLocal=3,metaCI=2,metaExactMain=1,productRuns=0,
        diagnostics=0,oldReset=False,oldTransfer=False,reserveBeforeActivation=True), 'META only finite allowance')

    extension=value['localBudgetExtension']
    require(extension['originalMaximum']==2 and extension['totalMaximum']==3
            and extension['retainedLocalOrdinals']==[1,2] and extension['newLocalOrdinals']==[3]
            and extension['additionalLocalMaximum']==1 and extension['reset'] is False
            and extension['transfer'] is False and extension['uniqueMutationTargetRequired'] is True,
            'one additional local attempt; no reset or broader change')
    require([r['ordinal'] for r in extension['retainedFailures']]==[1,2]
            and all(r['status']=='FAILED_EVIDENCE_RETAINED_NOT_ACCEPTANCE' for r in extension['retainedFailures']),
            'both earlier attempts remain failures')


def load_inputs(root):
    record=parse(regular_bytes(root,RECORD_PATH)); pinned(record)
    paths={*record['protectedFiles'],*record['inputFiles'],*record['metaRecipes']}
    return record,{p:regular_bytes(root,p) for p in paths}


def validate_authority(packets,record,inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS==set(record['metaRecipes']), 'exact history routing')
        require(validate_additions(packets)==[], 'exact new packet')
        packets = historical_catalog(packets)
        pins={**record['protectedFiles'],**record['inputFiles'],
              **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs)==set(pins), 'complete fresh source inputs')
        for path,checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(execution_history(path,runner_history(path,inputs[path])))==checksum, 'source drift: '+path)
        old={Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old)==169 and len(packets)==170 and set(packets)==old|set(NEW_IDS), '169 immutable plus one planning packet')
        require('CONF-PERF-006' not in packets and 'CONF-PERF-005' not in packets, 'no product grant')
        for name in packets:
            require(canonical(packets[name])==canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'raw packet parity')
        packet=packets['MET-PERF-011']; prior=packets['MET-PERF-009']
        require(packet['repository']=='Harness-Engineering' and packet['predecessors']==['MET-PERF-009']
                and packet['allowedPaths']==record['ownedPaths'], 'exact META owner')
        commands=packet['offlineAcceptanceCommands']
        require(len(commands)==39 and commands[:-3]+commands[-2:]==prior['offlineAcceptanceCommands']
                and commands[-3]==['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_document_repair_plan.py']
                and packet['offlineExecution']==prior['offlineExecution'], 'whole predecessor recipe')
        require(packet['sourceReuse']==packet['prefetchCommands']==[]
                and packet['warmSourceAccess']=='PROHIBITED_DURING_IMPLEMENTATION'
                and 'liveCampaignExecution' not in packet, 'no live or warm authority')
        value=parse(inputs[SPEC_PATH]); validate_plan(value)
        for path,checksum in value['contractPins'].items():
            require(digest(runner_history(path,inputs[path]))==checksum, 'immutable source contract')
        for path,rule in record['metaRecipes'].items():
            before=historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule)==execution_history(path,runner_history(path,inputs[path])), 'exact reversible metadata')
            if path.startswith('tests/'):
                require(test_ids(before)==test_ids(inputs[path]), 'all inherited test identities')
        for path in record['navigationPaths']:
            require(all(s in inputs[path] for s in (b'DOCUMENT_REPAIR_PLAN.md',b'MET-PERF-011',
                b'CONF-DIAG-003',b'INCOMPLETE_DIAGNOSTIC_RETAINED',b'BLOCKED_LOCAL_BUDGET_EXHAUSTED',
                b'HARNESS_PAPER_REPOSITORY_MAP.md',b'NOT_DUE')), 'consistent roadmap')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid document repair plan: '+str(exc)]


if __name__=='__main__':
    packets={p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors=validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Historical document repair plan valid:170-packet projection; no historical product grant or retry reset.')
