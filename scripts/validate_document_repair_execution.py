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
    from validate_benchmark_transport import historical_bytes as transport_history, current_test_bytes as transport_current, validate_additions as transport_additions, historical_catalog as transport_catalog
except ImportError:
    from scripts.validate_benchmark_transport import historical_bytes as transport_history, current_test_bytes as transport_current, validate_additions as transport_additions, historical_catalog as transport_catalog

try:
    from validate_ci_runner_admission import historical_bytes as runner_history
except ImportError:
    from scripts.validate_ci_runner_admission import historical_bytes as runner_history

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = 'architecture/document-repair-execution-authority.json'
RECORD_SHA256 = 'bafacca38370813f61965faa9076208b955502304b7245196d2956ad1f7d4617'
NEW_IDS = ('MET-PERF-012', 'CONF-PERF-006', 'CONF-BENCH-002')
RECORD_FILE_SHA256 = 'dcba5192b3d22f86cc0d54d225c11ae9f884a3fd1f5ae5376727252540340145'
HISTORY_PATHS = frozenset(['README.md', 'docs/DEVELOPMENT_STATUS.md', 'docs/MASTER_DEVELOPMENT_PLAN.md', 'docs/READINESS_INDEX.md', 'docs/alpha-2/CANONICAL_REPAIR_PLAN.md', 'docs/alpha-2/DOCUMENT_REPAIR_PLAN.md', 'docs/alpha-2/LIVE_BACKEND_READINESS.md', 'docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md', 'docs/repositories/00-harness-engineering.md', 'docs/repositories/12-mas-harness-conformance-labs.md', 'scripts/validate_backend_timing.py', 'scripts/validate_broker_handoff.py', 'scripts/validate_canonical_repair_plan.py', 'scripts/validate_ci_performance.py', 'scripts/validate_completion_profiling.py', 'scripts/validate_conformance_completion.py', 'scripts/validate_conformance_consumer_closure.py', 'scripts/validate_conformance_performance.py', 'scripts/validate_conformance_performance_followup.py', 'scripts/validate_conformance_publication.py', 'scripts/validate_conformance_reference_measurement.py', 'scripts/validate_conformance_successor_checkpoint.py', 'scripts/validate_credential_lifecycle.py', 'scripts/validate_credential_ordering.py', 'scripts/validate_custody_handoff.py', 'scripts/validate_document_repair_plan.py', 'scripts/validate_linux_readiness.py', 'scripts/validate_linux_repair.py', 'scripts/validate_linux_test_ownership.py', 'scripts/validate_live_backend_readiness.py', 'scripts/validate_local_acceptance.py', 'scripts/validate_model_api_inventory.py', 'scripts/validate_model_fixture_scope.py', 'scripts/validate_native_qualification.py', 'scripts/validate_packet_scalar_repair.py', 'scripts/validate_policy_observation.py', 'scripts/validate_provider_adoption.py', 'scripts/validate_proxy_contract.py', 'scripts/validate_proxy_diagnostics.py', 'scripts/validate_readiness.py', 'scripts/validate_readiness_repairs.py', 'scripts/validate_research_adoption.py', 'scripts/validate_reuse.py', 'scripts/validate_successor_inventory.py', 'scripts/validate_validation_performance.py', 'task-packets/README.md', 'tests/test_alpha2_readiness.py', 'tests/test_backend_timing.py', 'tests/test_broker_handoff.py', 'tests/test_canonical_repair_plan.py', 'tests/test_ci_performance.py', 'tests/test_completion_profiling.py', 'tests/test_conformance_completion.py', 'tests/test_conformance_consumer_closure.py', 'tests/test_conformance_performance.py', 'tests/test_conformance_performance_followup.py', 'tests/test_conformance_publication.py', 'tests/test_conformance_reference_measurement.py', 'tests/test_conformance_successor_checkpoint.py', 'tests/test_credential_lifecycle.py', 'tests/test_credential_ordering.py', 'tests/test_custody_handoff.py', 'tests/test_document_repair_plan.py', 'tests/test_linux_readiness.py', 'tests/test_linux_repair.py', 'tests/test_linux_test_ownership.py', 'tests/test_live_backend_readiness.py', 'tests/test_local_acceptance.py', 'tests/test_model_api_inventory.py', 'tests/test_model_fixture_scope.py', 'tests/test_native_qualification.py', 'tests/test_packet_scalar_repair.py', 'tests/test_policy_observation.py', 'tests/test_provider_adoption.py', 'tests/test_proxy_contract.py', 'tests/test_proxy_diagnostics.py', 'tests/test_research_adoption.py', 'tests/test_reuse.py', 'tests/test_successor_inventory.py', 'tests/test_task_packets.py', 'tests/test_validation_performance.py'])


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
    raw = transport_history(path, runner_history(path, raw))
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
        return transport_current(before)
    require(len(matches) == 1, "unique predecessor")
    return transport_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return transport_additions(packets)
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


SPEC_PATH = 'architecture/document-repair-execution.json'
SPEC_SHA256 = 'e702ff5daf0216429ddb1d5f8160a5af68e39bde710f73cbe794d5e3f1bf61ee'
MEMBER_DIGESTS = {'schemaVersion': 'b5d138ddae407fd95dc5a255cf20408c8afb156580e8ebbb4bb25ac641aad8da', 'packetId': 'c59a1f68eff64b5e799d11025b44a707d0d1cf5e7272d2b64fde4b73a7ec91f9', 'metaBase': '81005b9d9048f87f497404cf6801d2cdc964d97ac39dd5a648809abbc20f2460', 'status': '0da9365f401908507ca93b0b0a3016a6beaadd8af1310b652f540dc34b73a11f', 'productExecutionInMetaRun': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'productAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'benchmarkAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'predecessorSourceGates': 'a493aed786fbc2fbad4f3c25a98c529a76c1313adc6af594218215874943c65e', 'runtimeRegion': 'c955df172588b55d30ed3aa86b7f91a0355108f2cd0152e18cf8201790cfd33c', 'consumerEdits': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', 'unchangedProductFiles': 'dbb1ded63bc70732626c5dfe6c7f50ced3d560e970f30b15335ac290358748f6', 'preservedTestIds': '7cbc1f697e71f94e5e4871b5d4e89420f2823dc219d95a58b79482c206f5cbb1', 'budgets': '7e1098adfc03d094b509e4d8d289e9e11742702df89bedf15d2d37572a8b1cfb', 'limits': '55c877ff2cfdeb3570006b31f6a0bc121923356c6912855cccf6b8e7fa5cce47', 'sourceScopeSha256': '12abfb963162cef743b872c186b5130962de6fa264858a2c4ff18ac71e5bb849', 'semanticManifestSha256': 'f37fe488ad754feed946d864df31e8e05dfa1d6b03cbf28826177e71b8242cb9', 'measurementManifestSha256': '34d4dcc5cc739a5076d4e42d47e5a313c8ccc11a43ca4e94a7f4eb3db39c225c', 'measurementDriverSha256': 'b32c318cf5f177d2dd7bbcf15b23f7c1a1684c4601a65c1d913ee1b03bea5c15', 'reviewArtifacts': '49f3b0a59a0b21bc459639da352749c3b41b172c30005ea5755e728498063c30', 'reviewCorrections': '196439d6a6618d62b64945fa18d21439fa72d097e441aacca74705e5967f8b37', 'sequencing': 'adcb74b932c741f0005b1d7b80dc7ee511012320b1dd4ef88aaabfa2d5a27702', 'gates': '539e263183237d4d55aae488831b673e45a5d6a8c7a2bcd81d798852c1ae8b88', 'contractPins': 'cc0ff8bbc627267f56fbb228dc854f18eb1281a7e320aba758fd0733a0b89205', 'dispatch': '8ba94bffe8dcfe1cf61e5bc0ecd90a447ca5eb415ecf95c1fb3a94cb4b9f25c3', 'retainedLocalFailure': 'a83cb704e7acf977e0a6ddd383c1ba45d3a68a10b31cc0db0b68f47102674e4b', 'localBudgetExtension': '01eb8aaa85c5f17ca573d51be5b0ee149091a0f14e456c4f48aa333b8b2b409a', 'testAccounting': 'ecca6c22c64267287b3e9e941ec4a1076a6617d143919d6f0b1475fd9561d616'}
INPUT_PREFIX = 'architecture/document-repair-execution-inputs/'


def historical_catalog(packets):
    """Exact successor declarations are checked before the old planning-only view."""
    record = _record()
    pinned(record)
    require(validate_additions(packets) == [], 'exact successor declarations before projection')
    packets = transport_catalog(packets)
    old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
    require(len(old) == 170 and set(packets) == old | set(NEW_IDS), 'closed 173-packet catalog')
    return {name: packets[name] for name in old}


def validate_spec(value, *, bind=True):
    require(type(value) is dict and set(value) == set(MEMBER_DIGESTS), 'closed execution specification')
    if bind: require(digest(canonical(value)) == SPEC_SHA256, 'exact execution specification')
    for key, expected in MEMBER_DIGESTS.items():
        require(digest(canonical(value[key])) == expected, 'changed execution boundary: ' + key)
    require(value['productExecutionInMetaRun'] is value['productAcceptance'] is value['benchmarkAcceptance'] is False, 'declaration is not execution or acceptance')
    require(value['budgets'] == dict(meta={'LOCAL':3,'CI':2,'LOCAL_EXACT_MAIN':1}, product={'LOCAL':2,'CI':2,'LOCAL_EXACT_MAIN':1}, measurement={'runs':4,'retries':0}, resetOld=False), 'finite separate nontransferable allowances')

    extension=value['localBudgetExtension']
    require(extension['originalMaximum']==2 and extension['totalMaximum']==3
            and extension['retainedLocalOrdinals']==[1,2] and extension['newLocalOrdinals']==[3]
            and extension['additionalLocalMaximum']==1 and extension['reset'] is False
            and extension['transfer'] is False and extension['uniqueMutationTargets'] is True
            and extension['preserveAllAssertionsAndTestIdentities'] is True, 'one additional LOCAL; no reset or weakened tests')
    require([r['ordinal'] for r in extension['retainedFailures']]==[1,2]
            and all(r['status']=='FAILED_EVIDENCE_RETAINED_NOT_ACCEPTANCE' for r in extension['retainedFailures']),
            'both earlier failures retained')


def validate_artifacts(value, inputs):
    source = parse(inputs[INPUT_PREFIX+'source-scope.json'])
    oracle = parse(inputs[INPUT_PREFIX+'semantic-oracles.json'])
    workload = parse(inputs[INPUT_PREFIX+'workload.json'])
    program = inputs[INPUT_PREFIX+'benchmark.py.txt']
    for name,key in [('source-scope.json','sourceScopeSha256'),('semantic-oracles.json','semanticManifestSha256'),('workload.json','measurementManifestSha256'),('benchmark.py.txt','measurementDriverSha256')]:
        require(digest(inputs[INPUT_PREFIX+name]) == value[key], 'artifact substitution: '+name)
    require(len(source['files']) == 135 and source['unchangedFileCount'] == 132
            and sum(len(ids) for ids in source['testIds'].values()) == 1277, 'complete immutable baseline')
    require(source['productImported'] is source['testsCollected'] is source['acceptanceExecuted'] is False, 'static source evidence only')
    require(source['consumerEditsRequired'] is False and value['consumerEdits'] == [], 'no historical consumer rewrite')
    region = value['runtimeRegion']
    before,after = source['functionSource'],region['candidateSource']
    require(digest(before.encode()) == region['beforeSha256'] and digest(after.encode()) == region['candidateSha256'], 'exact bounded function candidate')
    a,b = ast.parse(before).body[0],ast.parse(after).body[0]
    require(ast.dump(a.args)==ast.dump(b.args) and a.name==b.name=='document'
            and after.endswith(before.split('\n',1)[1]) and len(b.body)==len(a.body)+1, 'unchanged signature and fallback')
    require(ast.dump(ast.Module(body=b.body[1:],type_ignores=[])) == ast.dump(ast.Module(body=a.body,type_ignores=[])), 'all fallback nodes preserved')
    require(len(oracle['requiredMethods'])==oracle['newTestCount']==32
            and len({row['id'] for row in oracle['requiredMethods']})==32
            and oracle['expectedTotalTestCount']==1309 and oracle['expectedBackendTestCount']==1139, 'independent exact test inventory')
    require(workload['schedule']==['BASELINE','CANDIDATE','CANDIDATE','BASELINE']
            and workload['maximumExecutions']==4 and workload['retries']==0
            and workload['candidateCommit']=='MUST_BE_FROZEN_BEFORE_FIRST_EXECUTION', 'separate unexecuted comparison')
    require(len(workload['cases'])==10 and digest(canonical(workload['cases']))==workload['workloadSha256'], 'ten frozen cases')
    for case in workload['cases']:
        raw=case['raw'].encode()
        require(len(raw)==case['bytes']<=case['maximum'] and digest(raw)==case['rawSha256'] and canonical(parse(raw))==raw, 'canonical workload bytes')
    require(len(program)<=4096, 'literal argv bound')
    tree=ast.parse(program)
    strings=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and type(n.value) is str]
    require('caf\u00e9' in strings and '\u754c' in strings
            and 'caf\\u00e9' not in strings and '\\u754c' not in strings, 'Unicode literals match frozen workload')
    require(workload['workloadSha256'] in strings and workload['fixtureSha256'] in strings, 'driver fixture/workload binding')


def load_inputs(root):
    record=parse(regular_bytes(root,RECORD_PATH)); pinned(record)
    paths={*record['protectedFiles'],*record['inputFiles'],*record['metaRecipes']}
    return record,{p:regular_bytes(root,p) for p in paths}


def close_document_dispatch(packets, errors):
    """Close only six pinned fork/read-only diagnostics; never retire draft PR18."""
    try:
        record=_record(); pinned(record)
        require(validate_additions(packets)==[], 'exact new packet boundaries')
        value=parse(regular_bytes(ROOT,SPEC_PATH)); validate_spec(value)
        for name in ('CONF-FIX-007','CONF-LIVE-003'):
            path='task-packets/'+name+'.yaml'; raw=regular_bytes(ROOT,path)
            require(digest(raw)==record['protectedFiles'][path]
                    and canonical(safe_load(raw))==canonical(packets[name]), 'unchanged prior packet')
        require(value['dispatch']['roles']=={
            'CONF-FIX-007':'PRESERVED_BLOCKED_DRAFT_NO_EXECUTION_OR_MUTATION',
            'CONF-PERF-006':'SEPARATE_REPAIR_FROM_ACCEPTED_092FCF4_NOT_FROM_DRAFT',
            'CONF-BENCH-002':'READ_ONLY_COMPARISON_NOT_SOURCE_OWNER'}, 'closed dispatch roles')
        closed=set()
        paths=packets['CONF-PERF-006']['allowedPaths']
        for left,right,count in value['dispatch']['overlapPairs']:
            overlap=set(packets[left]['allowedPaths']) & set(packets[right]['allowedPaths'])
            require(len(overlap)==count and overlap==(set(paths) if count==3 else {paths[0]}), 'exact overlap paths')
            closed.update('unordered same-repository packets '+left+' and '+right+' overlap at '+repr(p)+' and '+repr(p) for p in overlap)
        require(len(closed)==6 and all(errors.count(e)==1 for e in closed), 'six exact diagnostics')
        return [error for error in errors if error not in closed]
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        return errors+['missing or changed closed document repair dispatch']


def validate_authority(packets,record,inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS==set(record['metaRecipes']), 'exact history routing')
        require(validate_additions(packets)==[], 'exact new packets')
        pins={**record['protectedFiles'],**record['inputFiles'],**{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs)==set(pins), 'complete fresh source inputs')
        for path,checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(transport_history(path,runner_history(path,inputs[path])))==checksum, 'source drift: '+path)
        old=historical_catalog(packets)
        require(len(old)==170 and len(packets)==194 and 'CONF-PERF-006' not in old, 'historical planning boundary')
        for name in transport_catalog(packets):
            require(canonical(packets[name])==canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'raw packet parity')
        meta=packets['MET-PERF-012']; prior=packets['MET-PERF-011']
        require(meta['repository']=='Harness-Engineering' and meta['predecessors']==['MET-PERF-011'] and meta['allowedPaths']==record['ownedPaths'], 'exact META owner')
        commands=meta['offlineAcceptanceCommands']
        require(len(commands)==40 and commands[:-3]+commands[-2:]==prior['offlineAcceptanceCommands']
                and commands[-3]==['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_document_repair_execution.py']
                and meta['offlineExecution']==prior['offlineExecution'], 'all predecessor commands retained')
        value=parse(inputs[SPEC_PATH]); validate_spec(value); validate_artifacts(value,inputs)
        source=parse(inputs[INPUT_PREFIX+'source-scope.json'])
        product=packets['CONF-PERF-006']; bench=packets['CONF-BENCH-002']
        require(product['allowedPaths']==source['productAllowedPaths'] and len(product['allowedPaths'])==3
                and product['offlineAcceptanceCommands']==packets['CONF-FIX-007']['offlineAcceptanceCommands'], 'three paths and full eight-command product recipe')
        require(bench['allowedPaths']==source['productAllowedPaths'][:1] and bench['offlineAcceptanceCommands']==[['python3','-c',inputs[INPUT_PREFIX+'benchmark.py.txt'].decode()]], 'read-only literal comparison')
        for name in NEW_IDS:
            p=packets[name]
            require(p['sourceReuse']==p['prefetchCommands']==[] and p['warmSourceAccess']=='PROHIBITED_DURING_IMPLEMENTATION'
                    and p['offlineExecution']==prior['offlineExecution'] and 'liveCampaignExecution' not in p, 'no live/warm/online authority')
        for path,checksum in value['contractPins'].items(): require(digest(runner_history(path,inputs[path]))==checksum, 'immutable contract')
        for path,rule in record['metaRecipes'].items():
            before=historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule)==transport_history(path,runner_history(path,inputs[path])), 'exact reversible metadata')
            if path.startswith('tests/'): require(test_ids(before)==test_ids(inputs[path]), 'all inherited test identities')
        for path in record['navigationPaths']:
            require(all(s in inputs[path] for s in (b'DOCUMENT_REPAIR_AUTHORITY.md',b'MET-PERF-012',b'CONF-PERF-006',b'CONF-BENCH-002',b'WAITING_META',b'BLOCKED_LOCAL_BUDGET_EXHAUSTED',b'HARNESS_PAPER_REPOSITORY_MAP.md',b'NOT_DUE')), 'consistent current roadmap')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid document repair execution authority: '+str(exc)]


if __name__=='__main__':
    packets={p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors=validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Historical document repair execution valid:194 current specifications;173-packet projection; product and comparison not run.')
