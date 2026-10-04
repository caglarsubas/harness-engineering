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
    from validate_canonical_repair_plan import historical_bytes as repair_history, current_test_bytes as repair_current, validate_additions as repair_additions
except ImportError:
    from scripts.validate_canonical_repair_plan import historical_bytes as repair_history, current_test_bytes as repair_current, validate_additions as repair_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/proxy-diagnostics-authority.json"
RECORD_SHA256 = "3fd7313be067b32677adafec516c7f467bb8f147ffcfe84c192f10ef5a509a80"
NEW_IDS = ("MET-PERF-006", "CONF-DIAG-001")
RECORD_FILE_SHA256 = "4c0fe90fa317a3c0b102710d86a3c9795244bcf0505fdebb21899905f3c3628b"
HISTORY_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_broker_handoff.py","scripts/validate_ci_performance.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_provider_adoption.py","scripts/validate_proxy_contract.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_broker_handoff.py","tests/test_ci_performance.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_provider_adoption.py","tests/test_proxy_contract.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


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


SPEC_PATH = "architecture/proxy-diagnostics.json"
GUIDE_PATH = "docs/alpha-2/PROXY_PERFORMANCE_DIAGNOSTICS.md"
EXPECTED_SPEC_SHA256 = "3e058dae996027d72faf3e818a8ef12dd2f6d375202b9620068999bc654a2cc6"
EXPECTED_TEST_IDS_SHA256 = "e33f0745fbce712f32d5f9469b0805f9cdcf21e24f5e8df354208e31702adb07"
COMMANDS = parse("[[\"python3\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/live_backend\",\"-p\",\"test_proxy_server.py\",\"-k\",\"BrokerCreateRetirementTests\",\"-v\"],[\"python3\",\"-m\",\"cProfile\",\"-s\",\"cumulative\",\"-m\",\"unittest\",\"discover\",\"-s\",\"tests/live_backend\",\"-p\",\"test_proxy_server.py\",\"-k\",\"BrokerCreateRetirementTests\",\"-v\"]]")


OVERLAP = "unordered same-repository packets CONF-DIAG-001 and CONF-LIVE-003 overlap at 'tests/live_backend/test_proxy_server.py' and 'tests/live_backend/test_proxy_server.py'"


def validate_spec(spec, *, bind=True):
    """Planning data only. Never authenticates or executes a diagnostic run."""
    require(type(spec) is dict and set(spec) == {
        'schemaVersion', 'evidenceClass', 'packetId', 'sourceOwner', 'sourceEdits',
        'requiresBranchOrPr', 'acceptedSourcePredecessor', 'diagnosticIsAcceptance',
        'optimizationAuthorized', 'subject', 'remoteCheckpoint', 'recipe',
        'failures', 'diagnosticSample', 'gates'}, 'closed diagnostic specification')
    if bind:
        require(digest(canonical(spec)) == EXPECTED_SPEC_SHA256, 'exact diagnostic specification')
    require(spec['schemaVersion'] == 'planeon.internal.proxy-diagnostics/v1'
            and spec['evidenceClass'] == 'DIAGNOSTIC_PLAN_ONLY'
            and spec['packetId'] == 'CONF-DIAG-001'
            and spec['sourceOwner'] == 'CONF-LIVE-003', 'measurement identity')
    for key in ('sourceEdits', 'requiresBranchOrPr', 'acceptedSourcePredecessor',
                'diagnosticIsAcceptance', 'optimizationAuthorized'):
        require(spec[key] is False, 'no source or acceptance authority: '+key)
    subject = spec['subject']
    require(type(subject) is dict and set(subject) == {
        'repository', 'commit', 'tree', 'sourceStatus', 'fullAcceptance',
        'fullTestInventory', 'backendTestInventory', 'inventory',
        'inventoryDataSha256'}, 'closed subject')
    fixed = {k:v for k,v in subject.items() if k not in ('inventory', 'inventoryDataSha256')}
    require(canonical(fixed) == canonical({
        'repository':'mas-harness-conformance-labs',
        'commit':'7939626dc6aec99b58816e3a709fd0babf3a985f',
        'tree':'f5a25661c2df6c87e5d3429b0b5f62511c2e5988',
        'sourceStatus':'LOCAL_UNACCEPTED_NOT_PUSHED', 'fullAcceptance':False,
        'fullTestInventory':1277, 'backendTestInventory':1107}), 'exact unaccepted subject')
    inventory = subject['inventory']
    require(type(inventory) is list and len(inventory) == 135, 'complete135 source inventory')
    paths = []
    for row in inventory:
        require(type(row) is dict and set(row) == {'mode','path','sha256','size'}, 'closed inventory row')
        path = row['path']
        require(type(path) is str and path and not path.startswith('/')
                and all(p not in ('','.','..') for p in path.split('/')), 'canonical relative source')
        require(row['mode'] in ('100644','100755') and type(row['size']) is int
                and 0 <= row['size'] <= 16777216 and type(row['sha256']) is str
                and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'source mode size hash')
        paths.append(path)
    require(paths == sorted(set(paths)) and subject['inventoryDataSha256'] == digest(canonical(inventory)), 'ordered bound source inventory')
    require(canonical(spec['remoteCheckpoint']) == canonical({
        'main':'f988c78e93b28257810ed99e7f0c072e9b76bae5',
        'head':'699a00c2d26e36c9c710aa85d0338f0d926073f2',
        'pr':12,'draft':True,'merged':False}), 'remote is not diagnostic subject')
    recipe = spec['recipe']
    require(type(recipe) is dict and set(recipe) == {
        'commands','selectedTestIds','counts','skips','prefetchCommands','profile',
        'profiler','output','scope','successfulPairsMaximum','unchangedRetriesMaximum',
        'timeoutSeconds','nestedTimeoutSeconds','workflowTimeoutMinutes'}, 'closed recipe')
    require(canonical({k:v for k,v in recipe.items() if k != 'selectedTestIds'}) == canonical({
        'commands':COMMANDS,'counts':[40,40],'skips':0,'prefetchCommands':[],
        'profile':'python-conformance-stdlib',
        'profiler':'STDLIB_CPROFILE_CLI_DEFAULTS_SUBCALLS_AND_BUILTINS',
        'output':'STDOUT_COMPLETE_STATS_NO_PICKLE_FILE',
        'scope':'DISCOVERY_IMPORT_FIXTURE_TEST_CLEANUP_FOR_SELECTED_CLASS_ONLY',
        'successfulPairsMaximum':3,'unchangedRetriesMaximum':1,
        'timeoutSeconds':900,'nestedTimeoutSeconds':420,'workflowTimeoutMinutes':15}), 'fixed commands and measurement bounds')
    ids = recipe['selectedTestIds']
    require(type(ids) is list and len(ids) == 40 and ids == sorted(set(ids))
            and all(type(i) is str and i.startswith('test_proxy_server.BrokerCreateRetirementTests.test_') for i in ids)
            and digest(canonical(ids)) == EXPECTED_TEST_IDS_SHA256, 'exact40 selected identities')
    failures = spec['failures']
    require(type(failures) is list and len(failures) == 3, 'all failed attempts retained')
    for index, row in enumerate(failures):
        require(type(row) is dict and set(row) == {'label','activation','commit','exitCode',
            'elapsedSeconds','logSha256','requestSha256','sourceInventorySha256',
            'status','commandsSevenEight','fullAcceptance'}, 'closed failure row')
        require(row['label'] == 'candidate0'+str(index+1) and type(row['activation']) is int
                and row['activation'] == 252+index and type(row['exitCode']) is int
                and row['exitCode'] != 0 and row['commandsSevenEight'] == 'NOT_RUN'
                and row['fullAcceptance'] is False
                and row['status'] == ('FAILED_NEW_TEST' if index == 0 else 'TIMEOUT_NOT_PASS'), 'failure cannot become acceptance')
        require(type(row['elapsedSeconds']) in (int,float) and 0 < row['elapsedSeconds'] < 950
                and type(row['logSha256']) is str and re.fullmatch('[0-9a-f]{64}',row['logSha256']), 'bounded failed-run data')
        require(all(type(row[k]) is str and re.fullmatch('[0-9a-f]{64}',row[k])
                    for k in ('requestSha256','sourceInventorySha256')), 'retained request and inventory hashes')
    require(canonical(spec['diagnosticSample']) == canonical({
        'sha256':'0d0074a385636e59694414e4b52aef04b5a11213fd9f81e8c120f431397a162f',
        'status':'ONE_SECOND_OS_SAMPLE_NOT_ROOT_CAUSE'}), 'sample is not root cause')
    require(canonical(spec['gates']) == canonical({
        'metaSourceGatesRequired':True,'independentSignedCustodyRequired':True,
        'actualSourceInventoryBeforeAfterRequired':True,'completePairRequired':True,
        'partialPooling':False,'hostChanges':False,'uninterruptedAwakeIntervalRequired':True,
        'thermalEmergencyIntervalRejected':True,'sourceOverlays':False,
        'timeoutIncrease':False,'productAcceptanceCommandsUnchanged':True,
        'newRepairPacketRequired':True,'nativeQualification':'NOT_RUN_ENV_UNAVAILABLE',
        'tenantAcceptance':False,'modelEffortTransition':'NOT_DUE'}), 'unchanged acceptance and repair gates')


def close_diagnostic_dispatch(packets, errors):
    """Remove one exact read-only input overlap, never general ownership errors."""
    try:
        require(type(errors) is list and all(type(e) is str for e in errors), 'diagnostic list')
        record = _record()
        require(validate_additions(packets) == [], 'exact new packets')
        path = 'task-packets/CONF-LIVE-003.yaml'
        raw = regular_bytes(ROOT, path)
        require(digest(raw) == record['protectedFiles'][path]
                and canonical(packets.get('CONF-LIVE-003')) == canonical(safe_load(raw)), 'unchanged source owner')
        require(packets['CONF-DIAG-001']['allowedPaths'] == ['tests/live_backend/test_proxy_server.py']
                and packets['CONF-DIAG-001']['offlineAcceptanceCommands'] == COMMANDS,
                'exact read-only input and recipe')
        require(errors.count(OVERLAP) == 1, 'exact single read-only overlap')
        return [e for e in errors if e != OVERLAP]
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        return list(errors) + ['missing or changed closed proxy diagnostic dispatch']


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record, {p: regular_bytes(root,p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact history routing')
        require(validate_additions(packets) == [], 'packet binding')
        pins = {**record['protectedFiles'], **record['inputFiles'],
                **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'exact fresh input inventory')
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(repair_history(path, inputs[path])) == checksum, 'changed source: '+path)
        old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old) == 156 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {'MET-PERF-007', 'MET-PERF-008', 'CONF-DIAG-002', 'MET-ACCEPT-001', 'MET-PUBLISH-001', 'MET-REPAIR-017', 'CONF-FIX-007', 'MET-ADOPT-002', 'MET-PERF-010', 'MET-PERF-009', 'CONF-DIAG-003', 'MET-PERF-011', 'MET-PERF-012', 'CONF-PERF-006', 'CONF-BENCH-002', 'MET-PERF-013', 'CONF-BENCH-003', 'MET-REPAIR-018', 'CONF-FIX-008', 'MET-PERF-014', 'CONF-DIAG-004', 'MET-PERF-015', 'CONF-FIX-009', 'MET-PERF-016', 'MET-PERF-017', 'MET-REPAIR-019', 'MET-ENFORCE-001', 'MET-PERF-018', 'MET-ENFORCE-003', 'CONF-FIX-010', 'MET-UNIFY-005', 'MET-RUNNER-001', 'MET-PERF-028', 'MET-LINUX-005', 'MET-VERIFY-001', 'MET-PERF-029'}, '169 specifications with156 immutable predecessors')
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'packet raw semantic binding')
        meta, replay = (packets[name] for name in NEW_IDS)
        require(meta['allowedPaths'] == record['ownedPaths'] and meta['predecessors'] == ['MET-ADOPT-001']
                and meta['sourceReuse'] == [], 'meta-only owner')
        commands, prior = meta['offlineAcceptanceCommands'], packets['MET-ADOPT-001']['offlineAcceptanceCommands']
        require(len(commands) == 30 and commands[:-3] == prior[:-2] and commands[-2:] == prior[-2:]
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_proxy_diagnostics.py'], 'all29 prior commands plus diagnostic validator')
        require(replay['allowedPaths'] == ['tests/live_backend/test_proxy_server.py']
                and replay['predecessors'] == ['MET-PERF-006','CONF-FIX-006']
                and replay['offlineAcceptanceCommands'] == COMMANDS and replay['prefetchCommands'] == []
                and replay['offlineExecution'] == packets['CONF-LIVE-003']['offlineExecution']
                and replay['sourceReuse'] == [] and 'liveCampaignExecution' not in replay, 'read-only fixed diagnostic role')
        for path, rule in record['metaRecipes'].items():
            before = historical_bytes(path, inputs[path])
            require(apply_recipe(before,rule) == repair_history(path, inputs[path]), 'reversible amendment')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'all old test identities retained')
        validate_spec(parse(inputs[SPEC_PATH]))
        for path in record['navigationPaths']:
            require(b'PROXY_PERFORMANCE_DIAGNOSTICS.md' in inputs[path]
                    and b'MET-PERF-006' in inputs[path], 'current navigation: '+path)
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError) as exc:
        return ['invalid proxy diagnostic authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors))
        raise SystemExit(1)
    print('Proxy diagnostic authority valid:158 specifications;156 immutable predecessors; no product execution or optimization.')
