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
    from validate_completion_integration import historical_bytes as integration_history, current_test_bytes as integration_current, validate_additions as integration_additions, historical_catalog as integration_catalog
except ImportError:
    from scripts.validate_completion_integration import historical_bytes as integration_history, current_test_bytes as integration_current, validate_additions as integration_additions, historical_catalog as integration_catalog

try:
    from validate_ci_runner_admission import historical_bytes as runner_history
except ImportError:
    from scripts.validate_ci_runner_admission import historical_bytes as runner_history

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = 'architecture/benchmark-transport-authority.json'
RECORD_SHA256 = '6d81dac9a94a572c9e7c18a68395599434b9967643092c3c97b01751dc5d77c9'
NEW_IDS = ('MET-PERF-013', 'CONF-BENCH-003')
RECORD_FILE_SHA256 = '79d6d83847b99c72fda2007b8cab5edc88d4fb50da10122189db701f89016127'
HISTORY_PATHS = frozenset(['README.md', 'docs/DEVELOPMENT_STATUS.md', 'docs/MASTER_DEVELOPMENT_PLAN.md', 'docs/READINESS_INDEX.md', 'docs/alpha-2/CANONICAL_REPAIR_PLAN.md', 'docs/alpha-2/DOCUMENT_REPAIR_AUTHORITY.md', 'docs/alpha-2/LIVE_BACKEND_READINESS.md', 'docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md', 'docs/repositories/00-harness-engineering.md', 'docs/repositories/12-mas-harness-conformance-labs.md', 'scripts/validate_backend_timing.py', 'scripts/validate_broker_handoff.py', 'scripts/validate_canonical_repair_plan.py', 'scripts/validate_ci_performance.py', 'scripts/validate_completion_profiling.py', 'scripts/validate_conformance_completion.py', 'scripts/validate_conformance_consumer_closure.py', 'scripts/validate_conformance_performance.py', 'scripts/validate_conformance_performance_followup.py', 'scripts/validate_conformance_publication.py', 'scripts/validate_conformance_reference_measurement.py', 'scripts/validate_conformance_successor_checkpoint.py', 'scripts/validate_credential_lifecycle.py', 'scripts/validate_credential_ordering.py', 'scripts/validate_custody_handoff.py', 'scripts/validate_document_repair_execution.py', 'scripts/validate_linux_readiness.py', 'scripts/validate_linux_repair.py', 'scripts/validate_linux_test_ownership.py', 'scripts/validate_live_backend_readiness.py', 'scripts/validate_local_acceptance.py', 'scripts/validate_model_api_inventory.py', 'scripts/validate_model_fixture_scope.py', 'scripts/validate_native_qualification.py', 'scripts/validate_packet_scalar_repair.py', 'scripts/validate_policy_observation.py', 'scripts/validate_provider_adoption.py', 'scripts/validate_proxy_contract.py', 'scripts/validate_proxy_diagnostics.py', 'scripts/validate_readiness.py', 'scripts/validate_readiness_repairs.py', 'scripts/validate_research_adoption.py', 'scripts/validate_reuse.py', 'scripts/validate_successor_inventory.py', 'scripts/validate_validation_performance.py', 'task-packets/README.md', 'tests/test_alpha2_readiness.py', 'tests/test_backend_timing.py', 'tests/test_broker_handoff.py', 'tests/test_canonical_repair_plan.py', 'tests/test_ci_performance.py', 'tests/test_completion_profiling.py', 'tests/test_conformance_completion.py', 'tests/test_conformance_consumer_closure.py', 'tests/test_conformance_performance.py', 'tests/test_conformance_performance_followup.py', 'tests/test_conformance_publication.py', 'tests/test_conformance_reference_measurement.py', 'tests/test_conformance_successor_checkpoint.py', 'tests/test_credential_lifecycle.py', 'tests/test_credential_ordering.py', 'tests/test_custody_handoff.py', 'tests/test_document_repair_execution.py', 'tests/test_document_repair_plan.py', 'tests/test_linux_readiness.py', 'tests/test_linux_repair.py', 'tests/test_linux_test_ownership.py', 'tests/test_live_backend_readiness.py', 'tests/test_local_acceptance.py', 'tests/test_model_api_inventory.py', 'tests/test_model_fixture_scope.py', 'tests/test_native_qualification.py', 'tests/test_packet_scalar_repair.py', 'tests/test_policy_observation.py', 'tests/test_provider_adoption.py', 'tests/test_proxy_contract.py', 'tests/test_proxy_diagnostics.py', 'tests/test_research_adoption.py', 'tests/test_reuse.py', 'tests/test_successor_inventory.py', 'tests/test_task_packets.py', 'tests/test_validation_performance.py'])


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


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return integration_additions(packets)
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


SPEC_PATH = 'architecture/benchmark-transport.json'
SPEC_SHA256 = '9028a70ac9ec3ded2b03a86c35d99540bc1464a4d23171e4094c22e73b1daae8'
MEMBER_DIGESTS = {'schemaVersion': '149005847f4141490fbc7ef1db626f5718276e59da72034e9eb87e8ee62a1411', 'packetId': 'da8c1f00908e6350fe3dd5fe91ed6e253f257db6168edbf3fe8ccf7d5593c3d1', 'metaBase': '85aae609a9feca594f2c44520a0596fdb9db07fe6278b1b2f9f4bc258e2ff775', 'status': '0da9365f401908507ca93b0b0a3016a6beaadd8af1310b652f540dc34b73a11f', 'proposalSha256': '143ff8afe40e055b463ef00fe14ca89fbad39eb0cf6cb85c694c64bb2fdc4abd', 'predecessorSourceGates': '148ef77cc132ba19e8e2acd96d48c9681d6957057d719f870bfa85e622501335', 'baseline': '76a8e55f086613a99dc3d146274aa6e801e077268d80a78b21e283a5e4525c9a', 'candidate': 'b3a8ab9b2cea390147b4c513726816a42af7e7ccb0752000336da52a7bc4554f', 'comparison': '4d54708f4de21ab381d2f15c02f416b87ded55520ffb95cf78c78ca4b38c41a1', 'policy': '0fc7fc72cf4a834ec13252488d54a843be492374953493037767e96f0a6c34d1', 'budgets': '50331589713cca28e9438afe40a6220fa53aa6ab6352195f2a7a42d8019992c0', 'limits': '1ea4c4d72e5bfb8790d4e8873a32ffa2cf7810e040f564b44e0aa4512a96dd58', 'preservedArtifacts': 'bfa3e5a634bb5eed4e3d56c688d17262873f8507e12073c2208cd3b7a7956c8b', 'dispatchPairs': '157a1ba59b4002bd8261b2124bbd9fae3744b44a638930f4718f3f2bed89e257', 'productExecutionInMetaRun': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'productAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'benchmarkAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'testAccounting': '0f52c652d29a02bdae86090d806af446c4ec8dab2765834168ebd9ee8f5abe50'}
DRIVER = 'architecture/document-repair-execution-inputs/benchmark.py.txt'
FREEZE = 'architecture/benchmark-transport-inputs/candidate-freeze.json'


def historical_catalog(packets):
    record = _record(); pinned(record)
    require(validate_additions(packets) == [], 'exact transport successors')
    packets = integration_catalog(packets)
    old = {Path(p).stem for p in record['protectedFiles']
           if p.startswith('task-packets/') and p.endswith('.yaml')}
    require(len(old) == 173 and set(packets) == old | set(NEW_IDS), 'closed 175-packet catalog')
    return {name: packets[name] for name in old}


def validate_spec(value, *, bind=True):
    require(type(value) is dict and set(value) == set(MEMBER_DIGESTS), 'closed transport specification')
    if bind:
        require(digest(canonical(value)) == SPEC_SHA256, 'exact transport specification')
    for key, checksum in MEMBER_DIGESTS.items():
        require(digest(canonical(value[key])) == checksum, 'changed transport boundary: ' + key)
    require(value['budgets']['meta'] == {'LOCAL': 2, 'CI': 2, 'LOCAL_EXACT_MAIN': 1}, 'finite META gates')
    require(value['comparison']['maximumExecutions'] == 4 and value['comparison']['retries'] == 0
            and value['comparison']['schedule'] == ['BASELINE','CANDIDATE','CANDIDATE','BASELINE'], 'unchanged shared comparison')
    require(value['comparison']['retiredPacket'] == 'CONF-BENCH-002'
            and value['comparison']['activePacket'] == 'CONF-BENCH-003'
            and value['comparison']['sharedLedgerKey'] == 'DOCUMENT-COMPARISON-002'
            and value['comparison']['chargedPacketIds'] == ['CONF-BENCH-002','CONF-BENCH-003'], 'one shared budget, no reset')
    require(value['productExecutionInMetaRun'] is value['productAcceptance'] is value['benchmarkAcceptance'] is False,
            'publication is not execution or acceptance')


def argv_shape(commands):
    """Pure-data parity with pinned installed argument rules, never execute argv."""
    require(type(commands) is list and 1 <= len(commands) <= 64, 'acceptance command count')
    for argv in commands:
        require(type(argv) is list and 1 <= len(argv) <= 64, 'argv shape')
        require(all(type(a) is str and 0 < len(a) <= 4096 and not any(c in a for c in '\x00\r\n')
                    for a in argv), 'argv contents')
        require(Path(argv[0]).name not in {'sh','bash','zsh','dash','env','sudo','su'}, 'privileged/shell argv')
        require(not {'curl','wget','npx','prefetch','fetch','download','install','sync','add','pull'}
                .intersection(a.lower() for a in argv), 'online argv token')
        require(argv[:2] != ['make','verify-offline'], 'recursive wrapper')
        if argv[0] == 'uv':
            require({'--offline','--frozen','--no-sync'} <= set(argv), 'uv offline flags')


def validate_transport(commands, driver):
    argv_shape(commands)
    require(len(commands) == 1 and len(commands[0]) == 3 and commands[0][:2] == ['python3','-c'], 'exact Python entry')
    program = commands[0][2]
    require(digest(driver) == '2ae8a8ca39157ca7dd59158f86acdcea24e5fd7c755f8917bbf4af2fa0675995', 'unchanged driver')
    require(digest(program.encode()) == '435582160d2899fb68c2b70a08190e20c87edd434153006f375ad405915c5c4b', 'exact transport bytes')
    tree = ast.parse(program)
    require(len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr), 'single expression')
    call = tree.body[0].value
    require(isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'exec'
            and len(call.args) == 1 and not call.keywords and isinstance(call.args[0], ast.Constant)
            and type(call.args[0].value) is str, 'one literal, no dynamic input')
    require(call.args[0].value.encode() == driver and program == 'exec(' + repr(driver.decode()) + ')', 'exact literal roundtrip')


def next_comparison_slot(packet_id, value, reservations):
    """DATA_CHECK_ONLY; not signature, custody, prerequisite or execution authority."""
    validate_spec(value)
    c = value['comparison']
    require(packet_id == c['activePacket'], 'retired or unknown packet cannot dispatch')
    require(type(reservations) is list and len(reservations) < c['maximumExecutions'], 'shared comparison exhausted')
    for ordinal, row in enumerate(reservations, 1):
        require(type(row) is dict and set(row) == {'ordinal','packetId','subject','status'}, 'closed reservation data')
        require(type(row['ordinal']) is int and row['ordinal'] == ordinal
                and row['packetId'] in c['chargedPacketIds'] and row['subject'] == c['schedule'][ordinal-1], 'no holes, duplicates or foreign runs')
        require(row['status'] == 'COMPLETE', 'failed, partial or pending run forbids retries')
    return {'ordinal': len(reservations)+1, 'subject': c['schedule'][len(reservations)],
            'ledgerKey': c['sharedLedgerKey'], 'evidenceClass': 'DATA_CHECK_ONLY_NOT_AUTHORIZATION'}


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH)); pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record, {p: regular_bytes(root,p) for p in paths}


def close_transport_dispatch(packets, errors):
    """Only four pinned read-only overlaps; no source ownership or draft promotion."""
    try:
        record = _record(); pinned(record)
        historical_catalog(packets)
        value = parse(regular_bytes(ROOT,SPEC_PATH)); validate_spec(value)
        for name in ('CONF-BENCH-002','CONF-FIX-007','CONF-LIVE-003','CONF-PERF-006'):
            path = 'task-packets/'+name+'.yaml'
            raw = regular_bytes(ROOT,path)
            require(digest(raw) == record['protectedFiles'][path]
                    and canonical(safe_load(raw)) == canonical(packets[name]), 'preserved comparison neighbor')
        exact = set()
        for left,right in value['dispatchPairs']:
            paths = set(packets[left]['allowedPaths']) & set(packets[right]['allowedPaths'])
            require(paths == {'src/harness_conformance/live_mutation_admission.py'}, 'read-only subject only')
            exact.update('unordered same-repository packets '+left+' and '+right+' overlap at '+repr(p)+' and '+repr(p) for p in paths)
        require(len(exact) == 4 and all(errors.count(e) == 1 for e in exact), 'four exact diagnostics')
        return [e for e in errors if e not in exact]
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        return errors + ['missing or changed closed benchmark transport dispatch']


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact history routing')
        old = historical_catalog(packets)
        pins = {**record['protectedFiles'], **record['inputFiles'], **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'complete source inputs')
        for path,checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(integration_history(path,inputs[path])) == checksum, 'source drift: '+path)
        for name in integration_catalog(packets):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'packet byte parity')
        value = parse(inputs[SPEC_PATH]); validate_spec(value)
        meta,prior = packets['MET-PERF-013'],packets['MET-PERF-012']
        require(meta['repository'] == 'Harness-Engineering' and meta['predecessors'] == ['MET-PERF-012']
                and meta['allowedPaths'] == record['ownedPaths'], 'one META owner')
        commands = meta['offlineAcceptanceCommands']
        require(len(commands) == 41 and commands[:-3]+commands[-2:] == prior['offlineAcceptanceCommands']
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_benchmark_transport.py'], 'all forty predecessor commands retained')
        argv_shape(commands)
        bench = packets['CONF-BENCH-003']
        require(bench['repository'] == 'mas-harness-conformance-labs'
                and bench['predecessors'] == ['MET-PERF-013']
                and bench['allowedPaths'] == ['src/harness_conformance/live_mutation_admission.py'], 'read-only conditional successor')
        validate_transport(bench['offlineAcceptanceCommands'], inputs[DRIVER])
        old_command = old['CONF-BENCH-002']['offlineAcceptanceCommands']
        require(old_command == [['python3','-c',inputs[DRIVER].decode()]], 'old failed transport retained')
        try:
            argv_shape(old_command)
        except ValueError as exc:
            require(str(exc) == 'argv contents', 'expected installed refusal')
        else:
            raise ValueError('old multiline refusal absent')
        freeze = parse(inputs[FREEZE])
        require(freeze['head'] == value['candidate']['commit'] and freeze['tree'] == value['candidate']['tree']
                and freeze['baselineCommit'] == value['baseline']['commit'] and len(freeze['files']) == 135
                and freeze['preservedFiles'] == 132 and freeze['inheritedIds'] == 1277 and freeze['addedIds'] == 32
                and freeze['testsExecuted'] is freeze['benchmarkExecuted'] is False, 'exact source-only freeze')
        for name in NEW_IDS:
            p = packets[name]
            require(p['sourceReuse'] == p['prefetchCommands'] == []
                    and p['warmSourceAccess'] == 'PROHIBITED_DURING_IMPLEMENTATION'
                    and p['offlineExecution'] == prior['offlineExecution'] and 'liveCampaignExecution' not in p, 'unchanged offline boundary')
        for path,checksum in value['preservedArtifacts'].items():
            require(digest(runner_history(path, inputs[path])) == checksum, 'immutable driver, workload and source pins')
        for path,rule in record['metaRecipes'].items():
            before = historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule) == integration_history(path,inputs[path]), 'exact reversible metadata')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'all inherited test identities')
        for path in record['navigationPaths']:
            require(all(s in inputs[path] for s in (b'BENCHMARK_TRANSPORT.md',b'MET-PERF-013',b'CONF-BENCH-003',b'NON_DISPATCHABLE',b'CANDIDATE_FROZEN',b'HARNESS_PAPER_REPOSITORY_MAP.md',b'NOT_DUE')), 'consistent current roadmap')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid benchmark transport authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Historical benchmark transport valid:194 current specifications;175-packet projection; original comparison allowance unchanged.')
