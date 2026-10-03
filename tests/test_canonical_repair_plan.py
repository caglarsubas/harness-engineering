"""Independent planning refusals; no product imports, execution or run authentication."""
from copy import deepcopy
import pytest
from scripts.validate_backend_timing import historical_bytes as timing_history
from scripts import validate_canonical_repair_plan as module
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_exact_publication_preserves158_packets_and_all_test_identities(authority):
    assert module.validate_authority(*authority) == []
    packets,record,inputs = authority
    assert len(packets) == 194 and 'CONF-PERF-005' not in packets
    for path,rule in record['metaRecipes'].items():
        before = module.historical_bytes(path, inputs[path])
        assert module.apply_recipe(before,rule) == timing_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('fault',['old-packet','new-packet','product-grant','commands','missing','extra','record','source','guide'])
def test_source_and_packet_substitution_refuse(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'old-packet': inputs['task-packets/CONF-DIAG-001.yaml'] += b' '
    if fault == 'new-packet': packets['MET-PERF-007']['objective'] = 'changed'
    if fault == 'product-grant': packets['CONF-PERF-005'] = deepcopy(packets['CONF-PERF-004'])
    if fault == 'commands': packets['MET-PERF-007']['offlineAcceptanceCommands'].pop()
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['unauthorized'] = b'x'
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'source': inputs['scripts/validate_packet_ownership.py'] += b'\n'
    if fault == 'guide': inputs['docs/alpha-2/CANONICAL_REPAIR_PLAN.md'] += b'\n'
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['grant','ready','base','subject','root-cause','wall-time','unique-count','bool-count','pairs','retry','log','request','time','skip','cache','guard','crypto','speedup','semantics','consumer','extra'])
def test_planning_faults_refuse_without_outer_hash_binding(authority,fault):
    plan = module.parse(authority[2][module.SPEC_PATH])
    if fault == 'grant': plan['productGrant'] = True
    if fault == 'ready': plan['readiness'] = 'READY_TO_CODE'
    if fault == 'base': plan['productBase'] = plan['subject']
    if fault == 'subject': plan['subject'] = plan['productBase']
    if fault == 'root-cause': plan['fullTimeoutRootCause'] = 'CANONICALIZATION'
    if fault == 'wall-time': plan['individualCommandWall'] = 'MEASURED'
    if fault == 'unique-count': plan['uniqueTests'] = 240
    if fault == 'bool-count': plan['successfulPairs'] = True
    if fault == 'pairs': plan['remainingDiagnosticPairs'] = 1
    if fault == 'retry': plan['retriesUsed'] = 1
    if fault == 'log': plan['pairs'][0]['logSha256'] = '0'*64
    if fault == 'request': plan['pairs'][0]['requestSha256'] = '0'*64
    if fault == 'time': plan['pairs'][0]['unittestSeconds'][0] = 1.0
    if fault == 'skip': plan['pairs'][0]['skipped'] = 1
    if fault == 'cache': plan['candidate']['crossCallCache'] = True
    if fault == 'guard': plan['candidate']['guardRemoval'] = True
    if fault == 'crypto': plan['candidate']['cryptoChange'] = True
    if fault == 'speedup': plan['candidate']['speedup'] = 'PROVEN'
    if fault == 'semantics': plan['candidate']['publicSemantics'] = 'ALLOW_CHANGE'
    if fault == 'consumer': plan['consumerPaths'].pop()
    if fault == 'extra': plan['allowedPaths'] = ['src/']
    with pytest.raises(ValueError): module.validate_plan(plan,bind=False)


@pytest.mark.parametrize('key', ['exactConsumerBridgeRequired','independentSemanticOraclesRequired','fixedMatchedUnprofiledBenchmarkRequired','fullEightCommandsRequired','timeoutSeconds','nestedTimeoutSeconds','workflowTimeoutMinutes','productSkips','diagnosticBudgetReset','proxyRetryReset','currentSourceBeforeHistory','storedSourceExecution','sourceCiMergeExactMainSeparate','native','tenantAcceptance','billingChange','rootPolicyChange','modelEffortTransition'])
def test_every_delivery_gate_is_closed_even_when_resealed(authority,key):
    plan = module.parse(authority[2][module.SPEC_PATH])
    old = plan['gates'][key]
    plan['gates'][key] = not old if type(old) is bool else old+1 if type(old) is int else 'PASS'
    with pytest.raises(ValueError): module.validate_plan(plan,bind=False)


def test_measurement_is_repeated_scope_not_source_or_native_acceptance(authority):
    plan = module.parse(authority[2][module.SPEC_PATH])
    module.validate_plan(plan)
    assert plan['executions'] == 240 and plan['uniqueTests'] == 40
    assert plan['remainingDiagnosticPairs'] == 0 and not plan['productGrant']
    assert plan['fullTimeoutRootCause'] == 'NOT_ESTABLISHED'
    assert plan['candidate']['speedup'] == 'NOT_MEASURED'


def test_fresh_authority_read_refuses_second_read_substitution(monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH)
    calls = []
    def read(root,path):
        calls.append(path)
        return raw if len(calls) == 1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PERF-007'
    with pytest.raises(ValueError): module._record()
    assert len(calls) == 2
