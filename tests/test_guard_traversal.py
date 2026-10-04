"""META successor publication only; no product import, collection or execution."""
from copy import deepcopy
import pytest
from scripts import validate_guard_traversal as module
from scripts.validate_observation_enforcement import historical_bytes as observation_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_current_authority_and_reversible_history(authority):
    packets,record,inputs = authority
    assert module.validate_authority(*authority) == []
    value = module.parse(inputs[module.SPEC_PATH])
    errors = ['unordered same-repository packets '+r['left']+' and '+r['right']
              +' overlap at '+repr(r['path'])+' and '+repr(r['path'])
              for r in value['dispatchOverlaps']]
    assert len(errors) == len(set(errors)) == 8
    assert module.close_traversal_dispatch(packets, errors+['other']) == ['other']
    assert module.close_traversal_dispatch(packets, list(reversed(errors))) == []
    for bad in [[], errors[:-1], errors+errors[:1]]:
        assert module.close_traversal_dispatch(packets,bad) == bad+['missing or changed traversal dispatch']
    for name in ('CONF-FIX-010','CONF-FIX-007','CONF-BENCH-002','CONF-BENCH-003','CONF-DIAG-003'):
        changed = deepcopy(packets); changed[name]['objective'] += 'x'
        assert module.close_traversal_dispatch(changed,errors) == errors+['missing or changed traversal dispatch']
    changed_spec = deepcopy(value); changed_spec['dispatchOverlaps'] = []
    with pytest.raises(ValueError): module.validate_spec(changed_spec,bind=False)
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 182
    for p,rule in record['metaRecipes'].items():
        before = module.historical_bytes(p,inputs[p])
        assert module.apply_recipe(before,rule) == observation_history(p,inputs[p])
        if p.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[p])
            assert module.current_test_bytes(before) == inputs[p]


@pytest.mark.parametrize('key',['subject','accountingConsumers','designGate','budgets','limits','gates',
    'testAccounting','preservedArtifacts','productExecutionInMetaRun','productAcceptance',
    'nativeAcceptance','tenantAcceptance','phaseComplete'])
def test_resealed_scope_or_budget_change_refuses(authority,key):
    value = module.parse(authority[2][module.SPEC_PATH]); value[key] = None
    with pytest.raises(ValueError): module.validate_spec(value,bind=False)


@pytest.mark.parametrize('fault',['record','missing','extra','old','meta','product','source','guide'])
def test_substituted_input_or_packet_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['unknown'] = b'x'
    if fault == 'old': packets['CONF-FIX-009']['objective'] += 'x'
    if fault == 'meta': packets['MET-PERF-017']['offlineAcceptanceCommands'].pop()
    if fault == 'product': packets['CONF-FIX-010']['allowedPaths'].append('src/')
    if fault == 'source': inputs[module.SOURCE] += b' '
    if fault == 'guide': inputs['docs/alpha-2/GUARD_TRAVERSAL_REPAIR.md'] += b' '
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['missing','extra','changed','historical-only','wrong-owner'])
def test_current_catalog_before_history(authority,fault):
    packets = deepcopy(authority[0])
    if fault == 'missing': packets.pop('CONF-FIX-010')
    if fault == 'extra': packets['UNKNOWN-001'] = {}
    if fault == 'changed': packets['MET-PERF-017']['predecessors'] = []
    if fault == 'historical-only': packets = module.historical_catalog(packets)
    if fault == 'wrong-owner': packets['CONF-FIX-010']['repository'] = 'Harness-Engineering'
    with pytest.raises(ValueError): module.historical_catalog(packets)


def test_fresh_bytes_not_cached(authority,monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls=[]
    def read(root,path):
        calls.append(path); return raw if len(calls)==1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PERF-017'
    with pytest.raises(ValueError): module._record()


def test_failure_is_not_acceptance_or_budget_reset(authority):
    value = module.parse(authority[2][module.SPEC_PATH])
    source = module.parse(authority[2][module.SOURCE])
    assert source['exitCode'] == 247 and source['localConsumed'] == 2
    assert source['completedSuiteTests'] == 170 and not source['backendComplete']
    assert value['budgets']['oldProductLocalConsumed'] == 2
    assert not value['budgets']['resetOld'] and not value['budgets']['transfer']
    assert value['budgets']['meta'] == dict(LOCAL=3,CI=2,LOCAL_EXACT_MAIN=1)
    assert value['budgets']['conditionalProduct'] == dict(LOCAL=2,CI=2,LOCAL_EXACT_MAIN=1)
    amendment = value['localAllowanceAmendment']
    assert amendment['approved'] is True and amendment['oldAttemptsRetained'] is True
    assert (amendment['priorCeiling'],amendment['ceiling'],amendment['consumedBeforeAmendment'],
            amendment['additionalAttempts']) == (2,3,2,1)
    assert amendment['changedStages'] == ['LOCAL']
    assert not amendment['timeLimitsChanged'] and not amendment['productAuthorityChanged']
    changed = deepcopy(value); changed['localAllowanceAmendment']['consumedBeforeAmendment'] = 0
    with pytest.raises(ValueError): module.validate_spec(changed,bind=False)
    assert not any(value[k] for k in ('productExecutionInMetaRun','productAcceptance',
                                     'nativeAcceptance','tenantAcceptance','phaseComplete'))


def test_five_accounting_consumers_and_unchanged_temporal_gate(authority):
    value = module.parse(authority[2][module.SPEC_PATH])
    assert value['accountingConsumers'] == [
        '_doc_current_sources','DocumentRepairTests.test_consumer_history_preserved',
        'CompletionIntegrationSourceTests.setUp','GuardCostSourceTests.setUp',
        'GuardCostSourceTests.test_actual_unfiltered_collection_matches_current_ast']
    assert value['designGate']['unprovenEquivalence'] == 'STOP_NOT_WAIVE'
    assert not value['designGate']['safeDesignEstablished']
    assert value['gates']['independentC1C7DesignReview'] and value['gates']['independentC1C7CandidateReview']
    assert value['limits'] == dict(localSeconds=750,nestedSeconds=420,trustedSeconds=900,workflowMinutes=15)


def test_product_recipe_and_all_previous_packets_preserved(authority):
    packets,record,inputs = authority
    historical = module.historical_catalog(packets)
    assert len(historical) == 182
    assert historical['CONF-FIX-009'] == packets['CONF-FIX-009']
    assert packets['CONF-FIX-010']['offlineAcceptanceCommands'] == historical['CONF-FIX-009']['offlineAcceptanceCommands']
    assert packets['CONF-FIX-010']['allowedPaths'] == historical['CONF-FIX-009']['allowedPaths']
    assert len(packets['MET-PERF-017']['offlineAcceptanceCommands']) == 46
    assert all('task-packets/'+name+'.yaml' in record['protectedFiles'] for name in historical)


def test_history_refuses_current_tampering_before_projection(authority):
    for path,rule in authority[1]['metaRecipes'].items():
        with pytest.raises(ValueError):
            module.historical_bytes(path,authority[2][path]+b' ')
