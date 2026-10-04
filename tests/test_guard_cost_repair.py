"""META-only guard-cost authority regressions; no product import or execution."""
from copy import deepcopy
import pytest
from scripts import validate_guard_cost_repair as module
from scripts.validate_accounting_scope import historical_bytes as accounting_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_current_authority_and_reversible_history(authority):
    packets,record,inputs = authority
    assert module.validate_authority(*authority) == []
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 179
    for p,rule in record['metaRecipes'].items():
        before = module.historical_bytes(p,inputs[p])
        assert module.apply_recipe(before,rule) == accounting_history(p,inputs[p])
        if p.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[p])
            assert module.current_test_bytes(before) == inputs[p]


@pytest.mark.parametrize('key',['subject','diagnostic','repairPolicy','budgets','limits','gates','testAccounting','dispatchOverlaps','preservedArtifacts','productExecutionInMetaRun','productAcceptance','nativeAcceptance','tenantAcceptance','phaseComplete'])
def test_resealed_scope_or_budget_change_refuses(authority,key):
    value = module.parse(authority[2][module.SPEC_PATH]); value[key] = None
    with pytest.raises(ValueError): module.validate_spec(value,bind=False)


@pytest.mark.parametrize('fault',['record','missing','extra','old','meta','product','source','audit','guide','result'])
def test_substituted_input_or_packet_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['unknown'] = b'x'
    if fault == 'old': packets['CONF-FIX-008']['objective'] += 'x'
    if fault == 'meta': packets['MET-PERF-015']['offlineAcceptanceCommands'].pop()
    if fault == 'product': packets['CONF-FIX-009']['allowedPaths'].append('src/')
    if fault == 'source': inputs[module.SOURCE] += b' '
    if fault == 'audit': inputs[module.AUDIT] += b' '
    if fault == 'guide': inputs['docs/alpha-2/GUARD_COST_REPAIR.md'] += b' '
    if fault == 'result': inputs['architecture/guard-cost-repair-inputs/diagnostic01-result.json'] += b' '
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['missing','extra','changed','historical-only'])
def test_current_catalog_before_history(authority,fault):
    packets = deepcopy(authority[0])
    if fault == 'missing': packets.pop('CONF-FIX-009')
    if fault == 'extra': packets['UNKNOWN-001'] = {}
    if fault == 'changed': packets['MET-PERF-015']['predecessors'] = []
    if fault == 'historical-only': packets = module.historical_catalog(packets)
    with pytest.raises(ValueError): module.historical_catalog(packets)


def test_exact_overlap_closure_retains_unknown_and_duplicate_errors(authority):
    packets = authority[0]; value = module.parse(authority[2][module.SPEC_PATH])
    errors = ['unordered same-repository packets '+r['left']+' and '+r['right']+' overlap at '+repr(r['path'])+' and '+repr(r['path']) for r in value['dispatchOverlaps']]
    assert module.close_guard_dispatch(packets,errors+['other']) == ['other']
    for bad in [[],errors[:-1],errors+errors[:1]]:
        assert module.close_guard_dispatch(packets,bad) == bad+['missing or changed guard repair dispatch']


def test_fresh_bytes_not_cached(authority,monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls=[]
    def read(root,path):
        calls.append(path); return raw if len(calls)==1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PERF-015'
    with pytest.raises(ValueError): module._record()


def test_partial_diagnostic_is_not_product_acceptance(authority):
    audit = module.parse(authority[2][module.AUDIT])
    assert audit['completedCases'] + 1 + audit['notStartedCases'] == audit['expectedCases'] == 1447
    assert audit['sampledCompleted'] == 0 and audit['sampledStarted'] == 1
    assert audit['lastProgress']['callEvents'][3] == 2362068 and audit['lastProgress']['callEvents'][9] == 0
    assert audit['productAcceptance'] is audit['nativeAcceptance'] is audit['tenantAcceptance'] is False


def test_repair_keeps_old_allowances_and_review_boundary(authority):
    spec = module.parse(authority[2][module.SPEC_PATH])
    assert spec['budgets']['oldDiagnosticRetries'] == 0 and spec['budgets']['oldProductLocal2Held']
    assert not spec['budgets']['resetOld'] and not spec['budgets']['transfer']
    assert spec['gates']['independentC1C7DesignReview'] and spec['gates']['independentC1C7CandidateReview']
    assert spec['repairPolicy']['unprovenEquivalence'] == 'STOP_NOT_WAIVE'
    assert not any(spec['repairPolicy'][k] for k in ('clockChange','watchdogChange','fixtureMigration','documentChange','sixthPath'))
