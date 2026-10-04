"""META accounting amendment only; no product import, collection or execution."""
from copy import deepcopy
import pytest
from scripts import validate_accounting_scope as module
from scripts.validate_guard_traversal import historical_bytes as traversal_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_current_authority_and_reversible_history(authority):
    packets,record,inputs = authority
    assert module.validate_authority(*authority) == []
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 181
    for p,rule in record['metaRecipes'].items():
        before = module.historical_bytes(p,inputs[p])
        assert module.apply_recipe(before,rule) == traversal_history(p,inputs[p])
        if p.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[p])
            assert module.current_test_bytes(before) == inputs[p]


@pytest.mark.parametrize('key',['subject','accountingException','budgets','limits','gates','testAccounting','preservedArtifacts','productExecutionInMetaRun','productAcceptance','nativeAcceptance','tenantAcceptance','phaseComplete'])
def test_resealed_scope_or_budget_change_refuses(authority,key):
    value = module.parse(authority[2][module.SPEC_PATH]); value[key] = None
    with pytest.raises(ValueError): module.validate_spec(value,bind=False)


@pytest.mark.parametrize('fault',['record','missing','extra','old','meta','product','source','guide'])
def test_substituted_input_or_packet_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['unknown'] = b'x'
    if fault == 'old': packets['MET-PERF-015']['objective'] += 'x'
    if fault == 'meta': packets['MET-PERF-016']['offlineAcceptanceCommands'].pop()
    if fault == 'product': packets['CONF-FIX-009']['allowedPaths'].append('src/')
    if fault == 'source': inputs[module.SOURCE] += b' '
    if fault == 'guide': inputs['docs/alpha-2/ACCOUNTING_SCOPE_AMENDMENT.md'] += b' '
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['missing','extra','changed','historical-only','old-product'])
def test_current_catalog_before_history(authority,fault):
    packets = deepcopy(authority[0])
    if fault == 'missing': packets.pop('CONF-FIX-009')
    if fault == 'extra': packets['UNKNOWN-001'] = {}
    if fault == 'changed': packets['MET-PERF-016']['predecessors'] = []
    if fault == 'historical-only': packets = module.historical_catalog(packets)
    if fault == 'old-product': packets['CONF-FIX-009'] = module.historical_catalog(packets)['CONF-FIX-009']
    with pytest.raises(ValueError): module.historical_catalog(packets)


def test_fresh_bytes_not_cached(authority,monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls=[]
    def read(root,path):
        calls.append(path); return raw if len(calls)==1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PERF-016'
    with pytest.raises(ValueError): module._record()


def test_amendment_is_not_product_acceptance(authority):
    value = module.parse(authority[2][module.SPEC_PATH])
    source = module.parse(authority[2][module.SOURCE])
    assert source['status'] == 'STATIC_SCOPE_CONFLICT_NOT_TEST_RESULT'
    assert source['attemptsConsumed'] == 0 and not source['testsCollected']
    assert not any(value[k] for k in ('productAcceptance','nativeAcceptance','tenantAcceptance','phaseComplete'))


def test_single_exception_preserves_safety_and_old_budget(authority):
    value = module.parse(authority[2][module.SPEC_PATH])
    exception = value['accountingException']
    assert exception['additionalInheritedSymbol'] == 'CompletionIntegrationSourceTests.setUp'
    assert exception['preserveOldTestBodies'] == 18 and not exception['otherInheritedMigration']
    assert exception['preserveOldVerifier'] and exception['preserveOldProof']
    assert exception['currentFirst'] and exception['freshPhysicalDiscovery']
    assert value['budgets']['additionalProductAttempts'] == 0 and not value['budgets']['resetOld']
    assert value['gates']['independentC1C7DesignReview'] and value['gates']['independentC1C7CandidateReview']


def test_amended_packet_projects_only_after_current_validation(authority):
    packets,record,inputs = authority
    historical = module.historical_catalog(packets)
    assert historical['CONF-FIX-009']['predecessors'] == ['MET-PERF-015','CONF-FIX-008','CONF-DIAG-004']
    assert packets['CONF-FIX-009']['predecessors'] == ['MET-PERF-016',*historical['CONF-FIX-009']['predecessors']]
    raw = inputs[module.PRODUCT_PATH]
    for invalid in (raw+b' ', module.historical_bytes(module.PRODUCT_PATH,raw)):
        with pytest.raises(ValueError): module.historical_bytes(module.PRODUCT_PATH,invalid)
