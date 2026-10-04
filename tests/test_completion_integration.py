"""Independent META scope/history/evidence negatives; no product execution."""
import ast
from copy import deepcopy
import pytest
from scripts import validate_completion_integration as module
from scripts.validate_factory_diagnostics import historical_bytes as factory_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_complete_authority_and_reversible_current_history(authority):
    assert module.validate_authority(*authority) == []
    packets, record, inputs = authority
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 175
    for path,rule in record['metaRecipes'].items():
        old = module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(old,rule) == factory_history(path,inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(old) == module.test_ids(inputs[path])
            assert module.current_test_bytes(old) == inputs[path]


@pytest.mark.parametrize('key',['product','retiredPacket','effectivePredecessors','budgets','limits','dispatchOverlaps','preservedArtifacts','predecessorSourceGates','productExecutionInMetaRun','productAcceptance','nativeAcceptance','tenantAcceptance','phaseComplete','testAccounting','sourceAccountingSha256','proposalSha256'])
def test_resealed_spec_cannot_expand_scope(authority,key):
    value = module.parse(authority[2][module.SPEC_PATH]); value[key] = None
    with pytest.raises(ValueError): module.validate_spec(value,bind=False)


@pytest.mark.parametrize('fault',['record','missing','extra','old-packet','new-packet','recipe','source','guide','audit','accounting','closeout'])
def test_packet_and_current_source_substitution_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['undeclared'] = b'x'
    if fault == 'old-packet': packets['CONF-FIX-007']['objective'] += 'changed'
    if fault == 'new-packet': packets['CONF-FIX-008']['allowedPaths'].append('src/')
    if fault == 'recipe': packets['MET-REPAIR-018']['offlineAcceptanceCommands'].pop()
    if fault == 'source': inputs['scripts/validate_packet_ownership.py'] += b'\n'
    if fault == 'guide': inputs['docs/alpha-2/COMPLETION_INTEGRATION.md'] += b'\n'
    if fault == 'audit': inputs[module.AUDIT] += b' '
    if fault == 'accounting': inputs[module.ACCOUNTING] += b' '
    if fault == 'closeout': inputs[module.CLOSEOUT] += b' '
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['missing','extra','changed','historical-only'])
def test_current_catalog_must_precede_historical_projection(authority,fault):
    packets = deepcopy(authority[0])
    if fault == 'missing': packets.pop('CONF-FIX-008')
    if fault == 'extra': packets['UNKNOWN-001'] = {}
    if fault == 'changed': packets['MET-REPAIR-018']['predecessors'] = []
    if fault == 'historical-only': packets = module.historical_catalog(packets)
    with pytest.raises(ValueError): module.historical_catalog(packets)


def evidence():
    return dict(packetId='CONF-FIX-008',baseline='3a81c8ffb17be9e288c4368d443c57361d5a4fc8',
        tree='a'*40,reviewedTree='a'*40,localTree='a'*40,ciTree='a'*40,mainTree='a'*40,
        localPassed=True,requiredCIPassed=True,protectedMerge=True,exactMainPassed=True,
        remainingWork=[],reviewEvidenceSha256='b'*64,
        completion=[dict(id='C'+str(i),sourceSymbols=['symbol'+str(i)],testIds=['test_'+str(i)],reviewed=True) for i in range(1,8)],
        evidenceClass='SOURCE_ONLY_REQUIRES_INDEPENDENT_AUTHENTICATION')


def test_evidence_checker_returns_no_execution_or_readiness_token():
    assert module.completion_evidence(evidence()) is None


@pytest.mark.parametrize('fault',['old-packet','wrong-baseline','old-tree','draft-tree','zero-tree','tree-parity','local','ci','merge','main','remaining','missing-review','reviewed','empty-symbols','duplicate-tests','missing-obligation','reorder','extra-field','native-promotion','numeric-gate'])
def test_incomplete_or_mismatched_source_evidence_cannot_advance004(fault):
    value = evidence()
    if fault == 'old-packet': value['packetId'] = 'CONF-FIX-007'
    if fault == 'wrong-baseline': value['baseline'] = '0'*40
    if fault == 'old-tree': value['tree'] = '0627100bafa06443bfec1b4ab4ae17c86891186a'
    if fault == 'draft-tree': value['tree'] = '6f38052fb9a31e9fe8b9abb6b055ddd96f06854f'
    if fault == 'zero-tree': value['tree'] = '0'*40
    if fault == 'tree-parity': value['ciTree'] = 'c'*40
    if fault in ('local','ci','merge','main'): value[{'local':'localPassed','ci':'requiredCIPassed','merge':'protectedMerge','main':'exactMainPassed'}[fault]] = False
    if fault == 'remaining': value['remainingWork'] = ['cleanup']
    if fault == 'missing-review': value['reviewEvidenceSha256'] = '0'*64
    if fault == 'reviewed': value['completion'][0]['reviewed'] = False
    if fault == 'empty-symbols': value['completion'][0]['sourceSymbols'] = []
    if fault == 'duplicate-tests': value['completion'][0]['testIds'] *= 2
    if fault == 'missing-obligation': value['completion'].pop()
    if fault == 'reorder': value['completion'].reverse()
    if fault == 'extra-field': value['authorized'] = True
    if fault == 'native-promotion': value['evidenceClass'] = 'NATIVE_ACCEPTANCE'
    if fault == 'numeric-gate': value['localPassed'] = 1
    with pytest.raises(ValueError): module.completion_evidence(value)


def test_exact_retired_and_read_only_overlaps_preserve_unknown_errors(authority):
    packets = authority[0]; value = module.parse(authority[2][module.SPEC_PATH])
    errors = ['unordered same-repository packets '+r['left']+' and '+r['right']+' overlap at '+repr(r['path'])+' and '+repr(r['path']) for r in value['dispatchOverlaps']]
    assert len(errors) == len(set(errors)) == 8
    assert module.close_integration_dispatch(packets,errors+['unrelated']) == ['unrelated']
    for bad in [[],errors[:-1],errors+errors[:1]]:
        assert module.close_integration_dispatch(packets,bad) == bad+['missing or changed completion integration dispatch']
    for name in ('CONF-FIX-008','CONF-FIX-007','CONF-BENCH-002','CONF-BENCH-003','CONF-DIAG-003'):
        changed = deepcopy(packets); changed[name]['allowedPaths'].append('undeclared/')
        assert module.close_integration_dispatch(changed,errors) == errors+['missing or changed completion integration dispatch']


def test_fresh_authority_and_exact_inverse_refuse_mutations(authority,monkeypatch):
    path = 'tests/test_task_packets.py'; raw = authority[2][path]
    old = module.historical_bytes(path,raw)
    with pytest.raises(ValueError): module.historical_bytes(path,old)
    with pytest.raises(ValueError): module.historical_bytes(path,raw+b'\n')
    with pytest.raises(ValueError): module.current_test_bytes(b'def test_unknown(): pass\n')
    raw_record = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls=[]
    def read(root,path):
        calls.append(path); return raw_record if len(calls)==1 else raw_record+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-REPAIR-018'
    with pytest.raises(ValueError): module._record()


def test_no_product_execution_or_acceptance_promotion(authority):
    value = module.parse(authority[2][module.SPEC_PATH])
    assert value['productExecutionInMetaRun'] is value['productAcceptance'] is value['nativeAcceptance'] is value['tenantAcceptance'] is value['phaseComplete'] is False
    assert value['retiredPacket']['dispatchable'] is False
    assert value['budgets']['resetOld'] is value['budgets']['transfer'] is False
    tree = ast.parse((module.ROOT/'scripts/validate_completion_integration.py').read_bytes())
    forbidden = {'exec','eval','compile','__import__','Popen','system','CDLL','socket','syscall'}
    for node in ast.walk(tree):
        if isinstance(node,ast.Call):
            assert (node.func.id if isinstance(node.func,ast.Name) else getattr(node.func,'attr','')) not in forbidden
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            names = [n.name for n in node.names] if isinstance(node,ast.Import) else [node.module or '']
            assert not any(n.startswith(('harness_conformance','subprocess','ctypes','socket','cProfile')) for n in names)
