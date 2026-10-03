"""META-only completion policy tests. No product import, credential or probe."""
from copy import deepcopy
import pytest
from scripts.validate_research_adoption import historical_bytes as research_history
from scripts import validate_conformance_completion as module
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_exact_amendment_preserves163_packets_and_inherited_tests(authority):
    assert module.validate_authority(*authority) == []
    packets,record,inputs = authority
    assert len(packets) == 194 and module.NEW_IDS == ('MET-REPAIR-017','CONF-FIX-007')
    for path,rule in record['metaRecipes'].items():
        before = module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule) == research_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('fault',['old-packet','new-meta','new-product','commands','missing','extra','record','source','guide','extra-owner'])
def test_packet_source_or_scope_substitution_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'old-packet': inputs['task-packets/CONF-LIVE-004.yaml'] += b' '
    if fault == 'new-meta': packets['MET-REPAIR-017']['predecessors'] = []
    if fault == 'new-product': packets['CONF-FIX-007']['allowedPaths'].append('src/')
    if fault == 'commands': packets['CONF-FIX-007']['offlineAcceptanceCommands'].pop()
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['undeclared'] = b'x'
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'source': inputs['scripts/validate_packet_ownership.py'] += b'\n'
    if fault == 'guide': inputs['docs/alpha-2/CONFORMANCE_COMPLETION.md'] += b'\n'
    if fault == 'extra-owner': packets['CONF-FIX-008'] = deepcopy(packets['CONF-FIX-007'])
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('key',['schemaVersion','metaPacketId','correctivePacketId','metaBase','baseline','publication','product','completion','effectivePredecessors','contractPins','recipe','allowances','gates'])
def test_resealed_specification_member_change_refuses(authority,key):
    spec = module.parse(authority[2][module.SPEC_PATH]); spec[key] = 'CHANGED'
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('fault',['callback','new-path','delete-test','old-budget','more-local','more-ci','more-main','no-correction','no-review','native','root','timeout','filter','missing-command','weaken-contract'])
def test_nested_completion_or_execution_boundary_refuses(authority,fault):
    spec = module.parse(authority[2][module.SPEC_PATH])
    if fault == 'callback': spec['completion'][1]['requirement'] = 'delegate to004'
    if fault == 'new-path': spec['product']['allowedPaths'].append('ci/run_packet.py')
    if fault == 'delete-test': spec['product']['preserveTestIdentities'] = False
    if fault == 'old-budget': spec['allowances']['oldBudgetsReset'] = True
    if fault == 'more-local': spec['allowances']['LOCAL'] += 1
    if fault == 'more-ci': spec['allowances']['CI'] += 1
    if fault == 'more-main': spec['allowances']['LOCAL_EXACT_MAIN'] += 1
    if fault == 'no-correction': spec['effectivePredecessors']['CONF-LIVE-004'].pop()
    if fault == 'no-review': spec['gates']['completionReviewBeforeMerge'] = False
    if fault == 'native': spec['gates']['nativeAcceptance'] = True
    if fault == 'root': spec['gates']['rootPolicyChange'] = True
    if fault == 'timeout': spec['recipe']['trustedSeconds'] += 1
    if fault == 'filter': spec['recipe']['commands'][5] += ['-k','subset']
    if fault == 'missing-command': spec['recipe']['commands'].pop()
    if fault == 'weaken-contract': spec['contractPins'] = {}
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


def evidence_shape():
    value = dict(packetId='CONF-FIX-007',base='092fcf475c6f3ebd455e3c354cddb7664ea1f900',
                 localPassed=True,requiredCIPassed=True,protectedMerge=True,exactMainPassed=True,
                 remainingWork=[],reviewEvidenceSha256='1'*64,
                 evidenceClass='SOURCE_ONLY_REQUIRES_INDEPENDENT_AUTHENTICATION')
    for key in ('tree','reviewedTree','localTree','ciTree','mainTree'): value[key] = '1'*40
    value['completion'] = [dict(id='C'+str(i),sourceSymbols=['symbol'+str(i)],testIds=['test_'+str(i)],reviewed=True) for i in range(1,8)]
    return value


def test_valid_evidence_shape_returns_no_authority_and_does_not_mutate():
    value = evidence_shape(); before = deepcopy(value)
    assert module.validate_completion_evidence_shape(value) is None and value == before


@pytest.mark.parametrize('field',['localPassed','requiredCIPassed','protectedMerge','exactMainPassed'])
@pytest.mark.parametrize('bad',[False,1,None,'PASS'])
def test_each_source_gate_is_separate_and_boolean_exact(field,bad):
    value = evidence_shape(); value[field] = bad
    with pytest.raises(ValueError): module.validate_completion_evidence_shape(value)


@pytest.mark.parametrize('field',['reviewedTree','localTree','ciTree','mainTree'])
def test_assembly_review_ci_and_main_must_match_same_tree(field):
    value = evidence_shape(); value[field] = '2'*40
    with pytest.raises(ValueError): module.validate_completion_evidence_shape(value)


@pytest.mark.parametrize('fault',['old-packet','old-tree','zero-tree','remaining','missing-review','native-class','extra','missing-case','duplicate-case','unreviewed','no-symbol','no-test','duplicate-test'])
def test_publication_alone_or_unfinished_work_never_unblocks004(fault):
    value = evidence_shape()
    if fault == 'old-packet': value['packetId'] = 'CONF-LIVE-003'
    if fault == 'old-tree':
        for key in ('tree','reviewedTree','localTree','ciTree','mainTree'): value[key] = 'f5a25661c2df6c87e5d3429b0b5f62511c2e5988'
    if fault == 'zero-tree': value['tree'] = '0'*40
    if fault == 'remaining': value['remainingWork'] = ['C4']
    if fault == 'missing-review': value['reviewEvidenceSha256'] = '0'*64
    if fault == 'native-class': value['evidenceClass'] = 'NATIVE_PASS'
    if fault == 'extra': value['tenantAccepted'] = True
    if fault == 'missing-case': value['completion'].pop()
    if fault == 'duplicate-case': value['completion'][1] = deepcopy(value['completion'][0])
    if fault == 'unreviewed': value['completion'][0]['reviewed'] = False
    if fault == 'no-symbol': value['completion'][0]['sourceSymbols'] = []
    if fault == 'no-test': value['completion'][0]['testIds'] = []
    if fault == 'duplicate-test': value['completion'][0]['testIds'] = ['a','a']
    with pytest.raises(ValueError): module.validate_completion_evidence_shape(value)


def test_historical_publication_success_is_preserved_not_implementation(authority):
    spec = module.parse(authority[2][module.SPEC_PATH])
    assert spec['publication']['ciRun'] == 34828356129
    assert spec['publication']['offlineTestsPassed'] == 1277
    assert spec['publication']['sourcePublicationComplete'] is True
    assert spec['publication']['implementationComplete'] is False
    assert spec['allowances']['oldBudgetsReset'] is False
    assert spec['gates']['nativeAcceptance'] is spec['gates']['tenantAcceptance'] is False


def test_fresh_authority_read_cannot_cache_success(monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls = []
    def read(root,path):
        calls.append(path); return raw if len(calls) == 1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-REPAIR-017'
    with pytest.raises(ValueError): module._record()
    assert len(calls) == 2


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}'])
def test_duplicate_or_nonfinite_input_refuses(raw):
    with pytest.raises(ValueError): module.parse(raw)
