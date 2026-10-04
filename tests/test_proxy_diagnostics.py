"""Independent planning/dispatch negatives, not product measurement evidence."""
from copy import deepcopy
import pytest
from scripts.validate_canonical_repair_plan import historical_bytes as repair_history
from scripts import validate_proxy_diagnostics as module
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_exact_authority_preserves_all156_packet_bytes(authority):
    assert module.validate_authority(*authority) == []
    packets,record,inputs = authority
    assert len(packets) == 194
    assert len([p for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')]) == 156
    assert packets['CONF-LIVE-003']['offlineAcceptanceCommands'] == packets['CONF-PERF-004']['offlineAcceptanceCommands']
    for path,rule in record['metaRecipes'].items():
        before = module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule) == repair_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


def test_spec_has_same40_ids_two_modes_and_no_repair_authority(authority):
    spec = module.parse(authority[2][module.SPEC_PATH])
    module.validate_spec(spec)
    assert len(spec['recipe']['selectedTestIds']) == 40
    assert spec['recipe']['counts'] == [40,40]
    assert spec['optimizationAuthorized'] is False
    assert spec['sourceEdits'] is False
    assert all(row['fullAcceptance'] is False for row in spec['failures'])


@pytest.mark.parametrize('fault',['old-packet','new-packet','source-owner','scope','commands','input','missing','extra','record'])
def test_tampered_source_authority_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'old-packet': inputs['task-packets/CONF-LIVE-003.yaml'] += b' '
    if fault == 'new-packet': packets['CONF-DIAG-001']['objective'] = 'substitute'
    if fault == 'source-owner': packets['CONF-LIVE-003']['allowedPaths'].append('src/harness_conformance/crypto.py')
    if fault == 'scope': packets['MET-PERF-006']['allowedPaths'].append('product/')
    if fault == 'commands': packets['MET-PERF-006']['offlineAcceptanceCommands'].pop()
    if fault == 'input': inputs[module.SPEC_PATH] += b' '
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['unapproved'] = b'anything'
    if fault == 'record': record['metaBaseline'] = 'wrong'
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['source-write','branch','predecessor','acceptance','optimize','subject','tree','source-pass','bool-count','inventory-count','inventory-link','inventory-duplicate','inventory-hash','selector','profile','skips','timeout','nested-timeout','workflow-timeout','retry','pair-count','test-id','test-count','failure-pass','missing-failure','sample-cause','pooling','overlay','repair-gate','signed-custody','native','tenant','sleep','thermal','extra'])
def test_semantic_faults_refuse_even_with_outer_hash_binding_disabled(authority,fault):
    spec = module.parse(authority[2][module.SPEC_PATH])
    flags = {'source-write':'sourceEdits','branch':'requiresBranchOrPr','predecessor':'acceptedSourcePredecessor','acceptance':'diagnosticIsAcceptance','optimize':'optimizationAuthorized'}
    if fault in flags: spec[flags[fault]] = True
    if fault == 'subject': spec['subject']['commit'] = spec['remoteCheckpoint']['head']
    if fault == 'tree': spec['subject']['tree'] = '0'*40
    if fault == 'source-pass': spec['subject']['fullAcceptance'] = True
    if fault == 'bool-count': spec['subject']['fullTestInventory'] = True
    if fault == 'inventory-count': spec['subject']['inventory'].pop()
    if fault == 'inventory-link': spec['subject']['inventory'][0]['mode'] = '120000'
    if fault == 'inventory-duplicate': spec['subject']['inventory'][1] = deepcopy(spec['subject']['inventory'][0])
    if fault == 'inventory-hash': spec['subject']['inventory'][0]['sha256'] = '0'*64
    if fault == 'selector': spec['recipe']['commands'][0][-2] = 'OtherTests'
    if fault == 'profile': spec['recipe']['profile'] = 'python-meta'
    if fault == 'skips': spec['recipe']['skips'] = 1
    if fault == 'timeout': spec['recipe']['timeoutSeconds'] = 901
    if fault == 'nested-timeout': spec['recipe']['nestedTimeoutSeconds'] = 421
    if fault == 'workflow-timeout': spec['recipe']['workflowTimeoutMinutes'] = 16
    if fault == 'retry': spec['recipe']['unchangedRetriesMaximum'] = 2
    if fault == 'pair-count': spec['recipe']['successfulPairsMaximum'] = 4
    if fault == 'test-id': spec['recipe']['selectedTestIds'][0] += '_replacement'
    if fault == 'test-count': spec['recipe']['counts'] = [39,39]
    if fault == 'failure-pass': spec['failures'][1]['fullAcceptance'] = True
    if fault == 'missing-failure': spec['failures'].pop()
    if fault == 'sample-cause': spec['diagnosticSample']['status'] = 'ROOT_CAUSE'
    if fault == 'pooling': spec['gates']['partialPooling'] = True
    if fault == 'overlay': spec['gates']['sourceOverlays'] = True
    if fault == 'repair-gate': spec['gates']['newRepairPacketRequired'] = False
    if fault == 'signed-custody': spec['gates']['independentSignedCustodyRequired'] = False
    if fault == 'native': spec['gates']['nativeQualification'] = 'PASS'
    if fault == 'tenant': spec['gates']['tenantAcceptance'] = True
    if fault == 'sleep': spec['gates']['uninterruptedAwakeIntervalRequired'] = False
    if fault == 'thermal': spec['gates']['thermalEmergencyIntervalRejected'] = False
    if fault == 'extra': spec['extra'] = True
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


def test_only_one_exact_read_only_overlap_is_removed(authority):
    packets = authority[0]
    unrelated = 'unrelated source ownership error'
    assert module.close_diagnostic_dispatch(packets,[module.OVERLAP,unrelated]) == [unrelated]
    assert module.close_diagnostic_dispatch(packets,[module.OVERLAP]) == []
    assert module.close_diagnostic_dispatch(packets,[])
    assert len(module.close_diagnostic_dispatch(packets,[module.OVERLAP,module.OVERLAP])) == 3


@pytest.mark.parametrize('fault',['new-owner','live-owner','argv','predecessor','missing'])
def test_changed_dispatch_never_hides_errors(authority,fault):
    packets = deepcopy(authority[0])
    if fault == 'new-owner': packets['CONF-DIAG-001']['allowedPaths'].append('src/')
    if fault == 'live-owner': packets['CONF-LIVE-003']['allowedPaths'].append('src/')
    if fault == 'argv': packets['CONF-DIAG-001']['offlineAcceptanceCommands'][0].append('extra')
    if fault == 'predecessor': packets['CONF-DIAG-001']['predecessors'].append('CONF-LIVE-003')
    if fault == 'missing': packets.pop('CONF-DIAG-001')
    result = module.close_diagnostic_dispatch(packets,[module.OVERLAP,'unrelated'])
    assert module.OVERLAP in result and 'unrelated' in result and len(result) == 3


def test_fresh_authority_read_rejects_second_read_substitution(monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH)
    calls = []
    def read(root,path):
        calls.append(path)
        return raw if len(calls) == 1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PERF-006'
    with pytest.raises(ValueError): module._record()
    assert len(calls) == 2


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}'])
def test_duplicate_and_nonfinite_data_refuse(raw):
    with pytest.raises(ValueError): module.parse(raw)
