"""META source-only regression coverage; no product import or execution."""
from copy import deepcopy
import pytest
from scripts import validate_document_repair_execution as module
from scripts.validate_benchmark_transport import historical_bytes as transport_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets={p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_closed_authority_preserves_predecessors_and_full_recipe(authority):
    assert module.validate_authority(*authority)==[]
    packets,record,inputs=authority
    assert len(packets)==194 and len(module.historical_catalog(packets))==170
    for path in ('ci/test_offline_runner.py','ci/test_warm_snapshot.py'):
        raw=module.regular_bytes(module.ROOT,path)
        assert module.digest(raw)==record['unchangedTests'][path]
        assert module.current_test_bytes(raw)==raw
    for path,rule in record['metaRecipes'].items():
        before=module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule)==transport_history(path,inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before)==module.test_ids(inputs[path])
            assert module.current_test_bytes(before)==inputs[path]


@pytest.mark.parametrize('fault',['record','missing','extra','old-packet','new-packet','recipe','source','guide','test','oracle','workload','driver'])
def test_source_or_packet_substitution_refuses(authority,fault):
    packets,record,inputs=deepcopy(authority)
    if fault=='record': record['metaBaseline']='0'*40
    if fault=='missing': inputs.pop(module.SPEC_PATH)
    if fault=='extra': inputs['undeclared']=b'x'
    if fault=='old-packet': inputs['task-packets/CONF-FIX-007.yaml']+=b' '
    if fault=='new-packet': packets['CONF-PERF-006']['allowedPaths'].append('src/')
    if fault=='recipe': packets['MET-PERF-012']['offlineAcceptanceCommands'].pop()
    if fault=='source': inputs['scripts/validate_packet_ownership.py']+=b'\n'
    if fault=='guide': inputs['docs/alpha-2/DOCUMENT_REPAIR_AUTHORITY.md']+=b'\n'
    if fault=='test': inputs['tests/test_document_repair_execution.py']+=b'\n'
    for key,path in [('oracle','semantic-oracles.json'),('workload','workload.json'),('driver','benchmark.py.txt')]:
        if fault==key: inputs[module.INPUT_PREFIX+path]+=b' '
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('key',['runtimeRegion','consumerEdits','unchangedProductFiles','preservedTestIds','budgets','limits','sequencing','gates','contractPins','productExecutionInMetaRun','productAcceptance','benchmarkAcceptance','sourceScopeSha256','semanticManifestSha256','measurementManifestSha256','measurementDriverSha256','reviewCorrections','testAccounting'])
def test_resealed_scope_cannot_relax_authority(authority,key):
    value=module.parse(authority[2][module.SPEC_PATH]); value[key]=None
    with pytest.raises(ValueError): module.validate_spec(value,bind=False)


@pytest.mark.parametrize('fault',['missing','extra','changed','historical-only'])
def test_historical_projection_validates_successors_first(authority,fault):
    packets=deepcopy(authority[0])
    if fault=='missing': packets.pop('CONF-PERF-006')
    if fault=='extra': packets['CONF-PERF-UNKNOWN']={}
    if fault=='changed': packets['CONF-BENCH-002']['allowedPaths']=['src/']
    if fault=='historical-only': packets=module.historical_catalog(packets)
    with pytest.raises(ValueError): module.historical_catalog(packets)


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}'])
def test_duplicate_nonfinite_authority_refuses(raw):
    with pytest.raises(ValueError): module.parse(raw)


def test_fresh_authority_read_rejects_later_drift(monkeypatch):
    raw=module.regular_bytes(module.ROOT,module.RECORD_PATH); calls=[]
    def read(root,path):
        calls.append(path)
        return raw if len(calls)==1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket']=='MET-PERF-012'
    with pytest.raises(ValueError): module._record()
    assert len(calls)==2


@pytest.mark.parametrize('path',['scripts/validate_document_repair_plan.py','tests/test_task_packets.py','docs/MASTER_DEVELOPMENT_PLAN.md'])
def test_current_first_bridge_refuses_stale_or_unreviewed_bytes(authority,path):
    raw=authority[2][path]; rule=authority[1]['metaRecipes'][path]
    old=module.historical_bytes(path,raw)
    assert module.apply_recipe(old,rule)==transport_history(path,raw)
    with pytest.raises(ValueError): module.historical_bytes(path,old)
    with pytest.raises(ValueError): module.historical_bytes(path,raw+b'\n')


def test_unicode_driver_matches_frozen_payload_and_rejects_double_escape(authority):
    _,_,inputs=deepcopy(authority)
    value=module.parse(inputs[module.SPEC_PATH]); module.validate_artifacts(value,inputs)
    path=module.INPUT_PREFIX+'benchmark.py.txt'
    original=inputs[path]
    assert original.count(b'caf\\u00e9')==2 and original.count(b'\\u754c')==1
    inputs[path]=original.replace(b'\\u00e9',b'\\\\u00e9').replace(b'\\u754c',b'\\\\u754c')
    value['measurementDriverSha256']=module.digest(inputs[path])
    with pytest.raises(ValueError,match='Unicode literals'): module.validate_artifacts(value,inputs)


def test_unique_recipe_and_unchanged_test_routes_remain_closed(authority,monkeypatch):
    record=deepcopy(authority[1]); path='tests/test_task_packets.py'
    before=module.historical_bytes(path,authority[2][path])
    record['metaRecipes']['tests/duplicate.py']=deepcopy(record['metaRecipes'][path])
    monkeypatch.setattr(module,'_record',lambda:record)
    with pytest.raises(ValueError): module.current_test_bytes(before)
    with pytest.raises(ValueError): module.current_test_bytes(b'def test_forged(): pass\n')


def test_publication_never_promotes_product_benchmark_or_tenant_acceptance(authority):
    value=module.parse(authority[2][module.SPEC_PATH])
    assert value['productExecutionInMetaRun'] is value['productAcceptance'] is value['benchmarkAcceptance'] is False
    assert value['gates']['tenantAcceptance'] is value['gates']['pr18Mutation'] is False
    old=module.parse(authority[2]['architecture/document-repair-plan.json'])
    assert old['productGrant'] is False and old['candidate']['implemented'] is False
    assert old['diagnostic']['remainingAttempts']==0
    assert old['localBudgetExtension']['retainedLocalOrdinals']==[1,2]
    workload=module.parse(authority[2][module.INPUT_PREFIX+'workload.json'])
    assert workload['candidateCommit']=='MUST_BE_FROZEN_BEFORE_FIRST_EXECUTION'
    assert workload['qualification']['partialPooling'] is False


def test_dispatch_closes_only_exact_pinned_fork_and_readonly_pairs(authority,monkeypatch):
    packets=authority[0]
    paths=packets['CONF-PERF-006']['allowedPaths']
    pairs=[('CONF-BENCH-002','CONF-FIX-007',paths[:1]),('CONF-BENCH-002','CONF-LIVE-003',paths[:1]),
           ('CONF-BENCH-002','CONF-PERF-006',paths[:1]),('CONF-FIX-007','CONF-PERF-006',paths)]
    expected=['unordered same-repository packets '+a+' and '+b+' overlap at '+repr(p)+' and '+repr(p)
              for a,b,selected in pairs for p in selected]
    assert len(expected)==len(set(expected))==6
    assert module.close_document_dispatch(packets,expected+['unrelated'])==['unrelated']
    for bad in [[],expected[:-1],expected+expected[:1]]:
        assert module.close_document_dispatch(packets,bad)==bad+['missing or changed closed document repair dispatch']
    for name in ('MET-PERF-012','CONF-PERF-006','CONF-BENCH-002','CONF-FIX-007','CONF-LIVE-003'):
        changed=deepcopy(packets); changed[name]['allowedPaths'].append('undeclared/')
        assert module.close_document_dispatch(changed,expected)==expected+['missing or changed closed document repair dispatch']
    raw=module.regular_bytes(module.ROOT,module.SPEC_PATH)
    value=module.parse(raw)
    for key in ('dispatch','retainedLocalFailure'):
        changed=deepcopy(value); changed[key]=None
        with pytest.raises(ValueError): module.validate_spec(changed,bind=False)
    read=module.regular_bytes
    monkeypatch.setattr(module,'regular_bytes',lambda root,path: raw+b' ' if path==module.SPEC_PATH else read(root,path))
    # Formatting changes cannot alter semantics; a changed parsed dispatch still fails.
    changed=deepcopy(value); changed['dispatch']['exactDiagnostics']=7
    monkeypatch.setattr(module,'regular_bytes',lambda root,path: module.canonical(changed) if path==module.SPEC_PATH else read(root,path))
    assert module.close_document_dispatch(packets,expected)==expected+['missing or changed closed document repair dispatch']
