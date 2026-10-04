"""META planning/source regressions only. Never import or execute product code."""
from copy import deepcopy
import pytest
from scripts import validate_document_repair_plan as module
from scripts.validate_document_repair_execution import historical_bytes as execution_history, historical_catalog
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets={p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_closed_plan_preserves_every_predecessor_and_test_identity(authority):
    assert module.validate_authority(*authority)==[]
    packets,record,inputs=authority
    assert len(packets)==194 and len(historical_catalog(packets))==170 and module.NEW_IDS==('MET-PERF-011',)
    assert 'CONF-PERF-006' not in historical_catalog(packets) and 'CONF-PERF-005' not in packets
    for path in ('ci/test_offline_runner.py','ci/test_warm_snapshot.py'):
        raw=module.regular_bytes(module.ROOT,path)
        assert module.digest(raw)==record['unchangedTests'][path]
        assert module.current_test_bytes(raw)==raw
    for path,rule in record['metaRecipes'].items():
        before=module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule)==execution_history(path,inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before)==module.test_ids(inputs[path])
            assert module.current_test_bytes(before)==inputs[path]


@pytest.mark.parametrize('fault',['record','missing','extra','old-packet','new-packet','recipe','source','guide','test'])
def test_source_or_packet_substitution_refuses(authority,fault):
    packets,record,inputs=deepcopy(authority)
    if fault=='record': record['metaBaseline']='0'*40
    if fault=='missing': inputs.pop(module.SPEC_PATH)
    if fault=='extra': inputs['undeclared']=b'x'
    if fault=='old-packet': inputs['task-packets/CONF-FIX-007.yaml']+=b' '
    if fault=='new-packet': packets['MET-PERF-011']['allowedPaths'].append('src/')
    if fault=='recipe': packets['MET-PERF-011']['offlineAcceptanceCommands'].pop()
    if fault=='source': inputs['scripts/validate_packet_ownership.py']+=b'\n'
    if fault=='guide': inputs['docs/alpha-2/DOCUMENT_REPAIR_PLAN.md']+=b'\n'
    if fault=='test': inputs['tests/test_document_repair_plan.py']+=b'\n'
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('key',['diagnostic','evidenceDigests','subject','candidate','consumers','consumerMigration','proposedOwnerPaths','sequencing','budgets','limits','gates','contractPins','productGrant'])
def test_resealed_plan_cannot_change_scope_or_evidence(authority,key):
    plan=module.parse(authority[2][module.SPEC_PATH]); plan[key]=None
    with pytest.raises(ValueError): module.validate_plan(plan,bind=False)


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}'])
def test_duplicate_nonfinite_authority_refuses(raw):
    with pytest.raises(ValueError): module.parse(raw)


def test_fresh_authority_read_rejects_later_drift(monkeypatch):
    raw=module.regular_bytes(module.ROOT,module.RECORD_PATH); calls=[]
    def read(root,path):
        calls.append(path)
        return raw if len(calls)==1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket']=='MET-PERF-011'
    with pytest.raises(ValueError): module._record()
    assert len(calls)==2


@pytest.mark.parametrize('path',['scripts/validate_completion_profiling.py','tests/test_task_packets.py','docs/MASTER_DEVELOPMENT_PLAN.md'])
def test_current_first_bridge_rejects_stale_or_unknown_bytes(authority,path):
    raw=authority[2][path]; rule=authority[1]['metaRecipes'][path]
    old=module.historical_bytes(path,raw)
    assert module.apply_recipe(old,rule)==execution_history(path,raw)
    with pytest.raises(ValueError): module.historical_bytes(path,old)
    with pytest.raises(ValueError): module.historical_bytes(path,raw+b'\n')


def test_unique_recipe_and_unchanged_test_routes_remain_closed(authority,monkeypatch):
    record=deepcopy(authority[1]); path='tests/test_task_packets.py'
    before=module.historical_bytes(path,authority[2][path])
    record['metaRecipes']['tests/duplicate.py']=deepcopy(record['metaRecipes'][path])
    monkeypatch.setattr(module,'_record',lambda:record)
    with pytest.raises(ValueError): module.current_test_bytes(before)
    with pytest.raises(ValueError): module.current_test_bytes(b'def test_forged(): pass\n')


def test_no_product_implementation_or_acceptance_is_published(authority):
    plan=module.parse(authority[2][module.SPEC_PATH])
    assert plan['productGrant'] is False and plan['candidate']['implemented'] is False
    assert plan['budgets']['productRuns']==plan['budgets']['diagnostics']==0
    assert plan['diagnostic']['remainingAttempts']==0
    assert plan['diagnostic']['completedTestCount']==426<1397
    assert plan['candidate']['speedup']=='NOT_MEASURED'
    assert plan['gates']['tenantAcceptance'] is False
    assert plan['gates']['pr18Mutation'] is False

    extension=plan['localBudgetExtension']
    assert plan['budgets']['metaLocal']==3
    assert extension['retainedLocalOrdinals']==[1,2] and extension['newLocalOrdinals']==[3]
    assert extension['additionalLocalMaximum']==1 and extension['reset'] is False
    for key in ('retainedLocalOrdinals','newLocalOrdinals','additionalLocalMaximum','reset','retainedFailures'):
        changed=deepcopy(plan); changed['localBudgetExtension'][key]=None
        with pytest.raises(ValueError): module.validate_plan(changed,bind=False)
