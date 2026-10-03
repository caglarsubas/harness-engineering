"""META-only authority and synthetic observer tests; never imports product code."""
import ast
from copy import deepcopy
import io
import json
import runpy
import sys
from types import SimpleNamespace
import unittest
import pytest
from scripts import validate_factory_diagnostics as module
from scripts.validate_guard_cost_repair import historical_bytes as guard_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_current_authority_and_exact_reversible_history(authority):
    packets,record,inputs = authority
    assert module.validate_authority(*authority) == []
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 177
    for p,rule in record['metaRecipes'].items():
        before = module.historical_bytes(p,inputs[p])
        assert module.apply_recipe(before,rule) == guard_history(p,inputs[p])
        if p.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[p])
            assert module.current_test_bytes(before) == inputs[p]


@pytest.mark.parametrize('key',['subject','priorFailure','recipe','program','observer','budgets','limits','gates','testAccounting','dispatchOverlaps','preservedArtifacts','productExecutionInMetaRun','productAcceptance','nativeAcceptance','tenantAcceptance','phaseComplete'])
def test_resealed_scope_change_refuses(authority,key):
    value = module.parse(authority[2][module.SPEC_PATH]); value[key] = None
    with pytest.raises(ValueError): module.validate_spec(value,bind=False)


@pytest.mark.parametrize('fault',['record','missing','extra','old','meta','diag','source','program','guide','result'])
def test_substituted_input_or_packet_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['unknown'] = b'x'
    if fault == 'old': packets['CONF-FIX-008']['objective'] += 'x'
    if fault == 'meta': packets['MET-PERF-014']['offlineAcceptanceCommands'].pop()
    if fault == 'diag': packets['CONF-DIAG-004']['allowedPaths'].append('src/')
    if fault == 'source': inputs[module.SOURCE] += b' '
    if fault == 'program': inputs[module.PROGRAM_PATH] += b' '
    if fault == 'guide': inputs['docs/alpha-2/FACTORY_DIAGNOSTICS.md'] += b' '
    if fault == 'result': inputs[module.RESULT] += b' '
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['missing','extra','changed','historical-only'])
def test_current_catalog_before_history(authority,fault):
    packets = deepcopy(authority[0])
    if fault == 'missing': packets.pop('CONF-DIAG-004')
    if fault == 'extra': packets['UNKNOWN-001'] = {}
    if fault == 'changed': packets['MET-PERF-014']['predecessors'] = []
    if fault == 'historical-only': packets = module.historical_catalog(packets)
    with pytest.raises(ValueError): module.historical_catalog(packets)


def test_literal_program_ast_parity_and_no_dynamic_loader(authority):
    value = module.parse(authority[2][module.SPEC_PATH])
    module.validate_program(authority[2][module.PROGRAM_PATH],value)
    value['recipe']['commands'][0][2] = 'exec(input())'
    value['program']['argvCodeSha256'] = module.digest(b'exec(input())')
    with pytest.raises(ValueError): module.validate_program(authority[2][module.PROGRAM_PATH],value)


def test_exact_overlap_closure_retains_unknown_and_duplicate_errors(authority):
    packets = authority[0]; value = module.parse(authority[2][module.SPEC_PATH])
    errors = ['unordered same-repository packets '+r['left']+' and '+r['right']+' overlap at '+repr(r['path'])+' and '+repr(r['path']) for r in value['dispatchOverlaps']]
    assert module.close_factory_dispatch(packets,errors+['other']) == ['other']
    for bad in [[],errors[:-1],errors+errors[:1]]:
        assert module.close_factory_dispatch(packets,bad) == bad+['missing or changed factory diagnostic dispatch']


def test_fresh_bytes_not_cached(authority,monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls=[]
    def read(root,path):
        calls.append(path); return raw if len(calls)==1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PERF-014'
    with pytest.raises(ValueError): module._record()


@pytest.fixture
def observer():
    # __main__ is never called: only stdlib definitions and synthetic TestCases.
    namespace = runpy.run_path(str(module.ROOT/module.PROGRAM_PATH))
    return namespace['main'].__globals__


@pytest.mark.parametrize('outcome',['pass','failure','error','skip'])
@pytest.mark.parametrize('sampled',[True,False])
def test_synthetic_results_cleanup_and_timing_nulls(observer,capsys,outcome,sampled):
    calls=[]
    def body(self):
        calls.append('body')
        if outcome=='failure': self.fail('synthetic')
        if outcome=='error': raise RuntimeError('synthetic')
        if outcome=='skip': self.skipTest('synthetic')
    name='KernelQualificationFactoryTests' if sampled else 'Synthetic'
    case=type(name,(unittest.TestCase,),{'__module__':'test_proxy_server','runTest':body})()
    result=unittest.TextTestRunner(stream=io.StringIO(),resultclass=observer['Result']).run(case)
    assert calls==['body'] and result.testsRun==1
    assert (len(result.failures),len(result.errors),len(result.skipped)) == {'pass':(0,0,0),'failure':(1,0,0),'error':(0,1,0),'skip':(0,0,1)}[outcome]
    assert sys.getprofile() is None and observer['H'] is None
    rows=[json.loads(x) for x in capsys.readouterr().out.splitlines()]
    end=rows[-1]
    assert end['event']=='case-finish' and end['observationValid'] is True
    assert end['callEvents'] == ([0]*10 if sampled else None)
    assert end['returnEvents'] == ([0]*10 if sampled else None)
    assert all(x['evidenceClass']=='WORKLOAD_DIAGNOSTIC_ONLY' for x in rows)


@pytest.mark.parametrize('fault',['filename','qualname','line','event','none'])
def test_exact_identity_counters_fixed_storage_and_no_frame_retention(observer,fault):
    result=observer['Result'](unittest.runner._WritelnDecorator(io.StringIO()),True,2)
    result.calls=[0]*10; result.returns=[0]*10; result.events=0
    filename,qualname,line=next(iter(observer['KEYS']))
    code=SimpleNamespace(co_filename=filename,co_qualname=qualname,co_firstlineno=line)
    if fault=='filename': code.co_filename+='other'
    if fault=='qualname': code.co_qualname+='other'
    if fault=='line': code.co_firstlineno+=1
    frame=SimpleNamespace(f_code=code)
    result.hook(frame,'c_call' if fault=='event' else 'call',object())
    result.hook(frame,'c_return' if fault=='event' else 'return',object())
    assert result.calls==result.returns==([1]+[0]*9 if fault=='none' else [0]*10)
    assert all(value is not frame and value is not code for value in vars(result).values())
    assert len(result.calls)==len(result.returns)==10


def test_progress_minimum_interval_and_fixed_event_cadence(observer,monkeypatch):
    result=observer['Result'](unittest.runner._WritelnDecorator(io.StringIO()),True,2)
    result.calls=[0]*10; result.returns=[0]*10; result.events=0
    result.ident='synthetic'; result.start=result.cpu=result.last=0
    now=[1.99]; rows=[]
    monkeypatch.setitem(observer,'W',lambda:now[0]); monkeypatch.setitem(observer,'C',lambda:0)
    monkeypatch.setitem(observer,'emit',lambda event,**kw:rows.append((event,deepcopy(kw))))
    frame=SimpleNamespace(f_code=SimpleNamespace(co_filename='',co_qualname='',co_firstlineno=0))
    for _ in range(1024): result.hook(frame,'call',None)
    assert rows==[]
    now[0]=2
    for _ in range(1023): result.hook(frame,'call',None)
    assert rows==[]
    result.hook(frame,'return',None)
    assert len(rows)==1 and rows[0][0]=='progress' and rows[0][1]['events']==2048


@pytest.mark.parametrize('kind',['profile','trace','monitor'])
def test_ambient_observers_refused_without_replacement(observer,monkeypatch,kind):
    hook=lambda *args:None
    if kind=='profile': monkeypatch.setattr(sys,'getprofile',lambda:hook)
    if kind=='trace': monkeypatch.setattr(sys,'gettrace',lambda:hook)
    if kind=='monitor': monkeypatch.setattr(sys.monitoring,'get_tool',lambda i:'foreign' if i==2 else None)
    changed=[]; monkeypatch.setattr(sys,'setprofile',lambda value:changed.append(value))
    result=observer['Result'](unittest.runner._WritelnDecorator(io.StringIO()),True,2)
    with pytest.raises(RuntimeError,match='ambient'): result.startTest(unittest.FunctionTestCase(lambda:None))
    assert changed==[]


def test_foreign_hook_is_never_cleared(observer,monkeypatch):
    owned=lambda *args:None; foreign=lambda *args:None; changed=[]
    monkeypatch.setitem(observer,'H',owned)
    monkeypatch.setattr(sys,'getprofile',lambda:foreign)
    monkeypatch.setattr(sys,'setprofile',lambda value:changed.append(value))
    observer['close']()
    assert changed==[] and observer['H'] is None


def test_interference_aborts_observation_and_preserves_foreign_hook(observer,monkeypatch,capsys):
    owned=lambda *args:None; foreign=lambda *args:None; changed=[]
    result=observer['Result'](unittest.runner._WritelnDecorator(io.StringIO()),True,2)
    result.sampled=True; result.start=result.cpu=0; result.calls=[0]*10; result.returns=[0]*10
    monkeypatch.setitem(observer,'H',owned)
    monkeypatch.setattr(sys,'getprofile',lambda:foreign)
    monkeypatch.setattr(sys,'setprofile',lambda value:changed.append(value))
    with pytest.raises(RuntimeError,match='interference'):
        result.stopTest(unittest.FunctionTestCase(lambda:None))
    assert changed==[] and observer['H'] is None
    assert json.loads(capsys.readouterr().out)['observationValid'] is False


def test_only_identical_owned_hook_is_cleared(observer,monkeypatch):
    owned=lambda *args:None; changed=[]
    monkeypatch.setitem(observer,'H',owned)
    monkeypatch.setattr(sys,'getprofile',lambda:owned)
    monkeypatch.setattr(sys,'setprofile',lambda value:changed.append(value))
    observer['close']()
    assert changed==[None] and observer['H'] is None


def test_no_product_import_watchdog_threads_or_private_callbacks(authority):
    tree=ast.parse(authority[2][module.PROGRAM_PATH])
    imported={n.name for x in ast.walk(tree) if isinstance(x,ast.Import) for n in x.names}
    imported|={x.module for x in ast.walk(tree) if isinstance(x,ast.ImportFrom)}
    assert imported=={'hashlib','json','pathlib','sys','time','unittest'}
    calls={getattr(x.func,'attr',getattr(x.func,'id','')) for x in ast.walk(tree) if isinstance(x,ast.Call)}
    assert not calls & {'eval','exec','compile','enable','disable','dump_traceback_later','Thread','settrace','set_events','register_callback'}
    assignments=[n for n in ast.walk(tree) if isinstance(n,ast.Assign) for n in n.targets if isinstance(n,ast.Attribute)]
    assert all(isinstance(n.value,ast.Name) and n.value.id=='self' for n in assignments)
