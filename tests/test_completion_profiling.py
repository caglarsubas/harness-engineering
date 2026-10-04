"""META-only authority and synthetic observer tests. Never import product code."""
from copy import deepcopy
import hashlib
import io
import json
import runpy
import sys
import unittest
import gc
import threading
import pytest
from scripts import validate_completion_profiling as module
from scripts.validate_document_repair_plan import historical_bytes as document_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_all166_packets_and_inherited_test_ids_preserved(authority):
    assert module.validate_authority(*authority) == []
    packets, record, inputs = authority
    assert len(packets) == 194
    for path, rule in record['metaRecipes'].items():
        before = module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule) == document_history(path,inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('fault',['old-packet','new-meta','diagnostic','recipe','missing','extra','record','source','program','guide'])
def test_source_or_packet_substitution_refuses(authority,fault):
    packets, record, inputs = deepcopy(authority)
    if fault == 'old-packet': inputs['task-packets/CONF-FIX-007.yaml'] += b' '
    if fault == 'new-meta': packets['MET-PERF-009']['objective'] = 'changed'
    if fault == 'diagnostic': packets['CONF-DIAG-003']['allowedPaths'].append('src/')
    if fault == 'recipe': packets['MET-PERF-009']['offlineAcceptanceCommands'].pop()
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['undeclared'] = b'x'
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'source': inputs['scripts/validate_packet_ownership.py'] += b'\n'
    if fault == 'program': inputs[module.PROGRAM_PATH] += b'\n'
    if fault == 'guide': inputs['docs/alpha-2/COMPLETION_PROFILING.md'] += b'\n'
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['sourceEdits','diagnosticIsAcceptance','optimizationAuthorized','requiresBranchOrPr','acceptedSourcePredecessor'])
def test_diagnostic_cannot_grant_product_or_acceptance(authority,fault):
    spec = module.parse(authority[2][module.SPEC_PATH]); spec[fault] = True
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('fault',['argv','retry','attempt','timeout','nested','workflow','skip','order','ids','duplicate','timing-only','profiles','source','tree','inventory','failure','reset','remaining','program','toolchain','limits'])
def test_resealed_diagnostic_scope_or_budget_change_refuses(authority,fault):
    spec = module.parse(authority[2][module.SPEC_PATH]); recipe = spec['recipe']
    if fault == 'argv': recipe['commands'][0].append('-k')
    if fault == 'retry': recipe['retriesMaximum'] = 1
    if fault == 'attempt': recipe['attemptsMaximum'] = True
    if fault == 'timeout': recipe['timeoutSeconds'] = 901
    if fault == 'nested': recipe['nestedTimeoutSeconds'] = 421
    if fault == 'workflow': recipe['workflowTimeoutMinutes'] = 16
    if fault == 'skip': recipe['skips'] = 1
    if fault == 'order': recipe['selection'] = 'FAST_FIRST'
    if fault == 'ids': recipe['expectedTestIds'].pop()
    if fault == 'duplicate': recipe['expectedTestIds'][0] = recipe['expectedTestIds'][1]
    if fault == 'timing-only': recipe['timingOnlyTestIds'].pop()
    if fault == 'profiles': recipe['profiledTestCount'] = 1397
    if fault == 'source': spec['subject']['commit'] = spec['subject']['acceptedMain']
    if fault == 'tree': spec['subject']['tree'] = '0'*40
    if fault == 'inventory': spec['subject']['inventory'][0]['mode'] = '120000'
    if fault == 'failure': spec['priorFailures'][0]['fullAcceptance'] = True
    if fault == 'reset': spec['priorBudget']['resetAllowed'] = True
    if fault == 'remaining': spec['priorBudget']['remainingLocal'] = 1
    if fault == 'program': spec['program']['transport'] = 'ARBITRARY_SCRIPT'
    if fault == 'toolchain': spec['toolchain']['interpreterSha256'] = '0'*64
    if fault == 'limits': spec['limitations']['functionTime'] = 'CPU_WITHOUT_OVERHEAD'
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('key',['metaLocalRequired','metaRequiredCIRequired','protectedMetaMergeRequired','metaExactMainRequired','independentSignedCustodyRequired','reserveBeforeActivation','oneActiveExecution','timeoutConsumesAttempt','partialPooling','productAcceptanceRecipeUnchanged','c1ThroughC7Required','successor004StillBlocked','newRepairPacketRequired','oldBudgetsReset','productPushOrMerge','rootPolicyChange','hostPowerChange','testFiltering','testSubstitution','guardBypass','dependenciesOrDownloads','billingChange','warmSourceAccess','nativeQualification','tenantAcceptance','modelEffortTransition'])
def test_each_execution_boundary_is_fixed(authority,key):
    spec = module.parse(authority[2][module.SPEC_PATH]); old = spec['gates'][key]
    spec['gates'][key] = not old if type(old) is bool else 'PASS'
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


def test_literal_transport_is_source_identical_and_not_dynamic(authority):
    spec = module.parse(authority[2][module.SPEC_PATH])
    module.validate_program(authority[2][module.PROGRAM_PATH],spec)
    spec['recipe']['commands'][0][2] = 'exec(input())'
    spec['program']['argvCodeSha256'] = hashlib.sha256(b'exec(input())').hexdigest()
    with pytest.raises(ValueError): module.validate_program(authority[2][module.PROGRAM_PATH],spec)


def test_fresh_authority_read_rejects_later_drift(monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls = []
    def read(root,path):
        calls.append(path)
        return raw if len(calls) == 1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PERF-009'
    with pytest.raises(ValueError): module._record()
    assert len(calls) == 2


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}'])
def test_duplicate_and_nonfinite_data_refuses(raw):
    with pytest.raises(ValueError): module.parse(raw)


@pytest.fixture
def observer():
    # This module load defines only stdlib observer helpers; main/discovery is not run.
    return runpy.run_path(str(module.ROOT/module.PROGRAM_PATH))


@pytest.mark.parametrize('outcome',['pass','failure','error','skip'])
def test_synthetic_observer_preserves_results_and_test_body(observer,capfd,outcome):
    # The real stack watchdog needs descriptor-backed stderr, not StringIO.
    calls = []
    def body(self):
        calls.append('body')
        if outcome == 'failure': self.fail('synthetic failure')
        if outcome == 'error': raise RuntimeError('synthetic error')
        if outcome == 'skip': self.skipTest('synthetic skip')
    case = type('Synthetic', (unittest.TestCase,), {'runTest':body})()
    assert sys.getprofile() is None
    result = unittest.TextTestRunner(stream=io.StringIO(),resultclass=observer['Result']).run(case)
    assert calls == ['body'] and result.testsRun == 1 and sys.getprofile() is None
    assert len(result.failures) == (outcome == 'failure')
    assert len(result.errors) == (outcome == 'error')
    assert len(result.skipped) == (outcome == 'skip')
    rows = [json.loads(l) for l in capfd.readouterr().out.splitlines()]
    assert [r['event'] for r in rows] == ['case-start','case-finish']
    assert all(r['evidenceClass'] == 'WORKLOAD_DIAGNOSTIC_ONLY' for r in rows)
    assert rows[-1]['threadCpuSeconds'] >= 0 and rows[-1]['wallSeconds'] >= 0
    assert rows[-1]['hookOwnedAtFinish'] is True and rows[-1]['observationValid'] is True
    assert any(e.code is body.__code__ and e.callcount == 1 for e in result.p.getstats())
    assert not observer['busy']()
    assert 0 < len(rows[-1]['topSelf']) <= 20 and 0 < len(rows[-1]['topCumulative']) <= 20


@pytest.mark.parametrize('index',[0,1,2])
def test_each_timing_only_case_runs_without_ambient_profiler(observer,capfd,index):
    identity = sorted(observer['TIMING_ONLY'])[index]; seen = []
    def body(self): seen.append(sys.getprofile())
    case = type('Synthetic', (unittest.TestCase,), {'runTest':body,'id':lambda _:identity})()
    result = unittest.TextTestRunner(stream=io.StringIO(),resultclass=observer['Result']).run(case)
    assert seen == [None] and result.wasSuccessful() and result.testsRun == 1
    end = json.loads(capfd.readouterr().out.splitlines()[-1])
    assert end['functionCount'] == 0 and end['hookOwnedAtFinish'] is None
    assert end['observationValid'] is True and not observer['busy']()
    assert end['topSelf'] == end['topCumulative'] == []


def test_identity_walk_keeps_every_case_in_order(observer):
    first, second = unittest.FunctionTestCase(lambda:None), unittest.FunctionTestCase(lambda:None)
    first.id = lambda:'first'; second.id = lambda:'second'
    suite = unittest.TestSuite([unittest.TestSuite([first]),second])
    assert list(observer['identities'](suite)) == ['first','second']
    assert suite.countTestCases() == 2


def test_discovery_mismatch_refuses_before_runner(observer,monkeypatch):
    class Loader:
        def discover(self,*args):
            assert args == ('tests/live_backend','test_*.py')
            return unittest.TestSuite()
    monkeypatch.setattr(unittest,'defaultTestLoader',Loader())
    def forbidden(*args,**kwargs): raise AssertionError('runner must not start')
    monkeypatch.setattr(unittest,'TextTestRunner',forbidden)
    with pytest.raises(ValueError,match='inventory'): observer['main']()


def test_synthetic_external_path_label_omits_absolute_path(observer):
    namespace = {}; exec(compile('def f(): pass','/private/example-secret/fake.py','exec'),namespace)
    assert observer['label'](namespace['f'].__code__) == ['OTHER',1,'f']


@pytest.mark.parametrize('kind',['legacy','reserved','events','native-cprofile'])
def test_ambient_profiler_refuses_without_touching_it(observer,capfd,kind):
    import cProfile
    m = sys.monitoring
    assert sys.getprofile() is None and not observer['busy']()
    def foreign(*args): pass
    native = None
    try:
        if kind == 'legacy': sys.setprofile(foreign)
        elif kind == 'native-cprofile':
            native = cProfile.Profile(); native.enable()
        else:
            m.use_tool_id(0,'synthetic-occupied')
            if kind == 'events': m.set_events(0,m.events.PY_START)
        hook = sys.getprofile()
        state = [(m.get_tool(i),m.get_events(i)) for i in range(6)]
        calls = []
        case = unittest.FunctionTestCase(lambda:calls.append('executed'))
        with pytest.raises(RuntimeError,match='ambient'):
            unittest.TextTestRunner(stream=io.StringIO(),resultclass=observer['Result']).run(case)
        assert calls == [] and sys.getprofile() is hook
        assert state == [(m.get_tool(i),m.get_events(i)) for i in range(6)]
    finally:
        if kind == 'legacy': sys.setprofile(None)
        elif native: native.disable()
        else: m.set_events(0,0); m.free_tool_id(0)


@pytest.mark.parametrize('kind',['disabled','replacement','monitoring'])
def test_interference_invalidates_and_preserves_foreign_state(observer,capfd,kind):
    m = sys.monitoring
    assert sys.getprofile() is None and not observer['busy']()
    def foreign(*args): pass
    def body():
        if kind == 'monitoring':
            m.use_tool_id(0,'synthetic-new'); m.set_events(0,m.events.PY_START)
        else: sys.setprofile(foreign if kind == 'replacement' else None)
    case = unittest.FunctionTestCase(body)
    try:
        with pytest.raises(RuntimeError,match='interference'):
            unittest.TextTestRunner(stream=io.StringIO(),resultclass=observer['Result']).run(case)
        gc.collect()  # A discarded counter must not clear a foreign hook.
        assert sys.getprofile() is (foreign if kind == 'replacement' else None)
        if kind == 'monitoring':
            assert m.get_tool(0) == 'synthetic-new' and m.get_events(0) == m.events.PY_START
        else: assert not observer['busy']()
        end = json.loads(capfd.readouterr().out.splitlines()[-1])
        assert end['observationValid'] is False and end['functionCount'] == 0
        assert end['topSelf'] == end['topCumulative'] == []
        assert end['hookOwnedAtFinish'] is (kind == 'monitoring')
    finally:
        if kind == 'replacement': sys.setprofile(None)
        if kind == 'monitoring': m.set_events(0,0); m.free_tool_id(0)


def test_real_counter_recursion_builtins_and_thread_scope(observer,capfd):
    seen = []
    def other_thread(): seen.append(sys.getprofile())
    def recursive(n): return recursive(n-1) if n else sorted((3,1,2))
    def body():
        thread = threading.Thread(target=other_thread)
        thread.start(); thread.join(timeout=10)
        assert not thread.is_alive()
        assert recursive(2) == [1,2,3]
        try: [1].index(2)
        except ValueError: pass
    result = unittest.TextTestRunner(stream=io.StringIO(),resultclass=observer['Result']).run(unittest.FunctionTestCase(body))
    assert result.wasSuccessful() and seen == [None]
    entries = result.p.getstats()
    entry = next(e for e in entries if e.code is recursive.__code__)
    assert entry.callcount == 3 and entry.reccallcount == 2
    assert entry.totaltime >= entry.inlinetime >= 0
    assert not any(e.code is other_thread.__code__ for e in entries)
    assert any(isinstance(e.code,str) and 'sorted' in e.code and e.callcount == 1 for e in entries)
    assert any(isinstance(e.code,str) and 'index' in e.code and e.callcount == 1 for e in entries)
    assert sys.getprofile() is None and not observer['busy']()


@pytest.mark.parametrize('failure',['callback','setup'])
def test_observer_setup_failure_leaves_no_owned_hook(observer,monkeypatch,capfd,failure):
    def broken(): raise RuntimeError('synthetic setup failure')
    result_class = observer['Result']
    globals_ = result_class.startTest.__globals__
    if failure == 'setup': monkeypatch.setitem(globals_,'profile',broken)
    else:
        original = globals_['profile']
        def bad_profile():
            p,_ = original()
            def broken_hook(*args): raise RuntimeError('synthetic callback failure')
            return p,broken_hook
        monkeypatch.setitem(globals_,'profile',bad_profile)
    with pytest.raises(RuntimeError,match='synthetic'):
        unittest.TextTestRunner(stream=io.StringIO(),resultclass=result_class).run(unittest.FunctionTestCase(lambda:None))
    assert sys.getprofile() is None and not observer['busy']()


@pytest.mark.parametrize('version',[(3,12,13),(3,13,0)])
def test_counter_refuses_unqualified_interpreter(observer,monkeypatch,version):
    monkeypatch.setattr(sys,'version_info',version)
    with pytest.raises(RuntimeError,match='CPython'): observer['profile']()


def test_counter_has_no_global_monitoring_writes_or_private_runtime_patch(authority):
    import ast
    tree = ast.parse(authority[2][module.PROGRAM_PATH])
    calls = [n.func for n in ast.walk(tree) if isinstance(n,ast.Call)]
    assert not any(isinstance(f,ast.Attribute) and f.attr in
                   {'enable','disable','register_callback','set_events','use_tool_id','free_tool_id',
                    'setprofile_all_threads','settrace','settrace_all_threads'} for f in calls)
    spec = module.parse(authority[2][module.SPEC_PATH])
    assert spec['program']['profiler'] == 'PINNED_CPYTHON31214_CPROFILE_COUNTERS_OWNED_LEGACY_HOOK'
    assert spec['limitations']['profileScope'] == 'OWNED_CURRENT_THREAD_HOOK_NOT_NATIVE_GLOBAL_ENABLE'


def test_only_two_additional_meta_attempts_and_no_product_budget_change(authority):
    spec = module.parse(authority[2][module.SPEC_PATH])
    grant = spec['metaValidationExtension']
    assert grant['retainedLocalOrdinals'] == [1,2,3] and grant['additionalLocalMaximum'] == 2
    assert grant['newLocalOrdinals'] == [4,5] and grant['oldReservationsImmutable'] is True
    assert spec['priorBudget']['remainingLocal'] == 0 and spec['recipe']['attemptsMaximum'] == 1
    grant['additionalLocalMaximum'] = 3
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


def test_reconciliation_keeps_accepted_performance_and_observer(authority):
    from scripts import validate_validation_performance as repair
    packets, record, inputs = authority
    spec = module.parse(inputs[module.SPEC_PATH])
    grant = spec['reconciliation']
    assert grant['base'] == '91b320b9f8525e986260fc4792b01f125b5feae9'
    assert grant['draft'] == '1886aa2272f8d8bc73da60ebd7a6738f288de5fb'
    assert len(packets) == 194
    assert len([p for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')]) == 167
    assert packets['MET-PERF-009']['predecessors'] == ['MET-PERF-010']
    commands = packets['MET-PERF-009']['offlineAcceptanceCommands']
    assert len(commands) == 38
    assert commands[:-3] + commands[-2:] == packets['MET-PERF-010']['offlineAcceptanceCommands']
    assert module.digest(inputs[module.PROGRAM_PATH]) == 'cea27b7a29a7d0aa2d944f7e2389c53f015e627922c6e4a0348ce7c78d9373b9'
    path = 'tests/test_task_packets.py'
    current = inputs[path]
    accepted = module.historical_bytes(path,current)
    assert module.digest(accepted) == record['metaRecipes'][path]['beforeSha256']
    old = repair.historical_bytes(path,current)
    assert module.digest(accepted) == repair._record()['metaRecipes'][path]['afterSha256']
    assert module.digest(old) == repair._record()['metaRecipes'][path]['beforeSha256']
    assert current != accepted != old
    assert repair.current_test_bytes(old) == current


@pytest.mark.parametrize('field',[
    'base','draft','budgets','limits','retainedMetaFailures','retainedDiagnosticFailures',
    'predecessorAcceptance','proposalSha256','proposalMarkdownSha256','protectedAcceptedInputs',
    'currentFirstOrder','testAccounting',
])
def test_reconciliation_boundary_cannot_be_resealed(authority,field):
    spec = module.parse(authority[2][module.SPEC_PATH])
    spec['reconciliation'][field] = None
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('path',[
    'scripts/validate_custody_handoff.py','scripts/validate_validation_performance.py',
    'tests/test_task_packets.py','tests/test_validation_performance.py',
])
def test_current_first_routing_rejects_old_or_mutated_source(authority,path):
    from scripts import validate_validation_performance as repair
    inputs = authority[2]
    current = inputs[path]
    accepted = module.historical_bytes(path,current)
    assert module.apply_recipe(accepted,authority[1]['metaRecipes'][path]) == document_history(path,current)
    with pytest.raises(ValueError): module.historical_bytes(path,accepted)
    with pytest.raises(ValueError): module.historical_bytes(path,current+b'\n# altered\n')
    with pytest.raises(ValueError): repair.historical_bytes(path,accepted)


def test_profiling_lookup_retains_unique_match_and_fresh_hashes(authority,monkeypatch):
    path = 'tests/test_task_packets.py'
    current = authority[2][path]
    before = module.historical_bytes(path,current)
    original = module.digest
    calls = []
    def digest(raw):
        calls.append(raw)
        return original(raw)
    monkeypatch.setattr(module,'digest',digest)
    assert module.current_test_bytes(before) == current
    assert sum(raw == before for raw in calls) == 2
    record = deepcopy(module._record())
    record['metaRecipes']['tests/duplicate.py'] = deepcopy(record['metaRecipes'][path])
    monkeypatch.setattr(module,'_record',lambda:record)
    with pytest.raises(ValueError): module.current_test_bytes(before)


def test_reconciliation_budget_keeps_all_prior_attempts_consumed(authority):
    grant = module.parse(authority[2][module.SPEC_PATH])['reconciliation']
    assert grant['budgets'] == {'LOCAL':7,'newLocalOrdinals':[6,7],
        'retainedLocalOrdinals':[1,2,3,4,5],'CI':2,'LOCAL_EXACT_MAIN':1,
        'diagnostics':0,'productExecutions':0,'reset':False,'transfer':False}
    assert [row['ordinal'] for row in grant['retainedMetaFailures']] == [1,2,3,4,5]
    assert all(row['exitCode'] != 0 for row in grant['retainedMetaFailures'])
    assert len(grant['retainedDiagnosticFailures']) == 2
    assert grant['predecessorAcceptance']['status'] == 'FULL_LOCAL_ACCEPTANCE_VERIFIED'
