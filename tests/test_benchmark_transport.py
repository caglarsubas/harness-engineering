"""Transport/custody declaration tests, never product or benchmark execution."""
import ast
from copy import deepcopy
import pytest
from scripts import validate_benchmark_transport as module
from scripts.validate_completion_integration import historical_bytes as integration_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_closed_transport_authority_and_historical_projection(authority):
    assert module.validate_authority(*authority) == []
    packets,record,inputs = authority
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 173
    assert module.NEW_IDS == ('MET-PERF-013','CONF-BENCH-003')
    for path,rule in record['metaRecipes'].items():
        before = module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule) == integration_history(path,inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


def test_old_multiline_rejected_new_exact_literal_accepted(authority):
    packets,_,inputs = authority
    with pytest.raises(ValueError,match='argv contents'):
        module.argv_shape(packets['CONF-BENCH-002']['offlineAcceptanceCommands'])
    commands = packets['CONF-BENCH-003']['offlineAcceptanceCommands']
    module.validate_transport(commands,inputs[module.DRIVER])
    assert len(commands[0][2]) == 2726 and '\n' not in commands[0][2]
    assert ast.literal_eval(ast.parse(commands[0][2]).body[0].value.args[0]).encode() == inputs[module.DRIVER]


@pytest.mark.parametrize('fault',['nul','cr','lf','empty','too-long','wrong-type','shell','sudo','download','recursive','uv-online','too-many-args','too-many-commands','empty-commands'])
def test_installed_argument_boundary_parity(fault):
    command = ['python3','-c','pass']
    if fault in ('nul','cr','lf'): command[2] += {'nul':'\0','cr':'\r','lf':'\n'}[fault]
    if fault == 'empty': command[2] = ''
    if fault == 'too-long': command[2] = 'x'*4097
    if fault == 'wrong-type': command[2] = True
    if fault == 'shell': command[0] = '/bin/sh'
    if fault == 'sudo': command[0] = '/usr/bin/sudo'
    if fault == 'download': command.append('download')
    if fault == 'recursive': command = ['make','verify-offline']
    if fault == 'uv-online': command = ['uv','run','python']
    if fault == 'too-many-args': command = ['python3']*65
    commands = [command]
    if fault == 'too-many-commands': commands *= 65
    if fault == 'empty-commands': commands = []
    with pytest.raises(ValueError): module.argv_shape(commands)


@pytest.mark.parametrize('fault',['statement','dynamic','wrong-literal','extra-arg','other-entry','trailing-space','changed-driver','keyword'])
def test_literal_transport_cannot_expand_or_substitute(authority,fault):
    commands = deepcopy(authority[0]['CONF-BENCH-003']['offlineAcceptanceCommands'])
    driver = authority[2][module.DRIVER]
    if fault == 'statement': commands[0][2] += '; print(1)'
    if fault == 'dynamic': commands[0][2] = 'exec(input())'
    if fault == 'wrong-literal': commands[0][2] = 'exec("pass")'
    if fault == 'extra-arg': commands[0].append('extra')
    if fault == 'other-entry': commands[0][0] = 'python'
    if fault == 'trailing-space': commands[0][2] += ' '
    if fault == 'changed-driver': driver += b'\n'
    if fault == 'keyword': commands[0][2] = 'exec(source="pass")'
    with pytest.raises(ValueError): module.validate_transport(commands,driver)


@pytest.mark.parametrize('key',['candidate','baseline','comparison','budgets','preservedArtifacts','policy','dispatchPairs','predecessorSourceGates','productExecutionInMetaRun','productAcceptance','benchmarkAcceptance','testAccounting','proposalSha256'])
def test_resealed_scope_cannot_widen_boundaries(authority,key):
    value = module.parse(authority[2][module.SPEC_PATH]); value[key] = None
    with pytest.raises(ValueError): module.validate_spec(value,bind=False)


@pytest.mark.parametrize('fault',['record','missing','extra','old-packet','new-packet','recipe','source','guide','freeze','driver','workload'])
def test_packet_and_fresh_source_substitution_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['undeclared'] = b'x'
    if fault == 'old-packet': packets['CONF-BENCH-002']['objective'] += 'changed'
    if fault == 'new-packet': packets['CONF-BENCH-003']['allowedPaths'].append('src/')
    if fault == 'recipe': packets['MET-PERF-013']['offlineAcceptanceCommands'].pop()
    if fault == 'source': inputs['scripts/validate_packet_ownership.py'] += b'\n'
    if fault == 'guide': inputs['docs/alpha-2/BENCHMARK_TRANSPORT.md'] += b'\n'
    if fault == 'freeze': inputs[module.FREEZE] += b' '
    if fault == 'driver': inputs[module.DRIVER] += b' '
    if fault == 'workload': inputs['architecture/document-repair-execution-inputs/workload.json'] += b' '
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['missing','extra','changed','historical-only'])
def test_catalog_is_current_first_and_closed(authority,fault):
    packets = deepcopy(authority[0])
    if fault == 'missing': packets.pop('CONF-BENCH-003')
    if fault == 'extra': packets['UNKNOWN-001'] = {}
    if fault == 'changed': packets['MET-PERF-013']['predecessors'] = []
    if fault == 'historical-only': packets = module.historical_catalog(packets)
    with pytest.raises(ValueError): module.historical_catalog(packets)


def test_shared_budget_preserves_order_and_charges_old_packet(authority):
    value = module.parse(authority[2][module.SPEC_PATH]); rows = []
    for ordinal,subject in enumerate(['BASELINE','CANDIDATE','CANDIDATE','BASELINE'],1):
        result = module.next_comparison_slot('CONF-BENCH-003',value,rows)
        assert result == {'ordinal':ordinal,'subject':subject,'ledgerKey':'DOCUMENT-COMPARISON-002','evidenceClass':'DATA_CHECK_ONLY_NOT_AUTHORIZATION'}
        rows.append({'ordinal':ordinal,'subject':subject,'packetId':'CONF-BENCH-002' if ordinal==1 else 'CONF-BENCH-003','status':'COMPLETE'})
    with pytest.raises(ValueError): module.next_comparison_slot('CONF-BENCH-003',value,rows)
    with pytest.raises(ValueError): module.next_comparison_slot('CONF-BENCH-002',value,[])


@pytest.mark.parametrize('fault',['failed','pending','partial','hole','bool-ordinal','duplicate','wrong-order','foreign','extra-field'])
def test_bad_or_incomplete_reservation_never_grants_retry(authority,fault):
    value = module.parse(authority[2][module.SPEC_PATH])
    rows = [dict(ordinal=1,subject='BASELINE',packetId='CONF-BENCH-003',status='COMPLETE')]
    if fault in ('failed','pending','partial'): rows[0]['status'] = fault.upper()
    if fault == 'hole': rows[0]['ordinal'] = 2
    if fault == 'bool-ordinal': rows[0]['ordinal'] = True
    if fault == 'duplicate': rows *= 2
    if fault == 'wrong-order': rows[0]['subject'] = 'CANDIDATE'
    if fault == 'foreign': rows[0]['packetId'] = 'CONF-BENCH-UNKNOWN'
    if fault == 'extra-field': rows[0]['retry'] = True
    with pytest.raises(ValueError): module.next_comparison_slot('CONF-BENCH-003',value,rows)


def test_exact_four_dispatch_diagnostics_preserve_unknown_errors(authority):
    packets = authority[0]; value = module.parse(authority[2][module.SPEC_PATH])
    path = 'src/harness_conformance/live_mutation_admission.py'
    errors = ['unordered same-repository packets '+a+' and '+b+' overlap at '+repr(path)+' and '+repr(path) for a,b in value['dispatchPairs']]
    assert len(errors) == len(set(errors)) == 4
    assert module.close_transport_dispatch(packets,errors+['unrelated']) == ['unrelated']
    for bad in [[],errors[:-1],errors+errors[:1]]:
        assert module.close_transport_dispatch(packets,bad) == bad+['missing or changed closed benchmark transport dispatch']
    for name in ['MET-PERF-013','CONF-BENCH-003','CONF-BENCH-002','CONF-PERF-006','CONF-FIX-007','CONF-LIVE-003']:
        changed = deepcopy(packets); changed[name]['allowedPaths'].append('undeclared/')
        assert module.close_transport_dispatch(changed,errors) == errors+['missing or changed closed benchmark transport dispatch']


def test_fresh_record_and_history_routes_refuse_drift(authority,monkeypatch):
    path = 'tests/test_task_packets.py'; raw = authority[2][path]
    old = module.historical_bytes(path,raw)
    with pytest.raises(ValueError): module.historical_bytes(path,old)
    with pytest.raises(ValueError): module.historical_bytes(path,raw+b'\n')
    with pytest.raises(ValueError): module.current_test_bytes(b'def test_unknown(): pass\n')
    record = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls=[]
    def read(root,path):
        calls.append(path)
        return record if len(calls)==1 else record+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PERF-013'
    with pytest.raises(ValueError): module._record()


def test_no_execution_or_readiness_promotion(authority):
    value = module.parse(authority[2][module.SPEC_PATH])
    assert value['productExecutionInMetaRun'] is value['productAcceptance'] is value['benchmarkAcceptance'] is False
    assert value['policy']['changed'] is False
    tree = ast.parse((module.ROOT/'scripts/validate_benchmark_transport.py').read_bytes())
    forbidden = {'exec','eval','compile','__import__','Popen','system','CDLL','socket','syscall'}
    for node in ast.walk(tree):
        if isinstance(node,ast.Call):
            assert (node.func.id if isinstance(node.func,ast.Name) else getattr(node.func,'attr','')) not in forbidden
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            names = [n.name for n in node.names] if isinstance(node,ast.Import) else [node.module or '']
            assert not any(n.startswith(('harness_conformance','subprocess','ctypes','socket','cProfile')) for n in names)
