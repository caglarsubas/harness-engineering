"""Independent timing-authority refusals; never execute or import product code."""
from copy import deepcopy
import pytest
from scripts.validate_local_acceptance import historical_bytes as acceptance_history
from scripts import validate_backend_timing as module
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_exact_publication_preserves159_packets_and_inherited_test_ids(authority):
    assert module.validate_authority(*authority) == []
    packets,record,inputs = authority
    assert len(packets) == 194 and 'CONF-PERF-005' not in packets
    for path,rule in record['metaRecipes'].items():
        before = module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule) == acceptance_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('fault',['old-packet','new-meta','new-diagnostic','live-owner','commands','missing','extra','record','source','guide'])
def test_source_or_packet_substitution_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'old-packet': inputs['task-packets/CONF-DIAG-001.yaml'] += b' '
    if fault == 'new-meta': packets['MET-PERF-008']['objective'] = 'changed'
    if fault == 'new-diagnostic': packets['CONF-DIAG-002']['allowedPaths'].append('src/')
    if fault == 'live-owner': packets['CONF-LIVE-003']['allowedPaths'].append('src/')
    if fault == 'commands': packets['MET-PERF-008']['offlineAcceptanceCommands'].pop()
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['undeclared'] = b'x'
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'source': inputs['scripts/validate_packet_ownership.py'] += b'\n'
    if fault == 'guide': inputs['docs/alpha-2/BACKEND_TIMING_DIAGNOSTICS.md'] += b'\n'
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['sourceEdits','requiresBranchOrPr','acceptedSourcePredecessor','diagnosticIsAcceptance','optimizationAuthorized'])
def test_no_product_grant_even_when_resealed(authority,fault):
    spec = module.parse(authority[2][module.SPEC_PATH])
    spec[fault] = True
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('fault',['argv-filter','argv-duration','argv-profiler','ids-missing','ids-extra','ids-duplicate','ids-replaced','attempts','retry','timeout','nested','workflow','skip','bool-count','subject','inventory-hash','inventory-missing','inventory-link','stdlib','decision','speedup','time-ratio','old-budget','failure-pass','duration-scope','line-receipt','rounding','missing-time','extra'])
def test_recipe_semantics_refuse_without_outer_hash_binding(authority,fault):
    spec = module.parse(authority[2][module.SPEC_PATH]); recipe = spec['recipe']
    if fault == 'argv-filter': recipe['commands'][0] += ['-k','Selected']
    if fault == 'argv-duration': recipe['commands'][0][-2] = '10'
    if fault == 'argv-profiler': recipe['commands'][0][2] = 'cProfile'
    if fault == 'ids-missing': recipe['expectedTestIds'].pop()
    if fault == 'ids-extra': recipe['expectedTestIds'].append('test_unknown.Other.test_extra')
    if fault == 'ids-duplicate': recipe['expectedTestIds'][1] = recipe['expectedTestIds'][0]
    if fault == 'ids-replaced': recipe['expectedTestIds'][0] += '_replacement'
    if fault == 'attempts': recipe['attemptsMaximum'] = 2
    if fault == 'retry': recipe['retriesMaximum'] = 1
    if fault == 'timeout': recipe['timeoutSeconds'] = 901
    if fault == 'nested': recipe['nestedTimeoutSeconds'] = 421
    if fault == 'workflow': recipe['workflowTimeoutMinutes'] = 16
    if fault == 'skip': recipe['skips'] = 1
    if fault == 'bool-count': recipe['attemptsMaximum'] = True
    if fault == 'subject': spec['subject']['commit'] = spec['remoteCheckpoint']['main']
    if fault == 'inventory-hash': spec['subject']['inventory'][0]['sha256'] = '0'*64
    if fault == 'inventory-missing': spec['subject']['inventory'].pop()
    if fault == 'inventory-link': spec['subject']['inventory'][0]['mode'] = '120000'
    if fault == 'stdlib': spec['toolchain']['unittestFiles']['case.py']['sha256'] = '0'*64
    if fault == 'decision': spec['decision']['repairAuthorized'] = True
    if fault == 'speedup': spec['decision']['timeSaving'] = 'MEASURED'
    if fault == 'time-ratio': spec['decision']['ratioMeaning'] = 'TIME_SAVING'
    if fault == 'old-budget': spec['previousDiagnostic']['remainingPairs'] = 1
    if fault == 'failure-pass': spec['priorFailures'][1]['fullAcceptance'] = True
    if fault == 'duration-scope': spec['limitations']['durationScope'] = 'WHOLE_COMMAND'
    if fault == 'line-receipt': spec['limitations']['lineReceiptTime'] = 'EXECUTION_BOUNDARY'
    if fault == 'rounding': spec['limitations']['precisionDecimalPlaces'] = 9
    if fault == 'missing-time': spec['limitations']['missingDuration'] = 0
    if fault == 'extra': spec['productAcceptance'] = True
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('key',['metaSourceGatesRequired','independentSignedCustodyRequired','actualSourceInventoryBeforeAfterRequired','prefetchAndCommandSingleIsolatedTree','retainedAttemptReservationBeforeLaunch','timeoutConsumesAttempt','partialPooling','hostChanges','uninterruptedAwakeIntervalRequired','thermalEmergencyIntervalRejected','productAcceptanceCommandsUnchanged','proxyRetryReset','productSourcePush','requiredNewRepairPacket','rootPolicyChange','dependenciesOrDownloads','billingChange','nativeQualification','tenantAcceptance','modelEffortTransition'])
def test_each_gate_refuses_resealed_change(authority,key):
    spec = module.parse(authority[2][module.SPEC_PATH])
    old = spec['gates'][key]
    spec['gates'][key] = not old if type(old) is bool else 'PASS'
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


def test_exact_overlap_only_and_duplicate_or_absent_error_refuses(authority):
    packets = authority[0]
    assert module.close_timing_dispatch(packets,[module.OVERLAP,'unrelated']) == ['unrelated']
    assert module.close_timing_dispatch(packets,[module.OVERLAP]) == []
    assert module.close_timing_dispatch(packets,[])
    assert len(module.close_timing_dispatch(packets,[module.OVERLAP,module.OVERLAP])) == 3


@pytest.mark.parametrize('fault',['diagnostic','owner','argv','predecessors','missing'])
def test_changed_dispatch_cannot_hide_an_error(authority,fault):
    packets = deepcopy(authority[0])
    if fault == 'diagnostic': packets['CONF-DIAG-002']['allowedPaths'].append('src/')
    if fault == 'owner': packets['CONF-LIVE-003']['allowedPaths'].append('src/')
    if fault == 'argv': packets['CONF-DIAG-002']['offlineAcceptanceCommands'][0].append('extra')
    if fault == 'predecessors': packets['CONF-DIAG-002']['predecessors'].append('CONF-LIVE-003')
    if fault == 'missing': packets.pop('CONF-DIAG-002')
    found = module.close_timing_dispatch(packets,[module.OVERLAP,'unrelated'])
    assert module.OVERLAP in found and 'unrelated' in found and len(found) == 3


def test_authority_is_fresh_on_each_read(monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls = []
    def read(root,path):
        calls.append(path)
        return raw if len(calls) == 1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PERF-008'
    with pytest.raises(ValueError): module._record()
    assert len(calls) == 2


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}'])
def test_duplicate_or_nonfinite_input_refuses(raw):
    with pytest.raises(ValueError): module.parse(raw)


def test_positive_observation_never_means_product_acceptance(authority):
    spec = module.parse(authority[2][module.SPEC_PATH]); module.validate_spec(spec)
    assert len(spec['recipe']['expectedTestIds']) == 1107
    assert spec['recipe']['attemptsMaximum'] == 1 and spec['recipe']['retriesMaximum'] == 0
    assert spec['previousDiagnostic']['remainingPairs'] == 0
    assert not spec['sourceEdits'] and not spec['diagnosticIsAcceptance']
    assert spec['decision']['timeSaving'] == 'NOT_MEASURED'
