"""Independent local-allowance source checks; never execute product code."""
from copy import deepcopy
import pytest
from scripts.validate_conformance_publication import historical_bytes as publication_history
from scripts import validate_local_acceptance as module
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_exact_one_meta_packet_preserves161_packets_and_test_identities(authority):
    assert module.validate_authority(*authority) == []
    packets,record,inputs = authority
    assert len(packets) == 194 and module.NEW_IDS == ('MET-ACCEPT-001',)
    for path,rule in record['metaRecipes'].items():
        before = module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule) == publication_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('fault',['old-packet','new-meta','live-owner','commands','missing','extra','record','source','guide','duplicate-product-owner'])
def test_source_or_packet_substitution_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'old-packet': inputs['task-packets/CONF-DIAG-002.yaml'] += b' '
    if fault == 'new-meta': packets['MET-ACCEPT-001']['objective'] = 'changed'
    if fault == 'live-owner': packets['CONF-LIVE-003']['allowedPaths'].append('src/')
    if fault == 'commands': packets['MET-ACCEPT-001']['offlineAcceptanceCommands'].pop()
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['undeclared'] = b'x'
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'source': inputs['scripts/validate_packet_ownership.py'] += b'\n'
    if fault == 'guide': inputs['docs/alpha-2/LOCAL_ACCEPTANCE_REVALIDATION.md'] += b'\n'
    if fault == 'duplicate-product-owner': packets['CONF-REVALIDATE-001'] = deepcopy(packets['CONF-LIVE-003'])
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('fault',['argv-filter','argv-duration','argv-profiler','command-missing','command-reorder','ids-missing','ids-duplicate','suite-missing','suite-count','attempts','retry','timeout','nested','workflow','skip','bool-count','source','inventory-hash','inventory-missing','inventory-link','toolchain','product-packet','wrapper','prefetch','diagnostic-budget','old-diagnostic','failure-pass','old-budget-reset','new-maximum','reservation-path','reservation-binding','resume','missing-state','consume','history-missing','history-extra','history-digest','history-execution','evidence-class','extra'])
def test_recipe_and_custody_mutation_refuses_without_outer_hash_binding(authority,fault):
    spec = module.parse(authority[2][module.SPEC_PATH]); recipe = spec['recipe']
    if fault == 'argv-filter': recipe['commands'][5] += ['-k','Selected']
    if fault == 'argv-duration': recipe['commands'][5] += ['--durations','0','-v']
    if fault == 'argv-profiler': recipe['commands'][5][2] = 'cProfile'
    if fault == 'command-missing': recipe['commands'].pop()
    if fault == 'command-reorder': recipe['commands'].reverse()
    if fault == 'ids-missing': recipe['testSuites'][5]['identities'].pop()
    if fault == 'ids-duplicate': recipe['testSuites'][5]['identities'][1] = recipe['testSuites'][5]['identities'][0]
    if fault == 'suite-missing': recipe['testSuites'].pop()
    if fault == 'suite-count': recipe['testSuites'][5]['count'] = 1
    if fault == 'attempts': recipe['attemptsMaximum'] = 2
    if fault == 'retry': recipe['retriesMaximum'] = 1
    if fault == 'timeout': recipe['timeoutSeconds'] = 901
    if fault == 'nested': recipe['nestedTimeoutSeconds'] = 421
    if fault == 'workflow': recipe['workflowTimeoutMinutes'] = 16
    if fault == 'skip': recipe['expectedSkips'] = 1
    if fault == 'bool-count': recipe['attemptsMaximum'] = True
    if fault == 'source': spec['subject']['commit'] = '0'*40
    if fault == 'inventory-hash': spec['subject']['inventory'][0]['sha256'] = '0'*64
    if fault == 'inventory-missing': spec['subject']['inventory'].pop()
    if fault == 'inventory-link': spec['subject']['inventory'][0]['mode'] = '120000'
    if fault == 'toolchain': spec['toolchain']['inventorySha256'] = '0'*64
    if fault == 'product-packet': spec['productPacketSha256'] = '0'*64
    if fault == 'wrapper': recipe['offlineExecution']['wrapperArgv'] = ['python3','inner.py']
    if fault == 'prefetch': recipe['prefetchCommands'] = [['curl','https://example.test']]
    if fault == 'diagnostic-budget': spec['previousDiagnostic']['remainingAttempts'] = 1
    if fault == 'old-diagnostic': spec['earlierDiagnostic']['remainingPairs'] = 1
    if fault == 'failure-pass': spec['priorFailures'][1]['fullAcceptance'] = True
    if fault == 'old-budget-reset': spec['allowance']['oldBudgetsReset'] = True
    if fault == 'new-maximum': spec['allowance']['newMaximum'] = 2
    if fault == 'reservation-path': spec['allowance']['reservation'] = '/tmp/resettable.json'
    if fault == 'reservation-binding': spec['allowance']['requiredBinding'].pop()
    if fault == 'resume': spec['allowance']['resumeOrResignRenews'] = True
    if fault == 'missing-state': spec['allowance']['missingBeforeReservation'] = 'PASS'
    if fault == 'consume': spec['allowance']['consumeOnReservation'] = False
    if fault == 'history-missing': spec['signedHistory']['records'].pop()
    if fault == 'history-extra': spec['signedHistory']['records'].append(spec['signedHistory']['records'][0])
    if fault == 'history-digest': spec['signedHistory']['records'][0]['requestSha256'] = '0'*64
    if fault == 'history-execution': spec['signedHistory']['meaning'] = 'EIGHTY_EXECUTIONS'
    if fault == 'evidence-class': spec['previousDiagnostic']['evidenceClass'] = 'FULL_ACCEPTANCE'
    if fault == 'extra': spec['productAcceptance'] = True
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('key',['metaSourceGatesRequired','independentSignedCustodyRequired','priorSignedRequestsAndReservationsRequired','exact135FilesBeforeAfter','wholeToolchainInventoryRequired','prefetchAndCommandSingleIsolatedTree','reservationBeforeLaunch','timeoutConsumesAttempt','partialPooling','hostChanges','uninterruptedAwakeIntervalRequired','thermalEmergencyIntervalRejected','productAcceptanceCommandsUnchanged','productSourceEdits','productSourcePush','productCI','productMerge','newProductPacket','dispatchExemption','rootPolicyChange','dependenciesOrDownloads','billingChange','diagnosticRerun','maximumEvidenceClass','nativeQualification','tenantAcceptance','modelEffortTransition'])
def test_each_gate_refuses_resealed_change(authority,key):
    spec = module.parse(authority[2][module.SPEC_PATH]); value = spec['gates'][key]
    spec['gates'][key] = not value if type(value) is bool else 'PASS'
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


def test_no_duplicate_source_owner_or_generic_dispatch_exception(authority):
    packets,record,inputs = authority
    spec = module.parse(inputs[module.SPEC_PATH])
    assert not spec['gates']['newProductPacket'] and not spec['gates']['dispatchExemption']
    assert 'scripts/validate_packet_ownership.py' in record['protectedFiles']
    assert packets['CONF-LIVE-003']['offlineAcceptanceCommands'] == module.COMMANDS
    assert len(spec['signedHistory']['records']) == 80
    assert spec['signedHistory']['meaning'] == 'SIGNED_REQUESTS_NOT_EXECUTION_COUNT'


def test_authority_fresh_read_no_cached_validation(monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls = []
    def read(root,path):
        calls.append(path)
        return raw if len(calls) == 1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-ACCEPT-001'
    with pytest.raises(ValueError): module._record()
    assert len(calls) == 2


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}'])
def test_duplicate_or_nonfinite_input_refuses(raw):
    with pytest.raises(ValueError): module.parse(raw)


def test_local_offline_pass_cannot_promote_release_or_tenant_acceptance(authority):
    spec = module.parse(authority[2][module.SPEC_PATH]); module.validate_spec(spec)
    assert spec['allowance']['newMaximum'] == 1 and spec['allowance']['newRetries'] == 0
    assert spec['previousDiagnostic']['remainingAttempts'] == spec['earlierDiagnostic']['remainingPairs'] == 0
    assert spec['gates']['maximumEvidenceClass'] == 'LOCAL_OFFLINE_ACCEPTANCE_ONLY'
    assert not any(spec['gates'][k] for k in ('productMerge','productCI','productSourcePush','tenantAcceptance'))
    assert sum(row['count'] for row in spec['recipe']['testSuites']) == 1277
