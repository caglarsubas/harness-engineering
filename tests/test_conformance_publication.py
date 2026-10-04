"""Independent META-only publication checks. No product imports or execution."""
from copy import deepcopy
import pytest
from scripts.validate_conformance_completion import historical_bytes as completion_history
from scripts import validate_conformance_publication as module
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def test_one_meta_owner_keeps162_packets_and_every_inherited_test(authority):
    assert module.validate_authority(*authority) == []
    packets,record,inputs = authority
    assert len(packets) == 194 and module.NEW_IDS == ('MET-PUBLISH-001',)
    for path,rule in record['metaRecipes'].items():
        before = module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule) == completion_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('fault',['old-packet','new-meta','live-owner','commands','missing','extra','record','source','guide','duplicate-product-owner'])
def test_source_or_packet_substitution_refuses(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'old-packet': inputs['task-packets/MET-ACCEPT-001.yaml'] += b' '
    if fault == 'new-meta': packets['MET-PUBLISH-001']['objective'] = 'changed'
    if fault == 'live-owner': packets['CONF-LIVE-003']['allowedPaths'].append('src/')
    if fault == 'commands': packets['MET-PUBLISH-001']['offlineAcceptanceCommands'].pop()
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['undeclared'] = b'x'
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'source': inputs['scripts/validate_packet_ownership.py'] += b'\n'
    if fault == 'guide': inputs['docs/alpha-2/CONFORMANCE_PUBLICATION.md'] += b'\n'
    if fault == 'duplicate-product-owner': packets['CONF-PUBLISH-001'] = deepcopy(packets['CONF-LIVE-003'])
    assert module.validate_authority(packets,record,inputs)


PATHS = [
 'subject.commit','subject.tree','subject.branch','subject.sourceFiles','subject.sourceInventorySha256',
 'subject.inventoryAuthority','subject.staticTestIdentityAuthority','subject.staticTestIds','subject.productPacketSha256',
 'prerequisite.commit','prerequisite.packetSha256','prerequisite.specificationSha256','prerequisite.localAllowanceRemaining',
 'prerequisite.diagnosticBudgetsRemaining','prerequisite.oldBudgetsReset',
 'localEvidence.evidenceClass','localEvidence.requestSha256','localEvidence.reservationSha256','localEvidence.logSha256',
 'localEvidence.auditSha256','localEvidence.resultSha256','localEvidence.testsPassed','localEvidence.commandCount',
 'localEvidence.failures','localEvidence.errors','localEvidence.skips','localEvidence.monotonicSeconds',
 'localEvidence.wallSeconds','localEvidence.awakeIntervalValid','localEvidence.sourceUnchanged',
 'localEvidence.independentAuditRequired','localEvidence.retainedHashesAreAuthentication','localEvidence.attemptConsumed',
 'localEvidence.remainingAttempts','remoteCheckpoint.pr','remoteCheckpoint.head','remoteCheckpoint.main',
 'remoteCheckpoint.draft','remoteCheckpoint.merged','remoteCheckpoint.refreshBeforeAnyWrite',
 'signedHistory.basePath','signedHistory.baseCount','signedHistory.recordCount','signedHistory.meaning',
 'signedHistory.futureComparison','signedHistory.unexplainedRequests','signedHistory.resignRenewsAllowance',
 'recipe.profile','recipe.timeoutSeconds','recipe.nestedTimeoutSeconds','recipe.workflowTimeoutMinutes',
 'recipe.expectedTests','recipe.expectedSkips','recipe.sourceOverlay','recipe.filters','recipe.newProfiler',
 'recipe.output','recipe.caseEvidence','recipe.campaignOutput',
 'publication.mode','publication.reservation','publication.preserveExistingPR','publication.newBranch','publication.newPR',
 'publication.forcePush','publication.rebase','publication.sourceEdits','publication.expectedOldHead','publication.newHead',
 'publication.expectedBase','publication.requiredCheck','publication.merge','publication.bypassProtection',
 'publication.mergeMode','publication.uncertainMutation','publication.baseOrHeadDrift','publication.newSource',
 'custody.durable','custody.exclusiveCreate','custody.consumeOnReservation','custody.retryOnCrash','custody.retryOnTimeout',
 'custody.retryOnSleep','custody.noCrossStagePooling','custody.doNotReuseLocalAcceptance','custody.oneActiveExecution',
 'custody.storeOutsideDisposableCheckout','custody.terminalResultSeparate','custody.missingPrerequisite'
]


@pytest.mark.parametrize('pointer',PATHS)
def test_resealed_nested_boundary_changes_refuse(authority,pointer):
    spec = module.parse(authority[2][module.SPEC_PATH])
    parent,name = pointer.split('.')
    value = spec[parent][name]
    spec[parent][name] = not value if type(value) is bool else value+1 if type(value) in (int,float) else 'CHANGED'
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('stage',[0,1])
@pytest.mark.parametrize('fault',['maximum','bool-maximum','retry','reservation','tree','subject','requires','execution','missing','extra','shared-reservation'])
def test_ci_and_main_are_separate_one_attempt_gates(authority,stage,fault):
    spec = module.parse(authority[2][module.SPEC_PATH]); entry = spec['executions'][stage]
    if fault == 'maximum': entry['maximumAttempts'] = 2
    if fault == 'bool-maximum': entry['maximumAttempts'] = True
    if fault == 'retry': entry['retries'] = 1
    if fault == 'reservation': entry['reservation'] = '/tmp/resettable.json'
    if fault == 'tree': entry['expectedTree'] = '0'*40
    if fault == 'subject': entry['subject'] = 'ANY_COMMIT'
    if fault == 'requires': entry['requires'] = 'LOCAL_PASS_ONLY'
    if fault == 'execution': entry['execution'] = 'HOSTED_RUNNER'
    if fault == 'missing': entry.pop('requires')
    if fault == 'extra': entry['automaticRetry'] = True
    if fault == 'shared-reservation': entry['reservation'] = spec['executions'][1-stage]['reservation']
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('fault',['argv-filter','argv-profiler','missing-command','reordered-command','prefetch','wrapper','missing-binding','missing-ci-binding','missing-main-binding','old-request','extra-stage','missing-stage','extra'])
def test_complete_recipe_custody_and_scope_cannot_be_replaced(authority,fault):
    spec = module.parse(authority[2][module.SPEC_PATH])
    if fault == 'argv-filter': spec['recipe']['commands'][5] += ['-k','Selected']
    if fault == 'argv-profiler': spec['recipe']['commands'][5][2] = 'cProfile'
    if fault == 'missing-command': spec['recipe']['commands'].pop()
    if fault == 'reordered-command': spec['recipe']['commands'].reverse()
    if fault == 'prefetch': spec['recipe']['prefetchCommands'] = [['curl','https://example.test']]
    if fault == 'wrapper': spec['recipe']['offlineExecution']['wrapperArgv'] = ['python3','inner.py']
    if fault == 'missing-binding': spec['custody']['requiredBindings'].pop()
    if fault == 'missing-ci-binding': spec['custody']['ciAdditionalBindings'].pop()
    if fault == 'missing-main-binding': spec['custody']['mainAdditionalBindings'].pop()
    if fault == 'old-request': spec['signedHistory']['newLocalRequest']['requestSha256'] = '0'*64
    if fault == 'extra-stage': spec['executions'].append(deepcopy(spec['executions'][0]))
    if fault == 'missing-stage': spec['executions'].pop()
    if fault == 'extra': spec['tenantAcceptance'] = True
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


@pytest.mark.parametrize('key',['metaLocalHead','metaRequiredLocalhostCI','metaGreenMerge','metaLocalExactMain',
 'reverifyIndependentLocalAcceptance','sourceToolchainAndSignedCustody','preflightDenyAllOutbound',
 'productExecutionInThisMetaRun','productEdits','oldPacketEdits','warmSourceAccess','rootPolicyChange','hostPowerChange',
 'dependenciesOrDownloads','billingChange','technicalEvidencePromotion','nativeQualification','tenantAcceptance',
 'artifactAcceptance','deploymentAcceptance','runtimeAssurance','phaseCompletion','noNewProductOwner',
 'noGenericDispatchException','modelEffortTransition'])
def test_each_evidence_and_safety_gate_refuses_resealed_change(authority,key):
    spec = module.parse(authority[2][module.SPEC_PATH]); value = spec['gates'][key]
    spec['gates'][key] = not value if type(value) is bool else 'PASS'
    with pytest.raises(ValueError): module.validate_spec(spec,bind=False)


def test_old_local_allowance_stays_exhausted_and_native_unavailable(authority):
    packets,record,inputs = authority
    spec = module.parse(inputs[module.SPEC_PATH]); module.validate_spec(spec)
    old = module.parse(inputs['architecture/local-acceptance.json'])
    assert old['gates']['productSourcePush'] is old['gates']['productCI'] is old['gates']['productMerge'] is False
    assert spec['localEvidence']['remainingAttempts'] == 0 and spec['localEvidence']['attemptConsumed']
    assert spec['gates']['nativeQualification'] == 'NOT_RUN_ENV_UNAVAILABLE'
    assert not any(spec['gates'][key] for key in ('artifactAcceptance','deploymentAcceptance','runtimeAssurance','tenantAcceptance','phaseCompletion'))
    assert packets['CONF-LIVE-003']['offlineAcceptanceCommands'] == module.COMMANDS
    assert 'scripts/validate_packet_ownership.py' in record['protectedFiles']


def test_fresh_authority_read_has_no_acceptance_cache(monkeypatch):
    raw = module.regular_bytes(module.ROOT,module.RECORD_PATH); calls = []
    def read(root,path):
        calls.append(path)
        return raw if len(calls) == 1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-PUBLISH-001'
    with pytest.raises(ValueError): module._record()
    assert len(calls) == 2


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}'])
def test_duplicate_or_nonfinite_input_refuses(raw):
    with pytest.raises(ValueError): module.parse(raw)
