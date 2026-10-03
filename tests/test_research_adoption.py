"""Research adoption planning integrity; never imports or runs provider code."""
from copy import deepcopy
import pytest
from scripts.validate_validation_performance import historical_bytes as repair_history
from scripts import validate_research_adoption as module
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets,*module.load_inputs(module.ROOT)


def plan_inputs(authority):
    packets,_,inputs = authority
    return (module.parse(inputs[module.SPEC_PATH]),safe_load(inputs['architecture/taxonomy.yaml']),
            module.parse(inputs['architecture/provider-adoption.json']),set(packets))


def test_complete166_catalog_and_all_inherited_tests_remain(authority):
    assert module.validate_authority(*authority) == []
    packets,record,inputs = authority
    assert len(packets) == 194 and module.NEW_IDS == ('MET-ADOPT-002',)
    for path,rule in record['metaRecipes'].items():
        before = module.historical_bytes(path,inputs[path])
        assert module.apply_recipe(before,rule) == repair_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


def test_all16_harnesses_have_scoped_oss_and_real_delivery_trace(authority):
    args = plan_inputs(authority); before = deepcopy(args)
    assert module.validate_plan(*args,bind=False) is None
    assert args == before
    plan = args[0]
    assert len(plan['mappings']) == 16 and len(plan['upstreams']) == 32 and len(plan['papers']) == 18
    assert all(r['preferredUpstreams'] and r['researchLinks'] and r['relatedExistingPackets'] for r in plan['mappings'])
    assert all(r['installable'] is False and not r['qualificationEvidence'] for r in plan['mappings'])


@pytest.mark.parametrize('fault',['old-packet','meta','commands','missing','extra','record','source','guide','extra-owner','draft-boundary'])
def test_packet_and_exact_source_substitution_refuse(authority,fault):
    packets,record,inputs = deepcopy(authority)
    if fault == 'old-packet': inputs['task-packets/CONF-FIX-007.yaml'] += b' '
    if fault == 'meta': packets['MET-ADOPT-002']['allowedPaths'].append('src/')
    if fault == 'commands': packets['MET-ADOPT-002']['offlineAcceptanceCommands'].pop()
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['undeclared'] = b'x'
    if fault == 'record': record['metaBaseline'] = '0'*40
    if fault == 'source': inputs['architecture/repositories.yaml'] += b'\n'
    if fault == 'guide': inputs['docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md'] += b'\n'
    if fault == 'extra-owner': packets['UNDECLARED'] = deepcopy(packets['MET-ADOPT-002'])
    if fault == 'draft-boundary': inputs['architecture/conformance-completion.json'] += b' '
    assert module.validate_authority(packets,record,inputs)


@pytest.mark.parametrize('key',sorted(module.FALSE_POLICIES | module.TRUE_POLICIES))
def test_each_policy_remains_boolean_exact_and_fail_closed(authority,key):
    args = plan_inputs(authority); args[0]['policies'][key] = not args[0]['policies'][key]
    with pytest.raises(ValueError): module.validate_plan(*args,bind=False)


@pytest.mark.parametrize('fault',['missing-harness','duplicate-harness','owner','number','module-only',
    'no-paper','invented-official','invented-evaluated','paper-year','bad-url','qualified','installable',
    'evidence','release-version','artifact','published','double-credit','no-build-boundary','no-acceptance',
    'unknown-parent','cycle','no-contract','unknown-related','no-gates','minimum-zero','minimum-bool',
    'release-ceiling','metadata-license-approval','catalog-change','lost-correction','budget-reset','warm-copy',
    'dispatchable','duplicate-upstream','publication-gate','unknown-policy'])
def test_semantic_planning_defects_fail_without_relying_on_whole_file_hash(authority,fault):
    args = plan_inputs(authority); plan=args[0]; row=plan['mappings'][0]
    if fault == 'missing-harness': plan['mappings'].pop()
    if fault == 'duplicate-harness': plan['mappings'][1] = deepcopy(row)
    if fault == 'owner': row['ownerRepository'] = 'model-plane'
    if fault == 'number': row['number'] = 9
    if fault == 'module-only': row['preferredUpstreams'] = ['planeon.operator']
    if fault == 'no-paper': row['researchLinks'] = []
    if fault == 'invented-official': row['researchLinks'][0]['relationship'] = 'OFFICIAL_IMPLEMENTATION'
    if fault == 'invented-evaluated': row['researchLinks'][0]['relationship'] = 'EVALUATED_COMPONENT'
    if fault == 'paper-year': plan['papers'][1]['firstPublicationYear'] = 2026
    if fault == 'bad-url': plan['papers'][0]['url'] = 'https://example.invalid/paper'
    if fault == 'qualified': row['qualificationStatus'] = 'PASS'
    if fault == 'installable': row['installable'] = True
    if fault == 'evidence': row['qualificationEvidence'] = ['made-up']
    if fault == 'release-version': row['releaseVersion'] = 'latest'
    if fault == 'artifact': row['artifactDigest'] = 'sha256:'+'0'*64
    if fault == 'published': row['packetPublished'] = True
    if fault == 'double-credit': row['countsTowardQualifiedOptions'] = True
    if fault == 'no-build-boundary': row['platformResponsibility'] = ''
    if fault == 'no-acceptance': row['acceptance'] = ''
    if fault == 'unknown-parent': row['predecessors'].append('UNKNOWN')
    if fault == 'cycle': row['predecessors'].append(row['proposedPacketId'])
    if fault == 'no-contract': row['predecessors'].remove('CON-EXT-001')
    if fault == 'unknown-related': row['relatedExistingPackets'] = ['INVENTED']
    if fault == 'no-gates': row['acceptanceGateIds'].pop()
    if fault == 'minimum-zero': plan['minimumQualifiedBaselines'] = 0
    if fault == 'minimum-bool': plan['minimumQualifiedBaselines'] = True
    if fault == 'release-ceiling': plan['releaseRequirement'] = 'Exactly one baseline per harness'
    if fault == 'metadata-license-approval': plan['upstreams'][0]['licenseReview'] = 'APPROVED'
    if fault == 'catalog-change': row['catalogCandidateIds'] = []
    if fault == 'lost-correction': plan['preservedGate']['nativeSuccessorStatus'] = 'READY'
    if fault == 'budget-reset': plan['preservedGate']['budgetsReset'] = True
    if fault == 'warm-copy': plan['migration']['changeSourceReusePolicy'] = True
    if fault == 'dispatchable': plan['adoptionDelivery']['futurePacketsDispatchable'] = True
    if fault == 'duplicate-upstream': plan['upstreams'][1] = deepcopy(plan['upstreams'][0])
    if fault == 'publication-gate': row['publicationRequirements'].pop()
    if fault == 'unknown-policy': plan['policies']['allowHostedFallback'] = True
    with pytest.raises(ValueError): module.validate_plan(*args,bind=False)


def test_current_qualification_and_historical_records_not_rewritten(authority):
    _,record,inputs=authority
    assert all('task-packets/'+name+'.yaml' in record['protectedFiles'] for name in ('CONF-FIX-007','EXEC-ORCH-001','MODEL-OLLAMA-001','MET-ADOPT-001'))
    assert 'architecture/provider-adoption.json' in record['protectedFiles']
    previous=module.parse(inputs['architecture/conformance-completion.json'])
    assert previous['allowances']['oldBudgetsReset'] is False
    assert previous['publication']['implementationComplete'] is False
    assert previous['effectivePredecessors']['CONF-LIVE-004'] == ['CONF-LIVE-003','CONF-FIX-007']


def test_fresh_authority_cannot_cache_success(monkeypatch):
    raw=module.regular_bytes(module.ROOT,module.RECORD_PATH); calls=[]
    def read(root,path):
        calls.append(path); return raw if len(calls)==1 else raw+b' '
    monkeypatch.setattr(module,'regular_bytes',read)
    assert module._record()['authorityPacket'] == 'MET-ADOPT-002'
    with pytest.raises(ValueError): module._record()
    assert len(calls)==2


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}'])
def test_ambiguous_research_json_refuses(raw):
    with pytest.raises(ValueError): module.parse(raw)
