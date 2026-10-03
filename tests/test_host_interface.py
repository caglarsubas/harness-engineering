"""Source-only interface review tests; never simulate native enforcement."""
from copy import deepcopy
import pytest
from scripts import validate_host_interface as module
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem: safe_load(p.read_bytes()) for p in (module.ROOT / 'task-packets').glob('*.yaml')}
    return packets, *module.load_inputs(module.ROOT)


def test_exact_current_publication_and_history(authority):
    packets, record, inputs = authority
    assert module.validate_authority(*authority) == []
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 187
    for path, rule in record['metaRecipes'].items():
        before = module.historical_bytes(path, inputs[path])
        assert module.apply_recipe(before, rule) == module.unified_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('key', ['reviewGaps', 'modules', 'backlog', 'obligations', 'budgets',
    'limits', 'sourceStates', 'review', 'oldAttemptsReset', 'productPacketAdded',
    'productExecution', 'runtimeAdoptionAuthorized', 'independentReviewCompleted',
    'nativeAcceptance', 'tenantAcceptance', 'phaseComplete', 'testAccounting',
    'implementationReady', 'w01Complete', 'requestActionCorrelationProven', 'interfaces', 'requiredOpenDesignGates', 'reconciliation'])
def test_resealed_plan_member_refuses(authority, key):
    value = module.parse(authority[2][module.SPEC_PATH]); value[key] = None
    with pytest.raises(ValueError): module.validate_spec(value, bind=False)


@pytest.mark.parametrize('row', [0, 1, 2, 3])
def test_each_module_owner_and_separation(authority, row):
    original = module.parse(authority[2][module.SPEC_PATH])['modules']
    for key, change in [('ownerId', 'unknown'), ('logicalNamespace', 'cmd/operator/'),
                        ('state', 'READY'), ('separateFromController', False),
                        ('implementationPacket', 'OP-001'), ('artifactDigest', 'claimed'),
                        ('language', 'assumed'), ('nativeQualified', True)]:
        value = deepcopy(original); value[row][key] = change
        with pytest.raises(ValueError): module.validate_modules(value, {'operator'})


@pytest.mark.parametrize('row', [0, 1, 2, 3, 4, 5, 6])
def test_backlog_cannot_dispatch_or_skip_predecessors(authority, row):
    original = module.parse(authority[2][module.SPEC_PATH])['backlog']
    for key, change in [('ownerId', 'unknown'), ('predecessors', ['W07']),
                        ('state', 'DONE'), ('dispatchable', True), ('packetId', 'OP-001')]:
        value = deepcopy(original); value[row][key] = change
        with pytest.raises(ValueError): module.validate_backlog(value, {'operator', 'distribution', 'conformance-labs'})


@pytest.mark.parametrize('row', [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
def test_obligation_cannot_be_promoted_by_ownership(authority, row):
    value = module.parse(authority[2][module.SPEC_PATH]); value['obligations'][row]['state'] = 'QUALIFIED'
    with pytest.raises(ValueError): module.validate_spec(value, bind=False)


@pytest.mark.parametrize('fault', ['missing', 'extra', 'changed', 'historical', 'owner'])
def test_current_catalog_checked_before_history(authority, fault):
    packets = deepcopy(authority[0])
    if fault == 'missing': packets.pop('MET-ENFORCE-003')
    if fault == 'extra': packets['UNKNOWN-001'] = {}
    if fault == 'changed': packets['MET-ENFORCE-003']['allowedPaths'].append('host-enforcement/')
    if fault == 'historical': packets = module.historical_catalog(packets)
    if fault == 'owner': packets['MET-ENFORCE-003']['repository'] = 'mas-harness-operator'
    with pytest.raises(ValueError): module.historical_catalog(packets)


@pytest.mark.parametrize('fault', ['missing', 'extra', 'old', 'packet', 'plan', 'guide', 'authority'])
def test_inputs_are_exact_current_data(authority, fault):
    packets, record, inputs = deepcopy(authority)
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['unknown'] = b'x'
    if fault == 'old': packets['CONF-FIX-010']['objective'] += 'x'
    if fault == 'packet': packets['MET-ENFORCE-003']['offlineAcceptanceCommands'].pop()
    if fault == 'plan': inputs[module.SPEC_PATH] += b' '
    if fault == 'guide': inputs['docs/alpha-2/HOST_INTERFACE_PUBLICATION.md'] += b' '
    if fault == 'authority': record['metaBaseline'] = '0' * 40
    assert module.validate_authority(packets, record, inputs)


def test_fresh_history_refuses_stale_actual_bytes(authority, monkeypatch):
    raw = module.regular_bytes(module.ROOT, module.RECORD_PATH); calls = []
    def reader(root, path):
        calls.append(path)
        return raw if len(calls) == 1 else raw + b' '
    monkeypatch.setattr(module, 'regular_bytes', reader)
    assert module._record()['authorityPacket'] == 'MET-ENFORCE-003'
    with pytest.raises(ValueError): module._record()


def test_every_current_recipe_checked_before_projection(authority):
    for path in authority[1]['metaRecipes']:
        with pytest.raises(ValueError): module.historical_bytes(path, authority[2][path] + b' ')


def test_prior_contracts_and_evidence_are_preserved(authority):
    for path in ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md',
                 'docs/alpha-2/BROKER_HANDOFF_READINESS.md', 'task-packets/CONF-FIX-010.yaml',
                 'architecture/observation-enforcement-inputs/enforcement-matrix.json',
                 'architecture/repositories.yaml'):
        assert path in authority[1]['protectedFiles'] and path not in authority[1]['ownedPaths']
    assert len(authority[0]['MET-ENFORCE-003']['offlineAcceptanceCommands']) == 50


def test_parser_rejects_duplicate_and_nonfinite_data():
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
        with pytest.raises(ValueError): module.parse(raw)


@pytest.mark.parametrize("name", [
    "validate_backend_timing",
    "validate_benchmark_transport",
    "validate_conformance_performance_followup",
    "validate_accounting_scope",
    "validate_conformance_publication",
    "validate_guard_cost_repair",
    "validate_conformance_performance",
    "validate_conformance_consumer_closure",
    "validate_guard_traversal",
    "validate_observation_enforcement",
    "validate_conformance_completion",
    "validate_canonical_repair_plan",
    "validate_host_interface",
    "validate_factory_diagnostics",
    "validate_enforcement_integration",
    "validate_completion_profiling",
    "validate_proxy_diagnostics",
    "validate_catalog_traversal",
    "validate_completion_integration",
    "validate_research_adoption",
    "validate_document_repair_execution",
    "validate_validation_performance",
    "validate_local_acceptance",
    "validate_conformance_successor_checkpoint",
    "validate_provider_adoption",
])
def test_each_frozen_inverse_rechecks_complete_authority(name, monkeypatch):
    from importlib import import_module

    owner = import_module("scripts." + name)
    path = sorted(owner._PROJECTION_RULES)[0]
    expected = owner._record()["metaRecipes"][path]
    first = owner._checked_projection_rule(path)
    assert first == expected
    with pytest.raises(TypeError):
        owner._PROJECTION_RULES[path] = ()
    first["afterSha256"] = "0" * 64
    assert owner._checked_projection_rule(path) == expected

    original = owner.regular_bytes
    authority_raw = original(owner.ROOT, owner.RECORD_PATH)
    reads = []

    def changed(root, selected):
        if selected == owner.RECORD_PATH:
            reads.append(selected)
            return authority_raw + b" "
        return original(root, selected)

    monkeypatch.setattr(owner, "regular_bytes", changed)
    with pytest.raises(ValueError, match="exact fresh authority bytes"):
        owner._checked_projection_rule(path)
    assert reads == [owner.RECORD_PATH]


def test_public_history_rejects_late_host_authority_change(monkeypatch):
    path = "docs/MASTER_DEVELOPMENT_PLAN.md"
    current = (module.ROOT / path).read_bytes()
    original = module.regular_bytes
    authority_raw = original(module.ROOT, module.RECORD_PATH)
    reads = []

    def changed(root, selected):
        if selected == module.RECORD_PATH:
            reads.append(selected)
            return authority_raw + b" "
        return original(root, selected)

    monkeypatch.setattr(module, "regular_bytes", changed)
    with pytest.raises(ValueError, match="exact fresh authority bytes"):
        module.historical_bytes(path, current)
    assert reads == [module.RECORD_PATH]

@pytest.mark.parametrize('label', ['original', 'corrected'])
def test_review_subject_cannot_be_replaced(authority, label):
    packets, record, inputs = deepcopy(authority)
    prefix = 'architecture/host-interface-inputs/' + label + '/'
    for name in ('source-index.json', 'HOST_INTERFACE_SPEC.md', 'REVIEW_BRIEF.md', 'scope.json'):
        changed = dict(inputs); changed[prefix + name] += b' '
        assert module.validate_authority(packets, record, changed)


def test_review_does_not_authorize_implementation(authority):
    value = module.parse(authority[2][module.SPEC_PATH])
    for label in ('original', 'corrected'):
        index = module.parse(authority[2]['architecture/host-interface-inputs/' + label + '/source-index.json'])
        assert set(index['inputs']).issubset(authority[2])
    assert value['independentReviewCompleted'] is True
    assert value['review']['corrected']['verdict'] == 'PASS_FOR_SOURCE_PUBLICATION'
    assert value['requestActionCorrelationProven'] is False
    assert value['requiredOpenDesignGates'] == ['G04', 'G05', 'G06', 'G07', 'G09']
    assert value['backlog'][0]['state'] == 'ONGOING_DESIGN'
    assert all(row['dispatchable'] is False for row in value['backlog'])

@pytest.mark.parametrize('entry', ['validate_additions', 'historical_catalog'])
def test_new_link_has_one_successor_and_fresh_local_authority(authority, monkeypatch, entry):
    from scripts import validate_catalog_traversal as prior
    original = prior.integration_catalog; record_reader = prior._record
    calls = []; reads = []
    def successor(packets):
        calls.append(True)
        return original(packets)
    def record():
        reads.append(True)
        return record_reader()
    monkeypatch.setattr(prior, 'integration_catalog', successor)
    monkeypatch.setattr(prior, '_record', record)
    current = deepcopy(authority[0])
    result = getattr(prior, entry)(current)
    assert result == ([] if entry == 'validate_additions' else
                      {k: v for k, v in current.items() if k not in ('MET-PERF-029', 'MET-VERIFY-001', 'MET-LINUX-005', 'MET-PERF-028', 'MET-RUNNER-001', 'MET-UNIFY-005', 'MET-ENFORCE-003', 'MET-PERF-018')})
    assert current == authority[0]
    assert len(calls) == 1 and len(reads) == (1 if entry == 'validate_additions' else 2)
    prior.validate_call_structure(authority[2]['scripts/validate_catalog_traversal.py'], 'integration_catalog')


def test_new_link_preserves_malformed_refusal_messages(authority):
    from scripts import validate_catalog_traversal as prior
    cycle = []; cycle.append(cycle)
    for invalid in (b'not JSON', object(), cycle):
        packets = deepcopy(authority[0]); packets['MET-PERF-018']['objective'] = invalid
        assert prior.validate_additions(packets) == ['missing or changed performance packets']
        with pytest.raises(ValueError, match='^exact repair packet$'):
            prior.historical_catalog(packets)


@pytest.mark.parametrize('entry', ['validate_additions', 'historical_catalog'])
def test_new_link_rechecks_authority_after_successor(authority, monkeypatch, entry):
    from scripts import validate_catalog_traversal as prior
    original = prior.integration_catalog; fresh = prior._record()
    after = []
    def successor(packets):
        value = original(packets); after.append(True); return value
    def record():
        if after: raise ValueError('changed after projection')
        return fresh
    monkeypatch.setattr(prior, 'integration_catalog', successor)
    monkeypatch.setattr(prior, '_record', record)
    if entry == 'validate_additions':
        assert prior.validate_additions(authority[0]) == ['missing or changed performance packets']
    else:
        with pytest.raises(ValueError, match='^exact repair packet$'): prior.historical_catalog(authority[0])
    assert len(after) == 1


def test_reviewed_inputs_have_complete_two_stage_history(authority):
    inputs = authority[2]; value = module.parse(inputs[module.SPEC_PATH])
    bridges = module.reviewed_input_bridges(inputs, value['reconciliation'])
    assert set(bridges) == module.BRIDGE_DOCUMENTS
    for label in ('original', 'corrected'):
        index = module.parse(inputs['architecture/host-interface-inputs/' + label + '/source-index.json'])
        assert len(index['inputs']) == 23 and set(index['inputs']).issubset(inputs)
        for path, item in index['inputs'].items():
            assert module.digest(module.reviewed_input_bytes(path, inputs[path], bridges)) == item['sha256']
    assert value['reconciliation']['priorLineageLocalConsumed'] == 2
    assert value['reconciliation']['maximumCumulativeLineageLocal'] == 4
    assert 'MET-ENFORCE-002' not in authority[0]


@pytest.mark.parametrize('fault', ['authority', 'lineage', 'record', 'missing'])
def test_review_bridge_rejects_retargeting(authority, fault):
    inputs = dict(authority[2]); value = module.parse(inputs[module.SPEC_PATH])
    lineage = deepcopy(value['reconciliation'])
    if fault == 'authority': inputs[module.BRIDGE_PATH] += b' '
    if fault == 'lineage': lineage['oldPacketRetryAuthorized'] = True
    if fault == 'record': inputs[module.RECONCILIATION_PATH] = b'{}'
    if fault == 'missing': inputs.pop(module.BRIDGE_PATH)
    with pytest.raises((ValueError, KeyError)): module.reviewed_input_bridges(inputs, lineage)


@pytest.mark.parametrize('path', ['docs/MASTER_DEVELOPMENT_PLAN.md',
    'docs/alpha-2/ENFORCEMENT_INTEGRATION.md', 'docs/repositories/10-mas-harness-operator.md'])
def test_review_bridge_checks_each_current_and_intermediate_document(authority, path):
    inputs = authority[2]; value = module.parse(inputs[module.SPEC_PATH])
    bridges = module.reviewed_input_bridges(inputs, value['reconciliation'])
    with pytest.raises(ValueError): module.reviewed_input_bytes(path, inputs[path] + b' ', bridges)
    with pytest.raises(ValueError):
        module.reviewed_input_bytes(path, module.historical_bytes(path, inputs[path]), bridges)
    changed = deepcopy(bridges); changed[path]['beforeSha256'] = '0' * 64
    with pytest.raises(ValueError): module.reviewed_input_bytes(path, inputs[path], changed)
    changed = deepcopy(bridges); changed[path]['replacements'][0]['count'] += 1
    with pytest.raises(ValueError): module.reviewed_input_bytes(path, inputs[path], changed)
