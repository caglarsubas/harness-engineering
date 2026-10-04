"""META catalog traversal regression tests, not native/product qualification."""
from copy import deepcopy
import pytest
from scripts import validate_catalog_traversal as module
from scripts.validate_host_interface import historical_bytes as integration_history
from scripts import validate_guard_cost_repair, validate_accounting_scope, validate_guard_traversal
from scripts import validate_observation_enforcement, validate_enforcement_integration
from scripts.safe_yaml import safe_load

OWNERS = {
    'guard': (validate_guard_cost_repair, 'accounting_catalog'),
    'accounting': (validate_accounting_scope, 'traversal_catalog'),
    'traversal': (validate_guard_traversal, 'observation_catalog'),
    'observation': (validate_observation_enforcement, 'integration_catalog'),
    'enforcement': (validate_enforcement_integration, 'integration_catalog'),
}


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets, *module.load_inputs(module.ROOT)


def test_exact_current_publication_and_history(authority):
    packets, record, inputs = authority
    assert module.validate_authority(*authority) == []
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 186
    for path, rule in record['metaRecipes'].items():
        before = module.historical_bytes(path, inputs[path])
        assert module.apply_recipe(before, rule) == integration_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('key', ['targets','staticDiagnosis','repair','blockedDraft','budgets','limits',
    'sourceStates','productExecution','runtimeAdoptionAuthorized','nativeAcceptance','tenantAcceptance',
    'phaseComplete','oldAttemptsReset','productPacketAdded','testAccounting'])
def test_resealed_member_refuses(authority, key):
    value = module.parse(authority[2][module.SPEC_PATH]); value[key] = None
    with pytest.raises(ValueError): module.validate_spec(value, bind=False)


@pytest.mark.parametrize('owner', ['guard','accounting','traversal','observation','enforcement'])
def test_each_public_entry_traverses_successor_once(authority, monkeypatch, owner):
    target, alias = OWNERS[owner]; original = getattr(target, alias); calls = []
    def projected(packets):
        calls.append(1)
        return original(packets)
    monkeypatch.setattr(target, alias, projected)
    current = deepcopy(authority[0]); before = deepcopy(current)
    target.historical_catalog(current)
    assert len(calls) == 1 and current == before
    calls.clear()
    assert target.validate_additions(current) == []
    assert len(calls) == 1 and current == before


@pytest.mark.parametrize('owner', ['guard','accounting','traversal','observation','enforcement'])
def test_catalog_rereads_authority_after_projection(authority, monkeypatch, owner):
    target, alias = OWNERS[owner]; original = target.regular_bytes; reads = []
    def fresh(root, path):
        raw = original(root, path)
        if path == target.RECORD_PATH:
            reads.append(1)
            if len(reads) == 2:
                return raw + b' '
        return raw
    monkeypatch.setattr(target, 'regular_bytes', fresh)
    with pytest.raises(ValueError): target.historical_catalog(deepcopy(authority[0]))
    assert len(reads) == 2


@pytest.mark.parametrize('owner', ['guard','accounting','traversal','observation','enforcement'])
def test_repeated_additions_have_no_success_cache(authority, monkeypatch, owner):
    target, alias = OWNERS[owner]; original = target.regular_bytes; changed = [False]
    def fresh(root, path):
        raw = original(root, path)
        return raw + b' ' if changed[0] and path == target.RECORD_PATH else raw
    monkeypatch.setattr(target, 'regular_bytes', fresh)
    assert target.validate_additions(deepcopy(authority[0])) == []
    changed[0] = True
    assert target.validate_additions(deepcopy(authority[0])) == ['missing or changed performance packets']


@pytest.mark.parametrize('owner', ['guard','accounting','traversal','observation','enforcement'])
def test_current_catalog_and_local_digests_cannot_be_laundered(authority, owner):
    target, alias = OWNERS[owner]
    for identifier in ('MET-PERF-018', target.NEW_IDS[0]):
        for fault in ('missing','owner','digest'):
            packets = deepcopy(authority[0])
            if fault == 'missing': packets.pop(identifier)
            if fault == 'owner': packets[identifier]['repository'] = 'unknown'
            if fault == 'digest': packets[identifier]['objective'] += ' changed'
            assert target.validate_additions(packets)
            with pytest.raises(ValueError): target.historical_catalog(packets)
    packets = deepcopy(authority[0]); packets['UNKNOWN-001'] = {}
    with pytest.raises(ValueError): target.historical_catalog(packets)
    with pytest.raises(ValueError): target.historical_catalog(target.historical_catalog(authority[0]))


def test_accounting_projection_is_current_first_and_nonmutating(authority):
    current = deepcopy(authority[0]); before = deepcopy(current)
    projected = validate_accounting_scope.historical_catalog(current)
    assert current == before
    assert projected['CONF-FIX-009'] != current['CONF-FIX-009']
    record = validate_guard_cost_repair._record()
    assert module.digest(module.canonical(projected['CONF-FIX-009'])) == record['packetDigests']['CONF-FIX-009']
    assert validate_guard_cost_repair.validate_additions(current) == []
    for target in (validate_accounting_scope,validate_guard_cost_repair):
        injected = deepcopy(current); injected['CONF-FIX-009'] = deepcopy(projected['CONF-FIX-009'])
        assert target.validate_additions(injected)
        with pytest.raises(ValueError): target.historical_catalog(injected)


@pytest.mark.parametrize('owner', ['guard','accounting','traversal','observation','enforcement'])
def test_malformed_local_values_preserve_public_refusals(authority, owner):
    target, alias = OWNERS[owner]
    message = {'guard':'exact guard repair packets', 'accounting':'exact accounting amendment packets',
               'traversal':'exact guard traversal packets', 'observation':'exact new META packet',
               'enforcement':'exact new META packet'}[owner]
    cyclic = []; cyclic.append(cyclic)
    for malformed in (b'not JSON', object(), cyclic):
        current = deepcopy(authority[0])
        current[target.NEW_IDS[0]]['objective'] = malformed
        assert target.validate_additions(current) == ['missing or changed performance packets']
        with pytest.raises(ValueError) as refused: target.historical_catalog(current)
        assert str(refused.value) == message


@pytest.mark.parametrize('fault', ['missing','extra','old','packet','plan','guide','authority'])
def test_complete_current_input_closure(authority, fault):
    packets, record, inputs = deepcopy(authority)
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['unknown'] = b'x'
    if fault == 'old': packets['CONF-FIX-010']['objective'] += 'x'
    if fault == 'packet': packets['MET-PERF-018']['offlineAcceptanceCommands'].pop()
    if fault == 'plan': inputs[module.SPEC_PATH] += b' '
    if fault == 'guide': inputs['docs/alpha-2/CATALOG_TRAVERSAL_REPAIR.md'] += b' '
    if fault == 'authority': record['metaBaseline'] = '0' * 40
    assert module.validate_authority(packets, record, inputs)


def test_no_draft_retry_or_native_promotion(authority):
    value = module.parse(authority[2][module.SPEC_PATH])
    assert 'MET-ENFORCE-002' not in authority[0]
    assert value['blockedDraft']['localConsumed'] == 2
    assert value['blockedDraft']['retryAuthorized'] is value['blockedDraft']['packetImported'] is False
    assert value['sourceStates']['CONF-FIX-009'] == 'BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED'
    assert value['sourceStates']['CONF-FIX-010'] == 'BLOCKED_SAFE_DESIGN'


def test_fresh_history_refuses_stale_bytes(authority, monkeypatch):
    raw = module.regular_bytes(module.ROOT, module.RECORD_PATH); calls = []
    def reader(root, path):
        calls.append(path); return raw if len(calls) == 1 else raw + b' '
    monkeypatch.setattr(module, 'regular_bytes', reader)
    assert module._record()['authorityPacket'] == 'MET-PERF-018'
    with pytest.raises(ValueError): module._record()


def test_every_recipe_refuses_changed_current_input(authority):
    for path in authority[1]['metaRecipes']:
        with pytest.raises(ValueError): module.historical_bytes(path, authority[2][path] + b' ')


def test_parser_rejects_duplicate_and_nonfinite_data():
    for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":Infinity}'):
        with pytest.raises(ValueError): module.parse(raw)
