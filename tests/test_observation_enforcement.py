"""Source-only design publication; no product imports, execution or qualification."""
from copy import deepcopy
import pytest
from scripts import validate_observation_enforcement as module
from scripts.validate_enforcement_integration import historical_bytes as integration_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem: safe_load(p.read_bytes()) for p in (module.ROOT / 'task-packets').glob('*.yaml')}
    return packets, *module.load_inputs(module.ROOT)


def test_exact_current_publication_and_history(authority):
    packets, record, inputs = authority
    assert module.validate_authority(*authority) == []
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 184
    for path, rule in record['metaRecipes'].items():
        before = module.historical_bytes(path, inputs[path])
        assert module.apply_recipe(before, rule) == integration_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('key', ['budgets', 'limits', 'sourceStates', 'reviewProvenance',
    'oldAttemptsReset', 'productPacketAdded', 'productExecution', 'runtimeAdoptionAuthorized',
    'nativeAcceptance', 'tenantAcceptance', 'phaseComplete', 'testAccounting'])
def test_resealed_plan_member_refuses(authority, key):
    value = module.parse(authority[2][module.SPEC_PATH]); value[key] = None
    with pytest.raises(ValueError):
        module.validate_spec(value, bind=False)


@pytest.mark.parametrize('row', list(range(12)))
def test_each_enforcement_obligation_cannot_be_promoted(authority, row):
    original = module.parse(authority[2][module.MATRIX])
    for key, change in [('state', 'QUALIFIED'), ('proofEvidence', ['self-report']),
                        ('externalMaintainerSelected', 'assumed'), ('ownerIds', ['unknown'])]:
        value = deepcopy(original); value['rows'][row][key] = change
        with pytest.raises(ValueError):
            module.validate_matrix(value, {'operator', 'conformance-labs'})


@pytest.mark.parametrize('fault', ['missing', 'extra', 'duplicate', 'order', 'selected', 'native', 'runtime', 'unknown'])
def test_matrix_shape_and_no_authority(authority, fault):
    value = module.parse(authority[2][module.MATRIX])
    if fault == 'missing': value['rows'].pop()
    if fault == 'extra': value['rows'].append(deepcopy(value['rows'][0]))
    if fault == 'duplicate': value['rows'][1] = deepcopy(value['rows'][0])
    if fault == 'order': value['rows'].reverse()
    if fault == 'selected': value['selectedEnforcer'] = {'artifact': 'claimed'}
    if fault == 'native': value['nativeQualified'] = 0
    if fault == 'runtime': value['runtimeAdoptionAuthorized'] = True
    if fault == 'unknown': value['unknown'] = False
    with pytest.raises(ValueError): module.validate_matrix(value, {'operator', 'conformance-labs'})


@pytest.mark.parametrize('fault', ['delta', 'window', 'indirect', 'events', 'exhaustive', 'runtime', 'leaf', 'nested'])
def test_direct_indirect_and_event_windows_remain_required(authority, fault):
    value = module.parse(authority[2][module.DELTAS])
    if fault == 'delta': value['deltas'].pop()
    if fault == 'window': value['windows'][1] = value['windows'][0]
    if fault == 'indirect': value['indirectRemovalsIncluded'] = False
    if fault == 'events': value['autonomousEventTimingRequired'] = False
    if fault == 'exhaustive': value['exhaustive'] = True
    if fault == 'runtime': value['approvedForRuntime'] = True
    if fault == 'leaf': value['preservedLeafTests'] = True
    if fault == 'nested': value['deltas'][2]['lostWindowProof'] = 'Only host policy matters'
    with pytest.raises(ValueError): module.validate_deltas(value)


@pytest.mark.parametrize('fault', ['missing', 'extra', 'changed', 'historical', 'owner'])
def test_current_catalog_is_checked_before_history(authority, fault):
    packets = deepcopy(authority[0])
    if fault == 'missing': packets.pop('MET-REPAIR-019')
    if fault == 'extra': packets['UNKNOWN-001'] = {}
    if fault == 'changed': packets['MET-REPAIR-019']['allowedPaths'].append('src/')
    if fault == 'historical': packets = module.historical_catalog(packets)
    if fault == 'owner': packets['MET-REPAIR-019']['repository'] = 'mas-harness-conformance-labs'
    with pytest.raises(ValueError): module.historical_catalog(packets)


@pytest.mark.parametrize('fault', ['missing', 'extra', 'old', 'packet', 'matrix', 'review', 'guide', 'authority'])
def test_every_input_is_exact_current_data(authority, fault):
    packets, record, inputs = deepcopy(authority)
    if fault == 'missing': inputs.pop(module.MATRIX)
    if fault == 'extra': inputs['unknown'] = b'x'
    if fault == 'old': packets['CONF-FIX-010']['objective'] += 'x'
    if fault == 'packet': packets['MET-REPAIR-019']['offlineAcceptanceCommands'].pop()
    if fault == 'matrix': inputs[module.MATRIX] += b' '
    if fault == 'review': inputs[module.REVIEW] += b' '
    if fault == 'guide': inputs['docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md'] += b' '
    if fault == 'authority': record['metaBaseline'] = '0' * 40
    assert module.validate_authority(packets, record, inputs)


def test_fresh_history_refuses_stale_actual_bytes(authority, monkeypatch):
    raw = module.regular_bytes(module.ROOT, module.RECORD_PATH); calls = []
    def reader(root, path):
        calls.append(path)
        return raw if len(calls) == 1 else raw + b' '
    monkeypatch.setattr(module, 'regular_bytes', reader)
    assert module._record()['authorityPacket'] == 'MET-REPAIR-019'
    with pytest.raises(ValueError): module._record()


def test_all_current_recipe_inputs_validated_before_projection(authority):
    for path in authority[1]['metaRecipes']:
        with pytest.raises(ValueError): module.historical_bytes(path, authority[2][path] + b' ')


def test_old_attempts_and_runtime_contracts_unchanged(authority):
    packets, record, inputs = authority
    value = module.parse(inputs[module.SPEC_PATH])
    assert not value['oldAttemptsReset'] and not value['productPacketAdded']
    assert value['sourceStates']['CONF-FIX-009'] == 'BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED'
    assert value['sourceStates']['CONF-FIX-010'] == 'BLOCKED_SAFE_DESIGN'
    assert value['budgets'] == dict(LOCAL=2, CI=2, LOCAL_EXACT_MAIN=1, product=0, diagnostics=0, benchmarks=0)
    for path in ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md',
                 'docs/alpha-2/BROKER_HANDOFF_READINESS.md', 'task-packets/CONF-FIX-010.yaml'):
        assert path in record['protectedFiles'] and path not in record['ownedPaths']
    assert len(packets['MET-REPAIR-019']['offlineAcceptanceCommands']) == 47


def test_parser_rejects_duplicate_and_nonfinite_data():
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
        with pytest.raises(ValueError): module.parse(raw)
