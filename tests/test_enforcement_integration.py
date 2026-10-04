"""Source-only ownership tests; never implement or simulate native enforcement."""
from copy import deepcopy
import pytest
from scripts import validate_enforcement_integration as module
from scripts.validate_catalog_traversal import historical_bytes as integration_history
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem: safe_load(p.read_bytes()) for p in (module.ROOT / 'task-packets').glob('*.yaml')}
    return packets, *module.load_inputs(module.ROOT)


def test_exact_current_publication_and_history(authority):
    packets, record, inputs = authority
    assert module.validate_authority(*authority) == []
    assert len(packets) == 194 and len(module.historical_catalog(packets)) == 185
    for path, rule in record['metaRecipes'].items():
        before = module.historical_bytes(path, inputs[path])
        assert module.apply_recipe(before, rule) == integration_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]


@pytest.mark.parametrize('key', ['decisions', 'modules', 'backlog', 'obligations', 'budgets',
    'limits', 'sourceStates', 'researchProvenance', 'oldAttemptsReset', 'productPacketAdded',
    'productExecution', 'runtimeAdoptionAuthorized', 'independentReviewCompleted',
    'nativeAcceptance', 'tenantAcceptance', 'phaseComplete', 'testAccounting'])
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
    if fault == 'missing': packets.pop('MET-ENFORCE-001')
    if fault == 'extra': packets['UNKNOWN-001'] = {}
    if fault == 'changed': packets['MET-ENFORCE-001']['allowedPaths'].append('host-enforcement/')
    if fault == 'historical': packets = module.historical_catalog(packets)
    if fault == 'owner': packets['MET-ENFORCE-001']['repository'] = 'mas-harness-operator'
    with pytest.raises(ValueError): module.historical_catalog(packets)


@pytest.mark.parametrize('fault', ['missing', 'extra', 'old', 'packet', 'plan', 'guide', 'authority'])
def test_inputs_are_exact_current_data(authority, fault):
    packets, record, inputs = deepcopy(authority)
    if fault == 'missing': inputs.pop(module.SPEC_PATH)
    if fault == 'extra': inputs['unknown'] = b'x'
    if fault == 'old': packets['CONF-FIX-010']['objective'] += 'x'
    if fault == 'packet': packets['MET-ENFORCE-001']['offlineAcceptanceCommands'].pop()
    if fault == 'plan': inputs[module.SPEC_PATH] += b' '
    if fault == 'guide': inputs['docs/alpha-2/ENFORCEMENT_INTEGRATION.md'] += b' '
    if fault == 'authority': record['metaBaseline'] = '0' * 40
    assert module.validate_authority(packets, record, inputs)


def test_fresh_history_refuses_stale_actual_bytes(authority, monkeypatch):
    raw = module.regular_bytes(module.ROOT, module.RECORD_PATH); calls = []
    def reader(root, path):
        calls.append(path)
        return raw if len(calls) == 1 else raw + b' '
    monkeypatch.setattr(module, 'regular_bytes', reader)
    assert module._record()['authorityPacket'] == 'MET-ENFORCE-001'
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
    assert len(authority[0]['MET-ENFORCE-001']['offlineAcceptanceCommands']) == 48


def test_parser_rejects_duplicate_and_nonfinite_data():
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
        with pytest.raises(ValueError): module.parse(raw)
