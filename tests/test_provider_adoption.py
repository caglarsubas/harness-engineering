"""Planning authority and negative data checks; no provider or product execution."""
from copy import deepcopy
import json

import pytest

from scripts.validate_proxy_diagnostics import historical_bytes as diagnostic_history

from scripts import validate_provider_adoption as module
from scripts.safe_yaml import safe_load


@pytest.fixture(scope='module')
def authority():
    packets = {p.stem: safe_load(p.read_bytes()) for p in (module.ROOT/'task-packets').glob('*.yaml')}
    return packets, *module.load_inputs(module.ROOT)


def test_exact_new_catalog_and_all_historical_packet_bytes(authority):
    assert module.validate_authority(*authority) == []
    packets, record, inputs = authority
    assert len(packets) == 194
    assert len([p for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')]) == 155
    assert set(module.EXTENSIONS).isdisjoint(packets)
    assert packets['CONF-LIVE-003']['id'] == 'CONF-LIVE-003'


def test_exact_reversible_changes_preserve_every_old_test_identity(authority):
    _, record, inputs = authority
    for path, rule in record['metaRecipes'].items():
        before = module.historical_bytes(path, inputs[path])
        assert module.apply_recipe(before, rule) == diagnostic_history(path, inputs[path])
        if path.startswith('tests/'):
            assert module.test_ids(before) == module.test_ids(inputs[path])
            assert module.current_test_bytes(before) == inputs[path]
        with pytest.raises(ValueError):
            module.historical_bytes(path, inputs[path]+b' ')


def test_fresh_authority_reads_reject_substitution(monkeypatch):
    raw = module.regular_bytes(module.ROOT, module.RECORD_PATH)
    calls = []
    def read(root, path):
        calls.append(path)
        return raw if len(calls) == 1 else raw+b' '
    monkeypatch.setattr(module, 'regular_bytes', read)
    assert module._record()['authorityPacket'] == 'MET-ADOPT-001'
    with pytest.raises(ValueError):
        module._record()
    assert len(calls) == 2


@pytest.mark.parametrize('fault', ['old-packet','new-packet','scope','commands','input','missing','extra','record'])
def test_tampered_authority_refuses(authority, fault):
    packets, record, inputs = deepcopy(authority)
    if fault == 'old-packet': inputs['task-packets/CONF-LIVE-003.yaml'] += b' '
    if fault == 'new-packet': packets['MET-ADOPT-001']['objective'] = 'substitute'
    if fault == 'scope': packets['MET-ADOPT-001']['allowedPaths'].append('product/')
    if fault == 'commands': packets['MET-ADOPT-001']['offlineAcceptanceCommands'].pop()
    if fault == 'input': inputs[module.PLAN_PATH] += b' '
    if fault == 'missing': inputs.pop(module.PLAN_PATH)
    if fault == 'extra': inputs['unapproved'] = b'anything'
    if fault == 'record': record['metaBaseline'] = 'wrong'
    assert module.validate_authority(packets, record, inputs)


@pytest.mark.parametrize('fault', ['floor','boolean-floor','selection','owner','duplicate-owner','missing-harness','provider-pin','provider-pass','qualified-count','technology','mode','unknown-predecessor','cycle','registry-owner','executable','missing-gate','proprietary-distribution','native-pass','extra-key'])
def test_semantic_planning_faults_refuse_even_without_byte_pins(authority, fault):
    inputs = authority[2]
    plan = json.loads(inputs[module.PLAN_PATH])
    if fault == 'floor': plan['minimumQualifiedBaselines'] = 0
    if fault == 'boolean-floor': plan['minimumQualifiedBaselines'] = True
    if fault == 'selection': plan['selectionRule'] = 'AUTOMATIC'
    if fault == 'owner': plan['harnessCoverage'][0]['ownerRepository'] = 'control-plane'
    if fault == 'duplicate-owner': plan['repositoryMap'][1] = deepcopy(plan['repositoryMap'][0])
    if fault == 'missing-harness': plan['harnessCoverage'].pop()
    if fault == 'provider-pin': plan['relationships'][0]['version'] = 'latest'
    if fault == 'provider-pass': plan['relationships'][0]['qualificationStatus'] = 'PASS'
    if fault == 'qualified-count': plan['relationships'][0]['countsTowardQualifiedOptions'] = True
    if fault == 'technology': plan['relationships'][0]['technologyOptions'] = ['invented']
    if fault == 'mode': plan['relationships'][0]['integrationModes'] = ['CUSTOM']
    if fault == 'unknown-predecessor': plan['extensionBacklog'][0]['predecessors'] = ['UNKNOWN']
    if fault == 'cycle': plan['extensionBacklog'][0]['predecessors'] = ['OP-EXT-001']
    if fault == 'registry-owner': next(r for r in plan['extensionBacklog'] if r['id'] == 'TRUST-EXT-001')['repositoryId'] = 'control-plane'
    if fault == 'executable': plan['extensionBacklog'][0]['dispatchable'] = True
    if fault == 'missing-gate': plan['extensionBacklog'][0]['publicationGate'].pop()
    if fault == 'proprietary-distribution': plan['policies']['proprietaryTargetMayBeDistributed'] = True
    if fault == 'native-pass': plan['currentCheckpoint']['nativeQualification'] = 'PASS'
    if fault == 'extra-key': plan['implicitApproval'] = True
    with pytest.raises(ValueError):
        module.validate_plan(plan, safe_load(inputs['architecture/taxonomy.yaml']), safe_load(inputs['architecture/repositories.yaml']), safe_load(inputs['architecture/providers.yaml']))
