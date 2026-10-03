#!/usr/bin/env python3
"""Pinned source-only performance authority. No product imports or execution."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import stat
from types import MappingProxyType

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

try:
    from validate_local_acceptance import historical_bytes as acceptance_history, current_test_bytes as acceptance_current, validate_additions as acceptance_additions
except ImportError:
    from scripts.validate_local_acceptance import historical_bytes as acceptance_history, current_test_bytes as acceptance_current, validate_additions as acceptance_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/backend-timing-authority.json"
RECORD_SHA256 = "402fa42b371e83311112cc046c28e0887b68a887372c35727d50ae811745bd53"
NEW_IDS = ("MET-PERF-008", "CONF-DIAG-002")
RECORD_FILE_SHA256 = "0c42acfbb91d50c7f93263f0d3ba5d304c4064b1758980990a09200907146cda"
HISTORY_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_broker_handoff.py","scripts/validate_canonical_repair_plan.py","scripts/validate_ci_performance.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_provider_adoption.py","scripts/validate_proxy_contract.py","scripts/validate_proxy_diagnostics.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_broker_handoff.py","tests/test_canonical_repair_plan.py","tests/test_ci_performance.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_provider_adoption.py","tests/test_proxy_contract.py","tests/test_proxy_diagnostics.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, "duplicate JSON member")
            value[key] = item
        return value
    def nonfinite(_):
        raise ValueError("nonfinite JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def regular_bytes(root, path):
    require(type(path) is str and path and not path.startswith("/")
            and all(x not in ("", ".", "..") for x in path.split("/")), "relative path")
    current = Path(root)
    for part in path.split("/")[:-1]:
        current /= part
        require(stat.S_ISDIR(current.lstat().st_mode), "linked ancestor")
    target = current / path.split("/")[-1]
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= 16777216, "bounded unlinked regular file")
    raw = target.read_bytes()
    after = target.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size, "file changed")
    return raw


def pinned(record):
    require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256, "exact performance authority")


def _record():
    # Fresh read and byte digest every invocation; never cache parsed authority.
    raw = regular_bytes(ROOT, RECORD_PATH)
    require(digest(raw) == RECORD_FILE_SHA256, "exact fresh authority bytes")
    return parse(raw)


def _freeze_projection_rules():
    """Freeze only inverse recipes; current authority bytes are never cached."""
    record = _record()
    require(set(record["metaRecipes"]) == HISTORY_PATHS, "exact historical routing")
    return MappingProxyType({
        path: (
            rule["beforeSha256"],
            rule["afterSha256"],
            tuple((row["before"], row["after"], row["count"])
                  for row in rule["replacements"]),
        )
        for path, rule in record["metaRecipes"].items()
    })


_PROJECTION_RULES = _freeze_projection_rules()


def _checked_projection_rule(path):
    # Preserve a complete fresh regular-file read and SHA on every projection.
    raw = regular_bytes(ROOT, RECORD_PATH)
    require(digest(raw) == RECORD_FILE_SHA256, "exact fresh authority bytes")
    frozen = _PROJECTION_RULES.get(path)
    if frozen is None:
        return None
    before_sha, after_sha, replacements = frozen
    return {
        "beforeSha256": before_sha,
        "afterSha256": after_sha,
        "replacements": [
            {"before": before, "after": after, "count": count}
            for before, after, count in replacements
        ],
    }


def apply_recipe(before, rule):
    require(type(before) is bytes and type(rule) is dict
            and set(rule) == {"beforeSha256", "afterSha256", "replacements"}
            and digest(before) == rule["beforeSha256"], "exact before bytes")
    current = before
    for item in rule["replacements"]:
        require(type(item) is dict and set(item) == {"before", "after", "count"}
                and type(item["before"]) is type(item["after"]) is str
                and item["before"] and item["before"] != item["after"]
                and type(item["count"]) is int and item["count"] > 0, "closed effective replacement")
        old, new = item["before"].encode(), item["after"].encode()
        require(current.count(old) == item["count"], "replacement cardinality")
        current = current.replace(old, new)
    require(digest(current) == rule["afterSha256"], "exact current source")
    return current


def historical_bytes(path, raw):
    raw = acceptance_history(path, raw)
    # A closed code-pinned routing table, not an acceptance/result cache.
    # Unchanged inputs still receive the predecessor caller's exact hash check.
    if path not in HISTORY_PATHS:
        return raw
    rule = _checked_projection_rule(path)
    if rule is None:
        return raw
    require(type(raw) is bytes and digest(raw) == rule["afterSha256"], "current bytes changed: " + path)
    before = raw
    for row in reversed(rule["replacements"]):
        new, old = row["after"].encode(), row["before"].encode()
        require(before.count(new) == row["count"], "inverse cardinality")
        before = before.replace(new, old)
    require(apply_recipe(before, rule) == raw, "unreviewed inverse")
    return before


def current_test_bytes(before):
    require(type(before) is bytes, "test bytes")
    record = _record()
    input_digest = digest(before)
    matches = [r for p, r in record["metaRecipes"].items()
               if p.startswith("tests/") and r["beforeSha256"] == input_digest]
    if not matches:
        require(input_digest in record["unchangedTests"].values(), "unreviewed unchanged test")
        return acceptance_current(before)
    require(len(matches) == 1, "unique predecessor")
    return acceptance_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return acceptance_additions(packets)
    except (ValueError, TypeError, RecursionError):
        return ["missing or changed performance packets"]


def test_ids(raw):
    result = []
    def visit(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                result.append(prefix + node.name)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
    visit(ast.parse(raw).body)
    require(len(result) == len(set(result)), "duplicate test identity")
    return result


SPEC_PATH = "architecture/backend-timing.json"
EXPECTED_SPEC_SHA256 = "8f5cab1a55f97198349cf81665df4fc2cc663e973e873a52f1f567a98c249b5f"
EXPECTED_MEMBER_DIGESTS = {"schemaVersion":"4aaf4dddede59654634201e0894b4c4548eb6deed7df9b911c1157d53ea10458","packetId":"3cc16a35b2a20d16bb316bbc33a884771cc2c379b947c4531ae7144369ea9564","metaPacketId":"be1d899874c3b521c7f81777897539630ac6104820d6afa67641ca400ce4ac28","metaBase":"8dc8fdf2af3abea0e34530fcbfd1960b1262e16316d44a17842de8b4920e3fda","evidenceClass":"c696c0f4a34664bf3754c1d864600080f3032e33a4abe03bb413b51086305a59","sourceOwner":"d8e3cfb01e7fcf67910952da2bce81f2dcd698c5b08559853c3285148af50ba3","sourceEdits":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","requiresBranchOrPr":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","acceptedSourcePredecessor":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","diagnosticIsAcceptance":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","optimizationAuthorized":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","subject":"f04e8a636b21e1d1c9dc84350ed98b12f8f8b8d584ed9d3f505e5fe75f4ff893","remoteCheckpoint":"6bb60622be22e9e06b39298da9bb33287a21c891664b058d0a733746c1a37f5e","decision":"bb8c04476ad00c775c3f32d906facf04ecde8e541aa63bcd3a6e8ff72c0ceb4d","recipe":"6e54c8233840538e49775ad2b678c74a76080398945afc7df94415ef0c6fd14e","toolchain":"961c3bc7912245087f7c3e6a973de2e47c213318160d213567574c38eda25baf","limitations":"13854fb1b7d7f500359cb5dd6478e5c2c148ca5e43e59426c57ba459657ff31e","priorFailures":"1abbb34b9b0630ae6bcb045509d5d474335bd07b4e90e41d807c4d2687f911ca","previousDiagnostic":"bd86ee523570e7991db2179c0f63ca8086910b13329b3bdb39ced95334992a61","gates":"65c28238836d3b65dd655c1851306953c26b6e1dc9847da7f77b4cfc3d25277e"}
EXPECTED_TEST_IDS_SHA256 = "7ca11a06c2a444bf7699d37b765c31197823833d1d6c84d0b12c48d09d9d0c4d"
COMMANDS = [["python3","-m","unittest","discover","-s","tests/live_backend","-p","test_*.py","--durations","0","-v"]]


OVERLAP = "unordered same-repository packets CONF-DIAG-002 and CONF-LIVE-003 overlap at 'tests/live_backend/test_proxy_server.py' and 'tests/live_backend/test_proxy_server.py'"


def validate_spec(spec, *, bind=True):
    """Planning-data validation, never execution/signature authentication."""
    require(type(spec) is dict and set(spec) == set(EXPECTED_MEMBER_DIGESTS), 'closed timing specification')
    if bind:
        require(digest(canonical(spec)) == EXPECTED_SPEC_SHA256, 'exact timing specification')
    # Independently pin every member even when the outer document hash is disabled.
    # This also distinguishes booleans/numbers and rejects nested extra fields.
    for key, checksum in EXPECTED_MEMBER_DIGESTS.items():
        require(digest(canonical(spec[key])) == checksum, 'changed timing boundary: '+key)
    require(spec['packetId'] == 'CONF-DIAG-002' and spec['metaPacketId'] == 'MET-PERF-008'
            and spec['sourceOwner'] == 'CONF-LIVE-003', 'exact diagnostic identity')
    for key in ('sourceEdits','requiresBranchOrPr','acceptedSourcePredecessor',
                'diagnosticIsAcceptance','optimizationAuthorized'):
        require(spec[key] is False, 'no product/acceptance grant')
    recipe, subject = spec['recipe'], spec['subject']
    require(recipe['commands'] == COMMANDS and recipe['prefetchCommands'] == []
            and recipe['attemptsMaximum'] == 1 and recipe['retriesMaximum'] == 0
            and recipe['timeoutSeconds'] == 900 and recipe['nestedTimeoutSeconds'] == 420
            and recipe['workflowTimeoutMinutes'] == 15 and recipe['skips'] == 0, 'exact single attempt')
    ids = recipe['expectedTestIds']
    require(type(ids) is list and ids == sorted(set(ids)) and len(ids) == recipe['testCount'] == 1107
            and all(type(i) is str and re.fullmatch(r'test_[A-Za-z0-9_]+\.[A-Za-z0-9_]+\.test_[A-Za-z0-9_]+',i) for i in ids)
            and digest(canonical(ids)) == EXPECTED_TEST_IDS_SHA256, 'all exact backend identities')
    inventory = subject['inventory']
    require(len(inventory) == 135 and digest(canonical(inventory)) == subject['inventoryDataSha256']
            and subject['fullAcceptance'] is False and subject['backendTestInventory'] == 1107
            and subject['fullTestInventory'] == 1277, 'unchanged full subject')
    paths = [row['path'] for row in inventory]
    require(paths == sorted(set(paths)), 'complete ordered source paths')
    require(spec['decision']['outcome'] == 'NO_GO_AS_TIMEOUT_REPAIR'
            and spec['decision']['repairAuthorized'] is False
            and spec['decision']['timeSaving'] == 'NOT_MEASURED'
            and spec['previousDiagnostic']['remainingPairs'] == 0
            and spec['previousDiagnostic']['resetAllowed'] is False, 'no speculative repair or budget reset')


def close_timing_dispatch(packets, errors):
    """One exact read-only anchor overlap; no generic source-owner exemption."""
    try:
        require(type(errors) is list and all(type(e) is str for e in errors), 'diagnostic list')
        record = _record()
        require(validate_additions(packets) == [], 'exact new packets')
        path = 'task-packets/CONF-LIVE-003.yaml'
        raw = regular_bytes(ROOT,path)
        require(digest(raw) == record['protectedFiles'][path]
                and canonical(packets.get('CONF-LIVE-003')) == canonical(safe_load(raw)), 'unchanged product owner')
        replay = packets['CONF-DIAG-002']
        require(replay['allowedPaths'] == ['tests/live_backend/test_proxy_server.py']
                and replay['offlineAcceptanceCommands'] == COMMANDS
                and replay['predecessors'] == ['MET-PERF-008','CONF-FIX-006','CONF-DIAG-001'], 'exact read-only role')
        require(errors.count(OVERLAP) == 1, 'exact single timing overlap')
        return [e for e in errors if e != OVERLAP]
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        return list(errors) + ['missing or changed closed backend timing dispatch']


def load_inputs(root):
    record = parse(regular_bytes(root,RECORD_PATH))
    pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record,{p:regular_bytes(root,p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact history routing')
        require(validate_additions(packets) == [], 'packet binding')
        pins = {**record['protectedFiles'],**record['inputFiles'],
                **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'exact fresh source set')
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(acceptance_history(path, inputs[path])) == checksum, 'changed source: '+path)
        old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old) == 159 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {'MET-ACCEPT-001', 'MET-PUBLISH-001', 'MET-REPAIR-017', 'CONF-FIX-007', 'MET-ADOPT-002', 'MET-PERF-010', 'MET-PERF-009', 'CONF-DIAG-003', 'MET-PERF-011', 'MET-PERF-012', 'CONF-PERF-006', 'CONF-BENCH-002', 'MET-PERF-013', 'CONF-BENCH-003', 'MET-REPAIR-018', 'CONF-FIX-008', 'MET-PERF-014', 'CONF-DIAG-004', 'MET-PERF-015', 'CONF-FIX-009', 'MET-PERF-016', 'MET-PERF-017', 'MET-REPAIR-019', 'MET-ENFORCE-001', 'MET-PERF-018', 'MET-ENFORCE-003', 'CONF-FIX-010', 'MET-UNIFY-005', 'MET-RUNNER-001', 'MET-PERF-028', 'MET-LINUX-005', 'MET-VERIFY-001', 'MET-PERF-029'}, '159 immutable plus two new packets')
        require('CONF-PERF-005' not in packets, 'repair remains unauthorized')
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'raw semantic binding')
        meta,replay = (packets[name] for name in NEW_IDS)
        require(meta['allowedPaths'] == record['ownedPaths'] and meta['predecessors'] == ['MET-PERF-007']
                and meta['repository'] == 'Harness-Engineering' and meta['sourceReuse'] == []
                and meta['prefetchCommands'] == [] and 'liveCampaignExecution' not in meta, 'meta-only scope')
        commands,prior = meta['offlineAcceptanceCommands'],packets['MET-PERF-007']['offlineAcceptanceCommands']
        require(len(commands) == 32 and commands[:-3] == prior[:-2] and commands[-2:] == prior[-2:]
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_backend_timing.py']
                and meta['offlineExecution'] == packets['MET-PERF-007']['offlineExecution'], 'all31 prior commands plus timing validator')
        require(replay['repository'] == 'mas-harness-conformance-labs'
                and replay['allowedPaths'] == ['tests/live_backend/test_proxy_server.py']
                and replay['predecessors'] == ['MET-PERF-008','CONF-FIX-006','CONF-DIAG-001']
                and replay['offlineAcceptanceCommands'] == COMMANDS and replay['prefetchCommands'] == []
                and replay['offlineExecution'] == packets['CONF-LIVE-003']['offlineExecution']
                and replay['sourceReuse'] == [] and 'liveCampaignExecution' not in replay, 'closed read-only diagnostic')
        for path,rule in record['metaRecipes'].items():
            before = historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule) == acceptance_history(path, inputs[path]), 'exact reversible amendment')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'all inherited test identities')
        validate_spec(parse(inputs[SPEC_PATH]))
        for path in record['navigationPaths']:
            require(b'BACKEND_TIMING_DIAGNOSTICS.md' in inputs[path]
                    and b'MET-PERF-008' in inputs[path] and b'CONF-DIAG-002' in inputs[path]
                    and b'NOT_AUTHORIZED' in inputs[path], 'current navigation: '+path)
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid backend timing authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors))
        raise SystemExit(1)
    print('Backend timing authority valid:161 specifications;159 immutable predecessors; one read-only attempt, no product acceptance.')
