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
    from validate_document_repair_plan import historical_bytes as document_history, current_test_bytes as document_current, validate_additions as document_additions
except ImportError:
    from scripts.validate_document_repair_plan import historical_bytes as document_history, current_test_bytes as document_current, validate_additions as document_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/completion-profiling-authority.json"
RECORD_SHA256 = "abcd5ee23eaf9eb6da9ff8e40bff867fbae4c2cec75d53f9c23273e3b8e3c76a"
NEW_IDS = ("MET-PERF-009", "CONF-DIAG-003")
RECORD_FILE_SHA256 = "19b97e955a280cee0e2e9f4afa8bc38eb344f59924ef6a37dd277334cf2474d9"
HISTORY_PATHS = frozenset(["README.md","docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/CANONICAL_REPAIR_PLAN.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_backend_timing.py","scripts/validate_broker_handoff.py","scripts/validate_canonical_repair_plan.py","scripts/validate_ci_performance.py","scripts/validate_conformance_completion.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_publication.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_local_acceptance.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_provider_adoption.py","scripts/validate_proxy_contract.py","scripts/validate_proxy_diagnostics.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_research_adoption.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","scripts/validate_validation_performance.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_backend_timing.py","tests/test_broker_handoff.py","tests/test_canonical_repair_plan.py","tests/test_ci_performance.py","tests/test_conformance_completion.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_publication.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_local_acceptance.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_provider_adoption.py","tests/test_proxy_contract.py","tests/test_proxy_diagnostics.py","tests/test_research_adoption.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py","tests/test_validation_performance.py"])


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
    raw = document_history(path, raw)
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
        return document_current(before)
    require(len(matches) == 1, "unique predecessor")
    return document_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return document_additions(packets)
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


SPEC_PATH = "architecture/completion-profiling.json"
EXPECTED_SPEC_SHA256 = "c3340b25567bbb388c144b7546a3f141cc84ccd03ff1545d592230ab49776b7e"
EXPECTED_MEMBER_DIGESTS = {"schemaVersion":"f48feb29e86fe7696d5fe7a78c9b916c45d6551cd2db6e7f14e9f5d03d20cf4c","metaPacketId":"46be3e785b995a9dbbd723cfe74174fea3b39b8033aa5aeb19acaaa5b3a5d8d8","packetId":"891dc8854df736144642cd036db678b70eed392898ce624c70fb94e3efb9dad1","metaBase":"8d6b1ab1683ef609351b74b281e96c2d8f1b822e1d82804a22978b651f9bb5dd","evidenceClass":"f07fb1e0dee93df27db723be730e0723c84c2e49b5fe6a0d0cc94a4794a45002","sourceOwner":"5feb221f567fb6537008aaacde4aae9158a8363674655382aa93fcdb01a07e68","sourceEdits":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","diagnosticIsAcceptance":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","optimizationAuthorized":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","requiresBranchOrPr":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","acceptedSourcePredecessor":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","metaValidationExtension":"37f1d741451f928dba0507eca469eb6363afeacde80c8f46b6f3c9bf20f3cfa2","subject":"4b61d4546670821f199d00ccd7ed2e83e5567fcbfac2bdfa2d97a9e66a1422c0","priorFailures":"91c70a9df9b2b1a8a450e699593c304da3cb6ff9a45f786f22c500b10b9de9bb","priorBudget":"e1c4afa7dca74e8c94a01bb1cee66bfeb89e0472c45376391f61f79ef9560cfb","recipe":"ac12431f10af93d88d47f0ba946394fba24a6fcae4f9b4d554d1764879b72c5a","program":"a9476f361d50efb7efdeeb4e394f656d5a92eb98f5027f52438f8f5e2c9c0161","toolchain":"961c3bc7912245087f7c3e6a973de2e47c213318160d213567574c38eda25baf","contractPins":"47f5bf36e356e8792b6622f8d1eb7315b394d72e6653a160348c11d093bf32f3","limitations":"07346f4f1c54a9402210e89f3c433f70246c8d973004e2e1f879e046fcdd1ded","gates":"91b5c648408dd9556570750fc1fbd42f31c3e8d19b8fa09de731c04cfcec541a","reconciliation":"c2a7c8be246208275f8ac37a2cf165219ab9b545ce7eedb5dcbdb3edab0badfe"}
PROGRAM_PATH = "diagnostics/conf_diag_003.py"
PROGRAM_SHA256 = "cea27b7a29a7d0aa2d944f7e2389c53f015e627922c6e4a0348ce7c78d9373b9"


def validate_program(raw, spec):
    require(type(raw) is bytes and digest(raw) == PROGRAM_SHA256 == spec['program']['sha256'], 'exact diagnostic program')
    command = spec['recipe']['commands']
    require(type(command) is list and len(command) == 1 and command[0][:2] == ['python3','-c']
            and len(command[0]) == 3, 'one direct diagnostic argv')
    code = command[0][2]
    require(type(code) is str and code.isascii() and 0 < len(code) <= 4096
            and not any(c in code for c in '\x00\r\n')
            and digest(code.encode()) == spec['program']['argvCodeSha256'], 'exact bounded literal transport')
    transport = ast.parse(code)
    require(len(transport.body) == 1 and isinstance(transport.body[0], ast.Expr), 'single literal expression')
    call = transport.body[0].value
    require(isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'exec'
            and len(call.args) == 1 and not call.keywords and isinstance(call.args[0], ast.Constant)
            and type(call.args[0].value) is str, 'not a generic code loader or command parser')
    require(ast.dump(ast.parse(call.args[0].value)) == ast.dump(ast.parse(raw)), 'formatting-only AST parity')


def validate_spec(spec, *, bind=True):
    """Closed non-authorizing planning data. Never executes the diagnostic."""
    require(type(spec) is dict and set(spec) == set(EXPECTED_MEMBER_DIGESTS), 'closed profiling specification')
    if bind:
        require(digest(canonical(spec)) == EXPECTED_SPEC_SHA256, 'exact profiling specification')
    for key, checksum in EXPECTED_MEMBER_DIGESTS.items():
        require(digest(canonical(spec[key])) == checksum, 'changed profiling boundary: '+key)
    require(spec['metaPacketId'] == 'MET-PERF-009' and spec['packetId'] == 'CONF-DIAG-003'
            and spec['sourceOwner'] == 'CONF-FIX-007', 'exact owners')
    for key in ('sourceEdits','diagnosticIsAcceptance','optimizationAuthorized','requiresBranchOrPr','acceptedSourcePredecessor'):
        require(spec[key] is False, 'no product or acceptance grant')
    grant = spec['reconciliation']
    require(spec['metaBase'] == grant['base'] == '91b320b9f8525e986260fc4792b01f125b5feae9'
            and grant['draft'] == '1886aa2272f8d8bc73da60ebd7a6738f288de5fb', 'exact reconciled sources')
    require(grant['budgets'] == {'LOCAL':7,'newLocalOrdinals':[6,7],
        'retainedLocalOrdinals':[1,2,3,4,5],'CI':2,'LOCAL_EXACT_MAIN':1,
        'diagnostics':0,'productExecutions':0,'reset':False,'transfer':False}, 'finite reconciliation allowance')
    require([r['ordinal'] for r in grant['retainedMetaFailures']] == [1,2,3,4,5]
            and all(r['exitCode'] != 0 for r in grant['retainedMetaFailures']), 'all original failures retained')
    require(grant['currentFirstOrder'] == ['MET-PERF-009','MET-PERF-010','MET-ADOPT-002','OLDER_IMMUTABLE_AUTHORITIES'], 'one-way historical normalization')
    recipe, subject = spec['recipe'], spec['subject']
    ids = recipe['expectedTestIds']
    require(type(ids) is list and ids == sorted(set(ids)) and len(ids) == recipe['testCount'] == 1397, 'all backend identities')
    require(recipe['profiledTestCount'] == 1394 and len(recipe['timingOnlyTestIds']) == 3
            and set(recipe['timingOnlyTestIds']) <= set(ids), 'profile coverage not test filtering')
    require(recipe['attemptsMaximum'] == 1 and recipe['retriesMaximum'] == 0
            and recipe['timeoutSeconds'] == 900 and recipe['nestedTimeoutSeconds'] == 420
            and recipe['workflowTimeoutMinutes'] == 15 and recipe['skips'] == 0
            and recipe['prefetchCommands'] == [] and recipe['sourceOverlay'] is False, 'one unchanged-boundary diagnostic')
    require(subject['commit'] == '25fab12c168ff686e863291098fce0f3dba629bd'
            and subject['tree'] == '6f38052fb9a31e9fe8b9abb6b055ddd96f06854f'
            and subject['fullAcceptance'] is False and subject['fullTestInventory'] == 1567
            and len(subject['inventory']) == 135
            and digest(canonical(subject['inventory'])) == subject['inventoryDataSha256'], 'exact unaccepted subject')
    require([r['ordinal'] for r in spec['priorFailures']] == [1,2,3]
            and all(r['exitCode'] != 0 and r['fullAcceptance'] is False for r in spec['priorFailures'])
            and spec['priorBudget']['remainingLocal'] == 0 and spec['priorBudget']['resetAllowed'] is False,
            'failed LOCAL allowances remain consumed')


def load_inputs(root):
    record = parse(regular_bytes(root,RECORD_PATH)); pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record,{p:regular_bytes(root,p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact current-first history routing')
        require(validate_additions(packets) == [], 'exact new packets')
        pins = {**record['protectedFiles'], **record['inputFiles'], **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'fresh complete source input set')
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(document_history(path,inputs[path])) == checksum, 'changed source: '+path)
        old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old) == 167 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {"MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010", "MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}, '167 immutable plus two new packets')
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'raw packet parity')
        meta, replay = (packets[name] for name in NEW_IDS)
        require(meta['allowedPaths'] == record['ownedPaths'] and meta['predecessors'] == ['MET-PERF-010']
                and meta['repository'] == 'Harness-Engineering', 'META-only publication owner')
        commands, prior = meta['offlineAcceptanceCommands'], packets['MET-PERF-010']['offlineAcceptanceCommands']
        require(len(commands) == 38 and commands[:-3] == prior[:-2] and commands[-2:] == prior[-2:]
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_completion_profiling.py']
                and meta['offlineExecution'] == packets['MET-PERF-010']['offlineExecution'], 'whole37-command predecessor recipe')
        spec = parse(inputs[SPEC_PATH]); validate_spec(spec); validate_program(inputs[PROGRAM_PATH],spec)
        require(replay['repository'] == 'mas-harness-conformance-labs'
                and replay['allowedPaths'] == ['tests/live_backend/test_proxy_server.py']
                and replay['predecessors'] == ['MET-PERF-009','CONF-FIX-007']
                and replay['offlineAcceptanceCommands'] == spec['recipe']['commands']
                and replay['offlineExecution'] == packets['CONF-FIX-007']['offlineExecution'], 'one read-only subject diagnostic')
        for packet in (meta,replay):
            require(packet['sourceReuse'] == [] and packet['prefetchCommands'] == []
                    and packet['warmSourceAccess'] == 'PROHIBITED_DURING_IMPLEMENTATION'
                    and 'liveCampaignExecution' not in packet, 'no source reuse or live authority')
        for path, checksum in spec['contractPins'].items():
            require(digest(inputs[path]) == checksum, 'unchanged completion/reuse contract')
        for path, checksum in spec['reconciliation']['protectedAcceptedInputs'].items():
            require(digest(inputs[path]) == checksum, 'accepted performance input changed')
        for path, rule in record['metaRecipes'].items():
            before = historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule) == document_history(path,inputs[path]), 'exact reversible metadata')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'all inherited tests retained')
        for path in record['navigationPaths']:
            require(b'COMPLETION_PROFILING.md' in inputs[path] and b'MET-PERF-009' in inputs[path]
                    and b'CONF-DIAG-003' in inputs[path] and b'BLOCKED_LOCAL_BUDGET_EXHAUSTED' in inputs[path]
                    and b'HARNESS_PAPER_REPOSITORY_MAP.md' in inputs[path], 'current roadmap and research continuity')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid completion profiling authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Completion profiling authority valid:194 specifications;167 immutable packets; one diagnostic, no acceptance reset.')
