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
    from validate_conformance_publication import historical_bytes as publication_history, current_test_bytes as publication_current, validate_additions as publication_additions
except ImportError:
    from scripts.validate_conformance_publication import historical_bytes as publication_history, current_test_bytes as publication_current, validate_additions as publication_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/local-acceptance-authority.json"
RECORD_SHA256 = "24d37407d309f3355c4ad6bb0278c8a35481dce6955a1f89e9626b05d62497da"
NEW_IDS = ("MET-ACCEPT-001",)
RECORD_FILE_SHA256 = "d22a4cb6e3d0e8236722ff9bf102db9d70f39e9a1e91d8d8ca679bf03a1cbb28"
HISTORY_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_backend_timing.py","scripts/validate_broker_handoff.py","scripts/validate_canonical_repair_plan.py","scripts/validate_ci_performance.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_provider_adoption.py","scripts/validate_proxy_contract.py","scripts/validate_proxy_diagnostics.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_backend_timing.py","tests/test_broker_handoff.py","tests/test_canonical_repair_plan.py","tests/test_ci_performance.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_provider_adoption.py","tests/test_proxy_contract.py","tests/test_proxy_diagnostics.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


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
    raw = publication_history(path, raw)
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
        return publication_current(before)
    require(len(matches) == 1, "unique predecessor")
    return publication_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return publication_additions(packets)
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


SPEC_PATH = "architecture/local-acceptance.json"
EXPECTED_SPEC_SHA256 = "b3465d781c686ea454db2ea6e81f0cbc8fe7ebde1983e13f05e5326260d6721d"
EXPECTED_MEMBER_DIGESTS = {"schemaVersion":"9f44160b33224b654e8112a1d3df18cd301af502366011588a988a28e13c4af4","metaPacketId":"6e7216b6dd58cc615b9cb37a0255a73aceea45386b31bcf989d44d45cb736657","sourceOwner":"d8e3cfb01e7fcf67910952da2bce81f2dcd698c5b08559853c3285148af50ba3","metaBase":"b9d74e86a217c19ab057274506d19b369d14e7e993e2fd34267026989b765407","evidenceClass":"b2ee1fd97b9292c5e414d3a56ab59b402c4178115820a69a0e9d1d802105c007","productPacketSha256":"a6001611d95de10d8a9d96de87a9736fa5ff3146497512e5f7134220e2077ec1","subject":"f04e8a636b21e1d1c9dc84350ed98b12f8f8b8d584ed9d3f505e5fe75f4ff893","remoteCheckpoint":"6bb60622be22e9e06b39298da9bb33287a21c891664b058d0a733746c1a37f5e","toolchain":"961c3bc7912245087f7c3e6a973de2e47c213318160d213567574c38eda25baf","previousDiagnostic":"72e43b2d0ffe1efc8a1c20ed76133f564fdaef0eb4a3f85ae4f8f79760cd8329","earlierDiagnostic":"bd86ee523570e7991db2179c0f63ca8086910b13329b3bdb39ced95334992a61","priorFailures":"1abbb34b9b0630ae6bcb045509d5d474335bd07b4e90e41d807c4d2687f911ca","signedHistory":"4ad7ed24da61e59ed8a704c52f14a9e48181dc14790f2cb7bb1b35d89fb0cfd0","allowance":"98518e40371f3225320b4977199387b8bf75e50f6d9a8dfa5efc3659619f8dc3","recipe":"29b2c9934600112feb344aab2d0c327487694ed16317f615321867e45d5077ee","gates":"275c181887b1fe6aa393f4ac487baa464d99c95fa9238e87bb94b17dffd05ce4"}
COMMANDS = [["python3","-m","unittest","discover","-s","tests/meta","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/parity","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/alpha1","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/fixes/runner_boundary","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/platform/linux_baseline","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/live_backend","-p","test_*.py"],["make","campaign","CAMPAIGN=linux-baseline"],["make","evidence-verify","CAMPAIGN=linux-baseline"]]


def validate_spec(spec, *, bind=True):
    """Closed planning data, not signature verification or execution authority."""
    require(type(spec) is dict and set(spec) == set(EXPECTED_MEMBER_DIGESTS), 'closed local allowance')
    if bind:
        require(digest(canonical(spec)) == EXPECTED_SPEC_SHA256, 'exact specification')
    for key, checksum in EXPECTED_MEMBER_DIGESTS.items():
        require(digest(canonical(spec[key])) == checksum, 'changed allowance boundary: '+key)
    require(spec['metaPacketId'] == 'MET-ACCEPT-001' and spec['sourceOwner'] == 'CONF-LIVE-003', 'single existing owner')
    recipe = spec['recipe']
    require(recipe['commands'] == COMMANDS and len(COMMANDS) == 8
            and recipe['prefetchCommands'] == [] and recipe['profile'] == 'python-conformance-stdlib', 'original whole acceptance')
    require(recipe['attemptsMaximum'] == 1 and recipe['retriesMaximum'] == 0
            and recipe['timeoutSeconds'] == 900 and recipe['nestedTimeoutSeconds'] == 420
            and recipe['workflowTimeoutMinutes'] == 15 and recipe['expectedSkips'] == 0, 'one bounded attempt')
    inventory = spec['subject']['inventory']
    require(len(inventory) == 135 and digest(canonical(inventory)) == spec['subject']['inventoryDataSha256'], 'full source inventory')
    suites = recipe['testSuites']
    require([row['root'] for row in suites] == [argv[5] for argv in COMMANDS[:6]], 'exact discovery roots')
    require(sum(row['count'] for row in suites) == 1277 and len(suites) == 6, 'full test scope')
    for row in suites:
        require(row['identities'] == sorted(set(row['identities'])) and len(row['identities']) == row['count'], 'complete static identities')
    require(spec['previousDiagnostic']['remainingAttempts'] == 0
            and spec['previousDiagnostic']['evidenceClass'] == 'WORKLOAD_DIAGNOSTIC_ONLY'
            and spec['allowance']['kind'] == 'EXPLICIT_ADDITIONAL_LOCAL_ONLY'
            and spec['allowance']['oldBudgetsReset'] is False
            and spec['allowance']['consumeOnReservation'] is True, 'no hidden retry reset')
    require(spec['gates']['productSourcePush'] is False and spec['gates']['productCI'] is False
            and spec['gates']['productMerge'] is False and spec['gates']['productSourceEdits'] is False
            and spec['gates']['maximumEvidenceClass'] == 'LOCAL_OFFLINE_ACCEPTANCE_ONLY', 'local-only boundary')


def load_inputs(root):
    record = parse(regular_bytes(root,RECORD_PATH))
    pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record,{p:regular_bytes(root,p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact history routing')
        require(validate_additions(packets) == [], 'new meta packet binding')
        pins = {**record['protectedFiles'], **record['inputFiles'], **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'exact fresh inputs')
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(publication_history(path, inputs[path])) == checksum, 'changed source: '+path)
        old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old) == 161 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {'MET-PUBLISH-001', 'MET-REPAIR-017', 'CONF-FIX-007', 'MET-ADOPT-002', 'MET-PERF-010', 'MET-PERF-009', 'CONF-DIAG-003', 'MET-PERF-011', 'MET-PERF-012', 'CONF-PERF-006', 'CONF-BENCH-002', 'MET-PERF-013', 'CONF-BENCH-003', 'MET-REPAIR-018', 'CONF-FIX-008', 'MET-PERF-014', 'CONF-DIAG-004', 'MET-PERF-015', 'CONF-FIX-009', 'MET-PERF-016', 'MET-PERF-017', 'MET-REPAIR-019', 'MET-ENFORCE-001', 'MET-PERF-018', 'MET-ENFORCE-003', 'CONF-FIX-010', 'MET-UNIFY-005', 'MET-RUNNER-001', 'MET-PERF-028', 'MET-LINUX-005', 'MET-VERIFY-001', 'MET-PERF-029'}, '161 unchanged plus one META')
        require('CONF-PERF-005' not in packets, 'no speculative repair')
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'packet source parity')
        meta = packets['MET-ACCEPT-001']
        require(meta['allowedPaths'] == record['ownedPaths'] and meta['predecessors'] == ['MET-PERF-008']
                and meta['repository'] == 'Harness-Engineering' and meta['sourceReuse'] == []
                and meta['prefetchCommands'] == [] and 'liveCampaignExecution' not in meta, 'META-only scope')
        commands, prior = meta['offlineAcceptanceCommands'], packets['MET-PERF-008']['offlineAcceptanceCommands']
        require(len(commands) == 33 and commands[:-3] == prior[:-2] and commands[-2:] == prior[-2:]
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_local_acceptance.py']
                and meta['offlineExecution'] == packets['MET-PERF-008']['offlineExecution'], 'all32 prior commands retained')
        spec = parse(inputs[SPEC_PATH]); validate_spec(spec)
        product = packets['CONF-LIVE-003']
        require(digest(inputs['task-packets/CONF-LIVE-003.yaml']) == spec['productPacketSha256']
                and product['offlineAcceptanceCommands'] == COMMANDS
                and product['prefetchCommands'] == []
                and product['offlineExecution'] == spec['recipe']['offlineExecution'], 'unchanged product packet')
        for path, rule in record['metaRecipes'].items():
            before = historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule) == publication_history(path, inputs[path]), 'exact reversible amendment')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'inherited test identity preservation')
        for path in record['navigationPaths']:
            require(b'LOCAL_ACCEPTANCE_REVALIDATION.md' in inputs[path] and b'MET-ACCEPT-001' in inputs[path]
                    and b'CONF-LIVE-003' in inputs[path] and b'NOT_DUE' in inputs[path], 'current navigation')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid local acceptance authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors))
        raise SystemExit(1)
    print('Local acceptance authority valid:194 specifications;161 unchanged packets; one additional local-only attempt.')
