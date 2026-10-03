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
    from validate_conformance_completion import historical_bytes as completion_history, current_test_bytes as completion_current, validate_additions as completion_additions
except ImportError:
    from scripts.validate_conformance_completion import historical_bytes as completion_history, current_test_bytes as completion_current, validate_additions as completion_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/conformance-publication-authority.json"
RECORD_SHA256 = "a4d41df9c922307dc204f2e618e1ad7723e0c921b20742732349d429be1bd4a7"
NEW_IDS = ("MET-PUBLISH-001",)
RECORD_FILE_SHA256 = "742567802e0df4a9cb67ff029fb4f49953badf5e84117bfd935a7af4957db119"
HISTORY_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_backend_timing.py","scripts/validate_broker_handoff.py","scripts/validate_canonical_repair_plan.py","scripts/validate_ci_performance.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_local_acceptance.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_provider_adoption.py","scripts/validate_proxy_contract.py","scripts/validate_proxy_diagnostics.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_backend_timing.py","tests/test_broker_handoff.py","tests/test_canonical_repair_plan.py","tests/test_ci_performance.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_local_acceptance.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_provider_adoption.py","tests/test_proxy_contract.py","tests/test_proxy_diagnostics.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


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
    raw = completion_history(path, raw)
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
        return completion_current(before)
    require(len(matches) == 1, "unique predecessor")
    return completion_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return completion_additions(packets)
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


SPEC_PATH = "architecture/conformance-publication.json"
EXPECTED_SPEC_SHA256 = "b7900fb9a37802261e9e1aa9b6001521eed235809ee3e94313203f2c6cc140ea"
EXPECTED_MEMBER_DIGESTS = {"schemaVersion":"29a26498cbca00bbfe7d3dc08e97b3433ebe9417983ff04fe11c4abe920e38de","metaPacketId":"1b40ae52e103b5988d10158b05ae367c75054a9d5ecc4135732c9b1bae89415c","sourceOwner":"d8e3cfb01e7fcf67910952da2bce81f2dcd698c5b08559853c3285148af50ba3","metaBase":"f5d81a73e462e9f36bfa62a1910d1c5e13d270d0b2c747abf1415a6d6de5f403","evidenceClass":"b2ee1fd97b9292c5e414d3a56ab59b402c4178115820a69a0e9d1d802105c007","prerequisite":"ad94be79ecbde1a4f7e2ff64377d448589b6bcc40c2146e0fe50951b2997be77","subject":"ace01a621a5e4745af0b54ac63fcab85e4a1b8892ab961246a050a5b9be71765","localEvidence":"53e8ede52f7668e59db6cedab307ac59cfe0499f74c3953f193a8fd6166b6f10","remoteCheckpoint":"b2170cb0ef1326ee9ecf24a931fdb73b4a8ecf50b085c59f73d40a3a9788d0e0","signedHistory":"fefdd59ab3d300fa48885a007d23e3226ab51f6ff56f2251babb94550c585e50","recipe":"347e578126b81a7d384ae54c00ac667a13fd42b5c2ce56019b2a8f3161cbea90","publication":"05e31584d3ad77e395ede85c9cd24244a4d5bfd57399313a106358b6047d0f2d","executions":"5537147a8e5beaeb4123fc748d01c05a8adece6d9faa8475a7169987e2ae7b9a","custody":"956e212ab6f710005455982414c0e0c7cd84e4d3038db530ec703f4200bd1020","gates":"d0b775761868c2e7fc77c605fb1dffa41dbe60a1649e9021eb606afe7dd3ac8a"}
COMMANDS = [["python3","-m","unittest","discover","-s","tests/meta","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/parity","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/alpha1","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/fixes/runner_boundary","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/platform/linux_baseline","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/live_backend","-p","test_*.py"],["make","campaign","CAMPAIGN=linux-baseline"],["make","evidence-verify","CAMPAIGN=linux-baseline"]]



def validate_spec(spec, *, bind=True):
    """Closed source-only publication policy; no authentication or product execution."""
    require(type(spec) is dict and set(spec) == set(EXPECTED_MEMBER_DIGESTS), 'closed publication')
    if bind:
        require(digest(canonical(spec)) == EXPECTED_SPEC_SHA256, 'exact specification')
    for key, checksum in EXPECTED_MEMBER_DIGESTS.items():
        require(digest(canonical(spec[key])) == checksum, 'changed publication boundary: '+key)
    require(spec['metaPacketId'] == 'MET-PUBLISH-001' and spec['sourceOwner'] == 'CONF-LIVE-003', 'single existing owner')
    require(spec['subject']['commit'] == spec['publication']['newHead']
            and spec['subject']['sourceFiles'] == 135 and spec['subject']['staticTestIds'] == 1277, 'exact local subject')
    require(spec['recipe']['commands'] == COMMANDS and len(COMMANDS) == 8
            and spec['recipe']['prefetchCommands'] == [] and spec['recipe']['expectedSkips'] == 0, 'original whole recipe')
    require(spec['localEvidence']['testsPassed'] == 1277 and spec['localEvidence']['commandCount'] == 8
            and spec['localEvidence']['remainingAttempts'] == 0 and spec['localEvidence']['attemptConsumed']
            and spec['localEvidence']['evidenceClass'] == 'LOCAL_OFFLINE_ACCEPTANCE_ONLY', 'prior local boundary')
    require([row['stage'] for row in spec['executions']] == ['CI','LOCAL_EXACT_MAIN']
            and all(type(row['maximumAttempts']) is int and row['maximumAttempts'] == 1
                    and type(row['retries']) is int and row['retries'] == 0 for row in spec['executions']), 'separate bounded stages')
    paths = [spec['publication']['reservation'],*[row['reservation'] for row in spec['executions']]]
    require(len(set(paths)) == 3 and all(path.startswith('operator-attempts/MET-PUBLISH-001-CONF-LIVE-003-') for path in paths), 'durable distinct reservations')
    require(spec['signedHistory']['recordCount'] == 81 and not spec['signedHistory']['resignRenewsAllowance']
            and not spec['prerequisite']['oldBudgetsReset'], 'no new budget from signatures')
    require(not any(spec['publication'][key] for key in ('sourceEdits','newBranch','newPR','forcePush','rebase','bypassProtection')), 'publication only')
    require(not spec['gates']['productExecutionInThisMetaRun'] and not spec['gates']['productEdits']
            and not spec['gates']['tenantAcceptance'] and not spec['gates']['phaseCompletion'], 'evidence and run boundary')


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
            require(type(inputs[path]) is bytes and digest(completion_history(path, inputs[path])) == checksum, 'changed source: '+path)
        old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old) == 162 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {'MET-REPAIR-017','CONF-FIX-007', 'MET-ADOPT-002', 'MET-PERF-010', 'MET-PERF-009', 'CONF-DIAG-003', 'MET-PERF-011', 'MET-PERF-012', 'CONF-PERF-006', 'CONF-BENCH-002', 'MET-PERF-013', 'CONF-BENCH-003', 'MET-REPAIR-018', 'CONF-FIX-008', 'MET-PERF-014', 'CONF-DIAG-004', 'MET-PERF-015', 'CONF-FIX-009', 'MET-PERF-016', 'MET-PERF-017', 'MET-REPAIR-019', 'MET-ENFORCE-001', 'MET-PERF-018', 'MET-ENFORCE-003', 'CONF-FIX-010', 'MET-UNIFY-005', 'MET-RUNNER-001', 'MET-PERF-028', 'MET-LINUX-005', 'MET-VERIFY-001', 'MET-PERF-029'}, '162 immutable plus one META')
        require('CONF-PERF-005' not in packets, 'no speculative repair')
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'packet source parity')
        meta = packets['MET-PUBLISH-001']
        require(meta['allowedPaths'] == record['ownedPaths'] and meta['predecessors'] == ['MET-ACCEPT-001']
                and meta['repository'] == 'Harness-Engineering' and meta['sourceReuse'] == []
                and meta['prefetchCommands'] == [] and 'liveCampaignExecution' not in meta, 'META-only scope')
        commands, prior = meta['offlineAcceptanceCommands'], packets['MET-ACCEPT-001']['offlineAcceptanceCommands']
        require(len(commands) == 34 and commands[:-3] == prior[:-2] and commands[-2:] == prior[-2:]
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_conformance_publication.py']
                and meta['offlineExecution'] == packets['MET-ACCEPT-001']['offlineExecution'], 'all33 prior commands retained')
        spec = parse(inputs[SPEC_PATH]); validate_spec(spec)
        old_spec = parse(inputs['architecture/local-acceptance.json'])
        require(digest(inputs['architecture/local-acceptance.json']) == spec['prerequisite']['specificationSha256'], 'unchanged local allowance')
        require(spec['subject']['commit'] == old_spec['subject']['commit']
                and spec['subject']['tree'] == old_spec['subject']['tree']
                and spec['subject']['sourceInventorySha256'] == old_spec['subject']['inventoryDataSha256'], 'whole immutable subject')
        require(len(old_spec['subject']['inventory']) == 135
                and sum(row['count'] for row in old_spec['recipe']['testSuites']) == 1277, 'full predecessor source and tests')
        product = packets['CONF-LIVE-003']
        require(digest(inputs['task-packets/CONF-LIVE-003.yaml']) == spec['subject']['productPacketSha256']
                and product['offlineAcceptanceCommands'] == COMMANDS and product['prefetchCommands'] == []
                and product['offlineExecution'] == spec['recipe']['offlineExecution'], 'original product packet')
        for path, rule in record['metaRecipes'].items():
            before = historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule) == completion_history(path, inputs[path]), 'exact reversible amendment')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'inherited test identity preservation')
        for path in record['navigationPaths']:
            require(b'CONFORMANCE_PUBLICATION.md' in inputs[path] and b'MET-PUBLISH-001' in inputs[path]
                    and b'CONF-LIVE-003' in inputs[path] and b'NOT_DUE' in inputs[path], 'current navigation')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid conformance publication authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors))
        raise SystemExit(1)
    print('Conformance publication authority valid:194 specifications;162 unchanged packets; bounded later CI and LOCAL exact-main.')
