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
    from validate_guard_cost_repair import historical_bytes as guard_history, current_test_bytes as guard_current, validate_additions as guard_additions, historical_catalog as guard_catalog
except ImportError:
    from scripts.validate_guard_cost_repair import historical_bytes as guard_history, current_test_bytes as guard_current, validate_additions as guard_additions, historical_catalog as guard_catalog

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = 'architecture/factory-diagnostics-authority.json'
RECORD_SHA256 = 'b7c413a578ee78df11a541588404efb7dc521560f52f7ce9a4fdae11e50aff9d'
NEW_IDS = ('MET-PERF-014', 'CONF-DIAG-004')
RECORD_FILE_SHA256 = '7470ecc4449635a91293aef6ea5f4e984ac772123e87ff59f1d5669acfd87834'
HISTORY_PATHS = frozenset(['README.md', 'docs/DEVELOPMENT_STATUS.md', 'docs/MASTER_DEVELOPMENT_PLAN.md', 'docs/READINESS_INDEX.md', 'docs/alpha-2/BENCHMARK_TRANSPORT.md', 'docs/alpha-2/CANONICAL_REPAIR_PLAN.md', 'docs/alpha-2/COMPLETION_INTEGRATION.md', 'docs/alpha-2/CONFORMANCE_COMPLETION.md', 'docs/alpha-2/DOCUMENT_REPAIR_AUTHORITY.md', 'docs/alpha-2/DOCUMENT_REPAIR_PLAN.md', 'docs/alpha-2/LIVE_BACKEND_READINESS.md', 'docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md', 'docs/repositories/00-harness-engineering.md', 'docs/repositories/12-mas-harness-conformance-labs.md', 'scripts/validate_backend_timing.py', 'scripts/validate_benchmark_transport.py', 'scripts/validate_broker_handoff.py', 'scripts/validate_canonical_repair_plan.py', 'scripts/validate_ci_performance.py', 'scripts/validate_completion_integration.py', 'scripts/validate_completion_profiling.py', 'scripts/validate_conformance_completion.py', 'scripts/validate_conformance_consumer_closure.py', 'scripts/validate_conformance_performance.py', 'scripts/validate_conformance_performance_followup.py', 'scripts/validate_conformance_publication.py', 'scripts/validate_conformance_reference_measurement.py', 'scripts/validate_conformance_successor_checkpoint.py', 'scripts/validate_credential_lifecycle.py', 'scripts/validate_credential_ordering.py', 'scripts/validate_custody_handoff.py', 'scripts/validate_document_repair_execution.py', 'scripts/validate_linux_readiness.py', 'scripts/validate_linux_repair.py', 'scripts/validate_linux_test_ownership.py', 'scripts/validate_live_backend_readiness.py', 'scripts/validate_local_acceptance.py', 'scripts/validate_model_api_inventory.py', 'scripts/validate_model_fixture_scope.py', 'scripts/validate_native_qualification.py', 'scripts/validate_packet_scalar_repair.py', 'scripts/validate_policy_observation.py', 'scripts/validate_provider_adoption.py', 'scripts/validate_proxy_contract.py', 'scripts/validate_proxy_diagnostics.py', 'scripts/validate_readiness.py', 'scripts/validate_readiness_repairs.py', 'scripts/validate_research_adoption.py', 'scripts/validate_reuse.py', 'scripts/validate_successor_inventory.py', 'scripts/validate_validation_performance.py', 'task-packets/README.md', 'tests/test_alpha2_readiness.py', 'tests/test_backend_timing.py', 'tests/test_benchmark_transport.py', 'tests/test_broker_handoff.py', 'tests/test_canonical_repair_plan.py', 'tests/test_ci_performance.py', 'tests/test_completion_integration.py', 'tests/test_completion_profiling.py', 'tests/test_conformance_completion.py', 'tests/test_conformance_consumer_closure.py', 'tests/test_conformance_performance.py', 'tests/test_conformance_performance_followup.py', 'tests/test_conformance_publication.py', 'tests/test_conformance_reference_measurement.py', 'tests/test_conformance_successor_checkpoint.py', 'tests/test_credential_lifecycle.py', 'tests/test_credential_ordering.py', 'tests/test_custody_handoff.py', 'tests/test_document_repair_execution.py', 'tests/test_document_repair_plan.py', 'tests/test_linux_readiness.py', 'tests/test_linux_repair.py', 'tests/test_linux_test_ownership.py', 'tests/test_live_backend_readiness.py', 'tests/test_local_acceptance.py', 'tests/test_model_api_inventory.py', 'tests/test_model_fixture_scope.py', 'tests/test_native_qualification.py', 'tests/test_packet_scalar_repair.py', 'tests/test_policy_observation.py', 'tests/test_provider_adoption.py', 'tests/test_proxy_contract.py', 'tests/test_proxy_diagnostics.py', 'tests/test_research_adoption.py', 'tests/test_reuse.py', 'tests/test_successor_inventory.py', 'tests/test_task_packets.py', 'tests/test_validation_performance.py'])


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
    raw = guard_history(path, raw)
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
        return guard_current(before)
    require(len(matches) == 1, "unique predecessor")
    return guard_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return guard_additions(packets)
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


SPEC_PATH = 'architecture/factory-diagnostics.json'
SPEC_SHA256 = '7f1f7b8ade5fd27c5705e5d19092f40b070a76c7b1fa9c5212b3c51e18d2e223'
MEMBER_DIGESTS = {'schemaVersion': '15c23fbb23ffe18484f6ceaab44beee0d65728a59ca9ab2ea4215b221f1c59f8', 'packetId': '3b3d8e4fa404f44594cf854a093628cd60309a45995cc9ca3038a8621387de48', 'metaBase': '12c6ed92c6a04b3e0451c1786c9d0d78bb8d95bb8799bbcc50efec7877f926dc', 'status': '0da9365f401908507ca93b0b0a3016a6beaadd8af1310b652f540dc34b73a11f', 'subject': '38c9ade91053d4287d0160fdf0e7d488ff5e27d307f8c4a4ad0a122f59a9ef22', 'priorFailure': 'b9b649ee5293eba949fab0dd19b19fc5a9963da8bee479c7d9d8cc00e2d21d18', 'recipe': '45245a2de4fe7422b8e195835d48c8a8acd2b186b1ad625e81077810bee4664f', 'program': '9982035cfe3c42b3bfaa3d2b23a9db32325aadb5cf7b5248f203295480ffd860', 'observer': '38305cadcd89fdf88120411b289661a6518f4cc6c9c13470d74dccc9c7abb02a', 'budgets': 'c71aded0ad4e785d499c1719e4d38ae7dcf3e006e9d671d6e4094697176ca4ca', 'limits': '55c877ff2cfdeb3570006b31f6a0bc121923356c6912855cccf6b8e7fa5cce47', 'gates': 'e636388a65621b23c966668db10d80415d0a5713adb5e657f97ce166c3e96f27', 'preservedArtifacts': '5b46f8090b091a7c359b0e6b7b978dbc4e8aa47f43ef05a7499c5de1914596ec', 'dispatchOverlaps': '3bb0da32625d349596715fdc8d6078a7e6001923f3fe9eb271577bef5e3ac9a4', 'productExecutionInMetaRun': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'productAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'nativeAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'tenantAcceptance': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'phaseComplete': 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa', 'testAccounting': 'a529875bee871609163cf335e0c45d266ade2e2b39d48c9181cd934abbb6b46d'}
PROGRAM_PATH = 'diagnostics/conf_diag_004.py'
SOURCE = 'architecture/factory-diagnostics-inputs/static-source.json'
RESULT = 'architecture/factory-diagnostics-inputs/local01-result.json'


def historical_catalog(packets):
    record = _record(); pinned(record)
    require(validate_additions(packets) == [], 'exact factory packets')
    packets = guard_catalog(packets)
    old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
    require(len(old) == 177 and set(packets) == old | set(NEW_IDS), 'closed 179-packet catalog')
    return {name: packets[name] for name in old}


def validate_spec(value, *, bind=True):
    require(type(value) is dict and set(value) == set(MEMBER_DIGESTS), 'closed diagnostic specification')
    if bind:
        require(digest(canonical(value)) == SPEC_SHA256, 'exact diagnostic specification')
    for key, checksum in MEMBER_DIGESTS.items():
        require(digest(canonical(value[key])) == checksum, 'changed diagnostic boundary: '+key)
    require(value['productExecutionInMetaRun'] is value['productAcceptance'] is value['nativeAcceptance']
            is value['tenantAcceptance'] is value['phaseComplete'] is False, 'no execution or promotion')


def validate_program(raw, value):
    require(digest(raw) == value['program']['sha256'], 'exact observer asset')
    commands = value['recipe']['commands']
    require(len(commands) == 1 and len(commands[0]) == 3 and commands[0][:2] == ['python3','-c'], 'one direct argv')
    code = commands[0][2]
    require(type(code) is str and code.isascii() and len(code) <= 4096 and not any(x in code for x in '\n\r\0')
            and digest(code.encode()) == value['program']['argvCodeSha256'], 'bounded immutable argv')
    tree = ast.parse(code)
    require(len(tree.body) == 1 and isinstance(tree.body[0],ast.Expr), 'one literal expression')
    call = tree.body[0].value
    require(isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id == 'exec'
            and len(call.args) == 1 and not call.keywords and isinstance(call.args[0],ast.Constant)
            and type(call.args[0].value) is str, 'literal transport only')
    require(ast.dump(ast.parse(call.args[0].value)) == ast.dump(ast.parse(raw)), 'asset transport AST parity')


def load_inputs(root):
    record = parse(regular_bytes(root,RECORD_PATH)); pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record,{p:regular_bytes(root,p) for p in paths}


def close_factory_dispatch(packets, errors):
    try:
        record = _record(); pinned(record); historical_catalog(packets)
        value = parse(regular_bytes(ROOT,SPEC_PATH)); validate_spec(value)
        exact = []
        for row in value['dispatchOverlaps']:
            a,b,path = row['left'],row['right'],row['path']
            for name in (a,b):
                p = 'task-packets/'+name+'.yaml'; raw = regular_bytes(ROOT,p)
                expected = record['inputFiles'].get(p,record['protectedFiles'].get(p))
                require(digest(raw) == expected and canonical(safe_load(raw)) == canonical(packets[name]), 'exact overlap neighbors')
            require(path in packets[a]['allowedPaths'] and path in packets[b]['allowedPaths'], 'exact read-only anchor')
            exact.append('unordered same-repository packets '+a+' and '+b+' overlap at '+repr(path)+' and '+repr(path))
        require(exact and len(exact) == len(set(exact)) and all(errors.count(e) == 1 for e in exact), 'exact diagnostic overlaps')
        return [e for e in errors if e not in exact]
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        return errors+['missing or changed factory diagnostic dispatch']


def validate_authority(packets,record,inputs):
    try:
        pinned(record); old = historical_catalog(packets)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'closed history routing')
        pins = {**record['protectedFiles'],**record['inputFiles'],**{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'complete fresh inputs')
        for p,checksum in pins.items():
            require(type(inputs[p]) is bytes and digest(guard_history(p,inputs[p])) == checksum, 'source drift: '+p)
        for name in guard_catalog(packets):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'packet byte parity')
        value = parse(inputs[SPEC_PATH]); validate_spec(value); validate_program(inputs[PROGRAM_PATH],value)
        meta,diag,prior = packets['MET-PERF-014'],packets['CONF-DIAG-004'],old['MET-REPAIR-018']
        require(meta['repository'] == 'Harness-Engineering' and meta['predecessors'] == ['MET-REPAIR-018']
                and meta['allowedPaths'] == record['ownedPaths'], 'exact META owner')
        commands = meta['offlineAcceptanceCommands']
        require(len(commands) == 43 and commands[:-3]+commands[-2:] == prior['offlineAcceptanceCommands']
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_factory_diagnostics.py'], 'all42 inherited commands')
        require(diag['repository'] == 'mas-harness-conformance-labs' and diag['predecessors'] == ['MET-PERF-014','CONF-FIX-008']
                and diag['allowedPaths'] == ['tests/live_backend/test_proxy_server.py']
                and diag['offlineAcceptanceCommands'] == value['recipe']['commands'], 'one read-only diagnostic')
        for p in (meta,diag):
            require(p['sourceReuse'] == p['prefetchCommands'] == [] and 'liveCampaignExecution' not in p
                    and p['warmSourceAccess'] == 'PROHIBITED_DURING_IMPLEMENTATION'
                    and p['offlineExecution'] == prior['offlineExecution'], 'unchanged isolation')
        for path,checksum in value['preservedArtifacts'].items():
            require(digest(inputs[path]) == checksum, 'preserved contracts and locks')
        for path,rule in record['metaRecipes'].items():
            before = historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule) == guard_history(path,inputs[path]), 'exact reversible metadata')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'inherited test identities')
        for path in record['navigationPaths']:
            require(all(s in inputs[path] for s in (b'FACTORY_DIAGNOSTICS.md',b'MET-PERF-014',b'CONF-DIAG-004',b'BLOCKED_LOCAL_FAILURE',b'HARNESS_PAPER_REPOSITORY_MAP.md',b'NOT_DUE')), 'consistent navigation')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid factory diagnostics authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Factory diagnostics authority valid:179 specifications;177 immutable packets; product diagnostic not executed or accepted.')
