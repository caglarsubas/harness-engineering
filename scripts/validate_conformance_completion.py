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
    from validate_research_adoption import historical_bytes as research_history, current_test_bytes as research_current, validate_additions as research_additions
except ImportError:
    from scripts.validate_research_adoption import historical_bytes as research_history, current_test_bytes as research_current, validate_additions as research_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/conformance-completion-authority.json"
RECORD_SHA256 = "55a816fbeb8763450e8c27797444b275adbbbfc201c887661bb9e1183974af93"
NEW_IDS = ("MET-REPAIR-017","CONF-FIX-007")
RECORD_FILE_SHA256 = "17447fa1df241ea8287adf1220c3804e431c0794c51d02ecc588b8269ad15b94"
HISTORY_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_backend_timing.py","scripts/validate_broker_handoff.py","scripts/validate_canonical_repair_plan.py","scripts/validate_ci_performance.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_publication.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_local_acceptance.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_provider_adoption.py","scripts/validate_proxy_contract.py","scripts/validate_proxy_diagnostics.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_backend_timing.py","tests/test_broker_handoff.py","tests/test_canonical_repair_plan.py","tests/test_ci_performance.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_publication.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_local_acceptance.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_provider_adoption.py","tests/test_proxy_contract.py","tests/test_proxy_diagnostics.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


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
    raw = research_history(path, raw)
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
        return research_current(before)
    require(len(matches) == 1, "unique predecessor")
    return research_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return research_additions(packets)
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


SPEC_PATH = "architecture/conformance-completion.json"
EXPECTED_SPEC_SHA256 = "28588d6989d40e260ebc3dca7b572228de4852a07bf9c5c5d8f8b45a1432cffa"
EXPECTED_MEMBER_DIGESTS = {"schemaVersion":"94c1dea45278078092a1b2bfad0d51ab7ab42744905b0f132a2e550ebbc1a904","metaPacketId":"559b06de1c7f11a0761925150da3fa407b385b5356df48d45ab4eb09d250490e","correctivePacketId":"5feb221f567fb6537008aaacde4aae9158a8363674655382aa93fcdb01a07e68","metaBase":"cd842497288d6c1eb55f46335db87d6c10babd28e4395df1968778b11e06040a","baseline":"2161bd9cdbfdcc7a64c3101abab9f0ce026f5fd3129c10a3b232c7639b38144d","publication":"b417bf36a25c741fec0dcc5be05719a2b1c5ca9c74996dc1f1c2130240c89a04","product":"fc58442afe551263755de3d69ae72cae282869dcde56a817ad246a2054bb720a","completion":"ed87df00a623214a67cb5b3a1e3cbe9ea15c3eb80a6948f9b01fcaeadb79b250","effectivePredecessors":"0d1e1e6718ae8ae07895dbc5d32f1539797ef194bb7209a1a2246d7329ea36c2","contractPins":"2af1781cf5b1a2fd847c404a1e079238c29cca27a1e64c301b370931622d9a0c","recipe":"9e1a4668d59d09bb763922ce3bb5036fdbb66f329079a5046f652e203fdab827","allowances":"d3f9bb748e38767370c191df747bd283c3c735c5f8445c44ffc79f30b08e40f3","gates":"e428942640a32d8cf47520184e778a38148627989baa6a15fd6c86bd428d5f66"}
COMMANDS = [["python3","-m","unittest","discover","-s","tests/meta","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/parity","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/alpha1","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/fixes/runner_boundary","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/platform/linux_baseline","-p","test_*.py"],["python3","-m","unittest","discover","-s","tests/live_backend","-p","test_*.py"],["make","campaign","CAMPAIGN=linux-baseline"],["make","evidence-verify","CAMPAIGN=linux-baseline"]]


def validate_spec(spec, *, bind=True):
    """Closed planning authority, never installed qualification or execution."""
    require(type(spec) is dict and set(spec) == set(EXPECTED_MEMBER_DIGESTS), 'closed completion authority')
    if bind:
        require(digest(canonical(spec)) == EXPECTED_SPEC_SHA256, 'exact specification')
    for key, checksum in EXPECTED_MEMBER_DIGESTS.items():
        require(digest(canonical(spec[key])) == checksum, 'changed completion boundary: '+key)
    require(spec['metaPacketId'] == 'MET-REPAIR-017' and spec['correctivePacketId'] == 'CONF-FIX-007', 'exact owners')
    require(spec['baseline']['files'] == 135 and spec['baseline']['testIdentities'] == 1277, 'complete baseline')
    require(spec['effectivePredecessors'] == {'CONF-LIVE-004': ['CONF-LIVE-003','CONF-FIX-007']}, 'mandatory correction')
    require(spec['recipe']['commands'] == COMMANDS and len(COMMANDS) == 8
            and spec['recipe']['prefetchCommands'] == [], 'whole original recipe')
    require(spec['publication']['implementationComplete'] is False
            and spec['publication']['historicalEvidenceRewritten'] is False, 'publication not completion')
    require([row['id'] for row in spec['completion']] == ['C1','C2','C3','C4','C5','C6','C7'], 'all completion obligations')
    require(spec['product']['sourceFilesAfter'] == 135 and len(spec['product']['allowedPaths']) == 5, 'bounded corrective ownership')


def validate_completion_evidence_shape(value):
    """Non-authorizing data check only. A valid shape is NOT authenticated evidence."""
    require(type(value) is dict and set(value) == {
        'packetId','base','tree','reviewedTree','localTree','ciTree','mainTree',
        'localPassed','requiredCIPassed','protectedMerge','exactMainPassed',
        'remainingWork','completion','reviewEvidenceSha256','evidenceClass'}, 'closed evidence shape')
    require(value['packetId'] == 'CONF-FIX-007'
            and value['base'] == '092fcf475c6f3ebd455e3c354cddb7664ea1f900', 'corrective predecessor')
    require(value['evidenceClass'] == 'SOURCE_ONLY_REQUIRES_INDEPENDENT_AUTHENTICATION', 'no native promotion')
    tree = value['tree']
    require(type(tree) is str and re.fullmatch('[0-9a-f]{40}',tree) is not None
            and tree != '0'*40 and tree != 'f5a25661c2df6c87e5d3429b0b5f62511c2e5988', 'new reviewed source tree')
    require(all(value[key] == tree for key in ('reviewedTree','localTree','ciTree','mainTree')), 'exact tree parity')
    require(all(value[key] is True for key in ('localPassed','requiredCIPassed','protectedMerge','exactMainPassed')), 'all separate source gates')
    require(value['remainingWork'] == [] and type(value['remainingWork']) is list, 'unfinished implementation')
    checksum = value['reviewEvidenceSha256']
    require(type(checksum) is str and re.fullmatch('[0-9a-f]{64}',checksum) is not None
            and checksum != '0'*64, 'review evidence reference')
    rows = value['completion']
    require(type(rows) is list and len(rows) == 7, 'seven obligations')
    for index,row in enumerate(rows,1):
        require(type(row) is dict and set(row) == {'id','sourceSymbols','testIds','reviewed'}
                and row['id'] == 'C'+str(index) and row['reviewed'] is True, 'closed ordered reviewed obligation')
        for key in ('sourceSymbols','testIds'):
            items = row[key]
            require(type(items) is list and 0 < len(items) <= 128
                    and all(type(item) is str and 0 < len(item) <= 256 for item in items)
                    and len(set(items)) == len(items), 'nonempty unique source/test mapping')
    # Deliberately no return token, signature, native flag or authority handle.


def load_inputs(root):
    record = parse(regular_bytes(root,RECORD_PATH)); pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record,{p:regular_bytes(root,p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact history routing')
        require(validate_additions(packets) == [], 'new packets bound')
        pins = {**record['protectedFiles'], **record['inputFiles'], **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'exact fresh inputs')
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(research_history(path, inputs[path])) == checksum, 'changed source: '+path)
        old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old) == 163 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {'MET-ADOPT-002', 'MET-PERF-010', 'MET-PERF-009', 'CONF-DIAG-003', 'MET-PERF-011', 'MET-PERF-012', 'CONF-PERF-006', 'CONF-BENCH-002', 'MET-PERF-013', 'CONF-BENCH-003', 'MET-REPAIR-018', 'CONF-FIX-008', 'MET-PERF-014', 'CONF-DIAG-004', 'MET-PERF-015', 'CONF-FIX-009', 'MET-PERF-016', 'MET-PERF-017', 'MET-REPAIR-019', 'MET-ENFORCE-001', 'MET-PERF-018', 'MET-ENFORCE-003', 'CONF-FIX-010', 'MET-UNIFY-005', 'MET-RUNNER-001', 'MET-PERF-028', 'MET-LINUX-005', 'MET-VERIFY-001', 'MET-PERF-029'}, '163 immutable plus two successors')
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'packet source parity')
        meta, product = packets['MET-REPAIR-017'], packets['CONF-FIX-007']
        require(meta['allowedPaths'] == record['ownedPaths'] and meta['predecessors'] == ['MET-PUBLISH-001']
                and meta['repository'] == 'Harness-Engineering', 'META-only scope')
        commands, prior = meta['offlineAcceptanceCommands'], packets['MET-PUBLISH-001']['offlineAcceptanceCommands']
        require(len(commands) == 35 and commands[:-3] == prior[:-2] and commands[-2:] == prior[-2:]
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_conformance_completion.py']
                and meta['offlineExecution'] == packets['MET-PUBLISH-001']['offlineExecution'], 'all34 prior commands retained')
        spec = parse(inputs[SPEC_PATH]); validate_spec(spec)
        require(product['repository'] == 'mas-harness-conformance-labs'
                and product['predecessors'] == ['CONF-LIVE-003','CONF-DIAG-002','MET-REPAIR-017']
                and product['allowedPaths'] == spec['product']['allowedPaths']
                and product['offlineAcceptanceCommands'] == COMMANDS
                and product['offlineExecution'] == packets['CONF-LIVE-003']['offlineExecution'], 'closed product packet')
        for packet in (meta,product):
            require(packet['sourceReuse'] == [] and packet['prefetchCommands'] == []
                    and packet['warmSourceAccess'] == 'PROHIBITED_DURING_IMPLEMENTATION'
                    and 'liveCampaignExecution' not in packet, 'source-only no warm or live')
        for path, checksum in spec['contractPins'].items():
            require(digest(inputs[path]) == checksum, 'existing contract changed')
        local = parse(inputs['architecture/local-acceptance.json'])
        require(local['subject']['tree'] == spec['baseline']['tree']
                and len(local['subject']['inventory']) == 135
                and sum(row['count'] for row in local['recipe']['testSuites']) == 1277, 'baseline inventory and identities')
        require(set(spec['product']['allowedPaths']) < set(packets['CONF-LIVE-003']['allowedPaths']), 'correction narrows original paths')
        for path, rule in record['metaRecipes'].items():
            before = historical_bytes(path,inputs[path])
            require(apply_recipe(before,rule) == research_history(path, inputs[path]), 'exact reversible amendment')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'inherited identity preservation')
        for path in record['navigationPaths']:
            require(b'CONFORMANCE_COMPLETION.md' in inputs[path] and b'MET-REPAIR-017' in inputs[path]
                    and b'WAITING_PREDECESSOR_CORRECTION' in inputs[path] and b'NOT_DUE' in inputs[path], 'current navigation')
        return []
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,SyntaxError,RecursionError) as exc:
        return ['invalid conformance completion authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors)); raise SystemExit(1)
    print('Conformance completion authority valid:194 specifications;163 unchanged packets; correction required before004; no product/native acceptance.')
