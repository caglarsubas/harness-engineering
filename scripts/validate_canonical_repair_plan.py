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
    from validate_backend_timing import historical_bytes as timing_history, current_test_bytes as timing_current, validate_additions as timing_additions
except ImportError:
    from scripts.validate_backend_timing import historical_bytes as timing_history, current_test_bytes as timing_current, validate_additions as timing_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/canonical-repair-plan-authority.json"
RECORD_SHA256 = "b8d364ec8b1e3332931a2bc725b32796a9daba6d3faa793de7c3335c18e9d881"
NEW_IDS = ("MET-PERF-007",)
RECORD_FILE_SHA256 = "adee77fc1561ff5e4c6d1bc622806320c8f12e14f705e82d0be455a492d1e2f5"
HISTORY_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_broker_handoff.py","scripts/validate_ci_performance.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_provider_adoption.py","scripts/validate_proxy_contract.py","scripts/validate_proxy_diagnostics.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_broker_handoff.py","tests/test_ci_performance.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_provider_adoption.py","tests/test_proxy_contract.py","tests/test_proxy_diagnostics.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


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
    raw = timing_history(path, raw)
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
        return timing_current(before)
    require(len(matches) == 1, "unique predecessor")
    return timing_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return timing_additions(packets)
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


SPEC_PATH = "architecture/canonical-repair-plan.json"
EXPECTED_SPEC_SHA256 = "74a15aa596b043031d11044f984923aa8f31c8556c4730ac2f7efac11d138c7d"
EXPECTED_PLAN = parse("{\"candidate\":{\"crossCallCache\":false,\"cryptoChange\":false,\"function\":\"require_canonical_document\",\"guardRemoval\":false,\"implemented\":false,\"path\":\"src/harness_conformance/canonical.py\",\"proposal\":\"PER_INVOCATION_ENCODED_BYTES_REUSE_ONLY\",\"publicSemantics\":\"PRESERVE_OR_STOP\",\"speedup\":\"NOT_MEASURED\"},\"consumerPaths\":[\"src/harness_conformance/canonical.py\",\"tests/platform/linux_baseline/_successor_inventory.py\",\"tests/live_backend/_inventory.py\",\"tests/live_backend/test_supervisor.py\",\"docs/live-backend/linux-boundary.md\",\"tests/platform/linux_baseline/test_linux_inventory.py\",\"tests/platform/linux_baseline/test_packet_scalars.py\",\"tests/platform/linux_baseline/test_successor_inventory.py\"],\"diagnosticPacketSha256\":\"f38420268211065a2bd0ef34b2d0d5e4bc4ee835bcd7d775b82b6a1e3c202950\",\"evidenceClass\":\"RETAINED_DIAGNOSTIC_DATA_AND_PROPOSAL_ONLY\",\"executions\":240,\"fullTimeoutRootCause\":\"NOT_ESTABLISHED\",\"gates\":{\"billingChange\":false,\"currentSourceBeforeHistory\":true,\"diagnosticBudgetReset\":false,\"exactConsumerBridgeRequired\":true,\"fixedMatchedUnprofiledBenchmarkRequired\":true,\"fullEightCommandsRequired\":true,\"independentSemanticOraclesRequired\":true,\"modelEffortTransition\":\"NOT_DUE\",\"native\":\"NOT_RUN_ENV_UNAVAILABLE\",\"nestedTimeoutSeconds\":420,\"productSkips\":0,\"proxyRetryReset\":false,\"rootPolicyChange\":false,\"sourceCiMergeExactMainSeparate\":true,\"storedSourceExecution\":false,\"tenantAcceptance\":false,\"timeoutSeconds\":900,\"workflowTimeoutMinutes\":15},\"individualCommandWall\":\"NOT_MEASURED_NO_COMMAND_BOUNDARY_TIMESTAMPS\",\"metaBase\":\"f973598a66946d5f1d06c8db71291d144c83d363\",\"packetId\":\"MET-PERF-007\",\"pairs\":[{\"activation\":260,\"label\":\"pair01\",\"logSha256\":\"c2bcfa6d2a1ad51e0b3c7408d177078c9cf5a5c744b542258e8b0b8b4e523c02\",\"pairMonotonicSeconds\":43.973726666,\"pairWallSeconds\":43.97431206703186,\"profileTotalSeconds\":29.57,\"requestSha256\":\"d3b8b4accfb2dfbeafe54dd1a44cfa8afa3683e1b4e03c6fb7ff8360b2c26269\",\"skipped\":0,\"testCounts\":[40,40],\"unittestSeconds\":[12.36,29.368]},{\"activation\":261,\"label\":\"pair02\",\"logSha256\":\"0e3d6098c54eb713c3aaba0de1db50d9e73ddd18d30c5642e8d4a2d2b3cff942\",\"pairMonotonicSeconds\":47.443803625,\"pairWallSeconds\":47.444435834884644,\"profileTotalSeconds\":32.772,\"requestSha256\":\"5180f847a22cb4c2215176670fded0b8c65df7e353a3e170c737599e9450045e\",\"skipped\":0,\"testCounts\":[40,40],\"unittestSeconds\":[12.781,32.564]},{\"activation\":262,\"label\":\"pair03\",\"logSha256\":\"2810e700fb5e7289090c397a58a54a85e6fb04a25a33e55a0bb1765e326e5ed7\",\"pairMonotonicSeconds\":44.913253041,\"pairWallSeconds\":44.91385102272034,\"profileTotalSeconds\":30.277,\"requestSha256\":\"0456692f26592fb10ac1369aa595c3bb41b150d4db01146146deaa9cce33961a\",\"skipped\":0,\"testCounts\":[40,40],\"unittestSeconds\":[12.558,30.059]}],\"productBase\":\"f988c78e93b28257810ed99e7f0c072e9b76bae5\",\"productGrant\":false,\"profileOverhead\":\"SUBSTANTIAL_NOT_PRODUCTION_RANKING\",\"proposedPacketId\":\"CONF-PERF-005\",\"readiness\":\"WAITING_EXACT_CONSUMER_DESIGN\",\"readinessItem\":\"PLAN-CANON-001\",\"remainingDiagnosticPairs\":0,\"retriesUsed\":0,\"schemaVersion\":\"planeon.internal.canonical-repair-plan/v1\",\"sourceInventorySha256\":\"da56a96ea2f955382e95e6107dbeb7238c1f814692839d45eb02c1a973d4d85f\",\"subject\":\"7939626dc6aec99b58816e3a709fd0babf3a985f\",\"successfulPairs\":3,\"uniqueTests\":40}")


def validate_plan(plan, *, bind=True):
    """DATA_CHECK_ONLY: neither signatures nor actual run custody are verified here."""
    require(type(plan) is dict and set(plan) == set(EXPECTED_PLAN), 'closed planning data')
    if bind:
        require(digest(canonical(plan)) == EXPECTED_SPEC_SHA256, 'exact retained plan')
    # Compare every independently code-pinned member, even with outer binding disabled.
    # JSON byte comparison distinguishes booleans from integers and refuses extras.
    for key, expected in EXPECTED_PLAN.items():
        require(canonical(plan[key]) == canonical(expected), 'changed planning boundary: '+key)
    require(sum(sum(p['testCounts']) for p in plan['pairs']) == plan['executions'] == 240,
            'repeated executions are not unique identities')
    require(len(plan['pairs']) == plan['successfulPairs'] == 3 and plan['uniqueTests'] == 40,
            'exact measured scope')
    require(plan['productGrant'] is False and plan['remainingDiagnosticPairs'] == 0,
            'no product grant or diagnostic reset')


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    paths = {*record['protectedFiles'], *record['inputFiles'], *record['metaRecipes']}
    return record, {p: regular_bytes(root,p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record['metaRecipes']), 'exact history routing')
        require(validate_additions(packets) == [], 'packet binding')
        pins = {**record['protectedFiles'], **record['inputFiles'],
                **{p:r['afterSha256'] for p,r in record['metaRecipes'].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), 'exact fresh input inventory')
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(timing_history(path, inputs[path])) == checksum, 'changed source: '+path)
        old = {Path(p).stem for p in record['protectedFiles'] if p.startswith('task-packets/') and p.endswith('.yaml')}
        require(len(old) == 158 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {'MET-PERF-008','CONF-DIAG-002', 'MET-ACCEPT-001', 'MET-PUBLISH-001', 'MET-REPAIR-017', 'CONF-FIX-007', 'MET-ADOPT-002', 'MET-PERF-010', 'MET-PERF-009', 'CONF-DIAG-003', 'MET-PERF-011', 'MET-PERF-012', 'CONF-PERF-006', 'CONF-BENCH-002', 'MET-PERF-013', 'CONF-BENCH-003', 'MET-REPAIR-018', 'CONF-FIX-008', 'MET-PERF-014', 'CONF-DIAG-004', 'MET-PERF-015', 'CONF-FIX-009', 'MET-PERF-016', 'MET-PERF-017', 'MET-REPAIR-019', 'MET-ENFORCE-001', 'MET-PERF-018', 'MET-ENFORCE-003', 'CONF-FIX-010', 'MET-UNIFY-005', 'MET-RUNNER-001', 'MET-PERF-028', 'MET-LINUX-005', 'MET-VERIFY-001', 'MET-PERF-029'},
                'one new meta packet and158 immutable predecessors')
        require('CONF-PERF-005' not in packets, 'proposed product packet is not execution authority')
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs['task-packets/'+name+'.yaml'])), 'raw semantic binding')
        meta = packets['MET-PERF-007']
        require(meta['allowedPaths'] == record['ownedPaths'] and meta['predecessors'] == ['MET-PERF-006']
                and meta['repository'] == 'Harness-Engineering' and meta['sourceReuse'] == []
                and meta['prefetchCommands'] == [] and 'liveCampaignExecution' not in meta, 'meta-only scope')
        commands, prior = meta['offlineAcceptanceCommands'], packets['MET-PERF-006']['offlineAcceptanceCommands']
        require(len(commands) == 31 and commands[:-3] == prior[:-2] and commands[-2:] == prior[-2:]
                and commands[-3] == ['uv','run','--offline','--frozen','--no-sync','python','scripts/validate_canonical_repair_plan.py']
                and meta['offlineExecution'] == packets['MET-PERF-006']['offlineExecution'], 'unchanged30 plus planning validator')
        for path, rule in record['metaRecipes'].items():
            before = historical_bytes(path, inputs[path])
            require(apply_recipe(before,rule) == timing_history(path, inputs[path]), 'exact reversible bridge')
            if path.startswith('tests/'):
                require(test_ids(before) == test_ids(inputs[path]), 'all inherited test identities')
        validate_plan(parse(inputs[SPEC_PATH]))
        for path in record['navigationPaths']:
            require(b'CANONICAL_REPAIR_PLAN.md' in inputs[path] and b'MET-PERF-007' in inputs[path]
                    and b'NOT_AUTHORIZED' in inputs[path], 'current navigation: '+path)
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError) as exc:
        return ['invalid canonical repair planning authority: '+str(exc)]


if __name__ == '__main__':
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT/'task-packets').glob('*.yaml')}
    errors = validate_authority(packets,*load_inputs(ROOT))
    if errors:
        print('\n'.join(errors))
        raise SystemExit(1)
    print('Canonical repair proposal valid:159 specifications;158 immutable predecessors; product grant withheld.')
