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
    from validate_provider_adoption import historical_bytes as adoption_history, current_test_bytes as adoption_current, validate_additions as adoption_additions
except ImportError:
    from scripts.validate_provider_adoption import historical_bytes as adoption_history, current_test_bytes as adoption_current, validate_additions as adoption_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/conformance-successor-checkpoint.json"
BEFORE_PATH = "architecture/conformance-successor-checkpoint-inputs/meta-before.json"
PRODUCT_PATH = "architecture/conformance-successor-checkpoint-inputs/product-before.json"
CHECKPOINT_PATH = "architecture/conformance-successor-checkpoint-inputs/checkpoint.json"
RECORD_SHA256 = "cb0845f4fb906ce345a6490e46cfb1b6cb6b942fd917c260404143f9c8289d53"
NEW_IDS = ("MET-REPAIR-016", "CONF-FIX-006")
RECORD_FILE_SHA256 = "73488d6a0066b23a95954048ccaf4bcf78ddc0f66d88c7818db2c25ff33f128b"
HISTORY_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_broker_handoff.py","scripts/validate_ci_performance.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_proxy_contract.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_broker_handoff.py","tests/test_ci_performance.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_reference_measurement.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_proxy_contract.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


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
    raw = adoption_history(path, raw)
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
        return adoption_current(before)
    require(len(matches) == 1, "unique predecessor")
    return adoption_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return adoption_additions(packets)
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


def region(raw, name):
    tree = ast.parse(raw)
    parts = name.split(".")
    nodes = tree.body
    for part in parts:
        selected = [n for n in nodes if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == part]
        require(len(selected) == 1, "unique named source region")
        node = selected[0]
        nodes = node.body
    require(isinstance(node, ast.FunctionDef) and not node.decorator_list, "undecorated function region")
    lines = raw.splitlines(keepends=True)
    start, end = sum(map(len, lines[:node.lineno-1])), sum(map(len, lines[:node.end_lineno]))
    return start, end, node


DOC = "docs/live-backend/linux-boundary.md"
SUP = "tests/live_backend/test_supervisor.py"
REGION = "PerformanceSourceProofTests.test_exact_checkpoint_scope_and_all_fresh_test_roots"
LEGACY_MARKER = b"\n```harness-performance-source-proof\n"
CORRECTION_MARKER = b"\n```harness-successor-checkpoint-correction\n"


def legacy_proof(raw):
    require(type(raw) is bytes and raw.count(LEGACY_MARKER) == 1 and raw.endswith(b"\n```\n"), "single final legacy projection")
    prefix, encoded = raw.split(LEGACY_MARKER)
    proof = parse(encoded[:-5])
    require(canonical(proof) == encoded[:-5], "canonical legacy projection")
    return prefix, proof


def validate_product_delta(after, correction, record, inputs):
    """Exact two-file SOURCE_DELTA_ONLY check; no product code is executed."""
    try:
        pinned(record)
        require(type(inputs) is dict and type(inputs.get(PRODUCT_PATH)) is bytes
                and digest(inputs[PRODUCT_PATH]) == record["inputFiles"][PRODUCT_PATH], "exact immutable product input")
        before = parse(inputs[PRODUCT_PATH])["files"]
        require(type(after) is dict and set(after) == {SUP, DOC}, "two product paths only")
        test, old = after[SUP], before[SUP].encode()
        require(type(test) is bytes and len(test) <= len(old) + 131072, "bounded current test")
        start, end, _ = region(old, REGION)
        replacement = record["replacement"]["after"].encode()
        require(digest(old[start:end]) == record["replacement"]["beforeSha256"], "exact prior method")
        prefix = old[:start] + replacement + old[end:]
        require(test.startswith(prefix), "only exact method and append allowed")
        append = test[len(prefix):]
        require(0 < len(append) <= 131072, "bounded regression append")
        old_tree, added_tree = ast.parse(old), ast.parse(append)
        names = {n.name for n in old_tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        added_names = [n.name for n in added_tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
        require(len(added_names) == len(added_tree.body) and not names.intersection(added_names)
                and len(added_names) == len(set(added_names)), "definition-only nonshadowing append")
        forbidden = {"load_tests", "run", "discover", "setUpModule", "tearDownModule", "setUpClass", "tearDownClass",
                     "setUp", "tearDown", "__getattribute__", "__getattr__", "__init__"}
        for node in ast.walk(added_tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                require(not node.decorator_list and node.name not in forbidden, "no collection override or decorator")
            require(not isinstance(node, (ast.AsyncFunctionDef, ast.Global, ast.Nonlocal)), "ordinary isolated test definitions")
            if isinstance(node, ast.Attribute):
                require(node.attr not in ("skip", "skipIf", "skipUnless", "expectedFailure", "skipTest"), "no test omission")
        old_ids, current_ids = test_ids(old), test_ids(test)
        require(set(old_ids) <= set(current_ids), "accepted methods preserved")
        added_ids = sorted(set(current_ids) - set(old_ids))
        require(set(record["requiredNewTestIds"]) <= set(added_ids), "all correction regressions required")
        original_prefix, original = legacy_proof(before[DOC].encode())
        require(digest(canonical(original)) == record["originalProofSha256"], "immutable original v4 snapshot")
        expected_correction = dict(schemaVersion="planeon.internal.successor-checkpoint-correction/v1",
            evidenceClass="SOURCE_DELTA_ONLY", packetId="CONF-FIX-006", authorityDigest=RECORD_SHA256,
            baseCommit=record["sourceBaseline"]["commit"], beforeTestSha256=digest(old), afterTestSha256=digest(test),
            originalProofSha256=record["originalProofSha256"], replacementSha256=digest(replacement), addedTestIds=added_ids)
        require(type(correction) is dict and canonical(correction) == canonical(expected_correction), "exact independent correction binding")
        suffix = CORRECTION_MARKER + canonical(correction) + b"\n```\n"
        prefix, current = legacy_proof(after[DOC])
        require(prefix == original_prefix + suffix and prefix.count(CORRECTION_MARKER) == 1, "retained document prefix and unique correction")
        expected = parse(canonical(original))
        row = expected["sources"][SUP]
        require(row["append"].count(old[start:end].decode()) == 1, "one exact method in legacy append")
        row["append"] = row["append"].replace(old[start:end].decode(), replacement.decode()) + append.decode()
        row["afterSha256"] = digest(test)
        expected["newTestIds"] = sorted(original["newTestIds"] + added_ids)
        expected["documentSuffix"] += suffix.decode()
        require(len(expected["documentSuffix"].encode()) <= 65536, "unchanged suffix bound")
        require(canonical(current) == canonical(expected), "only exact legacy projection rebinding")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError):
        return ["invalid two-path SOURCE_DELTA_ONLY correction"]


def stage_test_map(paths, sources, record):
    """Independent source-data model, not a product or final-hook validator."""
    pinned(record)
    require(type(paths) is list and all(type(p) is str for p in paths) and len(paths) == len(set(paths)), "unique path inventory")
    expected_paths = set(record["checkpointFiles"])
    stages = []
    for stage in range(2, 7):
        if stage > 2:
            expected_paths.update(record["successorPaths"][str(stage)])
        if set(paths) == expected_paths:
            stages.append(stage)
    require(len(stages) == 1, "exact complete ordered stage")
    # Recompute the selected stage, not the final stage reached by the loop.
    selected = set(record["checkpointFiles"])
    for stage in range(3, stages[0] + 1):
        selected.update(record["successorPaths"][str(stage)])
    test_paths = {p for p in selected if p.startswith("tests/") and p.rsplit("/", 1)[-1].startswith("test_") and p.endswith(".py")}
    require(type(sources) is dict and set(sources) == test_paths, "exact stage test paths")
    result = {}
    for path, raw in sources.items():
        tree = ast.parse(raw)
        for scope in [tree, *[n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]]:
            names = [n.name for n in scope.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
            require(len(names) == len(set(names)), "no shadowed definition")
        require(not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "load_tests" for n in tree.body), "no custom collection")
        ids = sorted(test_ids(raw))
        require(ids, "nonempty test module")
        result[path] = ids
    for path, ids in record["checkpointTests"].items():
        require(set(ids) <= set(result[path]), "all354 accepted methods preserved")
        if path != SUP:
            require(sorted(ids) == result[path], "unchanged predecessor method set")
    return stages[0], result


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    paths = {*record["protectedFiles"], *record["inputFiles"], *record["metaRecipes"]}
    return record, {p: regular_bytes(root, p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record["metaRecipes"]), "exact routing table")
        require(not validate_additions(packets), "new packet substitution")
        pins = {**record["protectedFiles"], **record["inputFiles"], **{p:r["afterSha256"] for p,r in record["metaRecipes"].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), "exact input inventory")
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(adoption_history(path, inputs[path])) == checksum, "exact current source: " + path)
        old = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/") and p.endswith(".yaml")}
        require(len(old) == 153 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {"MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010", "MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}, "exact156 catalog")
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs["task-packets/"+name+".yaml"])), "raw semantic packet binding")
        meta, product = (packets[x] for x in NEW_IDS)
        require(meta["allowedPaths"] == record["ownedPaths"] and product["allowedPaths"] == [DOC, SUP], "exact ownership")
        require(meta["offlineAcceptanceCommands"] == record["metaCommands"] and len(record["metaCommands"]) == 28, "full28 commands")
        require(product["offlineAcceptanceCommands"] == packets["CONF-PERF-004"]["offlineAcceptanceCommands"] == record["productCommands"], "unchanged full8 product recipe")
        before = parse(inputs[BEFORE_PATH])
        require(before["baseCommit"] == record["metaBaseline"] and set(before["files"]) == set(record["metaRecipes"]), "exact before corpus")
        for path, rule in record["metaRecipes"].items():
            raw = before["files"][path].encode()
            require(apply_recipe(raw, rule) == adoption_history(path, inputs[path]), "reversible recipe")
            if path.startswith("tests/"):
                require(test_ids(raw) == test_ids(inputs[path]), "all previous test identities")
        checkpoint, product_before = parse(inputs[CHECKPOINT_PATH]), parse(inputs[PRODUCT_PATH])
        require(checkpoint["commit"] == product_before["baseCommit"] == record["sourceBaseline"]["commit"]
                and checkpoint["tree"] == record["sourceBaseline"]["tree"]
                and len(checkpoint["files"]) == 127 and sum(map(len, checkpoint["tests"].values())) == 354, "accepted127/354 checkpoint")
        require(record["checkpointFiles"] == sorted(checkpoint["files"]) and record["checkpointTests"] == checkpoint["tests"], "complete checkpoint identities")
        require(set(product_before["files"]) == {DOC, SUP}, "two inert sources")
        for path, value in product_before["files"].items():
            raw, pin = value.encode(), checkpoint["files"][path]
            require(len(raw) == pin["size"] and "sha256:"+digest(raw) == pin["sha256"]
                    and hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest() == pin["blob"], "exact product snapshot")
        raw = product_before["files"][SUP].encode()
        start, end, _ = region(raw, REGION)
        require(digest(raw[start:end]) == record["replacement"]["beforeSha256"]
                and digest(record["replacement"]["after"].encode()) == record["replacement"]["afterSha256"], "exact method specification")
        require(digest(canonical(legacy_proof(product_before["files"][DOC].encode())[1])) == record["originalProofSha256"], "retained original proof")
        for stage in range(3, 7):
            require(record["successorPaths"][str(stage)] == [p for p in packets[f"CONF-LIVE-{stage:03d}"]["allowedPaths"] if not (stage == 6 and p == "src/harness_conformance/live_launcher.py")], "unchanged successor path grants")
        require(record["failure"]["failures"] == 1 and record["failure"]["testsRun"] == 425
                and record["failure"]["notRunCommands"] == [7, 8] and record["failure"]["status"] == "AUTHENTICATED_FAILURE_NOT_ACCEPTANCE", "failed evidence remains failed")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError) as exc:
        return ["invalid successor checkpoint authority: " + str(exc)]


def close_dispatch_errors(packets, errors):
    """Close only eight exact immutable retired/read-only overlap diagnostics."""
    try:
        record = _record()
        require(not validate_additions(packets), "new packets")
        retired = set()
        for left, right, count in record["overlapPairs"]:
            for name in (left, right):
                if name in NEW_IDS:
                    continue
                path = "task-packets/" + name + ".yaml"
                raw = regular_bytes(ROOT, path)
                require(digest(raw) == record["protectedFiles"][path] and canonical(safe_load(raw)) == canonical(packets[name]), "unchanged predecessor packet")
            paths = set(packets[left]["allowedPaths"]) & set(packets[right]["allowedPaths"])
            require(len(paths) == count == 2 and paths == {DOC, SUP}, "exact two-path overlap")
            retired.update("unordered same-repository packets " + left + " and " + right + " overlap at " + repr(path) + " and " + repr(path) for path in paths)
        require(len(retired) == 8 and all(errors.count(x) == 1 for x in retired), "eight exact diagnostics")
        return [e for e in errors if e not in retired]
    except (ValueError, TypeError, KeyError, OSError):
        return errors + ["missing or changed successor correction dispatch"]


def main():
    try:
        packets = {p.stem:safe_load(regular_bytes(ROOT,str(p.relative_to(ROOT)))) for p in (ROOT/"task-packets").glob("*.yaml")}
        errors = validate_authority(packets, *load_inputs(ROOT))
    except (ValueError, TypeError, OSError):
        errors = ["successor checkpoint authority unavailable"]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Successor checkpoint authority valid:194 packets;153 immutable YAML; two product paths; source data only.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
