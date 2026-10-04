#!/usr/bin/env python3
"""Pinned source-only performance authority. No product imports or execution."""
from __future__ import annotations

import ast
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import stat

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

try:
    from validate_conformance_successor_checkpoint import historical_bytes as checkpoint_history, current_test_bytes as checkpoint_current, validate_additions as checkpoint_additions, close_dispatch_errors
except ImportError:
    from scripts.validate_conformance_successor_checkpoint import historical_bytes as checkpoint_history, current_test_bytes as checkpoint_current, validate_additions as checkpoint_additions, close_dispatch_errors

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/conformance-reference-measurement.json"
BEFORE_PATH = "architecture/conformance-reference-measurement-inputs/meta-before.json"
PRODUCT_PATH = "architecture/conformance-consumer-closure-inputs/product-before.json"
CHECKPOINT_PATH = "architecture/credential-ordering-inputs/checkpoint.json"
RECORD_SHA256 = "b3a81dd4e771580d13ba31dcac8405e91336a2229f7845a637de29f927e6672e"
NEW_IDS = ("MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001")
RECORD_FILE_SHA256 = "01b97634ff6d8d6251c68413838cadf6dd6b2079cde3794c31ec97cac46fd589"
HISTORY_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_broker_handoff.py","scripts/validate_ci_performance.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_proxy_contract.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_broker_handoff.py","tests/test_ci_performance.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_proxy_contract.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


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


_SOURCE_RECORD_READER = _record
_PROJECTION_BYTES = 200950
_PROJECTION_SHA256 = "01b97634ff6d8d6251c68413838cadf6dd6b2079cde3794c31ec97cac46fd589"


@lru_cache(maxsize=1)
def _decode_source_projection(raw):
    """Decode one fixed blob into immutable recipe data, never a verdict.

    The pinned parser is fixed within a process. Mock parser users must clear
    entries; a warm entry cannot detect arbitrary parser replacement.
    """
    require(type(raw) is bytes and len(raw) == _PROJECTION_BYTES
            and digest(raw) == _PROJECTION_SHA256, "eligible recipe projection bytes")
    record = parse(raw)
    recipes, unchanged = record["metaRecipes"], record["unchangedTests"]
    require(type(recipes) is dict and len(recipes) == 51
            and type(unchanged) is dict and len(unchanged) == 19,
            "exact immutable recipe projection inventory")
    frozen = []
    for path, rule in recipes.items():
        require(type(path) is str and type(rule) is dict
                and set(rule) == {"beforeSha256", "afterSha256", "replacements"}
                and type(rule["beforeSha256"]) is type(rule["afterSha256"]) is str
                and type(rule["replacements"]) is list, "immutable recipe projection shape")
        rows = []
        for row in rule["replacements"]:
            require(type(row) is dict and set(row) == {"before", "after", "count"}
                    and type(row["before"]) is type(row["after"]) is str
                    and type(row["count"]) is int and row["count"] > 0,
                    "immutable replacement projection shape")
            rows.append((row["before"], row["after"], row["count"]))
        frozen.append((path, rule["beforeSha256"], rule["afterSha256"], tuple(rows)))
    require(all(type(path) is str and type(value) is str for path, value in unchanged.items()),
            "immutable unchanged-test projection shape")
    return tuple(frozen), tuple(unchanged.items())


def _source_projection():
    """Fresh authority observation; only deterministic recipe decoding is reused."""
    # Preserve the explicit reader seam, including wrapped-reader observations,
    # supplied duplicate recipes and exceptions, without an extra preceding read.
    if _record is not _SOURCE_RECORD_READER:
        return _record()
    raw = regular_bytes(ROOT, RECORD_PATH)
    checksum = digest(raw)
    require(checksum == RECORD_FILE_SHA256, "exact fresh authority bytes")
    if type(raw) is not bytes or len(raw) != _PROJECTION_BYTES or checksum != _PROJECTION_SHA256:
        return parse(raw)
    recipes, unchanged = _decode_source_projection(raw)
    return {
        "metaRecipes": {
            path: {"beforeSha256": before_sha, "afterSha256": after_sha,
                   "replacements": [{"before": old, "after": new, "count": count}
                                    for old, new, count in rows]}
            for path, before_sha, after_sha, rows in recipes
        },
        "unchangedTests": dict(unchanged),
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
    raw = checkpoint_history(path, raw)
    # A closed code-pinned routing table, not an acceptance/result cache.
    # Unchanged inputs still receive the predecessor caller's exact hash check.
    if path not in HISTORY_PATHS:
        return raw
    record = _source_projection()
    rule = record["metaRecipes"].get(path)
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
    record = _source_projection()
    input_digest = digest(before)
    matches = [r for p, r in record["metaRecipes"].items()
               if p.startswith("tests/") and r["beforeSha256"] == input_digest]
    if not matches:
        require(input_digest in record["unchangedTests"].values(), "unreviewed unchanged test")
        return checkpoint_current(before)
    require(len(matches) == 1, "unique predecessor")
    return checkpoint_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return checkpoint_additions(packets)
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


def reconstruct_product(path, before, row, spec):
    require(type(before) is bytes and type(row) is dict
            and set(row) == {"regions", "append", "afterSha256", "constant"}, "closed source proof")
    require(type(row["regions"]) is dict and set(row["regions"]) == set(spec["regions"])
            and type(row["append"]) is str and len(row["append"].encode()) <= spec["append"], "bounded exact regions")
    if "fixedRegions" in spec:
        require(row["regions"] == spec["fixedRegions"], "exact historical-consumer bridge")
    replacements = []
    for name in spec["regions"]:
        start, end, old = region(before, name)
        replacement = row["regions"][name]
        require(type(replacement) is str and replacement.endswith("\n")
                and 0 < len(replacement.encode()) <= spec["maxRegionBytes"], "bounded region bytes")
        # AST only: snapshots never compile, import, execute or supply a callable.
        dedented = "\n".join(line[old.col_offset:] if line else line for line in replacement.splitlines()) + "\n"
        parsed = ast.parse(dedented).body
        annotation = lambda node: ast.dump(node) if node is not None else None
        require(len(parsed) == 1 and isinstance(parsed[0], ast.FunctionDef)
                and parsed[0].name == old.name and not parsed[0].decorator_list
                and ast.dump(parsed[0].args) == ast.dump(old.args)
                and annotation(parsed[0].returns) == annotation(old.returns),
                "function interface changed")
        if path == "src/harness_conformance/crypto.py":
            forbidden = (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal, ast.Attribute,
                         ast.With, ast.AsyncFunctionDef, ast.Await, ast.Yield, ast.Lambda)
            require(not any(isinstance(n, forbidden) for n in ast.walk(parsed[0])), "arithmetic-only region")
            require(all(isinstance(n.func, ast.Name) and n.func.id == "pow"
                        for n in ast.walk(parsed[0]) if isinstance(n, ast.Call)), "no runtime service/cache")
        if old.name.startswith("test_") and "fixedRegions" not in spec:
            assertions = lambda node: [ast.dump(n) for n in ast.walk(node)
                if isinstance(n, ast.Assert) or isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr.startswith("assert")]
            require(assertions(old) == assertions(parsed[0]), "predecessor accounting assertions changed")
        replacements.append((start, end, replacement.encode()))
    current = before
    for start, end, replacement in sorted(replacements, reverse=True):
        current = current[:start] + replacement + current[end:]
    if "constant" in spec:
        require(type(row["constant"]) is str and re.fullmatch("[0-9a-f]{64}", row["constant"]), "helper checksum")
        pattern = rb'^HELPER_SHA256 = "[0-9a-f]{64}"$'
        require(len(re.findall(pattern, current, re.M)) == 1, "unique fixed helper pin")
        current = re.sub(pattern, ('HELPER_SHA256 = "' + row["constant"] + '"').encode(), current, flags=re.M)
    else:
        require(row["constant"] is None, "unexpected constant replacement")
    current += row["append"].encode()
    if path.endswith(".py"):
        tree = ast.parse(current)
        old_ids, new_ids = test_ids(before), test_ids(current)
        require(set(old_ids) <= set(new_ids), "predecessor test lost")
        if row["append"]:
            appended = ast.parse(row["append"])
            existing = {n.name for n in ast.parse(before).body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
            added_names = [n.name for n in appended.body
                           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
            require(not existing.intersection(added_names) and len(added_names) == len(set(added_names)),
                    "appended source shadows existing behavior")
            require(not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                            n.name in ("load_tests", "run", "discover") for n in ast.walk(appended)),
                    "test collection override")
            require(not any(isinstance(n, ast.Attribute) and n.attr in
                            ("skip", "skipIf", "skipUnless", "expectedFailure") for n in ast.walk(appended)),
                    "test omission")
        require(tree.body, "empty source")
    require(digest(current) == row["afterSha256"], "product after digest")
    return current


def validate_product_delta(after, proof, record, before_raw):
    """Source scope only, never a behavioral/performance/native certificate."""
    try:
        pinned(record)
        require(type(before_raw) is bytes and digest(before_raw) == record["inputFiles"][PRODUCT_PATH], "before pin")
        before = parse(before_raw)
        require(type(proof) is dict and set(proof) == {"schemaVersion", "evidenceClass", "packetId",
                "authorityDigest", "baseCommit", "sources", "newTestIds", "beforeSources", "documentSuffix"}, "closed proof")
        require(proof["schemaVersion"] == "planeon.conformance-performance-delta/v4"
                and proof["evidenceClass"] == "SOURCE_DELTA_ONLY" and proof["packetId"] == "CONF-PERF-004"
                and proof["authorityDigest"] == RECORD_SHA256
                and proof["baseCommit"] == before["baseCommit"] == record["sourceBaseline"]["commit"], "proof identity")
        doc = "docs/live-backend/linux-boundary.md"
        require(type(after) is dict and type(proof["sources"]) is dict
                and set(after) == set(before["files"]) == set(record["productPaths"])
                and set(proof["sources"]) == set(after) - {doc}, "exact eight-path proof")
        require(proof["beforeSources"] == {p:r for p,r in before["files"].items() if p != doc}, "inert source history")
        suffix = proof["documentSuffix"]
        require(type(suffix) is str and len(suffix.encode()) <= 65536
                and "```harness-performance-source-proof" not in suffix, "bounded document suffix")
        addition = suffix.encode() + b"\n```harness-performance-source-proof\n" + canonical(proof) + b"\n```\n"
        require(len(addition) <= record["productRegions"][doc]["append"]
                and after[doc] == before["files"][doc].encode() + addition, "acyclic exact document append")
        for path, spec in record["productRegions"].items():
            if path == doc:
                continue
            expected = reconstruct_product(path, before["files"][path].encode(), proof["sources"][path], spec)
            require(type(after[path]) is bytes and expected == after[path], "actual product bytes changed")
        helper = "tests/platform/linux_baseline/_successor_inventory.py"
        require(proof["sources"]["tests/live_backend/_inventory.py"]["constant"] == digest(after[helper]), "actual helper import pin")
        path = "tests/live_backend/test_supervisor.py"
        added = sorted(set(test_ids(after[path])) - set(test_ids(before["files"][path].encode())))
        require(added and proof["newTestIds"] == added, "exact new test inventory")
        require(set(record["referenceBenchmark"]["requiredNewTestIds"]) <= set(added), "all21 required regression IDs")
        begin, end, _ = region(after[path], "PerformanceArithmeticTests.test_fixed_three_sample_workload")
        require(digest(after[path][begin:end]) == record["referenceBenchmark"]["templateSha256"], "exact matched benchmark method")
        forbidden_observers = {"setUpModule", "tearDownModule", "_performance_finish_profile"}
        require(not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in forbidden_observers for n in ast.parse(proof["sources"][path]["append"]).body), "no full-module profiling overlay")
        # The proof-bearing document has no self-digest. Exact assembly above
        # binds its original prefix, suffix and canonical five-source proof.
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError):
        return ["invalid SOURCE_DELTA_ONLY product scope; no behavior acceptance"]


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    paths = {*record["protectedFiles"], *record["inputFiles"], *record["metaRecipes"]}
    return record, {p: regular_bytes(root, p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record["metaRecipes"]), "exact historical routing table")
        require(not validate_additions(packets), "new packet mismatch")
        pins = {**record["protectedFiles"], **record["inputFiles"],
                **{p:r["afterSha256"] for p,r in record["metaRecipes"].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), "exact current input inventory")
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(checkpoint_history(path, inputs[path])) == checksum, "current source changed: " + path)
        old = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/") and p.endswith(".yaml")}
        require(len(old) == 150 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {"MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010", "MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}, "exact155 catalog")
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs["task-packets/"+name+".yaml"])), "packet raw/semantic mismatch")
        packet, product, reference = (packets[name] for name in NEW_IDS)
        require(packet["allowedPaths"] == record["ownedPaths"] and product["allowedPaths"] == record["productPaths"], "path grant")
        require(packet["offlineAcceptanceCommands"] == record["preserved"]["metaCommands"]
                and len(packet["offlineAcceptanceCommands"]) == 27, "complete meta commands")
        require(product["offlineAcceptanceCommands"] == packets["CONF-FIX-005"]["offlineAcceptanceCommands"]
                == record["preserved"]["productCommands"], "unchanged eight product commands")
        require(reference["allowedPaths"] == record["productPaths"] and reference["prefetchCommands"] == []
                and reference["offlineAcceptanceCommands"] == record["preserved"]["referenceCommands"]
                == [record["referenceBenchmark"]["command"]], "exact read-only benchmark recipe")
        template = parse(inputs[record["referenceBenchmark"]["templatePath"]])
        require(template["evidenceClass"] == "INERT_SOURCE_SPECIFICATION_ONLY"
                and digest(template["method"].encode()) == template["sha256"]
                == record["referenceBenchmark"]["templateSha256"], "exact inert benchmark method")
        ast.parse("\n".join(line[4:] if line else line for line in template["method"].splitlines()))
        require(len(record["referenceBenchmark"]["requiredProductTestIds"]) == 348
                and len(record["referenceBenchmark"]["requiredNewTestIds"]) == 21, "327 plus21 regression identity floor")
        before = parse(inputs[BEFORE_PATH])
        require(before["baseCommit"] == record["metaBaseline"] and set(before["files"]) == set(record["metaRecipes"]), "meta before inventory")
        for path, rule in record["metaRecipes"].items():
            raw = before["files"][path].encode()
            require(apply_recipe(raw, rule) == checkpoint_history(path, inputs[path]), "meta recipe differs")
            if path.startswith("tests/"):
                require(test_ids(raw) == test_ids(inputs[path]), "old test identity changed")
        checkpoint, sources = parse(inputs[CHECKPOINT_PATH]), parse(inputs[PRODUCT_PATH])
        require(checkpoint["commit"] == sources["baseCommit"] == record["sourceBaseline"]["commit"]
                and checkpoint["tree"] == record["sourceBaseline"]["tree"]
                and len(checkpoint["files"]) == 127 and sum(map(len, checkpoint["tests"].values())) == 327, "127/327 checkpoint")
        require(set(sources["files"]) == set(record["productPaths"]), "eight pinned product paths")
        for path, raw in sources["files"].items():
            require("sha256:"+digest(raw.encode()) == checkpoint["files"][path]["sha256"], "product source changed")
            for name in record["productRegions"][path]["regions"]:
                region(raw.encode(), name)
        require(len(record["productPaths"]) == 8 and len(record["accountingBridges"]) == 4, "exact eight-path closure")
        for bridge in record["accountingBridges"]:
            path = bridge["path"]
            raw = sources["files"][path].encode()
            start, end, _ = region(raw, bridge["region"])
            require(digest(raw[start:end]) == bridge["beforeSha256"]
                    and digest(bridge["after"].encode()) == bridge["afterSha256"]
                    and record["productRegions"][path]["fixedRegions"][bridge["region"]] == bridge["after"], "exact consumer before/after")
        validate_consumer_census(parse(inputs["architecture/conformance-consumer-closure-inputs/consumer-sources.json"]), checkpoint, sources, record)
        require(record["profiling"]["subcalls"] is False and record["profiling"]["builtins"] is True
                and record["profiling"]["fullBaselineRequired"] is False
                and record["profiling"]["completeReferenceBenchmarkRequired"] is True
                and record["profiling"]["fullCandidateRequired"] is True
                and record["profiling"]["partialMayAuthorizeOptimization"] is False
                and record["profiling"]["crossCallCacheAllowed"] is False, "full uncached measurement gate")
        require(record["stages"] == [110,120,127,135,141,146,151]
                and record["measurement"]["functionAttribution"] == "NOT_YET_MEASURED"
                and record["preserved"]["nativeAcceptance"] is record["preserved"]["tenantAcceptance"] is False, "evidence promotion")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError) as exc:
        return ["invalid performance authority: "+str(exc)]


def source_read_census(files):
    """Enumerate syntax from all pinned Python sources; never execute snapshots."""
    sites = []
    observed = {"read_bytes", "read_text", "regular_bytes", "tracked_inventory",
                "validate_checkpoint", "validate_composition", "verify_repository",
                "isolated_inventory", "check_edit", "corrected_test", "performance_current"}
    for path, raw in sorted(files.items()):
        tree = ast.parse(raw)
        def visit(node, scope):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope = scope + (node.name,)
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                if name in observed:
                    sites.append(dict(path=path, scope=".".join(scope), line=node.lineno,
                                      kind=name, expression=ast.dump(node, include_attributes=False)))
            for child in ast.iter_child_nodes(node):
                visit(child, scope)
        visit(tree, ())
    return sorted(sites, key=lambda row: (row["path"], row["line"], row["kind"], row["expression"]))


def validate_consumer_census(census, checkpoint, sources, record):
    require(type(census) is dict and set(census) == {"baseCommit", "evidenceClass", "files"}
            and census["baseCommit"] == checkpoint["commit"]
            and census["evidenceClass"] == "STATIC_SOURCE_CENSUS_ONLY", "closed inert census")
    expected = {p for p in checkpoint["files"] if p.endswith(".py")}
    require(type(census["files"]) is dict and set(census["files"]) == expected
            and len(expected) == record["consumerCensus"]["pythonFiles"], "complete Python census")
    for path, raw in census["files"].items():
        require(type(raw) is str, "inert source string")
        encoded, pin = raw.encode(), checkpoint["files"][path]
        require(len(encoded) == pin["size"] and "sha256:" + digest(encoded) == pin["sha256"]
                and hashlib.sha1(b"blob " + str(len(encoded)).encode() + b"\0" + encoded).hexdigest() == pin["blob"],
                "accepted census source pin")
        if path in sources["files"]:
            require(raw == sources["files"][path], "census and region sources disagree")
    tests = {p: sorted(test_ids(census["files"][p].encode())) for p in checkpoint["tests"]}
    require(tests == {p: sorted(v) for p, v in checkpoint["tests"].items()}
            and sum(map(len, tests.values())) == 327, "all 327 static predecessor IDs")
    sites = source_read_census(census["files"])
    require(len(record["accountingBridges"]) == 4, "four reviewed consumer bridges")
    grouped = {}
    for bridge in record["accountingBridges"]:
        path, name = bridge["path"], bridge["region"]
        require(any(row["path"] == path and row["scope"] == name and row["kind"] == "read_bytes"
                    for row in sites), "historical direct-read edge missing")
        after = ast.parse("\n".join(line[4:] if line else line for line in bridge["after"].splitlines()))
        require(not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                        and n.func.attr in ("read_bytes", "read_text") for n in ast.walk(after)),
                "bridge still reads current bytes as history")
        require(sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "performance_current" for n in ast.walk(after)) == 1,
                "fresh current custody before historical comparison")
        grouped.setdefault(path, {})[name] = bridge["after"]
    require(grouped == {p: s["fixedRegions"] for p, s in record["productRegions"].items()
                        if "fixedRegions" in s}, "complete exact bridge region map")
    require(record["consumerCensus"]["executionAllowed"] is False
            and record["consumerCensus"]["classification"] == "STATIC_SOURCE_CENSUS_ONLY",
            "static census cannot grant execution")
    return sites


def validate_measurement_data(report, custody, record, *, reference=None):
    """DATA_CHECK_ONLY. The operator must independently verify signed custody.

    Consistent caller-supplied JSON is not proof of a real run or authorization.
    No signature verification, program execution, promotion or mutation occurs.
    """
    try:
        import math
        import statistics
        pinned(record)
        spec = record["referenceBenchmark"]
        require(type(report) is dict and set(report) == set(spec["reportFields"]), "closed benchmark report")
        require(type(custody) is dict and set(custody) == set(spec["custodyFields"]), "closed retained custody data")
        for key, value in spec["fixedReport"].items():
            require(type(report[key]) is type(value) and report[key] == value, "fixed report identity: " + key)
        is_candidate = reference is not None
        packet = "CONF-PERF-004" if is_candidate else "CONF-BENCH-001"
        require(custody["packetId"] == packet and custody["status"] == "COMPLETE"
                and type(custody["exitCode"]) is int and custody["exitCode"] == 0
                and type(custody["commandsCompleted"]) is int
                and custody["commandsCompleted"] == (8 if is_candidate else 1)
                and type(custody["skipped"]) is int and custody["skipped"] == 0
                and custody["workingTreeOverlay"] is False and custody["trackedFilesUnchanged"] is True,
                "complete unchanged zero-skip run data")
        require(custody["execution"] == "SIGNED_DENY_ALL_OFFLINE"
                and custody["evidenceClass"] == "RETAINED_CUSTODY_DATA_ONLY", "data cannot self-grant authority")
        require(type(custody["activationSequence"]) is int and custody["activationSequence"] > 155,
                "fresh post-timeout activation")
        for key in ("checkoutCommit", "checkoutTree"):
            require(type(custody[key]) is str and re.fullmatch("[0-9a-f]{40}", custody[key]), "commit/tree identity")
        for key in ("packetSha256", "logSha256", "sourceInventorySha256", "referenceReportSha256"):
            require(type(custody[key]) is str and re.fullmatch("[0-9a-f]{64}", custody[key]), "custody digest")
        require(custody["packetSha256"] == record["inputFiles"]["task-packets/" + packet + ".yaml"], "exact replay packet")
        require(type(custody["testIds"]) is list and all(type(x) is str for x in custody["testIds"])
                and custody["testIds"] == sorted(set(custody["testIds"])), "exact nonduplicate executed IDs")
        expected_ids = spec["requiredProductTestIds"] if is_candidate else [spec["testId"]]
        require((set(expected_ids) <= set(custody["testIds"])) if is_candidate
                else custody["testIds"] == expected_ids, "full product or exact one-method benchmark inventory")
        number = lambda x: type(x) in (float, int) and math.isfinite(x) and x > 0
        require(number(custody["trustedElapsedSeconds"])
                and custody["trustedElapsedSeconds"] <= (750 if is_candidate else 900), "unchanged deadline")
        for key in ("interpreter", "platform"):
            require(type(report[key]) is str and 0 < len(report[key]) <= 1024, "bounded host metadata")
        require(type(report["sourceSha256"]) is str and re.fullmatch("[0-9a-f]{64}", report["sourceSha256"]), "source digest")
        if not is_candidate:
            require(report["sourceSha256"] == spec["unchangedCryptoSha256"], "exact original crypto")
        require(type(report["samplesSeconds"]) is list and len(report["samplesSeconds"]) == 3
                and all(number(x) for x in report["samplesSeconds"]), "three complete positive finite samples")
        require(report["resultDigests"] == [spec["resultDigest"]] * 3, "deterministic vector equality")
        wall = report["benchmarkWallSeconds"]
        require(number(wall) and sum(report["samplesSeconds"]) <= wall <= custody["trustedElapsedSeconds"], "consistent benchmark wall")
        require(type(report["functions"]) is list, "function attribution rows")
        names, rows = [], {}
        for row in report["functions"]:
            require(type(row) is dict and set(row) == {"function", "calls", "primitiveCalls", "selfSeconds", "cumulativeSeconds"}, "closed function row")
            name = row["function"]
            require(type(name) is str and name in spec["requiredFunctions"] and name not in names, "exact function attribution")
            require(type(row["calls"]) is int and type(row["primitiveCalls"]) is int
                    and 0 < row["primitiveCalls"] <= row["calls"], "nonzero integer call counts")
            require(number(row["selfSeconds"]) and number(row["cumulativeSeconds"])
                    and row["selfSeconds"] <= row["cumulativeSeconds"] <= wall, "finite function times")
            names.append(name)
            rows[name] = row
        require(names == sorted(spec["requiredFunctions"]), "all required complete function rows")
        if not is_candidate:
            require(custody["referenceReportSha256"] == digest(canonical(report)), "reference report identity")
            require(rows["_add"]["cumulativeSeconds"] / wall >= 0.50
                    and rows["builtins.pow"]["selfSeconds"] / wall >= 0.40, "material reference arithmetic attribution")
        else:
            require(type(reference) is dict and set(reference) == {"report", "custody"}, "closed reference binding")
            require(not validate_measurement_data(reference["report"], reference["custody"], record), "complete reference data required")
            prior = reference["report"]
            require(custody["referenceReportSha256"] == digest(canonical(prior)), "exact retained reference report")
            require(custody["activationSequence"] > reference["custody"]["activationSequence"]
                    and custody["checkoutCommit"] != reference["custody"]["checkoutCommit"], "ordered distinct candidate commit")
            for key in ("interpreter", "platform", "observerIdentity", "sampleIdentity", "benchmarkSha256", "recipeSha256", "warmColdDefinition"):
                require(report[key] == prior[key], "matched reference/candidate metadata: " + key)
            require(statistics.median(report["samplesSeconds"]) <= 0.85 * statistics.median(prior["samplesSeconds"]), "matched median performance gate")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        return ["invalid benchmark DATA_CHECK_ONLY; signatures and real-run custody remain external"]


def validate_reference_scaffold_data(after, proof, record, before_raw):
    """The exact unchanged-crypto source scope, not a completed reference run."""
    errors = validate_product_delta(after, proof, record, before_raw)
    if errors:
        return errors
    if digest(after["src/harness_conformance/crypto.py"]) != record["referenceBenchmark"]["unchangedCryptoSha256"]:
        return ["reference scaffold crypto is not the accepted unchanged source"]
    return []


def validate_dispatch_ownership(packets):
    try:
        from validate_backend_timing import close_timing_dispatch
    except ImportError:
        from scripts.validate_backend_timing import close_timing_dispatch
    try:
        from validate_proxy_diagnostics import close_diagnostic_dispatch
    except ImportError:
        from scripts.validate_proxy_diagnostics import close_diagnostic_dispatch
    try:
        from validate_document_repair_execution import close_document_dispatch
        from validate_benchmark_transport import close_transport_dispatch
        from validate_completion_integration import close_integration_dispatch
        from validate_factory_diagnostics import close_factory_dispatch
        from validate_guard_cost_repair import close_guard_dispatch
        from validate_guard_traversal import close_traversal_dispatch
    except ImportError:
        from scripts.validate_document_repair_execution import close_document_dispatch
        from scripts.validate_benchmark_transport import close_transport_dispatch
        from scripts.validate_completion_integration import close_integration_dispatch
        from scripts.validate_factory_diagnostics import close_factory_dispatch
        from scripts.validate_guard_cost_repair import close_guard_dispatch
        from scripts.validate_guard_traversal import close_traversal_dispatch
    """No generic weakening; close only the ten immutable, exact scoped pairs."""
    try:
        from validate_packet_ownership import validate_packet_ownership
    except ImportError:
        from scripts.validate_packet_ownership import validate_packet_ownership
    errors = validate_packet_ownership(packets)
    try:
        record = _record()
        require(validate_additions(packets) == [], "exact new packets")
        for name in ("CONF-PERF-001", "CONF-PERF-002", "CONF-PERF-003"):
            path = "task-packets/" + name + ".yaml"
            raw = regular_bytes(ROOT, path)
            require(digest(raw) == record["protectedFiles"][path]
                    and canonical(packets.get(name)) == canonical(safe_load(raw))
                    and record["dispatch"][name] == "SUPERSEDED_UNACCEPTED_HISTORY", "immutable retired packet")
        role = record["referenceBenchmark"]["executionRole"]
        require(role == {"packetId": "CONF-BENCH-001", "sourceOwner": "CONF-PERF-004",
                "sourceEdits": False, "requiresBranchOrPr": False, "acceptedSourcePredecessor": False,
                "class": "READ_ONLY_REFERENCE_REPLAY"}, "read-only replay role")
        retired = set()
        for pair in record["overlapPairs"]:
            left, right, count = pair
            paths = set(packets[left]["allowedPaths"]) & set(packets[right]["allowedPaths"])
            require(len(paths) == count, "exact pairwise path overlap")
            retired.update("unordered same-repository packets " + left + " and " + right + " overlap at "
                           + repr(path) + " and " + repr(path) for path in paths)
        require(len(retired) == 72 and all(errors.count(message) == 1 for message in retired), "exact72 diagnostics")
        return close_traversal_dispatch(packets, close_guard_dispatch(packets, close_factory_dispatch(packets, close_integration_dispatch(packets, close_transport_dispatch(packets, close_document_dispatch(packets, close_timing_dispatch(packets, close_diagnostic_dispatch(packets, close_dispatch_errors(packets, [error for error in errors if error not in retired])))))))))
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        return errors + ["missing or changed closed reference/candidate dispatch"]


def main():
    try:
        packets = {p.stem:safe_load(regular_bytes(ROOT,str(p.relative_to(ROOT)))) for p in (ROOT/"task-packets").glob("*.yaml")}
        errors = validate_authority(packets, *load_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError):
        errors = ["performance authority unavailable"]
    for error in errors:
        print("ERROR: "+error)
    if not errors:
        print("Conformance performance authority valid: 194 packets; 150 immutable YAML; 127/327 checkpoint; product/native NOT_RUN.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
