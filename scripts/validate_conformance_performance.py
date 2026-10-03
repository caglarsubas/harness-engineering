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
    from validate_conformance_performance_followup import historical_bytes as followup_history, current_test_bytes as followup_current, validate_additions as followup_additions
except ImportError:
    from scripts.validate_conformance_performance_followup import historical_bytes as followup_history, current_test_bytes as followup_current, validate_additions as followup_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/conformance-performance-amendment.json"
RECORD_FILE_SHA256 = "dc6019ef0c8ddb721a3f72ee10f98bb7925cc8313b09b74793865d01602d0243"
HISTORY_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_broker_handoff.py","scripts/validate_ci_performance.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_proxy_contract.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_broker_handoff.py","tests/test_ci_performance.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_proxy_contract.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])
BEFORE_PATH = "architecture/conformance-performance-inputs/meta-before.json"
PRODUCT_PATH = "architecture/conformance-performance-inputs/product-before.json"
CHECKPOINT_PATH = "architecture/credential-ordering-inputs/checkpoint.json"
RECORD_SHA256 = "2c2e855548fe9dfcc79838d6036472ba86f30cbf972dfebba5fc8d45bed9d699"
NEW_IDS = ("MET-PERF-002", "CONF-PERF-001")


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
    # Fresh read/hash/parse on every invocation, without a result cache.
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
    raw = followup_history(path, raw)
    # Successor history above is always validated before this identity route.
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
        return followup_current(before)
    require(len(matches) == 1, "unique predecessor")
    return followup_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return followup_additions(packets)
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
        if old.name.startswith("test_"):
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
        require(proof["schemaVersion"] == "planeon.conformance-performance-delta/v1"
                and proof["evidenceClass"] == "SOURCE_DELTA_ONLY" and proof["packetId"] == "CONF-PERF-001"
                and proof["authorityDigest"] == RECORD_SHA256
                and proof["baseCommit"] == before["baseCommit"] == record["sourceBaseline"]["commit"], "proof identity")
        doc = "docs/live-backend/linux-boundary.md"
        require(type(after) is dict and type(proof["sources"]) is dict
                and set(after) == set(before["files"]) == set(record["productPaths"])
                and set(proof["sources"]) == set(after) - {doc}, "exact six-path proof")
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
            require(type(inputs[path]) is bytes and digest(followup_history(path, inputs[path])) == checksum, "current source changed: " + path)
        old = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/") and p.endswith(".yaml")}
        require(len(old) == 144 and len(packets) == 194 and set(packets) == old | set(NEW_IDS) | {"MET-PERF-003", "CONF-PERF-002", "MET-PERF-004", "CONF-PERF-003", "MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001", "MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010", "MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}, "exact148 catalog")
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs["task-packets/"+name+".yaml"])), "packet raw/semantic mismatch")
        packet, product = (packets[name] for name in NEW_IDS)
        require(packet["allowedPaths"] == record["ownedPaths"] and product["allowedPaths"] == record["productPaths"], "path grant")
        require(packet["offlineAcceptanceCommands"] == record["preserved"]["metaCommands"]
                and len(packet["offlineAcceptanceCommands"]) == 24, "complete meta commands")
        require(product["offlineAcceptanceCommands"] == packets["CONF-FIX-005"]["offlineAcceptanceCommands"]
                == record["preserved"]["productCommands"], "unchanged eight product commands")
        before = parse(inputs[BEFORE_PATH])
        require(before["baseCommit"] == record["metaBaseline"] and set(before["files"]) == set(record["metaRecipes"]), "meta before inventory")
        for path, rule in record["metaRecipes"].items():
            raw = before["files"][path].encode()
            require(apply_recipe(raw, rule) == followup_history(path, inputs[path]), "meta recipe differs")
            if path.startswith("tests/"):
                require(test_ids(raw) == test_ids(inputs[path]), "old test identity changed")
        checkpoint, sources = parse(inputs[CHECKPOINT_PATH]), parse(inputs[PRODUCT_PATH])
        require(checkpoint["commit"] == sources["baseCommit"] == record["sourceBaseline"]["commit"]
                and checkpoint["tree"] == record["sourceBaseline"]["tree"]
                and len(checkpoint["files"]) == 127 and sum(map(len, checkpoint["tests"].values())) == 327, "127/327 checkpoint")
        require(set(sources["files"]) == set(record["productPaths"]), "six pinned product paths")
        for path, raw in sources["files"].items():
            require("sha256:"+digest(raw.encode()) == checkpoint["files"][path]["sha256"], "product source changed")
            for name in record["productRegions"][path]["regions"]:
                region(raw.encode(), name)
        require(record["stages"] == [110,120,127,135,141,146,151]
                and record["measurement"]["functionAttribution"] == "NOT_YET_MEASURED"
                and record["preserved"]["nativeAcceptance"] is record["preserved"]["tenantAcceptance"] is False, "evidence promotion")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError) as exc:
        return ["invalid performance authority: "+str(exc)]


def main():
    try:
        packets = {p.stem:safe_load(regular_bytes(ROOT,str(p.relative_to(ROOT)))) for p in (ROOT/"task-packets").glob("*.yaml")}
        errors = validate_authority(packets, *load_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError):
        errors = ["performance authority unavailable"]
    for error in errors:
        print("ERROR: "+error)
    if not errors:
        print("Conformance performance authority valid: 194 packets; 144 immutable YAML; 127/327 checkpoint; product/native NOT_RUN.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
