#!/usr/bin/env python3
"""Pinned source-delta DATA checks; snapshots are never imported or executed."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import textwrap

import yaml

try:
    from safe_yaml import safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import safe_load as safe_yaml_load

try:
    from validate_proxy_contract import canonical, digest, parse, regular_bytes
    from validate_successor_inventory import packet_semantics
except ImportError:
    from scripts.validate_proxy_contract import canonical, digest, parse, regular_bytes
    from scripts.validate_successor_inventory import packet_semantics

try:
    from validate_credential_ordering import historical_bytes, current_test_bytes, validate_additions as ordering_additions
except ImportError:
    from scripts.validate_credential_ordering import historical_bytes, current_test_bytes, validate_additions as ordering_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/custody-handoff-amendment.json"
RECORD_SHA256 = "26d0301045c60908850ec225fa497d73da4c4125c377e74a931d41c83d57c491"
PACKET_DIGESTS = {"MET-REPAIR-011":"aaa070d5ea2e7a4f6cfea9578d87bf82b7e12d5ef6c75d8456ed366701c7d7c1","CONF-FIX-004":"79c00496cab7cf4531b5d65d7aa292c662ed2d27c840b6e4d8ce8aa015ebb289"}
ADDITIONS = ("MET-REPAIR-011", "CONF-FIX-004", "MET-PERF-001", "MET-REPAIR-012", "CONF-FIX-005", "MET-REPAIR-013", "MET-REPAIR-014", "MET-REPAIR-015", "MET-PERF-002", "CONF-PERF-001", "MET-PERF-003", "CONF-PERF-002", "MET-PERF-004", "CONF-PERF-003", "MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001", "MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010")
BEFORE_PATH = "architecture/custody-handoff-inputs/baseline.json"
DOC_PATH = "docs/live-backend/linux-boundary.md"
PROOF_FIELDS = {"schemaVersion", "evidenceClass", "packetId", "packetSha256", "authorityDigest",
                "baseCommit", "baseTree", "sources", "tests", "baseline", "before"}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def pinned(record):
    require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256,
            "exact reviewed custody authority required")


def validate_additions(packets):
    try:
        require(type(packets) is dict, "packet map required")
        for name, checksum in PACKET_DIGESTS.items():
            require(digest(canonical(packets.get(name))) == checksum, "custody packet changed: " + name)
        try:
            from validate_ci_performance import validate_additions as performance_additions
        except ImportError:
            from scripts.validate_ci_performance import validate_additions as performance_additions
        try:
            from validate_credential_lifecycle import validate_additions as credential_additions
        except ImportError:
            from scripts.validate_credential_lifecycle import validate_additions as credential_additions
        return performance_additions(packets) + credential_additions(packets)
    except (TypeError, ValueError, RecursionError):
        return ["exact custody publication and correction packets required"]


def load_custody_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    return record, {p: regular_bytes(root, p) for p in
                    {*record["protectedFiles"], *record["inputFiles"]}}


def definitions(raw):
    """Read AST locations only. No compile, import, eval or snapshot execution."""
    require(type(raw) is bytes and len(raw) <= 2097152, "bounded source bytes required")
    tree = ast.parse(raw)
    lines = raw.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    result = {}
    def save(name, node):
        require(name not in result, "duplicate source definition")
        start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
        result[name] = (offsets[start - 1], offsets[node.end_lineno], node)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            save(node.name, node)
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, ast.FunctionDef):
                        save(node.name + "." + child.name, child)
                    elif isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
                        save(node.name + "." + child.targets[0].id, child)
    return tree, result


def _literal(node):
    # This deliberately small grammar also rejects executable defaults/bases.
    if isinstance(node, ast.Constant):
        return type(node.value) in (str, bytes, int, bool, type(None))
    return isinstance(node, (ast.Tuple, ast.List)) and all(_literal(n) for n in node.elts)


def appended_definitions(raw, original, *, tests=False):
    tree, old = definitions(original)
    appended, names = definitions(raw)
    seen = set(k for k in old if "." not in k)
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            seen.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            seen.update(n.id for target in targets for n in ast.walk(target) if isinstance(n, ast.Name))
    seen.update(("load_tests", "__getattr__", "__dir__"))
    require(appended.body, "nonempty definition append required")
    def safe_definition(node):
        require(isinstance(node, (ast.FunctionDef, ast.ClassDef)), "definitions only at append boundary")
        require(not node.decorator_list, "append decorators forbidden")
        if isinstance(node, ast.FunctionDef):
            require(node.returns is None and all(arg.annotation is None for arg in
                    [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                     *([node.args.vararg] if node.args.vararg else []),
                     *([node.args.kwarg] if node.args.kwarg else [])]), "append annotations forbidden")
            require(all(_literal(v) for v in [*node.args.defaults,
                    *(v for v in node.args.kw_defaults if v is not None)]), "executable default")
        else:
            require(not node.keywords, "class metaclass selection forbidden")
            for base in node.bases:
                require(isinstance(base, ast.Name) and base.id == "object" or tests
                        and isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name)
                        and base.value.id == "unittest" and base.attr == "TestCase", "unapproved class base")
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.ClassDef)):
                    safe_definition(child)
                else:
                    require(isinstance(child, ast.Pass) or isinstance(child, ast.Expr)
                            and isinstance(child.value, ast.Constant) and type(child.value.value) is str
                            or isinstance(child, ast.Assign) and _literal(child.value)
                            and all(isinstance(t, ast.Name) for t in child.targets), "executable class body")
    for node in appended.body:
        safe_definition(node)
        require(node.name not in seen, "existing definition rebound by append")
        seen.add(node.name)
    return sorted(name for name, (_, _, n) in names.items()
                  if "." in name and isinstance(n, ast.FunctionDef) and n.name.startswith("test_"))


def reconstruct_source(before, row, allowed, limits):
    require(type(row) is dict and set(row) == {"beforeSha256", "afterSha256", "regions", "append"},
            "closed source delta required")
    require(row["beforeSha256"] == digest(before) and type(row["regions"]) is dict
            and set(row["regions"]) <= set(allowed), "wrong original or region")
    _, locations = definitions(before)
    chunks = []
    for name, replacement in row["regions"].items():
        require(type(replacement) is str, "string replacement required")
        raw = replacement.encode("utf-8")
        require(0 < len(raw) <= limits["maxReplacementBytes"] and raw.endswith(b"\n")
                and b"\r" not in raw and b"\0" not in raw, "bounded complete replacement required")
        start, end, original = locations[name]
        parsed = ast.parse(textwrap.dedent(replacement))
        require(len(parsed.body) == 1 and type(parsed.body[0]) is type(original), "one matching definition required")
        changed = parsed.body[0]
        if isinstance(original, ast.FunctionDef):
            require(changed.name == original.name and ast.dump(changed.args) == ast.dump(original.args)
                    and (ast.dump(changed.returns) if changed.returns is not None else None)
                    == (ast.dump(original.returns) if original.returns is not None else None)
                    and changed.type_comment == original.type_comment
                    and [ast.dump(p) for p in changed.type_params] == [ast.dump(p) for p in original.type_params]
                    and not changed.decorator_list, "function interface or decorator changed")
        else:
            require(name == "InstalledContext.__slots__" and len(changed.targets) == 1
                    and ast.dump(changed.targets[0]) == ast.dump(original.targets[0])
                    and isinstance(changed.value, ast.Tuple) and all(isinstance(v, ast.Constant)
                    and type(v.value) is str for v in changed.value.elts), "literal context slots required")
            old_slots = [v.value for v in original.value.elts]
            new_slots = [v.value for v in changed.value.elts]
            require(new_slots[:len(old_slots)] == old_slots and len(new_slots) == len(set(new_slots))
                    and all(s.startswith("_") for s in new_slots), "original/private context slots required")
        # Preserve indentation at the original boundary, not just AST semantics.
        indentation = before[start:end].splitlines()[0][:original.col_offset]
        require(all(not line or line.startswith(indentation) for line in raw.splitlines()), "region indentation changed")
        chunks.append((start, end, raw))
    current, cursor = b"", 0
    for start, end, raw in sorted(chunks):
        require(start >= cursor, "overlapping source regions")
        current += before[cursor:start] + raw
        cursor = end
    current += before[cursor:]
    require(type(row["append"]) is str, "string append required")
    appended = row["append"].encode("utf-8")
    require(len(appended) <= limits["maxAppendBytes"], "append too large")
    if appended:
        require(appended.startswith(b"\n") and appended.endswith(b"\n"), "append line boundary required")
        appended_definitions(appended, current)
    current += appended
    definitions(current)
    require(current != before and digest(current) == row["afterSha256"], "source after digest mismatch")
    return current


def validate_delta(after, proof, record, before_raw):
    """Pure source compatibility only; no returned data grants execution."""
    try:
        pinned(record)
        require(type(before_raw) is bytes and digest(before_raw) == record["inputFiles"][BEFORE_PATH],
                "original before snapshot required")
        before = parse(before_raw)["files"]
        require(type(after) is dict and set(after) == set(before)
                and all(type(v) is bytes and len(v) <= 2097152 for v in after.values()), "exact bounded five-path map")
        require(type(proof) is dict and set(proof) == PROOF_FIELDS
                and len(canonical(proof)) <= record["change"]["maxProofBytes"], "bounded closed proof required")
        expected = dict(schemaVersion=record["change"]["proofSchemaVersion"], evidenceClass="SOURCE_DELTA_ONLY",
            packetId="CONF-FIX-004", packetSha256=record["inputFiles"]["task-packets/CONF-FIX-004.yaml"],
            authorityDigest=RECORD_SHA256, baseCommit=record["sourceBaseline"]["commit"],
            baseTree=record["sourceBaseline"]["tree"])
        require(all(proof[k] == v for k, v in expected.items()), "proof authority mismatch")
        require(type(proof["before"]) is str and proof["before"].encode() == before_raw, "snapshot substitution")
        baseline_raw = proof["baseline"].encode() if type(proof["baseline"]) is str else b""
        baseline_path = record["sourceBaseline"]["path"]
        require(digest(baseline_raw) == record["protectedFiles"][baseline_path], "baseline substitution")
        baseline = parse(baseline_raw)
        require(type(proof["sources"]) is dict and set(proof["sources"]) == set(record["change"]["sourceRegions"]),
                "two source deltas required")
        for path, allowed in record["change"]["sourceRegions"].items():
            require(reconstruct_source(before[path].encode(), proof["sources"][path], allowed, record["change"])
                    == after[path], "unreviewed source bytes")
        tests = set(record["change"]["appendOnlyPaths"]) - {DOC_PATH}
        require(type(proof["tests"]) is dict and set(proof["tests"]) == tests, "exact test proofs required")
        for path in tests:
            raw = before[path].encode()
            require(after[path].startswith(raw), "historical test changed")
            appended = after[path][len(raw):]
            require(0 < len(appended) <= record["change"]["maxAppendBytes"]
                    and appended.startswith(b"\n") and appended.endswith(b"\n"), "bounded test append required")
            ids = appended_definitions(appended, raw, tests=True)
            require(ids and not set(ids) & set(baseline["tests"][path]), "new noncolliding regressions required")
            require(proof["tests"][path] == dict(beforeSha256=digest(raw), afterSha256=digest(after[path]), newTestIds=ids),
                    "test prefix/hash/ID mismatch")
        doc = after[DOC_PATH]
        require(doc.startswith(before[DOC_PATH].encode()) and len(doc) > len(before[DOC_PATH].encode()),
                "original document prefix required")
        marker = ("```" + record["change"]["proofFence"] + "\n").encode()
        require(doc.count(marker) == 1, "one proof fence required")
        encoded, closing = doc.split(marker, 1)[1].split(b"\n```", 1)
        require((not closing or closing.startswith(b"\n")) and encoded == canonical(proof), "noncanonical/mismatched proof fence")
        return []
    except (TypeError, ValueError, KeyError, AttributeError, SyntaxError, UnicodeError, RecursionError):
        return ["invalid custody source delta; no execution authority"]


def validate_custody_handoff(packets, record, inputs):
    try:
        pinned(record)
        errors = validate_additions(packets)
        old = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/")}
        require(len(old) == 136 and set(packets) == old | set(ADDITIONS) | {"MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}, "136 predecessors plus two custody packets required")
        pins = {**record["protectedFiles"], **record["inputFiles"]}
        require(type(inputs) is dict and set(inputs) == set(pins), "exact custody input inventory required")
        for path, checksum in pins.items():
            raw = historical_bytes(path, inputs[path])
            require(type(raw) is bytes and digest(raw) == checksum, "immutable input changed: " + path)
            if path.startswith("task-packets/"):
                require(canonical(packets[Path(path).stem]) == packet_semantics(raw), "packet bytes/semantics mismatch")
        baseline = parse(inputs[record["sourceBaseline"]["path"]])
        before = parse(inputs[BEFORE_PATH])
        require(len(baseline["files"]) == 127 and baseline["testCount"] == 279
                and sum(map(len, baseline["tests"].values())) == 279, "127/279 original baseline required")
        require(set(before["files"]) == set(packets["CONF-FIX-004"]["allowedPaths"]), "five original source paths required")
        for path, raw in before["files"].items():
            require(type(raw) is str and "sha256:" + digest(raw.encode()) == baseline["files"][path]["sha256"],
                    "before source does not match exact baseline")
        for path, regions in record["change"]["sourceRegions"].items():
            _, actual = definitions(before["files"][path].encode())
            require(len(regions) == len(set(regions)) and set(regions) <= set(actual), "unknown or duplicate custody region")
        return errors
    except (TypeError, ValueError, KeyError, AttributeError, SyntaxError, UnicodeError, RecursionError, yaml.YAMLError) as exc:
        detail = str(exc) if type(exc) is ValueError else type(exc).__name__
        return ["malformed custody-handoff authority: " + detail]


def main():
    try:
        packets = {p.stem: safe_yaml_load(regular_bytes(ROOT, str(p.relative_to(ROOT))))
                   for p in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_custody_handoff(packets, *load_custody_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        errors = ["custody-handoff authority unavailable"]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Custody handoff authority valid: 194 packets; 127-file/279-ID history preserved; product/native NOT_RUN.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
