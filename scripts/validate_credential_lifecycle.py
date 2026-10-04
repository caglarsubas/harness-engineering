#!/usr/bin/env python3
"""Credential custody source-accounting DATA oracle; never executes snapshots."""
from __future__ import annotations

import ast
from pathlib import Path

import yaml

try:
    from safe_yaml import safe_load as safe_yaml_load
    from validate_proxy_contract import canonical, digest, parse, regular_bytes
    from validate_custody_handoff import definitions, reconstruct_source, appended_definitions, require
    from validate_successor_inventory import packet_semantics
except ImportError:
    from scripts.safe_yaml import safe_load as safe_yaml_load
    from scripts.validate_proxy_contract import canonical, digest, parse, regular_bytes
    from scripts.validate_custody_handoff import definitions, reconstruct_source, appended_definitions, require
    from scripts.validate_successor_inventory import packet_semantics

try:
    from validate_credential_ordering import historical_bytes, current_test_bytes, validate_additions as ordering_additions
except ImportError:
    from scripts.validate_credential_ordering import historical_bytes, current_test_bytes, validate_additions as ordering_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/credential-lifecycle-amendment.json"
RECORD_SHA256 = "851fd80ddeec7367405a3e8445e330290341e2b4d68bccf372c24a4b965c341c"
ADDITIONS = ("MET-REPAIR-012", "CONF-FIX-005", "MET-REPAIR-013", "MET-REPAIR-014", "MET-REPAIR-015", "MET-PERF-002", "CONF-PERF-001", "MET-PERF-003", "CONF-PERF-002", "MET-PERF-004", "CONF-PERF-003", "MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001", "MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010")
PACKET_DIGESTS = {"MET-REPAIR-012": "bb53b3538a50a6c4e26b7f40c6697376c3cb1cc5e3947dad573c9d45d9253a1e",
                  "CONF-FIX-005": "abb7c2a19d54f84789c2656164e1e9ac66f822620173401fe93c50d61cc5cf2a"}
BEFORE_PATH = "architecture/credential-lifecycle-inputs/before.json"
CHECKPOINT_PATH = "architecture/credential-lifecycle-inputs/checkpoint.json"
META_BEFORE_PATH = "architecture/credential-lifecycle-inputs/meta-tests.before.json"
DOC_PATH = "docs/live-backend/linux-boundary.md"
PROOF_FIELDS = {"schemaVersion", "evidenceClass", "packetId", "packetSha256", "authorityDigest",
                "baseCommit", "baseTree", "before", "checkpoint", "sources", "tests"}
ROOTS = ("tests/meta", "tests/parity", "tests/alpha1", "tests/fixes/runner_boundary",
         "tests/platform/linux_baseline", "tests/live_backend")


def pinned(record):
    require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256,
            "exact credential authority required")


def validate_additions(packets):
    try:
        require(type(packets) is dict, "packet map required")
        for name, checksum in PACKET_DIGESTS.items():
            require(digest(canonical(packets.get(name))) == checksum, "credential packet changed")
        return ordering_additions(packets)
    except (TypeError, ValueError, RecursionError):
        return ["exact credential publication and correction packets required"]


def load_credential_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    return record, {p: regular_bytes(root, p) for p in {*record["protectedFiles"], *record["inputFiles"]}}


def apply_meta_test_recipe(before, recipe):
    """Closed byte substitutions only; the record is pinned by every caller."""
    require(type(before) is bytes and type(recipe) is dict
            and set(recipe) == {"beforeSha256", "afterSha256", "replacements"}
            and digest(before) == recipe["beforeSha256"], "exact meta test before required")
    require(type(recipe["replacements"]) is list, "ordered meta substitutions required")
    after = before
    for item in recipe["replacements"]:
        require(type(item) is dict and set(item) == {"before", "after", "count"}
                and type(item["before"]) is str and type(item["after"]) is str
                and type(item["count"]) is int and item["count"] > 0
                and item["before"] and item["before"] != item["after"], "effective closed substitution required")
        old, new = item["before"].encode(), item["after"].encode()
        require(after.count(old) == item["count"], "exact substitution cardinality required")
        after = after.replace(old, new)
    require(digest(after) == recipe["afterSha256"], "meta test after differs")
    return after


def reconcile_meta_test_bytes(before):
    """Data-only bridge from accepted MET-PERF-001 tests, never a cached result."""
    record = parse(regular_bytes(ROOT, RECORD_PATH))
    pinned(record)
    require(type(before) is bytes, "meta test bytes required")
    input_digest = digest(before)
    recipes = [rule for rule in record["metaReconciliation"]["testRecipes"].values()
               if rule["beforeSha256"] == input_digest]
    require(len(recipes) == 1, "exact accepted meta test required")
    return current_test_bytes(apply_meta_test_recipe(before, recipes[0]))


def validate_meta_test_preservation(record, before_raw, current):
    try:
        pinned(record)
        require(type(before_raw) is bytes and digest(before_raw) == record["inputFiles"][META_BEFORE_PATH],
                "exact accepted meta test snapshot required")
        before = parse(before_raw)
        metadata = record["metaReconciliation"]
        require(before["baseCommit"] == record["metaBaseline"] == metadata["baseCommit"], "meta baseline identity")
        recipes = metadata["testRecipes"]
        require(type(current) is dict and set(current) == set(before["files"]) == set(recipes),
                "exact meta test inventory required")
        try:
            from validate_ci_performance import test_definitions
        except ImportError:
            from scripts.validate_ci_performance import test_definitions
        for path, recipe in recipes.items():
            old = before["files"][path].encode()
            require(type(current[path]) is bytes and current[path] == current_test_bytes(apply_meta_test_recipe(old, recipe)),
                    "unreviewed meta assertion or body change")
            require(test_definitions(old) == test_definitions(current[path]), "meta test identity changed")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, SyntaxError, UnicodeError, RecursionError):
        return ["invalid exact meta-test reconciliation"]


def test_ids(raw):
    """Independent AST identities only. Not discovery or behavioral acceptance."""
    tree, names = definitions(raw)
    require(not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "load_tests"
                    for n in tree.body), "custom discovery forbidden")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                text = ast.unparse(decorator)
                require(not any(word in text for word in ("skip", "expectedFailure", "xfail")), "hidden test")
    return sorted(k for k, (_, _, node) in names.items()
                  if "." in k and isinstance(node, ast.FunctionDef) and node.name.startswith("test_"))


def region_delta(before, row, allowed, limits, *, tests=False):
    require(type(row) is dict and set(row) == {"beforeSha256", "afterSha256", "regions", "append"},
            "closed region delta required")
    require(type(row["append"]) is str, "append text required")
    # Reuse the unchanged source-region oracle; test append has its own grammar.
    base_row = dict(row)
    appended = row["append"].encode()
    require(len(appended) <= limits["maxAppendBytes"], "append limit")
    if not tests:
        return reconstruct_source(before, row, allowed, limits)
    require(type(row["regions"]) is dict and set(row["regions"]) <= set(allowed), "test region scope")
    _, locations = definitions(before)
    chunks = [(locations[name][0], locations[name][1], value.encode()) for name, value in row["regions"].items()]
    base, cursor = b"", 0
    for start, end, raw in sorted(chunks):
        require(start >= cursor, "overlapping test region")
        base += before[cursor:start] + raw
        cursor = end
    base += before[cursor:]
    if chunks:
        base_row.update(append="", afterSha256=digest(base))
        require(reconstruct_source(before, base_row, allowed, limits) == base, "test region mismatch")
    else:
        require(row["beforeSha256"] == digest(before), "test before mismatch")
    require(appended.startswith(b"\n") and appended.endswith(b"\n"), "new test append required")
    ids = appended_definitions(appended, base, tests=True)
    require(ids and not set(ids) & set(test_ids(before)), "new test IDs required")
    after = base + appended
    require(digest(after) == row["afterSha256"] and set(test_ids(before)) <= set(test_ids(after)),
            "test hash or old ID changed")
    return after


def validate_delta(after, proof, record, before_raw, checkpoint_raw):
    try:
        pinned(record)
        require(type(before_raw) is bytes and digest(before_raw) == record["inputFiles"][BEFORE_PATH]
                and type(checkpoint_raw) is bytes and digest(checkpoint_raw) == record["inputFiles"][CHECKPOINT_PATH],
                "exact before checkpoint required")
        before = parse(before_raw)["files"]
        require(type(after) is dict and set(after) == set(before)
                and all(type(v) is bytes and len(v) <= 2097152 for v in after.values()), "five bounded files required")
        require(type(proof) is dict and set(proof) == PROOF_FIELDS
                and len(canonical(proof)) <= record["change"]["maxProofBytes"], "closed bounded proof required")
        expected = dict(schemaVersion=record["change"]["proofSchemaVersion"], evidenceClass="SOURCE_DELTA_ONLY",
            packetId="CONF-FIX-005", packetSha256=record["inputFiles"]["task-packets/CONF-FIX-005.yaml"],
            authorityDigest=RECORD_SHA256, baseCommit=record["sourceBaseline"]["commit"],
            baseTree=record["sourceBaseline"]["tree"], before=before_raw.decode(), checkpoint=checkpoint_raw.decode())
        require(all(proof[k] == v for k, v in expected.items()), "proof authority mismatch")
        for field, rules, tests in (("sources", "sourceRegions", False), ("tests", "testRegions", True)):
            require(type(proof[field]) is dict and set(proof[field]) == set(record["change"][rules]), "exact delta paths required")
            for path, regions in record["change"][rules].items():
                require(region_delta(before[path].encode(), proof[field][path], regions,
                                     record["change"], tests=tests) == after[path], "current source substitution")
        doc = after[DOC_PATH]
        require(doc.startswith(before[DOC_PATH].encode()), "historical document changed")
        marker = ("```" + record["change"]["proofFence"] + "\n").encode()
        require(doc.count(marker) == 1, "unique credential proof required")
        raw, closing = doc.split(marker, 1)[1].split(b"\n```", 1)
        require(raw == canonical(proof) and (not closing or closing.startswith(b"\n")), "proof fence mismatch")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, SyntaxError, UnicodeError, RecursionError):
        return ["invalid credential source delta; no execution authority"]


def validate_inventory(rows, test_sources, methods, after, proof, record, inputs,
                       launcher_after, launcher_proof=None):
    """Pinned cumulative accounting; neither stage nor hash exemptions are inputs."""
    try:
        pinned(record)
        pins = {**record["protectedFiles"], **record["inputFiles"]}
        require(type(inputs) is dict and set(inputs) == set(pins), "exact independent inputs required")
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(inputs[path]) == checksum, "input changed")
        require(not validate_delta(after, proof, record, inputs[BEFORE_PATH], inputs[CHECKPOINT_PATH]),
                "current credential proof required")
        checkpoint = parse(inputs[CHECKPOINT_PATH])
        try:
            from validate_successor_inventory import validate_composition
        except ImportError:
            from scripts.validate_successor_inventory import validate_composition
        successor = parse(inputs["architecture/successor-inventory-amendment.json"])
        source = "architecture/successor-inventory-inputs/"
        result = validate_composition(rows, successor, parse(inputs[source + "baseline.json"]),
            inputs[source + "test_packet_scalars.before.txt"], inputs[source + "live_launcher.before.txt"],
            launcher_after, launcher_proof)
        require(result["stage"] >= 2, "credential correction requires stage two or later")
        actual_rows = {r["path"]: r for r in rows}
        for path, row in checkpoint["files"].items():
            checksum, size = row["sha256"].removeprefix("sha256:"), row["size"]
            if path in after:
                checksum, size = digest(after[path]), len(after[path])
            elif path == successor["hook"]["path"]:
                checksum, size = digest(launcher_after), len(launcher_after)
            current = actual_rows[path]
            require((current["mode"], current["size"], current["sha256"]) == (row["mode"], size, checksum),
                    "current or historical source mismatch")
        new_tests = {p for p in actual_rows if p not in checkpoint["files"]
                     and any(p.startswith(root + "/") for root in ROOTS)
                     and Path(p).name.startswith("test_") and p.endswith(".py")}
        require(type(test_sources) is dict and set(test_sources) == new_tests | set(proof["tests"]),
                "exact current/new test bytes required")
        expected = dict(checkpoint["tests"])
        for path, raw in test_sources.items():
            row = actual_rows[path]
            require(type(raw) is bytes and digest(raw) == row["sha256"] and len(raw) == row["size"],
                    "test bytes differ from inventory")
            expected[path] = test_ids(raw)
            require(expected[path] and set(checkpoint["tests"].get(path, [])) <= set(expected[path]), "method lost")
        require(type(methods) is dict and methods == expected, "fresh collection must equal every old and new AST ID")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, SyntaxError, UnicodeError, RecursionError):
        return ["invalid cumulative credential source inventory"]


def validate_credential_lifecycle(packets, record, inputs):
    try:
        pinned(record)
        errors = validate_additions(packets)
        old = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/")}
        require(len(old) == 139 and len(packets) == 194
                and set(packets) == old | set(ADDITIONS) | {"MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"},
                "139 predecessors plus two credential packets and exact ordering authority required")
        pins = {**record["protectedFiles"], **record["inputFiles"]}
        require(type(inputs) is dict and set(inputs) == set(pins), "exact input map required")
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(historical_bytes(path, inputs[path])) == checksum, "immutable input changed: " + path)
            if path.startswith("task-packets/"):
                require(canonical(packets[Path(path).stem]) == packet_semantics(inputs[path]), "packet semantics differ")
        require(not validate_meta_test_preservation(record, inputs[META_BEFORE_PATH],
                    {p: inputs[p] for p in record["metaReconciliation"]["testRecipes"]}),
                "all accepted meta test bytes required")
        prefix = ["uv", "run", "--offline", "--frozen", "--no-sync", "python"]
        prior_commands = packets["MET-PERF-001"]["offlineAcceptanceCommands"]
        require(packets["MET-REPAIR-012"]["offlineAcceptanceCommands"] == [*prior_commands[:-2],
                prefix + ["scripts/validate_credential_lifecycle.py"], *prior_commands[-2:]],
                "all twenty cumulative commands required")
        checkpoint = parse(inputs[CHECKPOINT_PATH])
        before = parse(inputs[BEFORE_PATH])
        require(len(checkpoint["files"]) == 127 and checkpoint["testCount"] == 305
                and sum(map(len, checkpoint["tests"].values())) == 305, "127/305 checkpoint required")
        require(before["commit"] == checkpoint["commit"] == record["sourceBaseline"]["commit"]
                and before["tree"] == checkpoint["tree"] == record["sourceBaseline"]["tree"], "checkpoint identity mismatch")
        fix = packets["CONF-FIX-005"]
        require(set(before["files"]) == set(fix["allowedPaths"]), "exact before files required")
        for path, raw in before["files"].items():
            require("sha256:" + digest(raw.encode()) == checkpoint["files"][path]["sha256"], "before bytes mismatch")
        # Verify the actual accepted correction as inert source, not merely a
        # history label attached to the current checkpoint.
        try:
            from validate_custody_handoff import validate_delta as historical_delta
        except ImportError:
            from scripts.validate_custody_handoff import validate_delta as historical_delta
        historical = parse(inputs["architecture/custody-handoff-amendment.json"])
        document = before["files"][DOC_PATH].encode()
        marker = b"```harness-custody-source-proof\n"
        require(document.count(marker) == 1, "unique historical proof required")
        proof_raw = document.split(marker, 1)[1].split(b"\n```", 1)[0]
        proof = parse(proof_raw)
        require(proof_raw == canonical(proof), "canonical historical proof required")
        require(not historical_delta({p: raw.encode() for p, raw in before["files"].items()}, proof,
            historical, inputs["architecture/custody-handoff-inputs/baseline.json"]), "historical source proof failed")
        original = parse(inputs[record["sourceBaseline"]["originalPath"]])
        require(original["testCount"] == 279 and set(original["files"]) == set(checkpoint["files"]),
                "historical checkpoint changed")
        for path, ids in original["tests"].items():
            require(set(ids) <= set(checkpoint["tests"][path]), "historical test lost")
        for rules in ("sourceRegions", "testRegions"):
            for path, names in record["change"][rules].items():
                _, locations = definitions(before["files"][path].encode())
                require(len(names) == len(set(names)) and set(names) <= set(locations), "missing or duplicate source region")
        for path in record["change"]["testRegions"]:
            require(test_ids(before["files"][path].encode()) == checkpoint["tests"][path], "checkpoint test IDs differ")
        require(fix["offlineAcceptanceCommands"] == packets["CONF-LIVE-003"]["offlineAcceptanceCommands"]
                and len(fix["offlineAcceptanceCommands"]) == 8, "product command drift")
        return errors
    except (ValueError, TypeError, KeyError, AttributeError, SyntaxError, UnicodeError, RecursionError, yaml.YAMLError):
        return ["malformed credential lifecycle authority"]


def main():
    try:
        packets = {p.stem: safe_yaml_load(regular_bytes(ROOT, str(p.relative_to(ROOT))))
                   for p in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_credential_lifecycle(packets, *load_credential_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        errors = ["credential lifecycle authority unavailable"]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Credential lifecycle authority valid: 194 packets; exact performance/test reconciliation; 127/305 checkpoint; DATA_CHECK_ONLY, product/native NOT_RUN.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
