#!/usr/bin/env python3
"""Closed credential-ordering DATA oracle; never runs source snapshots or I/O probes."""
from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

import yaml

try:
    from safe_yaml import safe_load
    from validate_proxy_contract import canonical, digest, parse, regular_bytes
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts.validate_proxy_contract import canonical, digest, parse, regular_bytes

try:
    from validate_broker_handoff import historical_bytes as broker_history, current_test_bytes as broker_current, validate_additions as broker_additions
except ImportError:
    from scripts.validate_broker_handoff import historical_bytes as broker_history, current_test_bytes as broker_current, validate_additions as broker_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/credential-ordering-amendment.json"
BEFORE_PATH = "architecture/credential-ordering-inputs/meta-before.json"
CHECKPOINT_PATH = "architecture/credential-ordering-inputs/checkpoint.json"
SOURCE_PATH = "architecture/credential-ordering-inputs/source-before.json"
VECTORS_PATH = "architecture/credential-ordering-inputs/vectors.json"
RECORD_SHA256 = "7fa6920687a29f55adc088b5239951fa506f1e71ed826839bf7de8b970483f77"
PACKET_SHA256 = "0a0bb47c5636ae12b62e540eae100a146ab2db6982b4946b0642e02079040afe"
CLIENT_TRACE = ("AUTHORITY", "ISOLATION", "RESERVATION", "CLIENT_ELIGIBILITY",
                "CLIENT_CREDENTIAL", "TLS_AUTHENTICATED", "FIXED_REQUEST", "RECEIPT_CHECKED", "CLOSED")
SERVER_TRACE = ("AUTHORITY", "ISOLATION", "POLICY_OBSERVED", "RESERVATION",
                "SERVER_TLS_CREDENTIAL", "PEER_AUTHENTICATED", "FIXED_REQUEST_CHECKED",
                "POLICY_RECHECKED", "UPSTREAM_CREDENTIAL", "GENERATION_FENCED",
                "FIXED_PROBE", "POLICY_RECHECKED", "RECEIPT_CANDIDATE", "CLOSED")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pinned(record):
    require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256,
            "exact approved ordering authority required")


def _record():
    record = parse(regular_bytes(ROOT, RECORD_PATH))
    pinned(record)
    return record


def validate_additions(packets):
    try:
        require(type(packets) is dict and
                digest(canonical(packets.get("MET-REPAIR-013"))) == PACKET_SHA256,
                "exact credential-ordering packet required")
        return broker_additions(packets)
    except (ValueError, TypeError, RecursionError):
        return ["missing or changed credential-ordering authority packet"]


def apply_recipe(before, recipe):
    """Finite reviewed byte replacements, with before/after hashes and cardinality."""
    require(type(before) is bytes and type(recipe) is dict
            and set(recipe) == {"beforeSha256", "afterSha256", "replacements"}
            and digest(before) == recipe["beforeSha256"], "exact recipe before bytes required")
    require(type(recipe["replacements"]) is list, "ordered replacement list required")
    result = before
    for row in recipe["replacements"]:
        require(type(row) is dict and set(row) == {"before", "after", "count"}
                and type(row["before"]) is type(row["after"]) is str
                and type(row["count"]) is int and row["count"] > 0
                and row["before"] and row["before"] != row["after"], "effective closed replacement required")
        old, new = row["before"].encode(), row["after"].encode()
        require(result.count(old) == row["count"], "replacement cardinality differs")
        result = result.replace(old, new)
    require(digest(result) == recipe["afterSha256"], "unreviewed recipe after bytes")
    return result


_BEFORE_DECODE_BYTES = 290177
_BEFORE_DECODE_SHA256 = "5aed1292ff416c92a363ff34e0d570a152fb8029048701bd8b3fe77c69a486ff"


@lru_cache(maxsize=1)
def _decode_before_snapshot(raw):
    """Pure immutable decoding of one fixed blob, never file or authority state.

    The pinned parser is fixed during a process. A warm entry does not detect
    arbitrary parser replacement; regression fixtures clear mock entries.
    """
    require(type(raw) is bytes and len(raw) == _BEFORE_DECODE_BYTES
            and digest(raw) == _BEFORE_DECODE_SHA256, "eligible historical decode bytes required")
    before = parse(raw)
    baseline, files = before["baseCommit"], before["files"]
    require(type(baseline) is str and type(files) is dict and len(files) == 23
            and all(type(path) is str and type(value) is str for path, value in files.items()),
            "immutable historical decode projection required")
    return baseline, tuple(files.items())


def _before(record):
    raw = regular_bytes(ROOT, BEFORE_PATH)
    checksum = digest(raw)
    require(checksum == record["inputFiles"][BEFORE_PATH], "exact historical meta bytes required")
    if type(raw) is bytes and len(raw) == _BEFORE_DECODE_BYTES and checksum == _BEFORE_DECODE_SHA256:
        baseline, files = _decode_before_snapshot(raw)
        require(baseline == record["metaBaseline"], "meta baseline differs")
        return dict(files)
    # Eligibility is not acceptance: all other data retains the original path
    # and error ordering, including baseline refusal before reading files.
    before = parse(raw)
    require(before["baseCommit"] == record["metaBaseline"], "meta baseline differs")
    return before["files"]


def historical_bytes(path, raw):
    """Verify actual approved replacement BEFORE presenting old bytes to old pins.

    This is source accounting only. It neither hides current files from acceptance
    nor executes or imports the historical view. Unchanged inputs remain untouched.
    """
    raw = broker_history(path, raw)
    if path != "AGENTS.md" and not path.startswith("tests/"):
        return raw
    record = _record()
    recipe = record["metaRecipes"].get(path)
    if recipe is None or not recipe["replacements"]:
        return raw
    require(type(raw) is bytes, "current replacement bytes required")
    before = _before(record)[path].encode()
    require(raw == apply_recipe(before, recipe), "current bytes differ from exact approved replacement")
    return before


def current_test_bytes(before):
    """Compose the previous accepted recipe with this exact successor, not a cache."""
    require(type(before) is bytes, "test bytes required")
    record = _record()
    input_digest = digest(before)
    matches = [(p, r) for p, r in record["metaRecipes"].items()
               if p.startswith("tests/") and r["beforeSha256"] == input_digest]
    require(len(matches) == 1, "exact predecessor test bytes required")
    return broker_current(apply_recipe(before, matches[0][1]))


def validate_trace(role, trace, *, resources=False):
    """Non-authorizing data ordering only. Events are never runtime capability flags."""
    try:
        require(type(role) is str and role in ("CLIENT", "SERVER") and type(resources) is bool,
                "closed role and resource shape required")
        require(type(trace) is list and all(type(event) is str for event in trace), "plain event list required")
        expected = CLIENT_TRACE if role == "CLIENT" else tuple(
            event for event in SERVER_TRACE if resources or event != "UPSTREAM_CREDENTIAL")
        require(tuple(trace) == expected, "mandatory independent gates missing, changed or reordered")
        return []
    except (ValueError, TypeError):
        return ["invalid DATA_CHECK_ONLY ordering; no execution authority"]


def _test_ids(raw):
    names = []
    def visit(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                names.append(prefix + node.name)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
    visit(ast.parse(raw).body)
    require(len(names) == len(set(names)), "duplicate test identity")
    return names


def validate_recipes(record, before_raw, current):
    try:
        pinned(record)
        require(type(before_raw) is bytes and digest(before_raw) == record["inputFiles"][BEFORE_PATH],
                "pinned meta snapshot required")
        before = parse(before_raw)
        require(before["baseCommit"] == record["metaBaseline"], "historical meta identity")
        recipes = record["metaRecipes"]
        require(type(current) is dict and set(current) == set(recipes) == set(before["files"]),
                "exact current recipe inventory")
        for path, recipe in recipes.items():
            raw = before["files"][path].encode()
            require(type(current[path]) is bytes and broker_history(path, current[path]) == apply_recipe(raw, recipe),
                    "actual current bytes differ")
            if path.startswith("tests/"):
                require(_test_ids(raw) == _test_ids(current[path]), "old test identities changed")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError):
        return ["invalid exact ordering meta recipes"]


def load_ordering_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    paths = {*record["protectedFiles"], *record["inputFiles"], *record["metaChanges"]}
    return record, {p: regular_bytes(root, p) for p in paths}


def validate_credential_ordering(packets, record, inputs):
    try:
        pinned(record)
        require(not validate_additions(packets), "exact new packet required")
        pins = {**record["protectedFiles"], **record["inputFiles"],
                **{p: r["afterSha256"] for p, r in record["metaChanges"].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), "exact current input set")
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(broker_history(path, inputs[path])) == checksum, "changed input: " + path)
        old = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/")}
        require(len(old) == 141 and len(packets) == 194 and set(packets) == old | {"MET-REPAIR-013", "MET-REPAIR-014", "MET-REPAIR-015", "MET-PERF-002", "CONF-PERF-001", "MET-PERF-003", "CONF-PERF-002", "MET-PERF-004", "CONF-PERF-003", "MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001", "MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010", "MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"},
                "141 immutable predecessors and one exact addition required")
        for name in old | {"MET-REPAIR-013"}:
            require(canonical(packets[name]) == canonical(safe_load(inputs["task-packets/" + name + ".yaml"])),
                    "packet semantics differ from bytes")
        packet = packets["MET-REPAIR-013"]
        old_commands = packets["MET-REPAIR-012"]["offlineAcceptanceCommands"]
        require(packet["offlineAcceptanceCommands"] == [*old_commands[:-2],
            ["uv", "run", "--offline", "--frozen", "--no-sync", "python", "scripts/validate_credential_ordering.py"],
            *old_commands[-2:]] and len(packet["offlineAcceptanceCommands"]) == 21, "full cumulative commands")
        require(set(packet["allowedPaths"]) == set(record["ownedPaths"]), "exact ownership")
        require(not validate_recipes(record, inputs[BEFORE_PATH],
                    {p: inputs[p] for p in record["metaRecipes"]}), "current recipes fail")
        checkpoint = parse(inputs[CHECKPOINT_PATH])
        require(len(checkpoint["files"]) == 127 and sum(map(len, checkpoint["tests"].values())) == 327,
                "127/327 checkpoint required")
        source = parse(inputs[SOURCE_PATH])
        require(source["commit"] == record["sourceBaseline"]["commit"]
                and source["tree"] == record["sourceBaseline"]["tree"]
                and source["evidenceClass"] == "SOURCE_INSPECTION_ONLY", "source checkpoint identity")
        for path, raw in source["files"].items():
            require("sha256:" + digest(raw.encode()) == checkpoint["files"][path]["sha256"], "source snapshot changed")
        vectors = parse(inputs[VECTORS_PATH])
        require(vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["nativeAcceptance"] is False
                and vectors["tenantAcceptance"] is False, "data evidence promotion")
        require(not validate_trace("CLIENT", vectors["client"])
                and not validate_trace("SERVER", vectors["server"], resources=True)
                and not validate_trace("SERVER", vectors["serverWithoutResources"]), "positive ordering differs")
        require(packets["CONF-LIVE-003"]["allowedPaths"] == record["dispatchGate"]["consumerPaths"]
                and packets["CONF-LIVE-003"]["offlineAcceptanceCommands"] == record["dispatchGate"]["consumerCommands"],
                "product scope or command drift")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError, yaml.YAMLError) as exc:
        return ["invalid credential-ordering authority: " + (str(exc) if type(exc) is ValueError else type(exc).__name__)]


def main():
    try:
        packets = {p.stem: safe_load(regular_bytes(ROOT, str(p.relative_to(ROOT))))
                   for p in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_credential_ordering(packets, *load_ordering_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        errors = ["credential-ordering authority unavailable"]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Credential ordering valid: 194 packets; 127/327 source checkpoint; DATA_CHECK_ONLY; product/native NOT_RUN.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
