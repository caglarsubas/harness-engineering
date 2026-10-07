#!/usr/bin/env python3
"""Validate the MET-PERF-032 verify-time changes and the exact 208-to-207 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import json
import stat
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/verify-headroom-authority.json"
AUTHORITY_SHA256 = "3fc081b7b9612199fa334c69a1e22dcde77b37b9ea9abd43bd544a9d4b73d65b"
VALIDATOR_PATH = "scripts/validate_verify_headroom.py"
BASE_COMMIT = "8f77c3ff5289bade9752f2a3200645180f473e13"
NEW_PACKET = "MET-PERF-032"
PREVIOUS_PACKET = "MET-SECTOR-001"
MAX_FILE_BYTES = 16_777_216
# Test routes cover the top-level ci/test_ files as well as tests/.
TEST_PREFIXES = ("tests/", "ci/test_")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate verify-headroom authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite verify-headroom authority number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _path(path: Any) -> None:
    require(type(path) is str and bool(path) and not path.startswith("/")
            and "\\" not in path and not any(ord(char) < 32 for char in path)
            and all(part not in ("", ".", "..") for part in path.split("/")),
            "relative source path")


def regular_bytes(path: str) -> bytes:
    _path(path)
    parent = ROOT
    for part in path.split("/")[:-1]:
        parent /= part
        require(stat.S_ISDIR(parent.lstat().st_mode), "linked source ancestor")
    target = parent / path.split("/")[-1]
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= MAX_FILE_BYTES, "bounded regular source file")
    raw = target.read_bytes()
    after = target.lstat()
    identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink,
                            row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
            "source changed during read")
    return raw


# Exact bytes most recently proven to hash to the pin. Every call still reads
# the complete file; byte-identical input implies the identical digest, while
# any other bytes or pin are hashed in full before they are accepted.
_VERIFIED_AUTHORITY: tuple[str, bytes] | None = None


def _checked_authority_raw() -> bytes:
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "verify headroom history authority digest")
        if type(raw) is bytes:
            _VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw)
    return raw


def fresh_authority() -> None:
    """Re-read the complete pinned authority without reparsing its JSON."""
    _checked_authority_raw()


def _sha(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def authority() -> dict[str, Any]:
    value = parse(_checked_authority_raw())
    require(type(value) is dict and set(value) == {
        "schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets",
        "packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256",
    }, "closed verify headroom history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/verify-headroom-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 207
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 207-packet base")
    for name, expected in value["baselinePackets"].items():
        require(type(name) is str and name and "/" not in name
                and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for char in name)
                and _sha(expected), "predecessor packet identity")
    for path, expected in value["newFiles"].items():
        _path(path)
        require(_sha(expected), "new source digest")
    for path in value["changedFiles"]:
        _path(path)
    special = {AUTHORITY_PATH, VALIDATOR_PATH, "task-packets/" + NEW_PACKET + ".yaml"}
    require(not (set(value["changedFiles"]) & set(value["newFiles"]))
            and not (special & (set(value["changedFiles"]) | set(value["newFiles"])))
            and all(not path.startswith("task-packets/") or path == "task-packets/README.md"
                    for path in set(value["changedFiles"]) | set(value["newFiles"])),
            "disjoint source routes and immutable predecessor packets")
    return value


def _base64(value: Any) -> bytes:
    require(type(value) is str, "inverse hunk encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("inverse hunk encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical inverse hunk")
    return raw


def _rules() -> MappingProxyType:
    changed = authority()["changedFiles"]
    frozen = {}
    for path, rule in changed.items():
        require(type(rule) is dict
                and set(rule) == {"beforeSha256", "afterSha256", "reverseHunks"}
                and _sha(rule["beforeSha256"]) and _sha(rule["afterSha256"])
                and rule["beforeSha256"] != rule["afterSha256"]
                and type(rule["reverseHunks"]) is list
                and 0 < len(rule["reverseHunks"]) <= 4096, "closed inverse route")
        hunks = []
        prior_at, prior_end, total = -1, 0, 0
        for hunk in rule["reverseHunks"]:
            require(type(hunk) is dict
                    and set(hunk) == {"at", "removeBase64", "insertBase64"}
                    and type(hunk["at"]) is int
                    and 0 <= hunk["at"] <= MAX_FILE_BYTES
                    and prior_at < hunk["at"] and hunk["at"] >= prior_end,
                    "ordered inverse hunk")
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            require(removed != inserted, "effective inverse hunk")
            total += len(removed) + len(inserted)
            require(total <= MAX_FILE_BYTES and hunk["at"] + len(removed) <= MAX_FILE_BYTES,
                    "bounded inverse payload")
            hunks.append((hunk["at"], removed, inserted))
            prior_at, prior_end = hunk["at"], hunk["at"] + len(removed)
        frozen[path] = MappingProxyType({"beforeSha256": rule["beforeSha256"],
                                         "afterSha256": rule["afterSha256"],
                                         "reverseHunks": tuple(hunks)})
    return MappingProxyType(frozen)


_PROJECTION_RULES = _rules()


def _packet_byte_rules() -> MappingProxyType:
    record = authority()
    return MappingProxyType(dict(record["baselinePackets"],
                                 **{NEW_PACKET: record["packetSha256"]}))


_PACKET_BYTE_RULES = _packet_byte_rules()


def _new_packet_rule() -> tuple[str, str]:
    checksum = _PACKET_BYTE_RULES[NEW_PACKET]
    raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(raw) == checksum, "packet YAML drift: " + NEW_PACKET)
    return checksum, digest(canonical(safe_load(raw)))


_NEW_PACKET_RULE = _new_packet_rule()


@lru_cache(maxsize=1)
def _packet_rules_for(source_root: Path, authority_sha: str) -> MappingProxyType:
    """Freeze expected payload digests once per exact source-root/authority pin."""
    require(source_root == ROOT and authority_sha == AUTHORITY_SHA256,
            "packet source identity changed")
    _checked_authority_raw()
    own_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(own_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    rules = {NEW_PACKET: _NEW_PACKET_RULE}
    for name, checksum in _PACKET_BYTE_RULES.items():
        if name == NEW_PACKET:
            continue
        raw = regular_bytes("task-packets/" + name + ".yaml")
        require(digest(raw) == checksum, "packet YAML drift: " + name)
        rules[name] = (checksum, digest(canonical(safe_load(raw))))
    return MappingProxyType(rules)


def _packet_rules() -> MappingProxyType:
    return _packet_rules_for(ROOT, AUTHORITY_SHA256)


# Only expected parsed-data digests are cached, never a validation verdict.
# Historical traversal checks just this layer's packet. Full payload validation
# hashes every supplied packet anew, and validate() rereads every on-disk YAML.


def _inverse(raw: bytes, hunks: tuple[tuple[int, bytes, bytes], ...]) -> bytes:
    cursor, chunks = 0, []
    for at, removed, inserted in hunks:
        require(type(at) is int and cursor <= at and at + len(removed) <= len(raw),
                "inverse hunk bounds")
        require(raw[at:at + len(removed)] == removed, "inverse hunk current bytes")
        chunks.extend((raw[cursor:at], inserted))
        cursor = at + len(removed)
    chunks.append(raw[cursor:])
    before = b"".join(chunks)
    require(len(before) <= MAX_FILE_BYTES, "bounded predecessor bytes")
    return before


def historical_bytes(path: str, raw: bytes) -> bytes:
    """Recheck the pinned authority and undo only this reviewed successor."""
    _checked_authority_raw()
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
    return _undo_this_layer(path, raw)


def _undo_this_layer(path: str, raw: bytes) -> bytes:
    """Apply only this layer's reviewed inverse; callers have already rechecked authorities."""
    rule = _PROJECTION_RULES.get(path)
    if rule is None:
        return raw
    current_sha = digest(raw)
    require(current_sha in (rule["beforeSha256"], rule["afterSha256"]),
            "unreviewed current source: " + path)
    if current_sha == rule["beforeSha256"]:
        return raw
    before = _inverse(raw, rule["reverseHunks"])
    require(digest(before) == rule["beforeSha256"], "predecessor bytes: " + path)
    return before


def historical_test_bytes(raw: bytes) -> bytes:
    _checked_authority_raw()
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    _checked_authority_raw()
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        return before
    current = regular_bytes(matches[0])
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return current


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Remove only this layer, leaving predecessor checks to their owners."""
    _checked_authority_raw()
    require(type(packets) is dict, "packet mapping")
    current_ids = set(_PACKET_BYTE_RULES)
    require(NEW_PACKET in current_ids and set(packets) == current_ids,
            "unexpected packet addition or loss")
    packet_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(packet_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    try:
        supplied_sha = digest(canonical(packets[NEW_PACKET]))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("changed packet payload: " + NEW_PACKET) from exc
    require(supplied_sha == _NEW_PACKET_RULE[1],
            "changed packet payload: " + NEW_PACKET)
    return {name: packets[name] for name in current_ids - {NEW_PACKET}}


def validate_packet_payloads(packets: dict[str, Any]) -> None:
    """Check all current payloads separately from the inherited traversal."""
    record = authority()
    rules = _packet_rules()
    require(type(packets) is dict, "packet mapping")
    old = set(record["baselinePackets"])
    require(set(packets) == old | {NEW_PACKET}, "unexpected packet addition or loss")
    require(set(rules) == old | {NEW_PACKET}
            and all(rules[name][0] == expected
                    for name, expected in record["baselinePackets"].items())
            and rules[NEW_PACKET][0] == record["packetSha256"],
            "pinned packet data inventory")
    for name, (_byte_sha, payload_sha) in rules.items():
        try:
            supplied_sha = digest(canonical(packets[name]))
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("changed packet payload: " + name) from exc
        require(supplied_sha == payload_sha, "changed packet payload: " + name)


# MET-PERF-032 changes four test or validation paths so that required verify does less repeated work.
# Each check reads this packet's reviewed bytes, so a later bridged successor projects its own edits away first.
ROUTE_TEST = "test_newest_authority_is_freshly_checked_on_every_route"
# Cheap reads shared by several routes and by later setup lines; every other setup value is route-local.
ROUTE_SHARED = frozenset({"path", "raw", "master_raw"})
ROUTE_TEST_PATHS = tuple("tests/test_%s.py" % name for name in (
    "dedicated_verifier_account", "host_interface_resolution", "i05_gate_channel", "i06_backend_profile",
    "i07_policy_write", "in_session_predecessor_proof", "isolated_network_canary", "isolated_offline_runner",
    "linear_history_rechecks", "linux_runner_contract", "native_profile_v2", "owner_verifier",
    "portable_warm_snapshot_temp", "projection_reuse", "sector_direction", "selinux_matrix", "verify_headroom"))
STATUS_TEST_PATH = "tests/test_native_profile_v2.py"
STATUS_VALIDATOR_PATH = "scripts/validate_native_profile_v2.py"
LIFECYCLE_TEST_PATH = "tests/test_credential_lifecycle.py"
READINESS_PATH = "scripts/validate_readiness.py"
UNIQUE_PATH = "scripts/schema_unique.py"
STATUS_TEST = '''def test_contract_status_cannot_overclaim(monkeypatch, change):
    # The vector replay reads no status bytes; test_every_vector_replays_to_its_pinned_result
    # runs it and the full validator unstubbed. Under the same stub the unchanged status passes,
    # so the refusal below comes from the changed status alone.
    replays = []
    monkeypatch.setattr(profile, "validate_vectors", lambda *args: replays.append(args))
    assert profile.validate_native_profile() is None and len(replays) == 1
    _status_reader(monkeypatch, change)
    with pytest.raises(ValueError):
        profile.validate_native_profile()'''
FULL_REPLAY_TEST = '''def test_every_vector_replays_to_its_pinned_result():
    schema, vectors, v1_schema, v1_vectors = _contract()
    checks = profile.validate_vectors(schema, vectors, v1_schema, v1_vectors)
    assert checks == 4 + sum(len(vectors[key]) for key in ("negative", "accepted", "crossVersion", "migration"))
    assert profile.validate_native_profile() is None'''
PROJECTED_INPUTS = '''def projected_inputs(inputs):
    """Project each exact input set once per module for the inventory builder.

    The key is every (path, bytes) pair, so any new or changed input set reaches the real
    projection. Bytes are immutable and each caller gets its own mapping. This only prepares
    arguments for validate_inventory; validate_credential_lifecycle still projects afresh.
    """
    from scripts.validate_credential_ordering import historical_bytes
    key = tuple(sorted(inputs.items()))
    if key not in _PROJECTED:
        _PROJECTED[key] = {path: historical_bytes(path, raw) for path, raw in inputs.items()}
    return dict(_PROJECTED[key])'''
# A fixed corpus: hand-picked cases where jsonschema's equality differs from Python's, then seeded random arrays.
UNIQUE_EDGE_CASES = ([1, True], [0, False], [1, 1.0], [[1], [True]], [{"a": 1}, {"a": True}], [{"a": 1}, {"a": 1.0}],
                     [{"a": [1, {"b": None}]}, {"a": [1, {"b": None}]}], [{1: "x"}, {True: "x"}], [{"a": 1}, [1]],
                     [{}, []], [{"a": 1, "b": 2}, {"b": 2, "a": 1}], [None, {"a": None}, None], [{"a": "1"}, {"a": 1}],
                     [float("inf"), {"a": 1}, float("inf")], [[{"a": 1}], [{"a": 1}]], [{"a": 0}, {"a": False}])
UNIQUE_SEED = 20261007
UNIQUE_CASES = 4000


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _function(tree: ast.Module, name: str, path: str) -> ast.FunctionDef:
    found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    require(len(found) == 1, "one %s in %s" % (name, path))
    return found[0]


def _names(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _selected_routes(test: ast.expr) -> set[str] | None:
    """`route == "a"` or `route in ("a", "b", ...)`, else None."""
    if not (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "route"
            and len(test.ops) == 1):
        return None
    right = test.comparators[0]
    if isinstance(test.ops[0], ast.Eq) and isinstance(right, ast.Constant) and type(right.value) is str:
        return {right.value}
    if (isinstance(test.ops[0], ast.In) and isinstance(right, ast.Tuple) and len(right.elts) >= 2
            and all(isinstance(item, ast.Constant) and type(item.value) is str for item in right.elts)
            and len({item.value for item in right.elts}) == len(right.elts)):
        return {item.value for item in right.elts}
    return None


def validate_route_locality(path: str, source: bytes) -> int:
    """Each parametrized route computes exactly the setup values its own call reads, before the authority changes."""
    function = _function(ast.parse(source), ROUTE_TEST, path)
    marks = [node for node in function.decorator_list if isinstance(node, ast.Call)
             and ast.unparse(node.func) == "pytest.mark.parametrize" and len(node.args) == 2]
    require(len(marks) == 1 and isinstance(marks[0].args[1], ast.List)
            and all(isinstance(item, ast.Constant) and type(item.value) is str for item in marks[0].args[1].elts),
            "closed route parameters: " + path)
    routes = [item.value for item in marks[0].args[1].elts]
    tables = [index for index, node in enumerate(function.body) if isinstance(node, ast.Assign)
              and [ast.unparse(target) for target in node.targets] == ["calls"] and isinstance(node.value, ast.Dict)]
    require(len(tables) == 1, "one route table: " + path)
    table = function.body[tables[0]].value
    require(all(isinstance(key, ast.Constant) and type(key.value) is str for key in table.keys)
            and [key.value for key in table.keys] == routes, "route table matches the parameters: " + path)
    calls = {key.value: value for key, value in zip(table.keys, table.values)}
    setup, rest = function.body[:tables[0]], function.body[tables[0] + 1:]
    local = 0
    for index, statement in enumerate(setup):
        require(isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name), "route setup holds only assignments: " + path)
        name = statement.targets[0].id
        if name in ROUTE_SHARED:
            continue
        readers = {route for route, call in calls.items() if name in _names(call)}
        value = statement.value
        require(isinstance(value, ast.IfExp) and isinstance(value.orelse, ast.Constant) and value.orelse.value is None
                and readers and _selected_routes(value.test) == readers
                and not any(name in _names(later) for later in setup[index + 1:] + rest),
                "route-local setup %s: %s" % (name, path))
        local += 1
    require(local >= 6, "route setup is route-local: " + path)
    return local


def _segment(source: bytes, name: str, path: str) -> str:
    text = source.decode("utf-8")
    return ast.get_source_segment(text, _function(ast.parse(text), name, path))


def validate_status_stub(test_source: bytes, validator_source: bytes) -> None:
    """Status mutations stub only the vector replay, after a positive control; the replay stays fully tested."""
    require(_segment(test_source, "test_contract_status_cannot_overclaim", STATUS_TEST_PATH) == STATUS_TEST
            and _segment(test_source, "test_every_vector_replays_to_its_pinned_result", STATUS_TEST_PATH)
            == FULL_REPLAY_TEST, "status mutations stub only the vector replay")
    tree = ast.parse(validator_source)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    reached, pending = set(), ["validate_vectors"]
    while pending:
        name = pending.pop()
        if name in reached or name not in functions:
            continue
        reached.add(name)
        pending.extend(_names(functions[name]) & set(functions))
    used = set().union(*(_names(functions[name]) for name in reached))
    require("validate_vectors" in reached and not used & {"STATUS_PATH", "regular_bytes", "_json_file", "open"},
            "the stubbed vector replay reads no status bytes")
    caller = functions["validate_native_profile"]
    require(sum(isinstance(node, ast.Call) and ast.unparse(node.func) == "validate_vectors"
                for node in ast.walk(caller)) == 1, "the full validator replays the vectors once")


def validate_inventory_projection(source: bytes) -> None:
    """The inventory builder projects each exact input set once per module and hands out copies."""
    text = source.decode("utf-8")
    inventory = _segment(source, "inventory", LIFECYCLE_TEST_PATH)
    require(_segment(source, "projected_inputs", LIFECYCLE_TEST_PATH) == PROJECTED_INPUTS
            and text.count("\n_PROJECTED = {}\n") == 1 and text.count("_PROJECTED") == 4
            and "    inputs = projected_inputs(inputs)\n" in inventory and "historical_bytes" not in inventory,
            "the inventory builder shares only exact projections")


def _unique_corpus() -> list[list]:
    import random
    rng = random.Random(UNIQUE_SEED)
    atoms = [0, 1, 1.0, 2, -0.0, 0.5, 10 ** 30, True, False, None, "", "a", "b", "1", "true"]

    def value(depth: int) -> Any:
        roll = rng.random()
        if depth > 2 or roll < 0.4:
            return rng.choice(atoms)
        if roll < 0.65:
            return [value(depth + 1) for _ in range(rng.randint(0, 3))]
        return {rng.choice(("a", "b", "c", 1, True)): value(depth + 1) for _ in range(rng.randint(0, 3))}

    corpus = [list(case) for case in UNIQUE_EDGE_CASES]
    for _ in range(UNIQUE_CASES):
        pool = [value(0) for _ in range(rng.randint(1, 3))]
        corpus.append([json.loads(json.dumps(rng.choice(pool))) if rng.random() < 0.5 else value(0)
                       for _ in range(rng.randint(0, 6))])
    return corpus


def validate_schema_unique(readiness_source: bytes) -> int:
    """validate_schema_instance uses SchemaInstanceValidator, which differs from Draft 2020-12 only in
    uniqueItems and gives jsonschema's own answer on every corpus array."""
    from importlib.metadata import version
    import jsonschema
    from jsonschema import _utils
    try:
        import schema_unique
    except ImportError:
        from scripts import schema_unique
    function = _function(ast.parse(readiness_source), "validate_schema_instance", READINESS_PATH)
    built = [ast.unparse(node.func) for node in ast.walk(function) if isinstance(node, ast.Call)
             and ast.unparse(node.func).endswith("Validator")]
    require(built == ["SchemaInstanceValidator"]
            and readiness_source.count(b"    from schema_unique import SchemaInstanceValidator\n") == 1,
            "readiness schema instances use SchemaInstanceValidator")
    base, fast = jsonschema.Draft202012Validator, schema_unique.SchemaInstanceValidator
    require(version("jsonschema") == schema_unique.JSONSCHEMA_VERSION == "4.24.0"
            and fast.META_SCHEMA == base.META_SCHEMA and fast.TYPE_CHECKER is base.TYPE_CHECKER
            and set(fast.VALIDATORS) == set(base.VALIDATORS)
            and {key for key in base.VALIDATORS if fast.VALIDATORS[key] is not base.VALIDATORS[key]} == {"uniqueItems"}
            and fast.VALIDATORS["uniqueItems"] is schema_unique.unique_items, "only uniqueItems differs")
    corpus, unsortable, duplicated = _unique_corpus(), 0, 0
    for container in corpus:
        expected = _utils.uniq(container)
        require(schema_unique.unique(container) is expected, "uniqueItems answer differs: " + repr(container))
        try:
            sorted(_utils.unbool(item) for item in container)
        except TypeError:
            unsortable += 1
            duplicated += not expected
    require(unsortable >= 1000 and duplicated >= 100, "the corpus reaches the grouped comparison")
    return len(corpus)


def validate_verify_headroom() -> None:
    for path in ROUTE_TEST_PATHS:
        validate_route_locality(path, reviewed_bytes(path))
    validate_status_stub(reviewed_bytes(STATUS_TEST_PATH), reviewed_bytes(STATUS_VALIDATOR_PATH))
    validate_inventory_projection(reviewed_bytes(LIFECYCLE_TEST_PATH))
    validate_schema_unique(reviewed_bytes(READINESS_PATH))


def validate() -> None:
    record = authority()
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "verify headroom validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 208 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 208-packet catalog")
    packets = {}
    for path in paths:
        raw = regular_bytes("task-packets/" + path.name)
        expected = record["packetSha256"] if path.stem == NEW_PACKET else record["baselinePackets"][path.stem]
        require(digest(raw) == expected, "packet YAML drift: " + path.stem)
        packets[path.stem] = safe_load(raw)
    validate_packet_payloads(packets)
    packet = packets[NEW_PACKET]
    previous = packets[PREVIOUS_PACKET]
    commands = packet["offlineAcceptanceCommands"]
    require(packet["id"] == NEW_PACKET and packet["repository"] == "Harness-Engineering"
            and packet["predecessors"] == [PREVIOUS_PACKET]
            and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
            and packet["sourceReuse"] == packet["prefetchCommands"] == []
            and packet["offlineExecution"] == previous["offlineExecution"]
            and "liveCampaignExecution" not in packet
            and len(commands) == 64
            and commands == previous["offlineAcceptanceCommands"]
            and not any(VALIDATOR_PATH in argv for argv in commands),
            "closed source-only verify-headroom packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted verify-headroom packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_verify_headroom()


if __name__ == "__main__":
    validate()
    print("Verify headroom valid: 208 current specifications; exact 207-packet predecessor; route-local setup, stubbed status replay, shared inventory projection and grouped uniqueItems checked.")
