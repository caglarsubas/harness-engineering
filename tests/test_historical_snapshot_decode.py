"""One immutable decoding projection; no benchmark, cached verdict or live I/O."""
import ast
from copy import deepcopy
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import sys

import pytest

from scripts import validate_credential_ordering as ordering
from scripts import validate_packet_schema_performance as history


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "scripts/validate_credential_ordering.py"
SNAPSHOT_SHA = "5aed1292ff416c92a363ff34e0d570a152fb8029048701bd8b3fe77c69a486ff"


@pytest.fixture(autouse=True)
def isolated_decode_cache():
    # Capture the real function, not any later monkeypatched decoder.
    helper = ordering._decode_before_snapshot
    helper.cache_clear()
    yield
    helper.cache_clear()


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
    raw = (ROOT / ordering.BEFORE_PATH).read_bytes()
    assert len(raw) == 290177 and sha256(raw).hexdigest() == SNAPSHOT_SHA
    expected = ordering.parse(raw)
    destination = tmp_path / ordering.BEFORE_PATH
    destination.parent.mkdir(parents=True)
    destination.write_bytes(raw)
    monkeypatch.setattr(ordering, "ROOT", tmp_path)
    record = {"inputFiles": {ordering.BEFORE_PATH: SNAPSHOT_SHA},
              "metaBaseline": expected["baseCommit"]}
    return record, raw, expected, destination


def _original_before(record):
    """Literal old read/hash/parse/check sequence, not imported historic code."""
    raw = ordering.regular_bytes(ordering.ROOT, ordering.BEFORE_PATH)
    ordering.require(ordering.digest(raw) == record["inputFiles"][ordering.BEFORE_PATH],
                     "exact historical meta bytes required")
    before = ordering.parse(raw)
    ordering.require(before["baseCommit"] == record["metaBaseline"], "meta baseline differs")
    return before["files"]


def _outcome(function, record):
    try:
        return "return", function(record)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
        return "raise", type(error), error.args


def test_cold_and_warm_calls_reuse_only_decode_with_fresh_full_reads_and_hashes(snapshot, monkeypatch):
    record, raw, expected, _ = snapshot
    reads, hashes, parses = [], [], []
    real_read, real_digest, real_parse = ordering.regular_bytes, ordering.digest, ordering.parse

    def read(root, path):
        value = real_read(root, path)
        reads.append((path, len(value)))
        return value

    def digest(value):
        hashes.append(value)
        return real_digest(value)

    def parse(value):
        parses.append(value)
        return real_parse(value)

    monkeypatch.setattr(ordering, "regular_bytes", read)
    monkeypatch.setattr(ordering, "digest", digest)
    monkeypatch.setattr(ordering, "parse", parse)
    first = ordering._before(record)
    assert first == expected["files"] and parses == [raw]
    assert hashes == [raw, raw]  # Fresh caller pin then cold private admission.
    second = ordering._before(record)
    assert second == first and second is not first
    assert reads == [(ordering.BEFORE_PATH, len(raw))] * 2
    assert hashes == [raw] * 3 and parses == [raw]
    assert ordering._decode_before_snapshot.cache_info().hits == 1


@pytest.mark.parametrize("fault", ["wrong-pin", "missing-pins", "missing-pin", "wrong-baseline", "missing-baseline"])
def test_warm_decode_does_not_cache_current_record_acceptance(snapshot, fault):
    record, _, _, _ = snapshot
    ordering._before(record)
    changed = deepcopy(record)
    if fault == "wrong-pin":
        changed["inputFiles"][ordering.BEFORE_PATH] = "0" * 64
    elif fault == "missing-pins":
        del changed["inputFiles"]
    elif fault == "missing-pin":
        del changed["inputFiles"][ordering.BEFORE_PATH]
    elif fault == "wrong-baseline":
        changed["metaBaseline"] = "different"
    else:
        del changed["metaBaseline"]
    expected = _outcome(_original_before, changed)
    assert expected[0] == "raise"
    assert _outcome(ordering._before, changed) == expected


@pytest.mark.parametrize("fault", ["same-size-change", "deleted", "leaf-symlink", "leaf-hardlink", "ancestor-symlink"])
def test_warm_decode_never_hides_current_filesystem_drift(snapshot, fault):
    record, raw, _, path = snapshot
    ordering._before(record)
    if fault == "same-size-change":
        path.write_bytes(raw.replace(b'"baseCommit"', b'"baseCommiX"', 1))
    elif fault == "deleted":
        path.unlink()
    elif fault in {"leaf-symlink", "leaf-hardlink"}:
        target = path.with_name("retained.json")
        path.rename(target)
        if fault == "leaf-symlink":
            path.symlink_to(target)
        else:
            os.link(target, path)
    else:
        parent = path.parent
        moved = parent.with_name(parent.name + "-retained")
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
    with pytest.raises((ValueError, FileNotFoundError)):
        ordering._before(record)


def test_returned_map_mutation_cannot_contaminate_another_call(snapshot):
    record, raw, expected, _ = snapshot
    first = ordering._before(record)
    first.clear()
    first["invented"] = ["mutable caller data"]
    second = ordering._before(record)
    assert second == expected["files"] and second is not first
    baseline, entries = ordering._decode_before_snapshot(raw)
    assert type(baseline) is str and type(entries) is tuple and len(entries) == 23
    assert all(type(row) is tuple and len(row) == 2
               and all(type(item) is str for item in row) for row in entries)
    with pytest.raises(TypeError):
        entries[0][1] = "cannot mutate"


@pytest.mark.parametrize("raw", [b"", b"{}", b"x" * 290177, b"x" * 290178, "not-bytes", None, 12, bytearray(b"{}")],
                         ids=["empty", "small", "wrong-digest", "too-long", "text", "none", "integer", "mutable"])
def test_private_cache_admission_cannot_retain_other_or_unbounded_data(snapshot, raw):
    record, _, _, _ = snapshot
    ordering._before(record)
    with pytest.raises((ValueError, TypeError)):
        ordering._decode_before_snapshot(raw)
    info = ordering._decode_before_snapshot.cache_info()
    assert info.maxsize == 1 and info.currsize == 1


@pytest.mark.parametrize("fault", ["baseline-type", "files-type", "file-count", "value-type", "key-type"])
def test_mock_decoder_cannot_store_mutable_or_wrong_projection_shapes(snapshot, monkeypatch, fault):
    _, raw, expected, _ = snapshot
    decoded = deepcopy(expected)
    if fault == "baseline-type":
        decoded["baseCommit"] = []
    elif fault == "files-type":
        decoded["files"] = []
    elif fault == "file-count":
        decoded["files"].pop(next(iter(decoded["files"])))
    elif fault == "value-type":
        decoded["files"][next(iter(decoded["files"]))] = []
    else:
        first = next(iter(decoded["files"]))
        decoded["files"][12] = decoded["files"].pop(first)
    monkeypatch.setattr(ordering, "parse", lambda _raw: decoded)
    with pytest.raises(ValueError, match="immutable historical decode projection"):
        ordering._decode_before_snapshot(raw)
    assert ordering._decode_before_snapshot.cache_info().currsize == 0


@pytest.mark.parametrize("raw,baseline", [
    (b'{"baseCommit":"a","files":{"x":"value"}}', "a"),
    (b'{"baseCommit":"a","files":[1,2]}', "a"),
    (b'{"baseCommit":"a","files":null}', "a"),
    (b'{"baseCommit":12,"files":{}}', 12),
    (b'{"baseCommit":"wrong"}', "a"),
    (b'{"baseCommit":"a"}', "a"),
    (b'{"files":{}}', "a"),
    (b'{"baseCommit":"a","baseCommit":"a","files":{}}', "a"),
    (b'{"baseCommit":"a","files":NaN}', "a"),
    (b'{"baseCommit":"a","files":Infinity}', "a"),
    (b'{"baseCommit":"a","files":-Infinity}', "a"),
    (b'{', "a"), (b'[]', "a"), (b'null', "a"),
    (b'"scalar"', "a"), (b'\xff', "a"),
    (b' ' * 2097153, "a"), (bytearray(b'{}'), "a"),
    ("not-bytes", "a"), (None, "a"),
], ids=["object", "list-files", "null-files", "integer-baseline", "baseline-before-files",
        "missing-files", "missing-baseline", "duplicate", "nan", "infinity", "negative-infinity",
        "malformed", "array", "null", "scalar", "invalid-utf8", "oversized", "bytearray", "text", "none"])
def test_noneligible_data_keeps_original_parse_result_or_exact_exception(monkeypatch, raw, baseline):
    pin = sha256(raw).hexdigest() if isinstance(raw, (bytes, bytearray)) else "0" * 64
    record = {"inputFiles": {ordering.BEFORE_PATH: pin}, "metaBaseline": baseline}
    monkeypatch.setattr(ordering, "regular_bytes", lambda _root, _path: raw)
    expected = _outcome(_original_before, record)
    assert _outcome(ordering._before, record) == expected
    assert _outcome(ordering._before, record) == expected
    assert ordering._decode_before_snapshot.cache_info().currsize == 0


def test_equivalent_noneligible_snapshot_bytes_are_not_newly_rejected(snapshot, monkeypatch):
    record, raw, expected, path = snapshot
    alternate = raw + b"\n"
    path.write_bytes(alternate)
    record["inputFiles"][ordering.BEFORE_PATH] = sha256(alternate).hexdigest()
    real_parse, seen = ordering.parse, []

    def parse(value):
        seen.append(value)
        return real_parse(value)

    monkeypatch.setattr(ordering, "parse", parse)
    assert ordering._before(record) == ordering._before(record) == expected["files"]
    assert seen == [alternate, alternate]
    assert ordering._decode_before_snapshot.cache_info().currsize == 0


def test_combined_errors_keep_raw_pin_before_parser_and_baseline_before_files(monkeypatch):
    monkeypatch.setattr(ordering, "regular_bytes", lambda _root, _path: b"{")
    record = {"inputFiles": {ordering.BEFORE_PATH: "0" * 64}, "metaBaseline": "a"}
    real_parse = ordering.parse

    def unexpected(_raw):
        raise AssertionError("parser preceded raw pin refusal")

    monkeypatch.setattr(ordering, "parse", unexpected)
    with pytest.raises(ValueError, match="exact historical meta bytes required"):
        ordering._before(record)
    monkeypatch.setattr(ordering, "parse", real_parse)
    raw = b'{"baseCommit":"wrong"}'
    monkeypatch.setattr(ordering, "regular_bytes", lambda _root, _path: raw)
    record["inputFiles"][ordering.BEFORE_PATH] = sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="meta baseline differs"):
        ordering._before(record)


@pytest.mark.parametrize("module_name", ["scripts.validate_credential_ordering", "validate_credential_ordering"])
def test_direct_and_package_imports_keep_snapshot_parity_and_clear_new_aliases(monkeypatch, module_name):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    prior_names = set(sys.modules)
    helper = None
    try:
        module = importlib.import_module(module_name)
        helper = module._decode_before_snapshot
        helper.cache_clear()
        raw = (ROOT / module.BEFORE_PATH).read_bytes()
        expected = module.parse(raw)
        record = {"inputFiles": {module.BEFORE_PATH: SNAPSHOT_SHA},
                  "metaBaseline": expected["baseCommit"]}
        assert module._before(record) == module._before(record) == expected["files"]
        assert helper.cache_info().misses == 1 and helper.cache_info().hits == 1
    finally:
        if helper is not None:
            helper.cache_clear()
        for name in set(sys.modules) - prior_names:
            source = getattr(sys.modules[name], "__file__", None)
            if type(source) is str and source.startswith(str(ROOT / "scripts") + os.sep):
                sys.modules.pop(name, None)


def test_other_ordering_functions_keep_accepted_semantics_and_no_generic_parse_cache():
    raw = (ROOT / SOURCE).read_bytes()
    current = ast.parse(raw)
    accepted = ast.parse(history.historical_bytes(SOURCE, raw))
    names = {"pinned", "_record", "apply_recipe", "historical_bytes", "current_test_bytes",
             "validate_trace", "_test_ids", "validate_recipes", "load_ordering_inputs"}
    definitions = lambda tree: {node.name: ast.dump(node, include_attributes=False)
                               for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names}
    assert set(definitions(current)) == names
    assert definitions(current) == definitions(accepted)
    cached = [node.name for node in current.body if isinstance(node, ast.FunctionDef)
              and any(isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name)
                      and decorator.func.id == "lru_cache" for decorator in node.decorator_list)]
    assert cached == ["_decode_before_snapshot"]


def test_failed025_terminal_and_eight_consumed_attempts_remain_non_authorizing():
    record = json.loads((ROOT / "architecture/packet-schema-performance-inputs/prior-025-terminal.json").read_bytes())
    assert record["packetId"] == "MET-PERF-025"
    assert record["status"] == "RETAINED_FAILURE_NOT_ACCEPTED_PREDECESSOR"
    attempt = record["separateLocalException"]
    assert (attempt["maximum"], attempt["consumed"], attempt["cumulativeLineageOrdinal"]) == (1, 1, 8)
    assert attempt["commandsStarted"] == 52 and attempt["commandsExpected"] == 53
    assert attempt["timedOut"] is True and attempt["finalScanReached"] is False
    assert attempt["cleanupIndependentlyConfirmed"] is True
    assert record["nestedSuite"]["diagnosticsStatus"] == "INCOMPLETE"
    assert record["nestedSuite"]["commandsStarted"] == 1
    assert record["outerSuite"]["observedPassedCallRecords"] == 3134
    assert record["outerSuite"]["completeFinalPytestReportAvailable"] is False
    assert record["successorBoundary"]["newPacketId"] == "MET-PERF-026"
    assert record["successorBoundary"]["newExecutionGrants"] == 0
    assert record["successorBoundary"]["budgetReset"] is False
