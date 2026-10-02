"""Recipe decoding parity only; never stored-code execution or acceptance reuse."""
import ast
from copy import deepcopy
import importlib
import json
import os
from pathlib import Path
import sys

import pytest

from scripts import validate_conformance_reference_measurement as reference
from scripts import validate_document_repair_plan as plan
from scripts import validate_packet_schema_performance as history

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=[reference, plan], ids=["reference", "plan"])
def sample(request):
    module = request.param
    decoder = module._decode_source_projection
    decoder.cache_clear()
    raw = module.regular_bytes(module.ROOT, module.RECORD_PATH)
    record = module.parse(raw)
    try:
        yield module, raw, record
    finally:
        # Capture the actual cache, even if a test replaces the module attribute.
        decoder.cache_clear()


def outcome(call):
    try:
        return ("return", call())
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        return (type(exc), exc.args)


def projection(record):
    return {key: record[key] for key in ("metaRecipes", "unchangedTests")}


def test_cold_warm_projection_reuses_only_decoding_with_fresh_full_reads(sample, monkeypatch):
    module, raw, record = sample
    read, digest, parse = module.regular_bytes, module.digest, module.parse
    reads, hashes, parses = [], [], []

    def observed_read(root, path):
        reads.append((root, path))
        return read(root, path)

    def observed_digest(value):
        hashes.append(value)
        return digest(value)

    def observed_parse(value):
        parses.append(value)
        return parse(value)

    monkeypatch.setattr(module, "regular_bytes", observed_read)
    monkeypatch.setattr(module, "digest", observed_digest)
    monkeypatch.setattr(module, "parse", observed_parse)
    first, second = module._source_projection(), module._source_projection()
    assert first == second == projection(record)
    assert reads == [(module.ROOT, module.RECORD_PATH)] * 2
    assert hashes == [raw] * 3 and parses == [raw]
    assert first is not second
    assert list(first["metaRecipes"]) == list(record["metaRecipes"])
    assert list(first["unchangedTests"].items()) == list(record["unchangedTests"].items())
    assert module._decode_source_projection.cache_info().hits == 1


def test_full_record_reader_remains_fresh_and_uncached(sample, monkeypatch):
    module, raw, record = sample
    parse, calls = module.parse, []

    def observed(value):
        calls.append(value)
        return parse(value)

    monkeypatch.setattr(module, "parse", observed)
    first, second = module._record(), module._record()
    assert first == second == record and first is not second
    assert calls == [raw, raw]
    assert module._decode_source_projection.cache_info().currsize == 0


def test_projection_has_no_shared_mutable_descendants(sample):
    module, raw, record = sample
    result = module._source_projection()
    route = next(path for path, rule in result["metaRecipes"].items() if rule["replacements"])
    result["metaRecipes"][route]["beforeSha256"] = "changed"
    result["metaRecipes"][route]["replacements"][0]["before"] = "changed"
    result["metaRecipes"][route]["replacements"].append({"new": True})
    result["metaRecipes"]["unowned"] = {}
    result["unchangedTests"].clear()
    assert module._source_projection() == projection(record)

    def immutable(value):
        assert type(value) in (tuple, str, int)
        if type(value) is tuple:
            for child in value:
                immutable(child)

    immutable(module._decode_source_projection(raw))


@pytest.mark.parametrize("fault", ["content", "missing", "symlink", "hardlink", "ancestor", "directory"])
def test_warm_projection_never_hides_filesystem_drift(sample, monkeypatch, tmp_path, fault):
    module, raw, _ = sample
    root = tmp_path / "checkout"
    target = root / module.RECORD_PATH
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    monkeypatch.setattr(module, "ROOT", root)
    module._source_projection()
    if fault == "content":
        target.write_bytes(raw + b" ")
    elif fault == "missing":
        target.unlink()
    elif fault == "symlink":
        other = tmp_path / "authority"
        other.write_bytes(raw)
        target.unlink()
        target.symlink_to(other)
    elif fault == "hardlink":
        os.link(target, tmp_path / "alias")
    elif fault == "ancestor":
        previous = tmp_path / "moved"
        target.parent.rename(previous)
        target.parent.symlink_to(previous, target_is_directory=True)
    else:
        target.unlink()
        target.mkdir()
    with pytest.raises((OSError, ValueError)):
        module._source_projection()


def test_current_pin_is_checked_before_any_warm_lookup(sample, monkeypatch):
    module, _, _ = sample
    module._source_projection()
    monkeypatch.setattr(module, "RECORD_FILE_SHA256", "0" * 64)

    def unexpected(_):
        raise AssertionError("lookup before fresh authority check")

    monkeypatch.setattr(module, "_decode_source_projection", unexpected)
    monkeypatch.setattr(module, "parse", unexpected)
    with pytest.raises(ValueError, match="exact fresh authority bytes"):
        module._source_projection()


@pytest.mark.parametrize("raw", [b"{}", b"[]", b"null", b"{", b'{"x":1,"x":2}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b"\xff", b'"text"',
    b'{"metaRecipes":{},"unchangedTests":{}}'])
def test_noneligible_current_pin_keeps_full_strict_parser_semantics(sample, monkeypatch, raw):
    module, _, _ = sample
    monkeypatch.setattr(module, "regular_bytes", lambda root, path: raw)
    monkeypatch.setattr(module, "RECORD_FILE_SHA256", module.digest(raw))
    assert outcome(module._source_projection) == outcome(module._record)
    assert module._decode_source_projection.cache_info().currsize == 0


def test_reformatted_current_pin_uses_original_full_record_path(sample, monkeypatch):
    module, raw, record = sample
    module._source_projection()
    changed = raw + b"\n "
    monkeypatch.setattr(module, "regular_bytes", lambda root, path: changed)
    monkeypatch.setattr(module, "RECORD_FILE_SHA256", module.digest(changed))
    parse, calls = module.parse, []

    def observed(value):
        calls.append(value)
        return parse(value)

    monkeypatch.setattr(module, "parse", observed)
    assert module._source_projection() == record
    assert calls == [changed]
    assert module._decode_source_projection.cache_info().hits == 0


@pytest.mark.parametrize("fault", ["short", "same-size", "str", "bytearray", "list", "none"])
def test_private_decoder_admission_is_single_exact_blob_and_not_failure_cache(sample, fault):
    module, raw, _ = sample
    module._source_projection()
    bad = {"short": raw[:-1], "same-size": b"X" + raw[1:], "str": raw.decode(),
           "bytearray": bytearray(raw), "list": [raw], "none": None}[fault]
    with pytest.raises((ValueError, TypeError)):
        module._decode_source_projection(bad)
    info = module._decode_source_projection.cache_info()
    assert info.maxsize == info.currsize == 1
    assert module._decode_source_projection.cache_parameters() == {"maxsize": 1, "typed": False}


@pytest.mark.parametrize("fault", ["recipe-count", "unchanged-count", "rule-extra", "before-mutable",
    "rows-tuple", "row-extra", "row-mutable", "count-bool", "count-zero", "unchanged-mutable"])
def test_decoder_never_retains_malformed_or_mutable_projection(sample, monkeypatch, fault):
    module, raw, record = sample
    bad = deepcopy(record)
    route = next(path for path, rule in bad["metaRecipes"].items() if rule["replacements"])
    rule = bad["metaRecipes"][route]
    if fault == "recipe-count": del bad["metaRecipes"][route]
    if fault == "unchanged-count": bad["unchangedTests"].clear()
    if fault == "rule-extra": rule["extra"] = True
    if fault == "before-mutable": rule["beforeSha256"] = []
    if fault == "rows-tuple": rule["replacements"] = tuple(rule["replacements"])
    if fault == "row-extra": rule["replacements"][0]["extra"] = True
    if fault == "row-mutable": rule["replacements"][0]["before"] = []
    if fault == "count-bool": rule["replacements"][0]["count"] = True
    if fault == "count-zero": rule["replacements"][0]["count"] = 0
    if fault == "unchanged-mutable": bad["unchangedTests"][next(iter(bad["unchangedTests"]))] = []
    monkeypatch.setattr(module, "parse", lambda value: bad)
    with pytest.raises(ValueError): module._decode_source_projection(raw)
    assert module._decode_source_projection.cache_info().currsize == 0


def test_replaced_reader_is_called_once_without_extra_observation(sample, monkeypatch):
    module, _, _ = sample
    supplied, calls = object(), []

    def reader():
        calls.append("reader")
        return supplied

    def unexpected(*args):
        raise AssertionError("extra read/parse before overridden reader")

    monkeypatch.setattr(module, "_record", reader)
    monkeypatch.setattr(module, "regular_bytes", unexpected)
    monkeypatch.setattr(module, "parse", unexpected)
    assert module._source_projection() is supplied and calls == ["reader"]


def test_wrapped_reader_keeps_observability_and_exact_exception(sample, monkeypatch):
    module, _, record = sample
    original, calls = module._record, []

    def reader():
        calls.append("wrapped")
        return original()

    monkeypatch.setattr(module, "_record", reader)
    assert module._source_projection() == record and calls == ["wrapped"]
    error = OSError("unit reader unavailable")

    def failed():
        calls.append("failed")
        raise error

    monkeypatch.setattr(module, "_record", failed)
    with pytest.raises(OSError) as caught: module._source_projection()
    assert caught.value is error and calls == ["wrapped", "failed"]


def test_duplicate_predecessor_matches_are_not_collapsed(sample, monkeypatch):
    module, _, record = sample
    bad = deepcopy(record)
    route = next(path for path in bad["metaRecipes"] if path.startswith("tests/"))
    before = b"unit immutable source\n"
    bad["metaRecipes"][route]["beforeSha256"] = module.digest(before)
    bad["metaRecipes"]["tests/duplicate.py"] = deepcopy(bad["metaRecipes"][route])
    monkeypatch.setattr(module, "_record", lambda: bad)
    with pytest.raises(ValueError, match="unique predecessor"):
        module.current_test_bytes(before)


def test_immutable_projection_retains_distinct_paths_with_the_same_predecessor(sample, monkeypatch):
    module, _, record = sample
    supplied = deepcopy(record)
    first, second = [path for path in supplied["metaRecipes"] if path.startswith("tests/")][:2]
    before = b"unit duplicate predecessor\n"
    supplied["metaRecipes"][first]["beforeSha256"] = module.digest(before)
    supplied["metaRecipes"][second]["beforeSha256"] = module.digest(before)
    monkeypatch.setattr(module, "parse", lambda raw: supplied)
    projected = module._source_projection()
    matches = [path for path, rule in projected["metaRecipes"].items()
               if path.startswith("tests/") and rule["beforeSha256"] == module.digest(before)]
    assert matches == [first, second]
    with pytest.raises(ValueError, match="unique predecessor"):
        module.current_test_bytes(before)


@pytest.mark.parametrize("fault", ["after-digest", "cardinality", "forward-digest"])
def test_historical_recipe_integrity_remains_enforced_after_projection(sample, monkeypatch, fault):
    module, _, _ = sample
    before, after = b"old\n", b"new\n"
    rule = {"beforeSha256": module.digest(before), "afterSha256": module.digest(after),
            "replacements": [{"before": "old", "after": "new", "count": 1}]}
    if fault == "after-digest": rule["afterSha256"] = "0" * 64
    if fault == "cardinality": rule["replacements"][0]["count"] = 2
    if fault == "forward-digest": rule["beforeSha256"] = "0" * 64
    path = "tests/unit.py"
    monkeypatch.setattr(module, "HISTORY_PATHS", frozenset([path]))
    monkeypatch.setattr(module, "_record", lambda: {"metaRecipes": {path: rule}})
    downstream = ["checkpoint_history"] if module is reference else ["runner_history", "execution_history"]
    for name in downstream: monkeypatch.setattr(module, name, lambda path, raw: raw)
    with pytest.raises(ValueError): module.historical_bytes(path, after)


def test_predecessor_error_still_precedes_local_observation_and_unrouted_identity(sample, monkeypatch):
    module, _, _ = sample
    calls, failure = [], ValueError("unit predecessor refusal")

    def first(path, raw):
        calls.append("predecessor")
        raise failure

    def local(*args):
        raise AssertionError("local observation before predecessor")

    first_name = "checkpoint_history" if module is reference else "runner_history"
    monkeypatch.setattr(module, first_name, first)
    monkeypatch.setattr(module, "_record", local)
    with pytest.raises(ValueError) as caught: module.historical_bytes("unchanged.txt", b"untrusted")
    assert caught.value is failure and calls == ["predecessor"]
    downstream = ["checkpoint_history"] if module is reference else ["runner_history", "execution_history"]
    for name in downstream: monkeypatch.setattr(module, name, lambda path, raw: raw)
    assert module.historical_bytes("unchanged.txt", b"untrusted") == b"untrusted"


@pytest.mark.parametrize("style", ["package", "direct"])
def test_both_import_modes_have_identical_projection_and_isolated_cache(sample, monkeypatch, style):
    original, raw, record = sample
    stem = original.__name__.rsplit(".", 1)[-1]
    if style == "package":
        assert original._source_projection() == projection(record)
        return
    existing = set(sys.modules)
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = None
    try:
        monkeypatch.delitem(sys.modules, stem, raising=False)
        module = importlib.import_module(stem)
        assert module._decode_source_projection is not original._decode_source_projection
        assert module._SOURCE_RECORD_READER is module._record
        assert module._source_projection() == projection(record)
        assert module._decode_source_projection.cache_info().currsize == 1
        assert original._decode_source_projection.cache_info().currsize == 0
    finally:
        if module is not None: module._decode_source_projection.cache_clear()
        for name in set(sys.modules) - existing:
            source = getattr(sys.modules[name], "__file__", None)
            if type(source) is str and source.startswith(str(ROOT / "scripts") + os.sep):
                sys.modules.pop(name, None)


def test_only_declared_recipe_call_sites_change_and_readers_remain_identical(sample):
    module, _, _ = sample
    path = "scripts/" + Path(module.__file__).name
    raw = (ROOT / path).read_bytes()
    current, accepted = ast.parse(raw), ast.parse(history.historical_bytes(path, raw))
    names = {"_record", "parse", "pinned", "regular_bytes", "apply_recipe", "historical_bytes", "current_test_bytes"}

    def definitions(tree, normalize=False):
        result = {}
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or node.name not in names: continue
            if normalize and node.name in {"historical_bytes", "current_test_bytes"}:
                count = 0
                for item in ast.walk(node):
                    if isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id == "_source_projection":
                        assert not item.args and not item.keywords
                        item.func.id = "_record"
                        count += 1
                assert count == 1
            result[node.name] = ast.dump(node, include_attributes=False)
        return result

    assert set(definitions(accepted)) == names
    assert definitions(current, True) == definitions(accepted)
    cache_functions = [node.name for node in current.body if isinstance(node, ast.FunctionDef)
        and any(isinstance(row, ast.Call) and isinstance(row.func, ast.Name) and row.func.id == "lru_cache"
                for row in node.decorator_list)]
    assert cache_functions == ["_decode_source_projection"]
    assert "fixed within a process" in module._decode_source_projection.__doc__


def test_failed026_and_nine_consumed_attempts_are_not_execution_authority():
    record = json.loads((ROOT / "architecture/packet-schema-performance-inputs/prior-026-terminal.json").read_bytes())
    assert record["packetId"] == "MET-PERF-026"
    assert record["status"] == "RETAINED_FAILURE_NOT_ACCEPTED_PREDECESSOR"
    attempt = record["separateLocalException"]
    assert (attempt["maximum"], attempt["consumed"], attempt["cumulativeLineageOrdinal"]) == (1, 1, 9)
    assert attempt["timedOut"] is True and attempt["commandsStarted"] == 52 and attempt["commandsExpected"] == 53
    assert attempt["finalScanReached"] is False and attempt["cleanupIndependentlyConfirmed"] is True
    assert record["nestedSuite"]["commandsCompleted"] == record["nestedSuite"]["commandsExpected"] == 7
    assert record["nestedSuite"]["passed"] == 5128 and record["nestedSuite"]["skipped"] == 10
    assert record["outerSuite"]["observedPassedCallRecords"] == 4981
    assert record["outerSuite"]["observedFailedCallRecords"] == 0
    assert record["outerSuite"]["completeFinalPytestReportAvailable"] is False
    assert record["successorBoundary"]["newPacketId"] == "MET-PERF-027"
    assert record["successorBoundary"]["newExecutionGrants"] == 0
    assert record["successorBoundary"]["budgetReset"] is False
    assert record["diagnosis"]["speedupEstablished"] is False
