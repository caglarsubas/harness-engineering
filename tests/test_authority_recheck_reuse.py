"""Exact-bytes authority recheck reuse and uniqueItems parity; no acceptance reuse."""
import importlib
import json
import math
import os
from pathlib import Path
import random
import sys

import jsonschema
from jsonschema._utils import uniq as pinned_uniq
import pytest

from scripts import validate_ci_runner_admission as runner
from scripts import validate_packet_schema_performance as performance
from scripts import validate_reuse as reuse
from scripts import validate_unified_roadmap as roadmap

ROOT = Path(__file__).resolve().parents[1]
MESSAGES = {
    performance: "schema performance history authority digest",
    runner: "CI runner history authority digest",
    roadmap: "unified authority digest",
}


@pytest.fixture(params=[performance, runner, roadmap], ids=["performance", "runner", "roadmap"])
def layer(request, monkeypatch):
    module = request.param
    # Start cold and restore the captured process state after each case.
    monkeypatch.setattr(module, "_VERIFIED_AUTHORITY", None)
    reads, digests = [], []
    original_read, original_digest = module.regular_bytes, module.digest

    def read(path):
        reads.append(path)
        return original_read(path)

    def digest(raw):
        digests.append(len(raw))
        return original_digest(raw)

    monkeypatch.setattr(module, "regular_bytes", read)
    monkeypatch.setattr(module, "digest", digest)
    return module, reads, digests, original_read


def test_every_call_freshly_reads_and_only_first_identical_read_is_hashed(layer):
    module, reads, digests, _ = layer
    first = module._checked_authority_raw()
    second = module._checked_authority_raw()
    assert first == second
    assert reads == [module.AUTHORITY_PATH, module.AUTHORITY_PATH]
    assert digests == [len(first)]
    assert module._VERIFIED_AUTHORITY == (module.AUTHORITY_SHA256, first)


def test_warm_byte_drift_is_hashed_and_refused_with_original_message(layer, monkeypatch):
    module, reads, digests, original_read = layer
    raw = module._checked_authority_raw()
    for changed in (raw + b"\n", raw[:-1], b" " + raw[1:], b""):
        monkeypatch.setattr(module, "regular_bytes", lambda path, changed=changed: changed)
        before = len(digests)
        with pytest.raises(ValueError, match=MESSAGES[module]):
            module._checked_authority_raw()
        assert len(digests) == before + 1
        assert module._VERIFIED_AUTHORITY == (module.AUTHORITY_SHA256, raw)
    monkeypatch.setattr(module, "regular_bytes", original_read)
    assert module._checked_authority_raw() == raw


def test_changed_pin_rehashes_identical_bytes_and_refuses(layer, monkeypatch):
    module, _, digests, _ = layer
    module._checked_authority_raw()
    monkeypatch.setattr(module, "AUTHORITY_SHA256", "0" * 64)
    with pytest.raises(ValueError, match=MESSAGES[module]):
        module._checked_authority_raw()
    assert len(digests) == 2


def test_non_bytes_reader_results_are_never_admitted_without_hashing(layer, monkeypatch):
    module, _, digests, original_read = layer
    raw = original_read(module.AUTHORITY_PATH)
    monkeypatch.setattr(module, "regular_bytes", lambda path: bytearray(raw))
    assert module._checked_authority_raw() == raw
    assert module._checked_authority_raw() == raw
    assert len(digests) == 2 and module._VERIFIED_AUTHORITY is None
    monkeypatch.setattr(module, "regular_bytes", lambda path: raw.decode())
    with pytest.raises(TypeError):
        module._checked_authority_raw()


def test_history_routes_still_refuse_second_call_authority_drift(monkeypatch):
    original_read = performance.regular_bytes
    raw = original_read(performance.AUTHORITY_PATH)
    path = next(p for p in performance._PROJECTION_RULES)
    current = original_read(path)
    assert performance.historical_bytes(path, current)
    monkeypatch.setattr(performance, "regular_bytes",
                        lambda name: raw + b" " if name == performance.AUTHORITY_PATH else original_read(name))
    with pytest.raises(ValueError, match=MESSAGES[performance]):
        performance.historical_bytes(path, current)
    with pytest.raises(ValueError, match=MESSAGES[performance]):
        runner.historical_bytes(path, current)


@pytest.mark.parametrize("stem", ["validate_packet_schema_performance", "validate_ci_runner_admission",
                                  "validate_unified_roadmap"])
def test_direct_script_import_has_isolated_verified_state(monkeypatch, stem):
    package = importlib.import_module("scripts." + stem)
    existing = set(sys.modules)
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    try:
        monkeypatch.delitem(sys.modules, stem, raising=False)
        module = importlib.import_module(stem)
        assert module is not package
        monkeypatch.setattr(module, "_VERIFIED_AUTHORITY", None)
        raw = module._checked_authority_raw()
        assert module._VERIFIED_AUTHORITY == (module.AUTHORITY_SHA256, raw)
        assert package._VERIFIED_AUTHORITY in (None, (package.AUTHORITY_SHA256, raw))
    finally:
        for name in set(sys.modules) - existing:
            source = getattr(sys.modules[name], "__file__", None)
            if type(source) is str and source.startswith(str(ROOT / "scripts") + os.sep):
                sys.modules.pop(name, None)


UNIQUE_CASES = [
    [], [1], [1, 1], [1, 1.0], [True, 1], [False, 0], [True, True], [None, None], [None, 0],
    ["1", 1], ["a", "a"], [[1], [1.0]], [[True], [1]], [[1, 2], [2, 1]], [{"a": 1}, {"a": 1.0}],
    [{"a": 1, "b": 2}, {"b": 2, "a": 1}], [{"a": True}, {"a": 1}], [{"a": [1]}, {"a": [1]}],
    [{"a": {"b": None}}, {"a": {"b": False}}], [{}, []], [{}, {}], [[], []], [[{}], [{}]],
    [0.0, -0.0], [10 ** 20, 1e20], ["", None, False, 0, [], {}],
    # Pinned uniq sorts sortable arrays and compares neighbours only; these
    # stay "unique" there and must stay unique here.
    [[1], [True], [1]], [[0], [False], [0]], [[True], [1], [True]],
    [[{"a": 1}], [{"a": True}], [{"a": 1}]], [[1, 2], [1, 2]], [[True], [True]],
]


@pytest.mark.parametrize("container", UNIQUE_CASES, ids=[json.dumps(c) for c in UNIQUE_CASES])
def test_unique_json_matches_pinned_pairwise_semantics(container):
    assert reuse._unique_json(container) is pinned_uniq(container)


def test_unique_json_matches_pinned_semantics_on_seeded_generated_values():
    generator = random.Random(28)
    atoms = [0, 1, 1.0, 0.0, -0.0, True, False, None, "", "a", "1", "true", 2, 2.5]

    def value(depth=0):
        roll = generator.random()
        if depth > 3 or roll < 0.45:
            return generator.choice(atoms)
        if roll < 0.7:
            return [value(depth + 1) for _ in range(generator.randint(0, 3))]
        return {generator.choice("abc"): value(depth + 1) for _ in range(generator.randint(0, 3))}

    numbers = [0, 1, 1.0, True, False, 2, -0.0, 0.0]

    def sortable(depth=0):
        # Nested numbers/booleans keep the array sortable: pinned uniq's sort path.
        if depth > 2 or generator.random() < 0.5:
            return generator.choice(numbers)
        return [sortable(depth + 1) for _ in range(generator.randint(0, 3))]

    for ordinal in range(8000):
        make = sortable if ordinal % 2 else value
        container = [make() for _ in range(generator.randint(0, 6))]
        if container and generator.random() < 0.3:
            container.append(json.loads(json.dumps(generator.choice(container))))
        assert reuse._unique_json(container) is pinned_uniq(container), container


@pytest.mark.parametrize("container", [[math.nan, math.nan], [math.inf, math.inf], [{1: "a"}, {1: "a"}],
                                       [(1,), (1,)], [b"x", b"x"]], ids=["nan", "inf", "int-key", "tuple", "bytes"])
def test_unhashable_or_non_json_values_use_the_pinned_pairwise_fallback(monkeypatch, container):
    calls = []

    def fallback(items):
        calls.append(items)
        return pinned_uniq(items)

    monkeypatch.setattr(reuse, "_pinned_uniq", fallback)
    assert reuse._unique_json(container) is pinned_uniq(container)
    assert calls == [container]


def test_only_unsortable_json_arrays_skip_the_pinned_implementation(monkeypatch):
    calls = []

    def recorded(items):
        calls.append(items)
        return pinned_uniq(items)

    monkeypatch.setattr(reuse, "_pinned_uniq", recorded)
    sortable = [[1], [True], [1]]
    assert reuse._unique_json(sortable) is True and calls == [sortable]
    calls.clear()
    objects = [{"a": 1}, {"a": True}, {"a": 1.0}]
    assert reuse._unique_json(objects) is False and calls == []
    assert reuse._unique_json([{"a": 1}, {"a": True}]) is True and calls == []


@pytest.mark.parametrize("instance", [[{"a": 1}, {"a": 1.0}], [1, True], [[1], [1]], {"x": [{"a": 1}, {"a": 1}]},
                                      [[1], [True], [1]], {"x": [[0], [False], [0]]}])
def test_extended_validator_errors_match_pinned_validator_exactly(instance):
    schema = {"type": ["array", "object"], "uniqueItems": True,
              "properties": {"x": {"type": "array", "uniqueItems": True}}}
    expected = list(jsonschema.Draft202012Validator(schema).iter_errors(instance))
    actual = list(reuse._Draft202012Validator(schema).iter_errors(instance))
    rendered = lambda errors: [(e.message, list(e.absolute_path), e.validator, e.validator_value) for e in errors]
    assert rendered(actual) == rendered(expected)


def test_reuse_schema_check_keeps_check_schema_format_checker_and_refusal(tmp_path):
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "array", "uniqueItems": True,
              "items": {"type": "object"}}
    path = tmp_path / "schema.json"
    path.write_text(json.dumps(schema))
    assert reuse._validate_schema([{"a": 1}, {"a": 2}], path, "sample") == schema
    with pytest.raises(reuse.ReuseValidationError, match="sample schema violation at <root>: .* has non-unique elements"):
        reuse._validate_schema([{"a": 1}, {"a": 1}], path, "sample")
    path.write_text(json.dumps({"type": 5}))
    with pytest.raises(reuse.ReuseValidationError, match="sample schema is invalid"):
        reuse._validate_schema([], path, "sample")


def test_failed027_and_ten_consumed_attempts_are_not_execution_authority():
    record = json.loads((ROOT / "architecture/packet-schema-performance-inputs/prior-027-terminal.json").read_bytes())
    assert record["packetId"] == "MET-PERF-027"
    assert record["status"] == "RETAINED_FAILURE_NOT_ACCEPTED_PREDECESSOR"
    assert record["source"]["commit"] == "33af75369233764004262f4f26f0d029418b1b03"
    attempt = record["separateLocalException"]
    assert (attempt["maximum"], attempt["consumed"], attempt["cumulativeLineageOrdinal"]) == (1, 1, 10)
    assert attempt["timedOut"] is True and attempt["commandsStarted"] == 52 and attempt["commandsExpected"] == 53
    assert attempt["finalScanReached"] is False and attempt["cleanupIndependentlyConfirmed"] is True
    assert record["nestedSuite"]["failureType"] == "TimeoutExpired"
    assert record["nestedSuite"]["diagnosticsStatus"] == "INCOMPLETE"
    assert record["outerSuite"]["completeFinalPytestReportAvailable"] is False
    assert all(v == {"maximum": 1, "consumed": 1} or v == {"maximum": 2, "consumed": 2}
               for v in record["previousAllowances"].values())
    assert record["successorBoundary"]["newPacketId"] == "MET-PERF-028"
    assert record["successorBoundary"]["newExecutionGrants"] == 0
    assert record["successorBoundary"]["budgetReset"] is False
    assert record["diagnosis"]["speedupEstablished"] is False
