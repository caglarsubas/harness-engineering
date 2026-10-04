"""Source-only checks for the exact current-to-accepted runner packet bridge."""
from copy import deepcopy

import pytest

from scripts import validate_ci_runner_admission as runner
from scripts import validate_packet_schema_performance as successor
from scripts.safe_yaml import safe_load


def packets():
    return {path.stem: safe_load(path.read_bytes())
            for path in (runner.ROOT / "task-packets").glob("*.yaml")}


def test_exact_current_packet_and_complete_accepted_history():
    assert runner.validate() is None
    current = packets()
    accepted_runner = successor.historical_catalog(current)
    previous = runner.historical_catalog(current)
    assert len(current) == 194
    assert len(accepted_runner) == 190
    assert set(accepted_runner) == set(current) - {successor.NEW_PACKET, successor.successor.NEW_PACKET,
                                                    successor.successor.successor.NEW_PACKET,
                                                    successor.successor.successor.successor.NEW_PACKET}
    assert len(previous) == 189
    assert set(previous) == set(current) - {runner.NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET,
                                             successor.successor.successor.NEW_PACKET,
                                             successor.successor.successor.successor.NEW_PACKET}
    record = runner.authority()
    assert set(record["baselinePackets"]) == set(previous)
    for path, rule in record["changedFiles"].items():
        current_raw = runner.regular_bytes(path)
        accepted_raw = successor.historical_bytes(path, current_raw)
        assert runner.digest(accepted_raw) == rule["afterSha256"]
        assert runner.digest(runner.historical_bytes(path, current_raw)) == rule["beforeSha256"]


@pytest.mark.parametrize("fault", ["missing", "extra", "changed"])
def test_catalog_rejects_unreviewed_packet(fault):
    current = deepcopy(packets())
    if fault == "missing":
        current.pop(runner.NEW_PACKET)
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    else:
        current[runner.NEW_PACKET]["objective"] += " changed"
    with pytest.raises(ValueError):
        runner.historical_catalog(current)


def test_inverse_and_forward_test_projection_are_exact():
    record = runner.authority()
    changed = next(path for path in record["changedFiles"] if path.startswith("tests/"))
    current = runner.regular_bytes(changed)
    before = runner.historical_bytes(changed, current)
    assert before != current
    assert runner.historical_bytes(changed, before) == before
    assert runner.historical_test_bytes(current) == before
    assert runner.current_test_bytes(before) == current
    with pytest.raises(ValueError, match="unreviewed current source"):
        runner.historical_bytes(changed, current + b" ")


@pytest.mark.parametrize("route", ["changed", "unchanged", "catalog", "forward_test"])
def test_each_projection_freshly_rechecks_complete_authority(monkeypatch, route):
    record = runner.authority()
    changed = next(path for path in record["changedFiles"] if path.startswith("tests/"))
    current = runner.regular_bytes(changed)
    before = runner.historical_bytes(changed, current)
    if route == "changed":
        project = lambda: runner.historical_bytes(changed, current)
    elif route == "unchanged":
        project = lambda: runner.historical_bytes("architecture/repositories.yaml", b"unchanged")
    elif route == "catalog":
        project = lambda: runner.historical_catalog(packets())
    else:
        project = lambda: runner.current_test_bytes(before)
    original = runner.regular_bytes
    authority_raw = original(runner.AUTHORITY_PATH)
    reads = []

    def changed_reader(path):
        if path == runner.AUTHORITY_PATH:
            reads.append(path)
            return authority_raw if len(reads) == 1 else authority_raw + b" "
        return original(path)

    monkeypatch.setattr(runner, "regular_bytes", changed_reader)
    project()
    with pytest.raises(ValueError, match="CI runner history authority digest"):
        project()
    assert len(reads) == 2


def test_inverse_rules_are_frozen_and_malformed_hunks_refused():
    path = next(iter(runner._PROJECTION_RULES))
    rule = runner._PROJECTION_RULES[path]
    with pytest.raises(TypeError):
        runner._PROJECTION_RULES[path] = {}
    with pytest.raises(TypeError):
        rule["afterSha256"] = "0" * 64
    current = runner.regular_bytes(path)
    with pytest.raises(ValueError, match="inverse hunk current bytes"):
        runner._inverse(current, ((0, b"not-current", b"old"),))
    with pytest.raises(ValueError, match="inverse hunk bounds"):
        runner._inverse(current, ((len(current) + 1, b"", b"old"),))


def test_duplicate_and_nonfinite_authority_members_refused():
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
        with pytest.raises(ValueError):
            runner.parse(raw)


def test_mutable_projection_input_refused():
    with pytest.raises(ValueError, match="source bytes required"):
        runner.historical_bytes("AGENTS.md", bytearray(b"mutable"))
    with pytest.raises(ValueError, match="test bytes required"):
        runner.current_test_bytes(bytearray(b"mutable"))
