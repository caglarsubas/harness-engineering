"""Exact source/native amendment and accepted-history bridge regression tests."""
from __future__ import annotations

from copy import deepcopy

import pytest

from scripts import validate_native_gate_staging as gate
from scripts.safe_yaml import safe_load


def current_catalog():
    return {
        path.stem: safe_load(gate.regular_bytes("task-packets/" + path.name))
        for path in (gate.ROOT / "task-packets").glob("*.yaml")
    }


def test_current_publication_and_exact_accepted_history():
    assert gate.validate() is None
    record = gate.authority()
    current = current_catalog()
    historical = gate.historical_catalog(current)
    assert len(current) == 190
    assert set(historical) == set(record["baselinePacketIds"])
    assert "MET-UNIFY-008" not in historical
    for name in gate.GATED_PACKETS:
        path = "task-packets/" + name + ".yaml"
        raw = gate.regular_bytes(path)
        previous = gate.historical_bytes(path, raw)
        assert gate.digest(previous) == record["changedFiles"][path]["beforeSha256"]
        assert historical[name] == safe_load(previous)
        assert historical[name] != current[name]


def test_every_inverse_is_exact_and_accepts_only_pinned_predecessor():
    record = gate.authority()
    for path, rule in record["changedFiles"].items():
        current = gate.regular_bytes(path)
        previous = gate.historical_bytes(path, current)
        assert gate.digest(previous) == rule["beforeSha256"]
        assert gate.historical_bytes(path, previous) == previous
        with pytest.raises(ValueError, match="unreviewed current source"):
            gate.historical_bytes(path, current + b" ")


def test_changed_test_projections_preserve_exact_current_identity():
    changed_test = next(
        path for path in gate.authority()["changedFiles"]
        if path.startswith("tests/")
    )
    current = gate.regular_bytes(changed_test)
    previous = gate.historical_bytes(changed_test, current)
    assert gate.historical_test_bytes(current) == previous
    assert gate.current_test_bytes(previous) == current


@pytest.mark.parametrize("projection", ["changed", "unchanged", "test", "catalog"])
def test_every_public_projection_rechecks_authority_bytes(monkeypatch, projection):
    record = gate.authority()
    changed_test = next(
        path for path in record["changedFiles"] if path.startswith("tests/")
    )
    test_bytes = gate.regular_bytes(changed_test)
    previous = gate.historical_bytes(changed_test, test_bytes)
    changed_path = next(iter(record["changedFiles"]))
    if projection == "changed":
        method = lambda: gate.historical_bytes(changed_path, gate.regular_bytes(changed_path))
    elif projection == "unchanged":
        method = lambda: gate.historical_bytes("AGENTS.md", gate.regular_bytes("AGENTS.md"))
    elif projection == "test":
        method = lambda: gate.current_test_bytes(previous)
    else:
        catalog = current_catalog()
        method = lambda: gate.historical_catalog(catalog)

    actual_read = gate.regular_bytes
    original = actual_read(gate.AUTHORITY_PATH)
    reads = 0

    def changing_read(path):
        nonlocal reads
        if path == gate.AUTHORITY_PATH:
            reads += 1
            return original if reads == 1 else original + b" "
        return actual_read(path)

    monkeypatch.setattr(gate, "regular_bytes", changing_read)
    method()
    with pytest.raises(ValueError, match="native gate authority digest"):
        method()
    assert reads == 2


@pytest.mark.parametrize("fault", ["missing", "unknown", "changed"])
def test_catalog_rejects_missing_unknown_or_changed_successor(fault):
    catalog = deepcopy(current_catalog())
    if fault == "missing":
        catalog.pop("MET-UNIFY-008")
    elif fault == "unknown":
        catalog["UNKNOWN-001"] = {}
    else:
        catalog["MET-UNIFY-008"]["objective"] += " unreviewed"
    with pytest.raises(ValueError):
        gate.historical_catalog(catalog)


def test_new_source_has_no_historical_bytes():
    with pytest.raises(ValueError, match="new source has no predecessor"):
        gate.historical_bytes(gate.POLICY_PATH, gate.regular_bytes(gate.POLICY_PATH))


def test_stale_old_product_packet_cannot_pose_as_current():
    catalog = current_catalog()
    path = "task-packets/CTRL-INTEGRATE-001.yaml"
    catalog["CTRL-INTEGRATE-001"] = safe_load(
        gate.historical_bytes(path, gate.regular_bytes(path))
    )
    with pytest.raises(ValueError, match="changed current packet"):
        gate.historical_catalog(catalog)


def test_native_qualifier_cannot_be_omitted_even_with_matching_policy_hash(monkeypatch):
    policy = gate.parse(gate.regular_bytes(gate.POLICY_PATH))
    policy["sourceCoding"]["expectedEvidenceQualifier"] = (
        "Source coding may proceed; native qualification later."
    )
    changed = gate.canonical(policy)
    actual_read = gate.regular_bytes

    def changed_read(path):
        return changed if path == gate.POLICY_PATH else actual_read(path)

    monkeypatch.setattr(gate, "regular_bytes", changed_read)
    with pytest.raises(ValueError, match="missing native-gate qualifier"):
        gate._validate_policy({"policySha256": gate.digest(changed)})


@pytest.mark.parametrize("fault", ["count", "native_predecessor", "candidate_claim", "lost_failed_candidate", "lost_second_failed_candidate"])
def test_current_backlog_semantics_not_just_a_self_hash(monkeypatch, fault):
    backlog = gate.parse(gate.regular_bytes(gate.BACKLOG_PATH))
    rows = {row["id"]: row for row in backlog["items"]}
    if fault == "count":
        backlog["counts"]["countedChecklistProjections"] = 13
    elif fault == "native_predecessor":
        rows["MODEL-001"]["predecessorIds"].append("CONF-LINUX-001")
    elif fault == "lost_failed_candidate":
        rows["MET-UNIFY-006"]["status"] = "MERGED_SOURCE_RECORDED"
    elif fault == "lost_second_failed_candidate":
        rows["MET-UNIFY-007"]["status"] = "MERGED_SOURCE_RECORDED"
    else:
        rows["MET-UNIFY-008"]["publishedPacket"] = True
    changed = gate.canonical(backlog)
    actual_read = gate.regular_bytes

    def changed_read(path):
        return changed if path == gate.BACKLOG_PATH else actual_read(path)

    monkeypatch.setattr(gate, "regular_bytes", changed_read)
    record = {"changedFiles": {gate.BACKLOG_PATH: {"afterSha256": gate.digest(changed)}}}
    with pytest.raises(ValueError):
        gate._validate_current_backlog(record)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}'])
def test_authority_json_rejects_ambiguous_data(raw):
    with pytest.raises(ValueError):
        gate.parse(raw)


def test_mutable_inputs_are_not_accepted():
    with pytest.raises(ValueError, match="historical source path and bytes"):
        gate.historical_bytes("AGENTS.md", bytearray(b"mutable"))
    with pytest.raises(ValueError, match="test bytes required"):
        gate.historical_test_bytes(bytearray(b"mutable"))
    with pytest.raises(ValueError, match="test bytes required"):
        gate.current_test_bytes(bytearray(b"mutable"))
