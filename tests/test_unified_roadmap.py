"""Source-only successor tests; never execute product or live campaigns."""
from copy import deepcopy

import pytest

from scripts import validate_unified_roadmap as roadmap
from scripts.safe_yaml import safe_load


def packets():
    return {
        path.stem: safe_load(path.read_bytes())
        for path in (roadmap.ROOT / "task-packets").glob("*.yaml")
    }


def test_exact_current_publication_and_accepted_history():
    assert roadmap.validate() is None
    record = roadmap.authority()
    assert len(roadmap.historical_catalog(packets())) == 188
    assert (
        set(record["changedFiles"]) | set(record["newFiles"])
        | {roadmap.AUTHORITY_PATH, "scripts/validate_unified_roadmap.py"}
        == set(packets()["MET-UNIFY-003"]["allowedPaths"])
    )
    assert roadmap.historical_bytes(
        roadmap.MASTER_PATH, roadmap.regular_bytes(roadmap.MASTER_PATH)
    ) == roadmap.regular_bytes(roadmap.ARCHIVE_PATH)


@pytest.mark.parametrize("fault", ["missing", "extra", "changed"])
def test_catalog_projection_rejects_unreviewed_packet(fault):
    current = deepcopy(packets())
    if fault == "missing":
        current.pop("MET-UNIFY-003")
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    else:
        current["MET-UNIFY-003"]["objective"] += " unreviewed"
    with pytest.raises(ValueError):
        roadmap.historical_catalog(current)


def test_inverse_rejects_unreviewed_current_bytes():
    raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    with pytest.raises(ValueError):
        roadmap.historical_bytes(roadmap.MASTER_PATH, raw + b" ")


def test_forward_test_projection_is_exact_and_not_an_inverse():
    record = roadmap.authority()
    changed = next(path for path in record["changedFiles"] if path.startswith("tests/"))
    current = roadmap.regular_bytes(changed)
    previous = roadmap.historical_bytes(changed, current)
    assert previous != current
    assert roadmap.current_test_bytes(previous) == current
    assert roadmap.current_test_bytes(previous + b" ") == previous + b" "


def test_source_inventory_rejects_omitted_requirement(monkeypatch):
    record = roadmap.authority()
    changed = deepcopy(record)
    changed["baselinePackets"].pop(next(iter(changed["baselinePackets"])))
    monkeypatch.setattr(roadmap, "authority", lambda: changed)
    with pytest.raises(ValueError):
        roadmap.historical_catalog(packets())


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}'])
def test_json_authority_parser_rejects_ambiguous_data(raw):
    with pytest.raises(ValueError):
        roadmap.parse(raw)


def test_empty_historical_headings_do_not_inherit_delivery_or_acceptance():
    dispositions = roadmap.parse(roadmap.regular_bytes(roadmap.DISPOSITIONS_PATH))
    rows = [
        row for row in dispositions["units"]
        if row.get("deliveryJoinStatus") == "NAVIGATION_ONLY_NO_DELIVERABLE"
    ]
    assert len(rows) == dispositions["counts"]["navigationOnlyJoinsResolved"] == 203
    assert all(
        row["sourceUnitKind"] == "DOCUMENT_HEADING_SPAN"
        and row["sourceSpan"][1] == row["sourceSpan"][0] + 1
        and row["deliveryPacketIds"] == []
        and row["acceptancePlanRefs"] == []
        and row["unresolvedMarkers"] == []
        and row["evidenceState"] == "SOURCE_ONLY_NOT_ACCEPTANCE"
        for row in rows
    )
    assert dispositions["counts"]["unitsWithUnresolvedMarkers"] == 38
