"""Source-only successor tests; never execute product or live campaigns."""
from copy import deepcopy
import zlib

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
        == set(packets()["MET-UNIFY-005"]["allowedPaths"])
    )
    assert roadmap.historical_bytes(
        roadmap.MASTER_PATH, roadmap.regular_bytes(roadmap.MASTER_PATH)
    ) == roadmap.regular_bytes(roadmap.ARCHIVE_PATH)


@pytest.mark.parametrize("fault", ["missing", "extra", "changed"])
def test_catalog_projection_rejects_unreviewed_packet(fault):
    current = deepcopy(packets())
    if fault == "missing":
        current.pop("MET-UNIFY-005")
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    else:
        current["MET-UNIFY-005"]["objective"] += " unreviewed"
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
    assert roadmap.historical_bytes(changed, previous) == previous
    assert roadmap.historical_test_bytes(current) == previous
    assert roadmap.current_test_bytes(previous) == current
    assert roadmap.current_test_bytes(previous + b" ") == previous + b" "


@pytest.mark.parametrize("projection", ["changed", "unchanged", "historical_test", "current_test"])
def test_every_projection_rechecks_actual_authority_bytes(monkeypatch, projection):
    record = roadmap.authority()
    changed_test = next(path for path in record["changedFiles"] if path.startswith("tests/"))
    current_test = roadmap.regular_bytes(changed_test)
    previous_test = roadmap.historical_bytes(changed_test, current_test)
    if projection == "changed":
        current = roadmap.regular_bytes(roadmap.MASTER_PATH)
        project = lambda: roadmap.historical_bytes(roadmap.MASTER_PATH, current)
    elif projection == "unchanged":
        path = "docs/harnesses/runtime.infrastructure.md"
        current = roadmap.regular_bytes(path)
        project = lambda: roadmap.historical_bytes(path, current)
    elif projection == "historical_test":
        project = lambda: roadmap.historical_test_bytes(current_test)
    else:
        project = lambda: roadmap.current_test_bytes(previous_test)

    actual_read = roadmap.regular_bytes
    authority_raw = actual_read(roadmap.AUTHORITY_PATH)
    reads = 0

    def changing_read(path):
        nonlocal reads
        if path == roadmap.AUTHORITY_PATH:
            reads += 1
            return authority_raw if reads == 1 else authority_raw + b" "
        return actual_read(path)

    monkeypatch.setattr(roadmap, "regular_bytes", changing_read)
    project()
    with pytest.raises(ValueError, match="unified authority digest"):
        project()
    assert reads == 2


def test_projection_rules_are_immutable_and_fast_predecessor_is_exact(monkeypatch):
    rule = roadmap._PROJECTION_RULES[roadmap.MASTER_PATH]
    before = roadmap.regular_bytes(roadmap.ARCHIVE_PATH)
    assert roadmap.digest(before) == rule["beforeSha256"]
    with pytest.raises(TypeError):
        roadmap._PROJECTION_RULES[roadmap.MASTER_PATH] = {}
    with pytest.raises(TypeError):
        rule["beforeSha256"] = "0" * 64

    def unexpected_inflation():
        pytest.fail("predecessor or rejected bytes must not be inflated")

    monkeypatch.setattr(roadmap.zlib, "decompressobj", unexpected_inflation)
    assert roadmap.historical_bytes(roadmap.MASTER_PATH, before) == before
    with pytest.raises(ValueError, match="unreviewed current source"):
        roadmap.historical_bytes(roadmap.MASTER_PATH, before + b" ")
    with pytest.raises(ValueError, match="source bytes required"):
        roadmap.historical_bytes(roadmap.MASTER_PATH, bytearray(before))


def test_compact_inverse_hunks_are_immutable_exact_and_bounded():
    authority = roadmap.regular_bytes(roadmap.AUTHORITY_PATH)
    # The 25 additional inverse routes still keep the full checked authority
    # below one third of the original 794,644-byte snapshot representation.
    assert len(authority) < 250_000
    hunk_path = next(
        path for path, rule in roadmap._PROJECTION_RULES.items()
        if "reverseHunks" in rule
    )
    rule = roadmap._PROJECTION_RULES[hunk_path]
    current = roadmap.regular_bytes(hunk_path)
    before = roadmap.historical_bytes(hunk_path, current)
    assert roadmap.digest(before) == rule["beforeSha256"]
    with pytest.raises(TypeError):
        rule["reverseHunks"][0] = (0, b"", b"malicious")
    with pytest.raises(ValueError, match="inverse hunk current bytes"):
        roadmap._reconstruct_predecessor(current, ((0, b"not-current", b"old"),))
    with pytest.raises(ValueError, match="inverse hunk bounds"):
        roadmap._reconstruct_predecessor(current, ((len(current) + 1, b"", b"old"),))


def test_compressed_fallback_rejects_trailing_data():
    with pytest.raises(ValueError, match="bounded canonical predecessor decompression"):
        roadmap._inflate_predecessor(zlib.compress(b"exact") + b"trailing")


@pytest.mark.parametrize("fault", ["duplicate", "noncanonical_base64", "boolean_offset"])
def test_inverse_rule_parser_rejects_unreviewed_hunk_shape(monkeypatch, fault):
    record = deepcopy(roadmap.authority())
    path = next(
        path for path, rule in record["changedFiles"].items()
        if "reverseHunks" in rule
    )
    hunks = record["changedFiles"][path]["reverseHunks"]
    if fault == "duplicate":
        hunks.insert(0, deepcopy(hunks[0]))
    elif fault == "noncanonical_base64":
        hunks[0]["insertBase64"] += "!"
    else:
        hunks[0]["at"] = True
    monkeypatch.setattr(roadmap, "authority", lambda: record)
    with pytest.raises(ValueError):
        roadmap._load_projection_rules()


def test_test_projections_reject_mutable_inputs():
    with pytest.raises(ValueError, match="test bytes required"):
        roadmap.historical_test_bytes(bytearray(b"mutable"))
    with pytest.raises(ValueError, match="test bytes required"):
        roadmap.current_test_bytes(bytearray(b"mutable"))


def test_projection_reuses_only_sha_pinned_parsed_data(monkeypatch):
    current = roadmap.regular_bytes(roadmap.MASTER_PATH)

    def unexpected_parse(_raw):
        pytest.fail("historical projection reparsed the entire authority")

    monkeypatch.setattr(roadmap, "parse", unexpected_parse)
    assert roadmap.digest(roadmap.historical_bytes(roadmap.MASTER_PATH, current)) == (
        roadmap._PROJECTION_RULES[roadmap.MASTER_PATH]["beforeSha256"]
    )


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
