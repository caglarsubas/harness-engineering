"""Real packet-loop parity and source lineage; no performance threshold or host claim."""
from __future__ import annotations

import ast
from copy import deepcopy
from importlib.metadata import version
import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from scripts import validate_readiness as readiness


SOURCE_ROOT = Path(__file__).resolve().parents[1]
DRAFT_2020 = "https://json-schema.org/draft/2020-12/schema"
DRAFT_7 = "http://json-schema.org/draft-07/schema#"


class _StopAfterPacketLoop(RuntimeError):
    """The unit test reached the unchanged first post-loop dependency."""


class _Facade:
    def __init__(self, original, **overrides):
        self.original = original
        self.overrides = overrides

    def __getattr__(self, name):
        return self.overrides.get(name, getattr(self.original, name))


class _LoopHarness:
    def __init__(self, root, monkeypatch):
        self.root = root
        self.events = []
        self.selected_schemas = []
        self.selected_classes = []
        self.constructed = []
        self.instances = []
        self.chosen_errors = []
        self.boundaries = []
        self.owners = {}
        self.last_validation = None
        self.base_packet = readiness.load_yaml(SOURCE_ROOT / "task-packets/MET-001.yaml")
        for directory in ("schemas", "architecture", "task-packets"):
            (root / directory).mkdir()
        (root / "schemas/live-campaign-execution-envelope.schema.json").write_bytes(
            (SOURCE_ROOT / "schemas/live-campaign-execution-envelope.schema.json").read_bytes()
        )
        (root / "architecture/repositories.yaml").write_text(
            json.dumps({"repositories": [{"name": "Harness-Engineering", "id": "meta"}]}),
            encoding="utf-8",
        )
        self.write_schema(_schema())
        original_json, original_yaml = readiness.load_json, readiness.load_yaml

        def read_json(path):
            self.events.append(("json", str(path.relative_to(root))))
            return original_json(path)

        def read_yaml(path):
            self.events.append(("yaml", str(path.relative_to(root))))
            return original_yaml(path)

        def validator_for(schema, *args, **kwargs):
            actual_class = jsonschema.validators.validator_for(schema, *args, **kwargs)
            self.events.append(("select", schema))
            self.selected_schemas.append(schema)
            self.selected_classes.append(actual_class)
            owner = self

            class ObservedValidator:
                @classmethod
                def check_schema(cls, checked_schema):
                    owner.events.append(("check", checked_schema))
                    return actual_class.check_schema(checked_schema)

                def __init__(self, checked_schema, **options):
                    owner.events.append(("construct", checked_schema))
                    assert options.get("format_checker") is readiness.SCHEMA_FORMAT_CHECKER
                    self.actual = actual_class(checked_schema, **options)
                    owner.constructed.append(self.actual)

                def iter_errors(self, instance):
                    owner.events.append(("instance", instance["id"]))
                    owner.instances.append(instance)
                    return self.actual.iter_errors(instance)

            return ObservedValidator

        def best_match(errors, *args, **kwargs):
            chosen = jsonschema.exceptions.best_match(errors, *args, **kwargs)
            self.chosen_errors.append(chosen)
            self.events.append(("best_match", chosen))
            return chosen

        def stop_after_loop(validation, nodes, edges, label):
            assert label == "task packet"
            self.boundaries.append((set(nodes), deepcopy(edges)))
            self.events.append(("boundary", label))
            raise _StopAfterPacketLoop()

        # Only the module-under-test reference is changed. The oracle and the
        # delegated implementations use the untouched, pinned jsonschema module.
        monkeypatch.setattr(readiness, "jsonschema", _Facade(
            jsonschema,
            validators=_Facade(jsonschema.validators, validator_for=validator_for),
            exceptions=_Facade(jsonschema.exceptions, best_match=best_match),
        ))
        monkeypatch.setattr(readiness, "ROOT", root)
        monkeypatch.setattr(readiness, "load_json", read_json)
        monkeypatch.setattr(readiness, "load_yaml", read_yaml)
        monkeypatch.setattr(readiness, "assert_acyclic", stop_after_loop)

    def write_schema(self, schema):
        (self.root / "schemas/task-packet.schema.json").write_text(
            json.dumps(schema, allow_nan=False), encoding="utf-8"
        )

    def write_packet(self, ordinal, **changes):
        packet = deepcopy(self.base_packet)
        packet_id = f"TST-SCHEMA-{ordinal:03d}"
        packet.update(id=packet_id, branch=f"codex/{packet_id.casefold()}-fixture")
        packet.update(changes)
        path = self.root / "task-packets" / f"{packet_id}.yaml"
        path.write_text(json.dumps(packet, allow_nan=False), encoding="utf-8")
        self.owners[packet_id] = "Harness-Engineering"
        return path, packet

    def call(self):
        self.last_validation = readiness.Validation()
        readiness.validate_packets(
            self.last_validation, {"Harness-Engineering"}, {"meta"},
            self.owners, {}, {}, {},
        )

    def run_loop(self):
        with pytest.raises(_StopAfterPacketLoop):
            self.call()
        return self.last_validation

    def count(self, kind):
        return sum(event[0] == kind for event in self.events)


@pytest.fixture
def loop(tmp_path, monkeypatch):
    return _LoopHarness(tmp_path, monkeypatch)


def _schema(**changes):
    value = {"$schema": DRAFT_2020, "type": "object"}
    value.update(changes)
    return value


def _oracle(instance, schema):
    try:
        jsonschema.validate(instance, schema, format_checker=readiness.SCHEMA_FORMAT_CHECKER)
    except jsonschema.ValidationError as error:
        return error
    return None


def _signature(error):
    if error is None:
        return None
    return (
        type(error), tuple(error.absolute_path), tuple(error.absolute_schema_path),
        error.validator, error.validator_value, error.message,
        tuple(_signature(child) for child in error.context),
    )


def _render(path, error):
    return f"{path}: schema error at {list(error.absolute_path)}: {error.message}"


def test_pinned_jsonschema_oracle_version():
    assert version("jsonschema") == "4.24.0"


def test_schema_lifecycle_is_once_per_invocation_after_fresh_first_packet(loop):
    for ordinal in (3, 1, 2):
        loop.write_packet(ordinal)
    validation = loop.run_loop()
    assert validation.errors == []
    assert loop.count("select") == loop.count("check") == loop.count("construct") == 1
    assert loop.count("instance") == loop.count("best_match") == 3
    assert [instance["id"] for instance in loop.instances] == [
        "TST-SCHEMA-001", "TST-SCHEMA-002", "TST-SCHEMA-003",
    ]
    assert loop.chosen_errors == [None, None, None]
    first_yaml = loop.events.index(("yaml", "task-packets/TST-SCHEMA-001.yaml"))
    task_schema_read = loop.events.index(("json", "schemas/task-packet.schema.json"))
    first_select = next(i for i, event in enumerate(loop.events) if event[0] == "select")
    first_check = next(i for i, event in enumerate(loop.events) if event[0] == "check")
    first_construct = next(i for i, event in enumerate(loop.events) if event[0] == "construct")
    assert task_schema_read < first_yaml < first_select < first_check < first_construct
    assert loop.boundaries == [(
        {"TST-SCHEMA-001", "TST-SCHEMA-002", "TST-SCHEMA-003"},
        {"TST-SCHEMA-001": [], "TST-SCHEMA-002": [], "TST-SCHEMA-003": []},
    )]


@pytest.mark.parametrize("case", ["valid", "type", "multiple", "any_of", "one_of", "local_ref"])
def test_acceptance_and_complete_diagnostics_match_unmodified_library(loop, case):
    schema = _schema(properties={"objective": {"type": "string"}})
    objective = "valid"
    if case == "type":
        objective = 7
    elif case == "multiple":
        objective = 7
        schema["required"] = ["missing_top_level"]
    elif case == "any_of":
        objective = {"count": 1}
        schema["properties"]["objective"] = {"anyOf": [
            {"type": "object", "properties": {"count": {"type": "integer", "minimum": 3}}, "required": ["count"]},
            {"type": "array", "items": {"type": "string"}},
        ]}
    elif case == "one_of":
        objective = "b"
        schema["properties"]["objective"] = {"oneOf": [
            {"type": "string", "pattern": "^a"}, {"type": "string", "minLength": 4},
        ]}
    elif case == "local_ref":
        objective = 6
        schema["$defs"] = {"count": {"type": "integer", "minimum": 7}}
        schema["properties"]["objective"] = {"$ref": "#/$defs/count"}
    path, packet = loop.write_packet(1, objective=objective)
    expected = _oracle(packet, schema)
    loop.write_schema(schema)
    actual = loop.run_loop()
    assert len(loop.chosen_errors) == 1
    assert _signature(loop.chosen_errors[0]) == _signature(expected)
    assert actual.errors == ([] if expected is None else [_render(path, expected)])
    assert loop.boundaries[-1][0] == ({packet["id"]} if expected is None else set())
    if case == "multiple":
        selected_class = jsonschema.validators.validator_for(schema)
        first = next(selected_class(schema, format_checker=readiness.SCHEMA_FORMAT_CHECKER).iter_errors(packet))
        assert _signature(first) != _signature(expected)
        assert list(first.absolute_path) == ["objective"]
        assert list(expected.absolute_path) == []


@pytest.mark.parametrize("draft,expected_class", [(DRAFT_7, jsonschema.Draft7Validator), (DRAFT_2020, jsonschema.Draft202012Validator)])
def test_draft_selection_uses_real_library_class(loop, draft, expected_class):
    schema = _schema(**{"$schema": draft}, properties={"objective": {"type": "string"}})
    path, packet = loop.write_packet(1, objective=8)
    loop.write_schema(schema)
    expected = _oracle(packet, schema)
    result = loop.run_loop()
    assert loop.selected_classes == [expected_class]
    assert _signature(loop.chosen_errors[0]) == _signature(expected)
    assert result.errors == [_render(path, expected)]


@pytest.mark.parametrize("objective", ["2026-10-01T12:30:00Z", "not-a-date", "2026-10-01T12:30:00"])
def test_existing_format_checker_remains_active(loop, objective):
    schema = _schema(properties={"objective": {"type": "string", "format": "date-time"}})
    path, packet = loop.write_packet(1, objective=objective)
    loop.write_schema(schema)
    expected = _oracle(packet, schema)
    result = loop.run_loop()
    assert _signature(loop.chosen_errors[0]) == _signature(expected)
    assert result.errors == ([] if expected is None else [_render(path, expected)])
    assert len(loop.constructed) == 1
    assert loop.constructed[0].format_checker is readiness.SCHEMA_FORMAT_CHECKER
    assert (expected is None) == (objective == "2026-10-01T12:30:00Z")


def test_invalid_schema_prevents_construction_and_retains_schema_error(loop):
    invalid_schema = _schema(type=42)
    _, packet = loop.write_packet(1)
    loop.write_schema(invalid_schema)
    with pytest.raises(jsonschema.SchemaError) as expected:
        jsonschema.validate(packet, invalid_schema, format_checker=readiness.SCHEMA_FORMAT_CHECKER)
    with pytest.raises(jsonschema.SchemaError) as actual:
        loop.call()
    assert _signature(actual.value) == _signature(expected.value)
    assert loop.count("select") == loop.count("check") == 1
    assert loop.count("construct") == loop.count("instance") == 0
    assert loop.chosen_errors == loop.boundaries == []


def test_malformed_first_yaml_precedes_invalid_schema_check(loop):
    path, _ = loop.write_packet(1)
    path.write_text("[unterminated", encoding="utf-8")
    loop.write_schema(_schema(type=42))
    with pytest.raises(yaml.YAMLError):
        loop.call()
    assert ("yaml", "task-packets/TST-SCHEMA-001.yaml") in loop.events
    assert loop.count("select") == loop.count("check") == loop.count("construct") == 0
    assert loop.chosen_errors == loop.boundaries == []


def test_empty_loop_adds_no_task_schema_check(loop):
    loop.write_schema(_schema(type=42))
    result = loop.run_loop()
    assert result.errors == ["no task packets found"]
    assert loop.count("select") == loop.count("check") == loop.count("construct") == 0
    assert loop.boundaries == [(set(), {})]
    assert ("json", "schemas/task-packet.schema.json") in loop.events


@pytest.mark.parametrize("objectives", [(9, "valid"), ("valid", 9)])
def test_invalid_and_valid_instances_never_share_a_verdict(loop, objectives):
    schema = _schema(properties={"objective": {"type": "string"}})
    loop.write_schema(schema)
    rows = [loop.write_packet(i, objective=value) for i, value in enumerate(objectives, start=1)]
    expected = [_oracle(packet, schema) for _, packet in rows]
    result = loop.run_loop()
    assert [_signature(error) for error in loop.chosen_errors] == [_signature(error) for error in expected]
    assert result.errors == [_render(path, error) for (path, _), error in zip(rows, expected) if error is not None]
    assert [packet["objective"] for packet in loop.instances] == list(objectives)
    assert loop.boundaries[-1][0] == {packet["id"] for (_, packet), error in zip(rows, expected) if error is None}
    assert loop.count("check") == loop.count("construct") == 1


@pytest.mark.parametrize("second_schema", ["changed_constraint", "invalid_schema"])
def test_second_invocation_freshly_reads_and_checks_schema_bytes(loop, second_schema):
    path, packet = loop.write_packet(1, objective="valid")
    loop.write_schema(_schema(properties={"objective": {"type": "string"}}))
    assert loop.run_loop().errors == []
    replacement = (_schema(properties={"objective": {"type": "integer"}})
                   if second_schema == "changed_constraint" else _schema(type=42))
    loop.write_schema(replacement)
    if second_schema == "invalid_schema":
        with pytest.raises(jsonschema.SchemaError):
            loop.call()
        assert loop.count("construct") == loop.count("instance") == 1
    else:
        expected = _oracle(packet, replacement)
        assert loop.run_loop().errors == [_render(path, expected)]
        assert loop.count("construct") == loop.count("instance") == 2
        assert loop.constructed[0] is not loop.constructed[1]
    assert loop.count("select") == loop.count("check") == 2
    assert loop.events.count(("json", "schemas/task-packet.schema.json")) == 2
    assert loop.selected_schemas[0] is not loop.selected_schemas[1]
    assert loop.selected_schemas[1] == replacement


def test_second_invocation_reads_changed_packet_bytes(loop):
    schema = _schema(properties={"objective": {"type": "string"}})
    loop.write_schema(schema)
    loop.write_packet(1, objective="valid")
    assert loop.run_loop().errors == []
    path, changed = loop.write_packet(1, objective=9)
    expected = _oracle(changed, schema)
    assert loop.run_loop().errors == [_render(path, expected)]
    assert loop.events.count(("yaml", "task-packets/TST-SCHEMA-001.yaml")) == 2
    assert [packet["objective"] for packet in loop.instances] == ["valid", 9]
    assert loop.instances[0] is not loop.instances[1]
    assert loop.count("check") == loop.count("construct") == 2


@pytest.mark.parametrize("source", ["task_schema_json", "packet_yaml", "repositories_yaml"])
def test_existing_duplicate_key_loaders_remain_in_force(loop, source):
    packet_path, _ = loop.write_packet(1)
    if source == "task_schema_json":
        (loop.root / "schemas/task-packet.schema.json").write_text(
            '{"type":"object","type":"string"}', encoding="utf-8"
        )
        expected = readiness.DuplicateJsonKeyError
    elif source == "packet_yaml":
        packet_path.write_text("id: TST-SCHEMA-001\nid: TST-SCHEMA-002\n", encoding="utf-8")
        expected = readiness.DuplicateYamlKeyError
    else:
        (loop.root / "architecture/repositories.yaml").write_text(
            "repositories: []\nrepositories: []\n", encoding="utf-8"
        )
        expected = readiness.DuplicateYamlKeyError
    with pytest.raises(expected):
        loop.call()
    assert loop.count("select") == loop.count("check") == loop.count("construct") == 0
    assert loop.boundaries == []


def _history_modules():
    from scripts import validate_packet_schema_performance as performance
    from scripts import validate_ci_runner_admission as runner
    from scripts import validate_unified_roadmap as roadmap
    return performance, runner, roadmap


def test_retained_020_terminal_never_resets_any_consumed_allowance():
    raw = (SOURCE_ROOT / "architecture/packet-schema-performance-inputs/prior-020-terminal.json").read_bytes()
    record = json.loads(raw)
    assert record["status"] == "RETAINED_FAILURE_NOT_ACCEPTED_PREDECESSOR"
    assert record["packetId"] == "MET-PERF-020"
    assert record["source"]["commit"] == "50acfd4f2cd5cc070a2dfde4c44f5aff49c8e608"
    assert record["source"]["packetSha256"] == "8b37f501315182b0b5f48c62fbc2cf8e99c14dda0b40c307a6fa8da847617f33"
    original = record["originalAllowance"]
    assert original["lineage"] == ["MET-PERF-019", "MET-PERF-020"]
    assert original["maximum"] == original["consumed"] == 2
    assert original["metPerf020CommandsStarted"] == 0
    assert original["metPerf020Outcome"] == "RESERVED_PRELAUNCH_REFUSAL"
    extra = record["separateLocalException"]
    assert extra["maximum"] == extra["consumed"] == 1
    assert extra["cumulativeLineageOrdinal"] == 3
    assert extra["status"] == "LOCAL_FAILED_OR_INCOMPLETE"
    assert (extra["commandsStarted"], extra["commandsExpected"]) == (52, 53)
    assert extra["nestedElapsedSeconds"] > 420
    assert extra["outerElapsedSeconds"] > 750
    assert extra["exitCode"] == -15 and extra["externalHelperExitCode"] == 1
    assert extra["finalPytestSummary"] is extra["finalScanReached"] is False
    assert extra["additionalFailureIdentities"] == "UNKNOWN"
    assert extra["cleanupIndependentlyConfirmed"] is True
    assert record["immutableEvidenceSha256"]["exception1-result.json"] == "428ada28d676274f7537f17986b37728db3ca484f81f0c245ae347861377844b"
    assert record["successorBoundary"] == {
        "newPacketId": "MET-PERF-021", "newExecutionGrants": 0,
        "budgetReset": False, "automaticCiOrExactMain": False,
        "sourceAccepted": False, "nativeLinux": False, "tenantAcceptance": False,
    }
    # The current source validator separately pins every byte of this record.
    # These assertions are not verification of private evidence or a new grant.


def _current_catalog(module):
    return {path.stem: module.safe_load(path.read_bytes())
            for path in (module.ROOT / "task-packets").glob("*.yaml")}


def test_retained_022_terminal_preserves_exact_identity_failure_and_consumed_allowance():
    record = json.loads((SOURCE_ROOT / "architecture/packet-schema-performance-inputs/prior-022-terminal.json").read_bytes())
    assert record["status"] == "RETAINED_FAILURE_NOT_ACCEPTED_PREDECESSOR"
    assert record["packetId"] == "MET-PERF-022"
    assert record["source"]["commit"] == "dca0163596a766efa0fabea7f1b5946daf5598cd"
    assert record["source"]["packetSha256"] == "e3caf28221cce5d7b467640337c524802308fa0ccb219432f594c5c19b5ca8d3"
    assert record["previousAllowances"] == {
        "original019020": {"maximum": 2, "consumed": 2},
        "separate020CustodyException": {"maximum": 1, "consumed": 1},
        "separate021Local": {"maximum": 1, "consumed": 1},
    }
    attempt = record["separateLocalException"]
    assert attempt["maximum"] == attempt["consumed"] == 1
    assert attempt["cumulativeLineageOrdinal"] == 5 and attempt["activation"] == 383
    assert attempt["status"] == "LOCAL_FAILED_AT_READINESS"
    assert (attempt["commandsStarted"], attempt["commandsExpected"], attempt["failedCommandOrdinal"]) == (2, 53, 2)
    assert attempt["readinessErrors"] == 4 and attempt["elapsedSeconds"] == 16.44750250002835
    assert attempt["exitCode"] == attempt["externalHelperExitCode"] == 1
    assert attempt["timedOut"] is attempt["pytestStarted"] is False
    assert attempt["diagnosticHooksExercised"] is attempt["finalScanReached"] is False
    assert attempt["cleanupIndependentlyConfirmed"] is attempt["sourceAndHistoryUnchanged"] is True
    assert record["diagnosis"]["acceptedTestFunctions"] == 10
    assert record["diagnosis"]["failedCurrentTestFunctions"] == 14
    assert record["diagnosis"]["testFailureIdentitiesFromEarlierTimeouts"] == "STILL_UNKNOWN"
    assert record["immutableEvidenceSha256"]["local1-result.json"] == "67d5112ee1deaad826aad1e1176e61a0d479b2de453de33661195de6840e59dc"
    assert record["successorBoundary"] == {
        "newPacketId": "MET-PERF-023", "newExecutionGrants": 0,
        "budgetReset": False, "automaticCiOrExactMain": False,
        "sourceAccepted": False, "nativeLinux": False, "tenantAcceptance": False,
    }


def test_retained_021_terminal_does_not_claim_diagnostic_execution_or_new_allowance():
    raw = (SOURCE_ROOT / "architecture/packet-schema-performance-inputs/prior-021-terminal.json").read_bytes()
    record = json.loads(raw)
    assert record["status"] == "RETAINED_FAILURE_NOT_ACCEPTED_PREDECESSOR"
    assert record["packetId"] == "MET-PERF-021"
    assert record["source"]["commit"] == "29161763f0653498c37bb80cdab291105809abed"
    assert record["source"]["packetSha256"] == "9c35ac30088f9e3914719f763e7cb7c20848d745fe2b8166fc9524ef5b6a2c71"
    assert record["previousAllowances"] == {
        "original019020": {"maximum": 2, "consumed": 2},
        "separate020CustodyException": {"maximum": 1, "consumed": 1},
    }
    attempt = record["separateLocalException"]
    assert attempt["maximum"] == attempt["consumed"] == 1
    assert attempt["cumulativeLineageOrdinal"] == 4
    assert attempt["activation"] == 382
    assert attempt["status"] == "LOCAL_FAILED_AT_READINESS"
    assert (attempt["commandsStarted"], attempt["commandsExpected"]) == (2, 53)
    assert attempt["failedCommandOrdinal"] == 2 and attempt["readinessErrors"] == 4
    assert attempt["elapsedSeconds"] == 29.908430583018344
    assert attempt["exitCode"] == attempt["externalHelperExitCode"] == 1
    assert attempt["timedOut"] is attempt["pytestStarted"] is False
    assert attempt["diagnosticHooksExercised"] is attempt["finalScanReached"] is False
    assert attempt["cleanupIndependentlyConfirmed"] is attempt["sourceAndHistoryUnchanged"] is True
    assert record["immutableEvidenceSha256"]["local1-result.json"] == "dedc064bede8e8a4a9d236ed484faba33d8bb7049f5a4e6d1ca96d6426c7546c"
    assert record["successorBoundary"] == {
        "newPacketId": "MET-PERF-022", "newExecutionGrants": 0,
        "budgetReset": False, "automaticCiOrExactMain": False,
        "sourceAccepted": False, "nativeLinux": False, "tenantAcceptance": False,
    }
    # These source assertions do not re-verify private evidence or grant a run.


def _changed_test(module):
    return next(path for path in module._PROJECTION_RULES if path.startswith("tests/"))


def test_schema_performance_publication_preserves_complete_source_history():
    performance, runner, roadmap = _history_modules()
    assert performance.validate() is None
    current = _current_catalog(performance)
    accepted = performance.historical_catalog(current)
    assert len(current) == 194 and len(accepted) == 190
    assert set(accepted) == set(current) - {performance.NEW_PACKET, performance.successor.NEW_PACKET,
                                            performance.successor.successor.NEW_PACKET,
                                            performance.successor.successor.successor.NEW_PACKET}
    assert len(runner.historical_catalog(current)) == 189
    assert len(roadmap.historical_catalog(current)) == 188
    for path, rule in performance._PROJECTION_RULES.items():
        raw = performance.successor.historical_bytes(path, performance.regular_bytes(path))
        before = performance.historical_bytes(path, raw)
        assert performance.digest(raw) == rule["afterSha256"]
        assert performance.digest(before) == rule["beforeSha256"]
        assert performance.historical_bytes(path, before) == before


@pytest.mark.parametrize("fault", ["missing_new", "missing_old", "extra", "changed_new", "already_projected"])
def test_schema_performance_catalog_rejects_unreviewed_successor(fault):
    performance, _, _ = _history_modules()
    current = _current_catalog(performance)
    if fault == "missing_new":
        current.pop(performance.NEW_PACKET)
    elif fault == "missing_old":
        current.pop("MET-RUNNER-001")
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    elif fault == "changed_new":
        current[performance.NEW_PACKET]["objective"] += " unreviewed"
    else:
        current = performance.historical_catalog(current)
    with pytest.raises(ValueError):
        performance.historical_catalog(current)


@pytest.mark.parametrize("fault", ["opaque", "cyclic"])
def test_schema_performance_projection_preserves_predecessor_refusal_semantics(fault):
    performance, _, _ = _history_modules()
    current = _current_catalog(performance)
    if fault == "opaque":
        current["MET-001"] = object()
    else:
        malformed = {}
        malformed["cycle"] = malformed
        current["MET-001"] = malformed
    accepted = performance.historical_catalog(current)
    assert accepted["MET-001"] is current["MET-001"]


def test_schema_performance_test_projection_round_trip_is_exact():
    performance, runner, roadmap = _history_modules()
    path = _changed_test(performance)
    current = performance.regular_bytes(path)
    before = performance.historical_bytes(path, current)
    assert before != current
    assert performance.historical_test_bytes(current) == before
    assert performance.current_test_bytes(before) == current
    assert runner.current_test_bytes(runner.historical_bytes(path, current)) == current
    assert roadmap.current_test_bytes(roadmap.historical_bytes(path, current)) == current
    with pytest.raises(ValueError, match="unreviewed current source"):
        performance.historical_bytes(path, current + b" ")


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "runner_old", "roadmap_old"])
def test_schema_performance_authority_is_rechecked_through_every_history_route(monkeypatch, route):
    performance, runner, roadmap = _history_modules()
    path = _changed_test(performance)
    current = performance.regular_bytes(path)
    before = performance.historical_bytes(path, current)
    current_packets = _current_catalog(performance) if route == "catalog" else None
    master_raw = performance.regular_bytes(roadmap.MASTER_PATH)
    runner_old = runner.historical_bytes(roadmap.MASTER_PATH, master_raw)
    roadmap_old = roadmap.historical_bytes(roadmap.MASTER_PATH, master_raw)
    routes = {
        "authority": performance.authority,
        "changed": lambda: performance.historical_bytes(path, current),
        "old_bytes": lambda: performance.historical_bytes(path, before),
        "unchanged": lambda: performance.historical_bytes("architecture/repositories.yaml", b"unrelated"),
        "historical_test": lambda: performance.historical_test_bytes(current),
        "current_test": lambda: performance.current_test_bytes(before),
        "catalog": lambda: performance.historical_catalog(current_packets),
        "runner_old": lambda: runner.historical_bytes(roadmap.MASTER_PATH, runner_old),
        "roadmap_old": lambda: roadmap.historical_bytes(roadmap.MASTER_PATH, roadmap_old),
    }
    routes[route]()
    original = performance.regular_bytes

    def changed_reader(relative):
        raw = original(relative)
        return raw + b" " if relative == performance.AUTHORITY_PATH else raw

    monkeypatch.setattr(performance, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="schema performance history authority digest"):
        routes[route]()


@pytest.mark.parametrize("path,message", [
    # The newer MET-LINUX-005 layer refuses a mutated validator before this layer.
    ("scripts/validate_packet_schema_performance.py", "unreviewed current source: scripts/validate_packet_schema_performance.py"),
    ("task-packets/MET-001.yaml", "changed predecessor YAML"),
    ("task-packets/MET-PERF-028.yaml", "schema performance packet YAML drift"),
])
def test_schema_performance_validation_freshly_rejects_source_drift(monkeypatch, path, message):
    performance, _, _ = _history_modules()
    original = performance.regular_bytes

    def changed_reader(relative):
        raw = original(relative)
        return raw + b" " if relative == path else raw

    monkeypatch.setattr(performance, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match=message):
        performance.validate()


@pytest.mark.parametrize("fault", ["duplicate_offset", "boolean_offset", "negative_offset", "outside_bound", "bad_base64", "no_change", "overlap"])
def test_schema_performance_inverse_parser_rejects_malformed_routes(monkeypatch, fault):
    performance, _, _ = _history_modules()
    record = deepcopy(performance.authority())
    path = next(iter(record["changedFiles"]))
    hunks = record["changedFiles"][path]["reverseHunks"]
    if fault == "duplicate_offset":
        hunks.insert(0, deepcopy(hunks[0]))
    elif fault == "boolean_offset":
        hunks[0]["at"] = True
    elif fault == "negative_offset":
        hunks[0]["at"] = -1
    elif fault == "outside_bound":
        hunks[0]["at"] = performance.MAX_FILE_BYTES + 1
    elif fault == "bad_base64":
        hunks[0]["insertBase64"] += "!"
    elif fault == "no_change":
        hunks[0]["insertBase64"] = hunks[0]["removeBase64"]
    else:
        hunks[:] = [{"at": 0, "removeBase64": "YWJj", "insertBase64": "eA=="},
                    {"at": 1, "removeBase64": "Yg==", "insertBase64": "eQ=="}]
    monkeypatch.setattr(performance, "authority", lambda: record)
    with pytest.raises(ValueError):
        performance._rules()


def test_schema_performance_inverse_rules_are_immutable_and_exact():
    performance, _, _ = _history_modules()
    path = next(iter(performance._PROJECTION_RULES))
    rule = performance._PROJECTION_RULES[path]
    with pytest.raises(TypeError):
        performance._PROJECTION_RULES[path] = {}
    with pytest.raises(TypeError):
        rule["afterSha256"] = "0" * 64
    raw = performance.regular_bytes(path)
    with pytest.raises(ValueError, match="inverse hunk current bytes"):
        performance._inverse(raw, ((0, b"not-current", b"old"),))
    with pytest.raises(ValueError, match="inverse hunk bounds"):
        performance._inverse(raw, ((len(raw) + 1, b"", b"old"),))


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_schema_performance_authority_parser_rejects_ambiguous_json(raw):
    performance, _, _ = _history_modules()
    with pytest.raises(ValueError):
        performance.parse(raw)


@pytest.mark.parametrize("route", ["source", "historical_test", "current_test"])
def test_schema_performance_projection_rejects_mutable_input(route):
    performance, _, _ = _history_modules()
    if route == "source":
        call = lambda: performance.historical_bytes("unrelated.txt", bytearray(b"mutable"))
    elif route == "historical_test":
        call = lambda: performance.historical_test_bytes(bytearray(b"mutable"))
    else:
        call = lambda: performance.current_test_bytes(bytearray(b"mutable"))
    with pytest.raises(ValueError):
        call()


def test_schema_performance_projection_never_imports_predecessor_source():
    performance, _, _ = _history_modules()
    tree = ast.parse(performance.regular_bytes("scripts/validate_packet_schema_performance.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert "validate_" not in (node.module or "")
        elif isinstance(node, ast.Import):
            # Only the newer successor layer may be imported, never a predecessor.
            assert all("validate_" not in alias.name or alias.name == "validate_linux_runner_contract"
                       for alias in node.names)


@pytest.mark.parametrize("route", ["guard", "runner_authority", "runner_old_bytes"])
def test_freshness_only_routes_read_full_authority_without_reparsing(monkeypatch, route):
    performance, runner, _ = _history_modules()
    raw = performance.regular_bytes(performance.AUTHORITY_PATH)
    if route == "guard":
        call = performance.fresh_authority
    elif route == "runner_authority":
        call = runner.authority
    else:
        path = next(iter(runner._PROJECTION_RULES))
        old = runner.historical_bytes(path, runner.regular_bytes(path))
        call = lambda: runner.historical_bytes(path, old)

    original = performance.regular_bytes
    reads = []
    tampered = False

    def read_source(path):
        nonlocal tampered
        actual = original(path)
        if path == performance.AUTHORITY_PATH:
            reads.append(actual)
            return actual + b" " if tampered else actual
        return actual

    monkeypatch.setattr(performance, "regular_bytes", read_source)

    def forbid_parse(_raw):
        raise AssertionError("freshness-only route reparsed successor authority")

    monkeypatch.setattr(performance, "parse", forbid_parse)
    call()
    call()
    assert reads == [raw, raw]
    tampered = True
    with pytest.raises(ValueError, match="schema performance history authority digest"):
        call()
    assert reads == [raw, raw, raw]


@pytest.mark.parametrize("route,first,message", [
    ("runner_authority", "old", "CI runner history authority digest"),
    ("runner_old_bytes", "new", "schema performance history authority digest"),
    ("runner_current_bytes", "new", "schema performance history authority digest"),
    ("runner_catalog", "new", "schema performance history authority digest"),
])
def test_runner_bridge_retains_each_routes_authority_refusal_order(monkeypatch, route, first, message):
    performance, runner, _ = _history_modules()
    if route == "runner_authority":
        call = runner.authority
    elif route == "runner_catalog":
        current = _current_catalog(performance)
        call = lambda: runner.historical_catalog(current)
    elif route == "runner_current_bytes":
        path = next(iter(runner._PROJECTION_RULES))
        current = runner.regular_bytes(path)
        call = lambda: runner.historical_bytes(path, current)
    else:
        path = next(iter(runner._PROJECTION_RULES))
        old = runner.historical_bytes(path, runner.regular_bytes(path))
        call = lambda: runner.historical_bytes(path, old)
    events = []
    original_old = runner.regular_bytes
    original_new = performance.regular_bytes

    def read_old(path):
        raw = original_old(path)
        if path == runner.AUTHORITY_PATH:
            events.append("old")
            return raw + b" "
        return raw

    def read_new(path):
        raw = original_new(path)
        if path == performance.AUTHORITY_PATH:
            events.append("new")
            return raw + b" "
        return raw

    monkeypatch.setattr(runner, "regular_bytes", read_old)
    monkeypatch.setattr(performance, "regular_bytes", read_new)
    with pytest.raises(ValueError, match=message):
        call()
    assert events == [first]


def test_retained_019_failure_is_not_a_predecessor_or_a_new_execution_grant():
    performance, _, _ = _history_modules()
    record = json.loads(performance.regular_bytes(
        "architecture/packet-schema-performance-inputs/prior-local-failure.json"))
    assert record["packetId"] == "MET-PERF-019"
    assert record["status"] == "RETAINED_FAILURE_NOT_ACCEPTED_PREDECESSOR"
    assert record["attempt"]["status"] == "LOCAL_FAILED_OR_INCOMPLETE"
    assert record["attempt"]["commandsReached"] == 52
    assert record["attempt"]["commandsExpected"] == 53
    assert record["attempt"]["completedNestedSummary"] is False
    assert record["attempt"]["completedOuterSummary"] is False
    assert len(record["immutableEvidenceSha256"]) == 16
    assert all(len(value) == 64 for value in record["immutableEvidenceSha256"].values())
    policy = record["successorPolicy"]
    assert policy["packetId"] == "MET-PERF-020"
    assert performance.NEW_PACKET == "MET-PERF-028"
    assert (policy["cumulativeLocalCeiling"], policy["consumedPrior"],
            policy["proposedMaximumAdditionalLocal"]) == (2, 1, 1)
    assert policy["newExecutionGrants"] == 0
    assert policy["budgetReset"] is False
    assert policy["automaticCiOrExactMain"] is False
    names = {path.stem for path in (performance.ROOT / "task-packets").glob("*.yaml")}
    assert len(names) == 194 and performance.NEW_PACKET in names and "MET-PERF-019" not in names and "MET-PERF-020" not in names
