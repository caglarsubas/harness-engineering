"""Independent DATA-only protocol/model tests; never installed/native evidence."""
import ast
from copy import deepcopy
import itertools
import json
from pathlib import Path

import jsonschema
import pytest

from scripts.safe_yaml import safe_load
from scripts.validate_native_qualification import historical_bytes as qualification_history
from scripts.validate_broker_handoff import (
    BEFORE_PATH, CHECKPOINT_PATH, SCHEMA_PATH, VECTORS_PATH, COMMON, ZERO, CASES,
    FenceModel, _shape, _tests, apply_recipe, canonical, current_test_bytes,
    digest, historical_bytes, load_handoff_inputs, validate_additions,
    validate_binding, validate_handoff, validate_transcript,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem:safe_load(p.read_bytes()) for p in (ROOT / "task-packets").glob("*.yaml")}
    return packets, *load_handoff_inputs(ROOT)


@pytest.fixture(scope="module")
def data(authority):
    return json.loads(authority[2][SCHEMA_PATH]), json.loads(authority[2][VECTORS_PATH])


def reseal(frames):
    previous = ZERO
    for sequence, frame in enumerate(frames, 1):
        frame.update(sequence=sequence, previousDigest=previous)
        previous = "sha256:" + digest(canonical(frame))
    return frames


def model():
    resources = {case:[] for case in CASES}
    resources[CASES[0]] = ["resource-one", "resource-two"]
    return FenceModel("generation-a", resources)


def test_exact_authority_catalog_and_immutable_consumer_checkpoint(authority):
    packets, record, inputs = authority
    assert validate_handoff(*authority) == []
    assert len(packets) == 194
    assert sum(p.startswith("task-packets/") for p in record["protectedFiles"]) == 142
    assert len(packets["MET-REPAIR-014"]["offlineAcceptanceCommands"]) == 22
    checkpoint = json.loads(inputs[CHECKPOINT_PATH])
    assert checkpoint["commit"] == "9df7dd7f2df8ac64096ef37d8df259761947d552"
    assert checkpoint["tree"] == "1310cc74cc0ed39cfeb1068e998a0f78502a4be4"
    assert len(checkpoint["files"]) == 127
    assert sum(map(len, checkpoint["tests"].values())) == 327
    assert record["stages"] == [110,120,127,135,141,146,151]
    assert set(record["dispatch"]) == {"CONF-LIVE-003","CONF-LIVE-004","CONF-LIVE-005","CONF-LIVE-006"}
    assert all(len(v["commands"]) == 8 for v in record["dispatch"].values())


@pytest.mark.parametrize("index", [0,1])
def test_complete_resource_and_zero_resource_transcripts_are_only_data(data, index):
    schema, vectors = data
    sample = vectors["positive"][index]
    assert validate_binding(sample["binding"], sample["profile"], sample["observationBinding"], schema) is None
    assert validate_transcript(sample["binding"], sample["request"], sample["frames"], schema) == []
    assert vectors["evidenceClass"] == "DATA_CHECK_ONLY"
    assert vectors["nativeAcceptance"] is vectors["tenantAcceptance"] is False
    if index == 0:
        assert sample["profile"]["binding"]["apiEndpointId"] is None
        assert not sample["profile"]["capacityEntries"]["kubernetesApiRules"]
        assert not any(f["kind"].startswith("RESOURCE_") for f in sample["frames"])


@pytest.mark.parametrize("variant", ["binding", "dispatch", "frame", "workerStart"])
def test_every_closed_nested_object_rejects_extra_missing_and_wrong_type(data, variant):
    schema, vectors = data
    sample = vectors["positive"][1]
    values = [sample["binding"]] if variant == "binding" else [sample["request"]] if variant == "dispatch" else sample["frames"]
    if variant == "workerStart":
        values = [dict(schemaVersion="planeon.internal.broker-worker/v1", operation="START",
            executionId="c" * 64, bindingDigest=sample["request"]["bindingDigest"],
            caseId=CASES[0], requestDigest=sample["request"]["requestDigest"], generation="a" * 64)]
    def objects(value, path=()):
        if type(value) is dict:
            yield path, value
            for key, item in value.items():
                yield from objects(item, path + (key,))
        elif type(value) is list:
            for key, item in enumerate(value):
                yield from objects(item, path + (key,))
    for value in values:
        for path, mapping in objects(value):
            for key in [None, *mapping]:
                changed = deepcopy(value)
                parent = changed
                for part in path:
                    parent = parent[part]
                if key is None:
                    parent["unreviewed"] = True
                else:
                    del parent[key]
                with pytest.raises((ValueError, jsonschema.ValidationError)):
                    _shape(changed, variant, schema)
            for key in mapping:
                changed = deepcopy(value)
                parent = changed
                for part in path:
                    parent = parent[part]
                parent[key] = {"truthy": True}
                with pytest.raises((ValueError, jsonschema.ValidationError)):
                    _shape(changed, variant, schema)


@pytest.mark.parametrize("field", COMMON)
def test_each_scope_and_generation_substitution_fails_even_with_rehashed_chain(data, field):
    schema, vectors = data
    sample = vectors["positive"][0]
    frames = deepcopy(sample["frames"])
    original = frames[1][field]
    frames[1][field] = CASES[1] if field == "caseId" else "other-run" if field == "runNonce" else original[:-1] + ("d" if original[-1] != "d" else "e")
    assert validate_transcript(sample["binding"], sample["request"], reseal(frames), schema)


@pytest.mark.parametrize("fault", ["missing-start","duplicate-start","sequence-gap","old-hash","new-execution",
    "missing-terminal","after-terminal","duplicate-chunk","wrong-receipt","not-reaped","missing-cleanup",
    "cleanup-substitution","zero-resource-action","token-grant","abort","refused"])
def test_protocol_failure_and_ambiguous_completion_never_complete(data, fault):
    schema, vectors = data
    sample = vectors["positive"][0]
    frames = deepcopy(sample["frames"])
    if fault == "missing-start": frames.pop(0)
    if fault == "duplicate-start": frames.insert(1, deepcopy(frames[0]))
    if fault == "new-execution": frames[1]["executionId"] = "f" * 64
    if fault == "missing-terminal": frames.pop()
    if fault == "after-terminal": frames.append(deepcopy(frames[-1]))
    if fault == "duplicate-chunk": frames.insert(2, deepcopy(frames[1]))
    if fault == "wrong-receipt": frames[-1]["payload"]["receiptDigest"] = ZERO
    if fault == "not-reaped": frames[-1]["payload"]["workerReaped"] = False
    if fault == "missing-cleanup": frames.pop(-2)
    if fault == "cleanup-substitution": frames[-1]["payload"]["cleanupDigest"] = ZERO
    if fault == "zero-resource-action":
        frame = deepcopy(vectors["positive"][1]["frames"][1])
        frame.update({k:sample["request"][k] for k in COMMON})
        frames.insert(1, frame)
    if fault in ("token-grant","abort","refused"):
        frames[0]["kind"] = {"token-grant":"GRANTED", "abort":"ABORT", "refused":"REFUSED"}[fault]
        frames[0]["payload"] = {"reason":"REVOKED" if fault == "abort" else "UNAVAILABLE"}
    reseal(frames)
    if fault == "sequence-gap": frames[1]["sequence"] += 1
    if fault == "old-hash": frames[1]["previousDigest"] = ZERO
    assert validate_transcript(sample["binding"], sample["request"], frames, schema)


@pytest.mark.parametrize("fault", ["action-overlap","wrong-action-result","foreign-manifest","chunk-during-action",
    "duplicate-action","noncanonical-base64","oversize-chunk","pending-completed"])
def test_resource_message_and_cleanup_failures_are_independent_of_chain(data, fault):
    schema, vectors = data
    sample = vectors["positive"][1]
    frames = deepcopy(sample["frames"])
    if fault == "action-overlap": frames.insert(2, deepcopy(frames[1]))
    if fault == "wrong-action-result": frames[2]["payload"]["actionId"] += 1
    if fault == "foreign-manifest": frames[1]["payload"]["manifestDigest"] = ZERO
    if fault == "chunk-during-action": frames.insert(2, deepcopy(frames[-3]))
    if fault == "duplicate-action": frames[3]["payload"]["actionId"] = 1
    if fault == "noncanonical-base64": frames[-3]["payload"]["dataBase64"] = "YQ=== "
    if fault == "oversize-chunk": frames[-3]["payload"]["dataBase64"] = "YWFh" * 8193
    if fault == "pending-completed":
        row = sample["profile"]["resources"][0]
        manifest = row["manifest"]
        frames[-2]["payload"].update(state="CLEANUP_PENDING", remainingResources=[dict(
            apiVersion="v1",kind=manifest["kind"],namespace=manifest["metadata"]["namespace"],
            name=manifest["metadata"]["name"],uid=None,manifestDigest=row["manifestDigest"],reasonCode="IO_AMBIGUOUS")])
    assert validate_transcript(sample["binding"], sample["request"], reseal(frames), schema)


@pytest.mark.parametrize("fault", ["duplicate-owner","missing-resource","extra-resource","profile-substitution","observer-substitution"])
def test_binding_cannot_create_or_reassign_capacity(data, fault):
    schema, vectors = data
    sample = vectors["positive"][1]
    binding = deepcopy(sample["binding"])
    if fault == "duplicate-owner": binding["caseResourceDigests"][CASES[1]] = list(binding["caseResourceDigests"][CASES[0]])
    if fault == "missing-resource": binding["caseResourceDigests"][CASES[0]].pop()
    if fault == "extra-resource": binding["caseResourceDigests"][CASES[1]] = [ZERO]
    if fault == "profile-substitution": binding["profileDigest"] = ZERO
    if fault == "observer-substitution": binding["observationBindingDigest"] = ZERO
    with pytest.raises(ValueError):
        validate_binding(binding, sample["profile"], sample["observationBinding"], schema)


@pytest.mark.parametrize("order", list(itertools.permutations(("server-a","server-b","server-c"))))
def test_all_competing_admission_interleavings_have_one_shared_winner(order):
    state = model()
    state.admit(order[0], CASES[0], "generation-a")
    for contender in order[1:]:
        with pytest.raises(ValueError):
            state.admit(contender, CASES[0], "generation-a")
        with pytest.raises(ValueError):
            state.effect(contender, CASES[0], "generation-a")
    state.effect(order[0], CASES[0], "generation-a")
    assert len(state.effects) == len(state.consumed) == 1
    assert state.nativeAcceptance is state.tenantAcceptance is False


def test_normal_policy_update_waits_until_reaped_completed_transaction():
    state = model()
    state.admit("run", CASES[0], "generation-a")
    assert state.policy_change("generation-b") == "DEFERRED"
    assert state.generation == "generation-a"
    state.effect("run", CASES[0], "generation-a")
    with pytest.raises(ValueError): state.finish()
    state.reap()
    state.finish()
    assert state.generation == "generation-b"
    with pytest.raises(ValueError): state.effect("run", CASES[0], "generation-a")
    with pytest.raises(ValueError): state.admit("run", CASES[0], "generation-b")


@pytest.mark.parametrize("when", ["before-effect", "after-effect", "after-create"])
def test_urgent_revocation_stops_new_effects_and_never_erases_prior_effects(when):
    state = model()
    state.admit("run", CASES[0], "generation-a")
    if when == "after-effect": state.effect("run", CASES[0], "generation-a")
    if when == "after-create": state.effect("run", CASES[0], "generation-a", "resource-one", "CREATE")
    count = len(state.effects)
    assert state.policy_change("generation-b", urgent=True) == "DEFERRED"
    with pytest.raises(ValueError): state.effect("run", CASES[0], "generation-a")
    state.reap()
    with pytest.raises(ValueError): state.finish()
    assert len(state.effects) == count
    assert state.active is not None


@pytest.mark.parametrize("persistence", ["PARTIAL", "AMBIGUOUS"])
def test_durable_write_failure_consumes_case_holds_capacity_and_denies_effect(persistence):
    state = model()
    with pytest.raises(ValueError): state.admit("run", CASES[0], "generation-a", persistence)
    assert ("run", CASES[0]) in state.consumed
    assert state.poisoned
    with pytest.raises(ValueError): state.effect("run", CASES[0], "generation-a")
    with pytest.raises(ValueError): state.admit("other", CASES[1], "generation-a")


def test_crash_and_lost_create_response_keep_unknown_uid_and_forbid_blind_delete():
    state = model()
    state.admit("run", CASES[0], "generation-a")
    state.effect("run", CASES[0], "generation-a", "resource-one", "CREATE")
    assert state.created["resource-one"] is None
    with pytest.raises(ValueError): state.effect("run", CASES[0], "generation-a", "resource-one", "DELETE", "guessed")
    with pytest.raises(ValueError): state.effect("run", CASES[0], "generation-a", "resource-one", "CREATE")
    state.crash()
    with pytest.raises(ValueError): state.confirmed_absent("resource-one", "guessed")
    assert state.created["resource-one"] is None
    assert state.active is not None


def test_exact_uid_absence_and_reaping_required_without_name_reuse():
    state = model()
    state.admit("run", CASES[0], "generation-a")
    state.effect("run", CASES[0], "generation-a", "resource-one", "CREATE")
    state.created_response("resource-one", "created-uid")
    for uid in (None, "other-uid"):
        with pytest.raises(ValueError): state.effect("run", CASES[0], "generation-a", "resource-one", "DELETE", uid)
        with pytest.raises(ValueError): state.confirmed_absent("resource-one", uid)
    with pytest.raises(ValueError): state.confirmed_absent("resource-one", "created-uid")
    state.effect("run", CASES[0], "generation-a", "resource-one", "DELETE", "created-uid")
    state.confirmed_absent("resource-one", "created-uid")
    with pytest.raises(ValueError): state.effect("run", CASES[0], "generation-a", "resource-one", "CREATE")
    state.reap()
    state.finish()
    assert ("run", CASES[0]) in state.consumed


def test_zero_resource_case_still_requires_broker_and_rejects_every_api_action():
    state = model()
    case = CASES[1]
    with pytest.raises(ValueError): state.effect("run", case, "generation-a")
    state.admit("run", case, "generation-a")
    for verb in ("CREATE","GET","DELETE"):
        with pytest.raises(ValueError): state.effect("run", case, "generation-a", "resource-one", verb)
    state.effect("run", case, "generation-a")
    state.reap()
    state.finish()


@pytest.mark.parametrize("pretend", [True, {"granted":True}, {"generation":"generation-a"}, ["AUTHORITY","FENCED"]])
def test_flags_tokens_callbacks_and_trace_lists_cannot_replace_shared_state(pretend):
    state = model()
    with pytest.raises(ValueError): state.admit(pretend, CASES[0], "generation-a")
    with pytest.raises(ValueError): state.effect("run", CASES[0], pretend)
    assert not state.effects


def test_all_prior_source_bytes_and_test_identities_have_exact_current_recipes(authority):
    _, record, inputs = authority
    before = json.loads(inputs[BEFORE_PATH])["files"]
    assert set(before) == set(record["metaRecipes"])
    for path, rule in record["metaRecipes"].items():
        raw = before[path].encode()
        assert apply_recipe(raw, rule) == qualification_history(path, inputs[path])
        assert historical_bytes(path, inputs[path]) == raw
        if path.startswith("tests/"):
            assert _tests(raw) == _tests(inputs[path])
            assert current_test_bytes(raw) == inputs[path]
        with pytest.raises(ValueError): historical_bytes(path, inputs[path] + b"\n# unreviewed\n")


@pytest.mark.parametrize("field", ["allowedPaths","contracts","predecessors","sourceReuse","offlineAcceptanceCommands","offlineExecution"])
def test_packet_and_recipe_scope_cannot_be_relaxed(authority, field):
    changed = deepcopy(authority[0])
    changed["MET-REPAIR-014"][field] = {"unreviewed":True}
    assert validate_additions(changed)
    assert validate_handoff(changed, *authority[1:])


def test_missing_unknown_and_modified_inputs_fail(authority):
    packets, record, inputs = authority
    assert validate_handoff(packets, record, {**inputs,"unowned":b"x"})
    for path in (BEFORE_PATH,SCHEMA_PATH,VECTORS_PATH,CHECKPOINT_PATH,"task-packets/CONF-LIVE-003.yaml"):
        changed = dict(inputs)
        changed[path] += b" "
        assert validate_handoff(packets, record, changed)
    changed = deepcopy(record)
    changed["nativeAcceptance"] = True
    assert validate_handoff(packets, changed, inputs)


def test_data_oracle_cannot_execute_snapshots_or_native_primitives():
    tree = ast.parse((ROOT / "scripts/validate_broker_handoff.py").read_bytes())
    forbidden = {"exec","eval","compile","__import__","socket","connect","Popen","system","load_cert_chain"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func,"attr","")
            assert name not in forbidden


def test_unchanged_legacy_test_bridge_accepts_only_six_exact_pinned_sources(authority):
    _, record, inputs = authority
    assert len(record["unchangedTests"]) == 6
    for path, checksum in record["unchangedTests"].items():
        raw = inputs[path]
        assert digest(raw) == checksum
        assert current_test_bytes(raw) == raw
        with pytest.raises(ValueError): current_test_bytes(raw + b"\n# altered\n")
    with pytest.raises(ValueError): current_test_bytes(b"def test_unknown(): pass\n")


@pytest.mark.parametrize("outcome", ["DENIED", "AMBIGUOUS", "DELETED"])
def test_denied_ambiguous_or_wrong_verb_result_cannot_produce_completed(data, outcome):
    schema, vectors = data
    sample = vectors["positive"][1]
    frames = deepcopy(sample["frames"])
    frames[2]["payload"].update(outcome=outcome, objectBase64=None)
    assert validate_transcript(sample["binding"], sample["request"], reseal(frames), schema)


def test_absolute_deadline_revokes_execution_without_releasing_consumed_case():
    state = model()
    state.admit("run", CASES[0], "generation-a")
    state.advance(899)
    state.effect("run", CASES[0], "generation-a")
    state.advance(1)
    with pytest.raises(ValueError): state.effect("run", CASES[0], "generation-a")
    state.reap()
    with pytest.raises(ValueError): state.finish()
    assert ("run", CASES[0]) in state.consumed
    for invalid in (-1, True, 1.5):
        with pytest.raises(ValueError): state.advance(invalid)


def test_delete_ambiguity_cannot_be_retried_with_the_same_uid():
    state = model()
    state.admit("run", CASES[0], "generation-a")
    state.effect("run", CASES[0], "generation-a", "resource-one", "CREATE")
    state.created_response("resource-one", "created-uid")
    state.effect("run", CASES[0], "generation-a", "resource-one", "DELETE", "created-uid")
    with pytest.raises(ValueError):
        state.effect("run", CASES[0], "generation-a", "resource-one", "DELETE", "created-uid")
    assert state.created["resource-one"] == "created-uid"


def test_roadmap_distinguishes_source_publication_from_product_and_native_acceptance():
    current = (ROOT / "docs/DEVELOPMENT_STATUS.md").read_text().split("## Historical MET-REPAIR-015 publication checkpoint\n",1)[1].split("## Historical MET-REPAIR-013")[0]
    assert "during `MET-REPAIR-015` publication" in current
    assert "MET-REPAIR-013 / PR108 | DONE_SOURCE_GATES" in current
    assert "MET-REPAIR-015 | ONGOING" in current
    assert "127 files / 327 tests" in current
    assert "NOT_RUN_ENV_UNAVAILABLE" in current and "effort transition NOT_DUE" in current
