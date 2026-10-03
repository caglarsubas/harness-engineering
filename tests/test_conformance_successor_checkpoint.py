"""Inert source/authority checks only. No product source is imported or executed."""
from copy import deepcopy
import json

import pytest

from scripts.validate_provider_adoption import historical_bytes as adoption_history

from scripts.safe_yaml import safe_load
from scripts import validate_conformance_successor_checkpoint as module


@pytest.fixture(scope="module")
def authority():
    packets = {p.stem: safe_load(p.read_bytes()) for p in (module.ROOT / "task-packets").glob("*.yaml")}
    return packets, *module.load_inputs(module.ROOT)


def candidate(authority):
    _, record, inputs = authority
    before = json.loads(inputs[module.PRODUCT_PATH])["files"]
    old = before[module.SUP].encode()
    start, end, _ = module.region(old, module.REGION)
    replacement = record["replacement"]["after"].encode()
    # Synthetic source strings are data for scope checking, never loaded tests.
    append = "\n\nclass SuccessorCheckpointRepairTests(unittest.TestCase):\n"
    for name in record["requiredNewTestIds"]:
        append += "    def " + name.split(".")[1] + "(self):\n        self.assertEqual(1, 1)\n\n"
    raw = old[:start] + replacement + old[end:] + append.encode()
    binding = dict(schemaVersion="planeon.internal.successor-checkpoint-correction/v1",
        evidenceClass="SOURCE_DELTA_ONLY", packetId="CONF-FIX-006", authorityDigest=module.RECORD_SHA256,
        baseCommit=record["sourceBaseline"]["commit"], beforeTestSha256=module.digest(old),
        afterTestSha256=module.digest(raw), originalProofSha256=record["originalProofSha256"],
        replacementSha256=module.digest(replacement), addedTestIds=record["requiredNewTestIds"])
    prefix, legacy = module.legacy_proof(before[module.DOC].encode())
    suffix = module.CORRECTION_MARKER + module.canonical(binding) + b"\n```\n"
    legacy["documentSuffix"] += suffix.decode()
    legacy["sources"][module.SUP]["append"] = legacy["sources"][module.SUP]["append"].replace(old[start:end].decode(), replacement.decode()) + append
    legacy["sources"][module.SUP]["afterSha256"] = module.digest(raw)
    legacy["newTestIds"] = sorted(legacy["newTestIds"] + binding["addedTestIds"])
    return {module.SUP: raw, module.DOC: prefix + suffix + module.LEGACY_MARKER + module.canonical(legacy) + b"\n```\n"}, binding


def test_current155_catalog_preserves153_yaml_and_exact_two_path_scope(authority):
    packets, record, inputs = authority
    assert module.validate_authority(*authority) == []
    assert len(packets) == 194
    assert packets["CONF-FIX-006"]["allowedPaths"] == [module.DOC, module.SUP]
    assert packets["CONF-FIX-006"]["predecessors"] == ["MET-REPAIR-016", "CONF-PERF-004"]
    assert packets["MET-REPAIR-016"]["offlineAcceptanceCommands"][:-3] == packets["MET-PERF-005"]["offlineAcceptanceCommands"][:-2]
    assert packets["MET-REPAIR-016"]["offlineAcceptanceCommands"][-2:] == packets["MET-PERF-005"]["offlineAcceptanceCommands"][-2:]
    assert len(packets["CONF-FIX-006"]["offlineAcceptanceCommands"]) == 8
    assert sum(p.startswith("task-packets/") and p.endswith(".yaml") for p in record["protectedFiles"]) == 153
    for path, pin in record["protectedFiles"].items():
        assert module.digest(adoption_history(path, inputs[path])) == pin


def test_original_v4_proof_and_b758_checkpoint_remain_immutable(authority):
    _, record, inputs = authority
    before = json.loads(inputs[module.PRODUCT_PATH])
    checkpoint = json.loads(inputs[module.CHECKPOINT_PATH])
    assert before["baseCommit"] == checkpoint["commit"] == "b7586c4b8315dc92051f0b5445b2a9a0204a97bf"
    assert (len(checkpoint["files"]), sum(map(len, checkpoint["tests"].values()))) == (127, 354)
    _, proof = module.legacy_proof(before["files"][module.DOC].encode())
    assert proof["packetId"] == "CONF-PERF-004" and proof["schemaVersion"].endswith("/v4")
    assert module.digest(module.canonical(proof)) == record["originalProofSha256"]
    assert len(record["requiredNewTestIds"]) == 8


def test_exact_meta_replacements_keep_all_old_test_identities(authority):
    _, record, inputs = authority
    before = json.loads(inputs[module.BEFORE_PATH])["files"]
    for path, rule in record["metaRecipes"].items():
        raw = before[path].encode()
        assert module.apply_recipe(raw, rule) == adoption_history(path, inputs[path])
        assert module.historical_bytes(path, inputs[path]) == raw
        if path.startswith("tests/"):
            assert module.test_ids(raw) == module.test_ids(inputs[path])
            assert module.current_test_bytes(raw) == inputs[path]
        with pytest.raises(ValueError):
            module.historical_bytes(path, inputs[path] + b"\n")


def test_record_bytes_are_fresh_and_identity_route_is_not_acceptance(monkeypatch):
    raw = module.regular_bytes(module.ROOT, module.RECORD_PATH)
    calls = []
    def reader(root, path):
        calls.append(path)
        return raw if len(calls) == 1 else raw + b" "
    monkeypatch.setattr(module, "regular_bytes", reader)
    assert module.historical_bytes("unowned.txt", b"untrusted") == b"untrusted" and calls == []
    assert module._record()["authorityPacket"] == "MET-REPAIR-016"
    with pytest.raises(ValueError):
        module._record()
    assert calls == [module.RECORD_PATH] * 2


@pytest.mark.parametrize("fault", ["record", "old-yaml", "new-packet", "input", "before", "source", "missing", "extra", "scope", "commands"])
def test_authority_tampering_refuses(authority, fault):
    packets, record, inputs = deepcopy(authority)
    if fault == "record": record["approvalDate"] = "old"
    if fault == "old-yaml": inputs["task-packets/CONF-PERF-004.yaml"] += b" "
    if fault == "new-packet": packets["CONF-FIX-006"]["id"] = "CONF-FIX-007"
    if fault == "input": inputs[module.CHECKPOINT_PATH] += b" "
    if fault == "before": inputs[module.BEFORE_PATH] += b" "
    if fault == "source": inputs[module.PRODUCT_PATH] += b" "
    if fault == "missing": inputs.pop(module.PRODUCT_PATH)
    if fault == "extra": inputs["unapproved"] = b"x"
    if fault == "scope": packets["CONF-FIX-006"]["allowedPaths"].append("src/harness_conformance/crypto.py")
    if fault == "commands": packets["CONF-FIX-006"]["offlineAcceptanceCommands"].pop()
    assert module.validate_authority(packets, record, inputs)


def test_two_path_projection_is_data_only_and_has_separate_current_binding(authority):
    after, binding = candidate(authority)
    assert module.validate_product_delta(after, binding, authority[1], authority[2]) == []
    assert binding["packetId"] == "CONF-FIX-006" and binding["evidenceClass"] == "SOURCE_DELTA_ONLY"
    assert module.legacy_proof(after[module.DOC])[1]["packetId"] == "CONF-PERF-004"
    assert "nativeAcceptance" not in binding and "tenantAcceptance" not in binding


@pytest.mark.parametrize("fault", ["runtime", "method", "old-byte", "duplicate-method", "skip", "override", "shadow", "oversize", "binding", "native", "projection", "prefix", "duplicate-proof", "original-proof"])
def test_product_scope_and_proof_substitution_refuse(authority, fault):
    after, binding = candidate(authority)
    if fault == "runtime": after["src/harness_conformance/crypto.py"] = b"x"
    if fault == "method": after[module.SUP] = after[module.SUP].replace(b"self.assertIn(stage, (2, 3, 4, 5, 6))", b"self.assertTrue(True)")
    if fault == "old-byte": after[module.SUP] = after[module.SUP].replace(b"import pickle", b"import random", 1)
    if fault == "duplicate-method": after[module.SUP] += b"\nclass Duplicate:\n    def test_a(self): pass\n    def test_a(self): pass\n"
    if fault == "skip": after[module.SUP] += b"\n@unittest.skip('hidden')\nclass Hidden: pass\n"
    if fault == "override": after[module.SUP] += b"\ndef load_tests(a,b,c): return b\n"
    if fault == "shadow": after[module.SUP] += b"\nclass FakeBoundary: pass\n"
    if fault == "oversize": after[module.SUP] += b"\n" * 131073
    if fault == "binding": binding["packetId"] = "CONF-PERF-004"
    if fault == "native": binding["nativeAcceptance"] = True
    if fault == "projection": after[module.DOC] = after[module.DOC].replace(b'"packetId":"CONF-PERF-004"', b'"packetId":"CONF-FIX-006"')
    if fault == "prefix": after[module.DOC] = b"unreviewed\n" + after[module.DOC]
    if fault == "duplicate-proof": after[module.DOC] += module.CORRECTION_MARKER + b"{}\n```\n"
    if fault == "original-proof": binding["originalProofSha256"] = "0" * 64
    assert module.validate_product_delta(after, binding, authority[1], authority[2])


def stage_data(record, stage):
    paths = list(record["checkpointFiles"])
    tests = {}
    for path, methods in record["checkpointTests"].items():
        classes = {}
        for method in methods:
            owner, name = method.split(".")
            classes.setdefault(owner, []).append(name)
        tests[path] = "\n".join("class " + owner + ":\n" + "\n".join("    def " + name + "(self): return None" for name in names) for owner, names in classes.items()).encode()
    for number in range(3, stage + 1):
        for path in record["successorPaths"][str(number)]:
            paths.append(path)
            if path.startswith("tests/") and path.rsplit("/",1)[-1].startswith("test_") and path.endswith(".py"):
                tests[path] = b"class UnitOnly:\n    def test_data(self): return None\n"
    return paths, tests


@pytest.mark.parametrize("stage,count", [(2,127),(3,135),(4,141),(5,146),(6,151)])
def test_all_five_exact_stage_maps_are_non_authorizing_data(authority, stage, count):
    paths, tests = stage_data(authority[1], stage)
    selected, methods = module.stage_test_map(paths, tests, authority[1])
    assert selected == stage and len(paths) == count and set(methods) == set(tests)


@pytest.mark.parametrize("fault", ["missing", "extra", "duplicate", "partial", "missing-test", "extra-test", "method", "shadow", "class-shadow", "extra-old-method", "collector"])
def test_partial_stage_or_incomplete_method_inventory_refuses(authority, fault):
    paths, tests = stage_data(authority[1], 3)
    if fault == "missing": paths.pop()
    if fault == "extra": paths.append("unapproved.py")
    if fault == "duplicate": paths.append(paths[0])
    if fault == "partial": paths.append(authority[1]["successorPaths"]["4"][0])
    if fault == "missing-test": tests.pop(next(iter(tests)))
    if fault == "extra-test": tests["tests/live_backend/test_unknown.py"] = b"class X:\n def test_x(self): pass\n"
    if fault == "method": tests[module.SUP] = b"class X:\n def test_x(self): pass\n"
    if fault == "shadow": tests[module.SUP] += b"\nclass Duplicate:\n def test_x(self): pass\n def test_x(self): pass\n"
    if fault == "class-shadow": tests[module.SUP] += b"\nclass Duplicate:\n def test_a(self): pass\nclass Duplicate:\n def test_b(self): pass\n"
    if fault == "extra-old-method": tests[next(p for p in authority[1]["checkpointTests"] if p != module.SUP)] += b"\nclass Unapproved:\n def test_extra(self): pass\n"
    if fault == "collector": tests[module.SUP] += b"\ndef load_tests(a,b,c): return b\n"
    with pytest.raises(ValueError):
        module.stage_test_map(paths, tests, authority[1])


def test_exact_dispatch_preserves_prior72_and_only_closes_eight_additional_pairs(authority):
    from scripts.validate_packet_ownership import validate_packet_ownership
    from scripts.validate_conformance_reference_measurement import validate_dispatch_ownership
    generic = validate_packet_ownership(authority[0])
    assert len(generic) == 118
    closed = module.close_dispatch_errors(authority[0], generic)
    assert len(closed) == 110
    assert validate_dispatch_ownership(authority[0]) == []
    assert module.close_dispatch_errors(authority[0], generic + ["unrelated error"])[-1] == "unrelated error"


@pytest.mark.parametrize("fault", ["missing", "extra"])
def test_history_routes_cannot_hide_changes(authority, monkeypatch, fault):
    paths = set(module.HISTORY_PATHS)
    if fault == "missing": paths.remove("scripts/validate_readiness.py")
    else: paths.add("unapproved.py")
    monkeypatch.setattr(module, "HISTORY_PATHS", frozenset(paths))
    assert module.validate_authority(*authority)


def test_failure_and_phase_axes_are_not_promoted(authority):
    failure = authority[1]["failure"]
    assert (failure["testsRun"], failure["passed"], failure["failures"], failure["skips"]) == (425,424,1,0)
    assert failure["attemptedCommands"] == 6 and failure["notRunCommands"] == [7,8]
    assert failure["nativeAcceptance"] is failure["tenantAcceptance"] is failure["sourceComplete"] is False
    assert failure["result"]["exitCode"] == 1


@pytest.mark.parametrize("fault", ["changed", "missing", "wrong-type"])
def test_product_oracle_checks_original_input_independently(authority, fault):
    after, binding = candidate(authority)
    inputs = deepcopy(authority[2])
    if fault == "changed": inputs[module.PRODUCT_PATH] += b" "
    if fault == "missing": inputs.pop(module.PRODUCT_PATH)
    if fault == "wrong-type": inputs[module.PRODUCT_PATH] = inputs[module.PRODUCT_PATH].decode()
    assert module.validate_product_delta(after, binding, authority[1], inputs)
