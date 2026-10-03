#!/usr/bin/env python3
"""Non-authorizing broker protocol and shared-state DATA oracle; no native I/O."""
from __future__ import annotations

import ast
import base64
from pathlib import Path

import jsonschema
import yaml

try:
    from safe_yaml import safe_load
    from validate_proxy_contract import canonical, digest, parse, regular_bytes, CASES, _bounded
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts.validate_proxy_contract import canonical, digest, parse, regular_bytes, CASES, _bounded

try:
    from validate_native_qualification import historical_bytes as qualification_history, current_test_bytes as qualification_current, validate_additions as qualification_additions
except ImportError:
    from scripts.validate_native_qualification import historical_bytes as qualification_history, current_test_bytes as qualification_current, validate_additions as qualification_additions

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/broker-handoff-amendment.json"
BEFORE_PATH = "architecture/broker-handoff-inputs/meta-before.json"
SCHEMA_PATH = "architecture/broker-handoff-inputs/channel.schema.json"
VECTORS_PATH = "architecture/broker-handoff-inputs/vectors.json"
CHECKPOINT_PATH = "architecture/credential-ordering-inputs/checkpoint.json"
RECORD_SHA256 = "2012532803f16e846b537cc377e9125d90a15a6190ccce4a181b10f4192380a7"
PACKET_SHA256 = "37063b4b23be808442a48002c917afbb1d2ac15f75bf8fbb0e5ce739a9f3cfba"
ZERO = "sha256:" + "0" * 64
BRIDGED_PATHS = frozenset(["docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md","docs/adr/0004-sol-high-packet-boundary.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_ci_performance.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_proxy_contract.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_ci_performance.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_proxy_contract.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])
COMMON = ("bindingDigest", "reservationDigest", "runNonce", "caseId", "requestDigest",
          "observationDigest", "generation", "challenge")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pinned(record):
    require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256,
            "exact broker authority required")


def _record():
    record = parse(regular_bytes(ROOT, RECORD_PATH))
    pinned(record)
    return record


def validate_additions(packets):
    try:
        require(type(packets) is dict and digest(canonical(packets.get("MET-REPAIR-014"))) == PACKET_SHA256,
                "exact broker packet required")
        return qualification_additions(packets)
    except (ValueError, TypeError, RecursionError):
        return ["missing or changed broker handoff packet"]


def apply_recipe(before, recipe):
    require(type(before) is bytes and type(recipe) is dict
            and set(recipe) == {"beforeSha256", "afterSha256", "replacements"}
            and digest(before) == recipe["beforeSha256"], "exact before bytes required")
    result = before
    require(type(recipe["replacements"]) is list, "ordered recipe required")
    for row in recipe["replacements"]:
        require(type(row) is dict and set(row) == {"before", "after", "count"}
                and type(row["before"]) is type(row["after"]) is str
                and type(row["count"]) is int and row["count"] > 0
                and row["before"] and row["before"] != row["after"], "closed effective recipe required")
        old, new = row["before"].encode(), row["after"].encode()
        require(result.count(old) == row["count"], "recipe cardinality differs")
        result = result.replace(old, new)
    require(digest(result) == recipe["afterSha256"], "unreviewed replacement bytes")
    return result


def historical_bytes(path, raw):
    """Check exact current replacements before exposing old bytes to old pins."""
    raw = qualification_history(path, raw)
    if path not in BRIDGED_PATHS:
        return raw
    record = _record()
    rule = record["metaRecipes"].get(path)
    if rule is None or not rule["replacements"]:
        return raw
    require(type(raw) is bytes and digest(raw) == rule["afterSha256"], "current bytes differ: " + path)
    before = raw
    for replacement in reversed(rule["replacements"]):
        current, old = replacement["after"].encode(), replacement["before"].encode()
        require(before.count(current) == replacement["count"], "inverse recipe cardinality")
        before = before.replace(current, old)
    require(digest(before) == rule["beforeSha256"] and apply_recipe(before, rule) == raw, "invalid inverse recipe")
    return before


def current_test_bytes(before):
    require(type(before) is bytes, "test source bytes required")
    record = _record()
    input_digest = digest(before)
    matches = [r for p, r in record["metaRecipes"].items()
               if p.startswith("tests/") and r["beforeSha256"] == input_digest]
    if not matches:
        require(input_digest in record["unchangedTests"].values(), "unreviewed unchanged test source")
        return qualification_current(before)
    require(len(matches) == 1, "exact predecessor test source required")
    return qualification_current(apply_recipe(before, matches[0]))


def _shape(value, variant, schema):
    _bounded(value)
    limit = 16384 if variant in ("dispatch", "workerStart") else 65536
    require(len(canonical(value)) <= limit, "bounded message required")
    jsonschema.Draft202012Validator({**schema, "oneOf": [{"$ref": "#/$defs/" + variant}]}).validate(value)


def validate_binding(binding, profile, observation_binding, schema):
    """Data relationships only; never an installed broker/worker capability."""
    _shape(binding, "binding", schema)
    require(binding["profileDigest"] == "sha256:" + digest(canonical(profile))
            and binding["observationBindingDigest"] == "sha256:" + digest(canonical(observation_binding)),
            "release inputs differ")
    assigned = [d for case in CASES for d in binding["caseResourceDigests"][case]]
    require(len(assigned) == len(set(assigned)) and set(assigned) == {r["manifestDigest"] for r in profile["resources"]},
            "exact disjoint case resource ownership required")
    return None


def validate_transcript(binding, request, frames, schema):
    """Reject structural/transcript ambiguity; no enforcement result is issued."""
    try:
        _shape(binding, "binding", schema)
        _shape(request, "dispatch", schema)
        require(request["bindingDigest"] == "sha256:" + digest(canonical(binding)), "binding mismatch")
        require(type(frames) is list and 2 <= len(frames) <= 2048, "bounded transcript required")
        previous, execution, pending, chunk_index = ZERO, None, None, 0
        actions, payload, cleanup, ended, action_failed = set(), bytearray(), None, False, False
        for sequence, frame in enumerate(frames, 1):
            _shape(frame, "frame", schema)
            require(not ended and all(frame[k] == request[k] for k in COMMON), "scope/generation changed")
            require(frame["sequence"] == sequence and frame["previousDigest"] == previous, "frame chain mismatch")
            if execution is None:
                require(frame["kind"] == "STARTED", "controlled start required")
                execution = frame["executionId"]
            else:
                require(frame["executionId"] == execution and frame["kind"] != "STARTED", "execution replay")
            kind, data = frame["kind"], frame["payload"]
            if kind == "RESOURCE_ACTION":
                require(pending is None and not payload and cleanup is None
                        and data["actionId"] not in actions
                        and data["manifestDigest"] in binding["caseResourceDigests"][request["caseId"]],
                        "unowned/overlapping resource action")
                pending = data
                actions.add(data["actionId"])
            elif kind == "RESOURCE_RESULT":
                require(pending is not None and pending["actionId"] == data["actionId"], "result has no matching action")
                outcomes = {"CREATE": {"CREATED"}, "GET": {"ABSENT", "PRESENT"}, "DELETE": {"DELETED"}}
                require(data["outcome"] in outcomes[pending["verb"]] | {"DENIED", "AMBIGUOUS"}, "verb/outcome mismatch")
                action_failed |= data["outcome"] in ("DENIED", "AMBIGUOUS")
                if data["objectBase64"] is not None:
                    raw = base64.b64decode(data["objectBase64"], validate=True)
                    require(len(raw) <= 16384 and base64.b64encode(raw).decode() == data["objectBase64"]
                            and canonical(parse(raw)) == raw, "noncanonical resource data")
                require((data["outcome"] in ("CREATED", "PRESENT")) == (data["objectBase64"] is not None),
                        "resource outcome/data mismatch")
                pending = None
            elif kind == "RECEIPT_CHUNK":
                require(pending is None and cleanup is None and data["index"] == chunk_index, "chunk ordering")
                raw = base64.b64decode(data["dataBase64"], validate=True)
                require(0 < len(raw) <= 24576 and base64.b64encode(raw).decode() == data["dataBase64"], "canonical chunk")
                payload.extend(raw)
                require(len(payload) <= 4194304, "receipt size")
                chunk_index += 1
            elif kind == "CLEANUP_RECORDED":
                require(pending is None and payload and cleanup is None, "cleanup order")
                require((data["state"] == "CLEAN") == (not data["remainingResources"]), "cleanup state mismatch")
                names = set()
                for row in data["remainingResources"]:
                    key = (row["kind"], row["namespace"], row["name"])
                    require(key not in names and row["manifestDigest"] in binding["caseResourceDigests"][request["caseId"]]
                            and (row["uid"] is not None or row["reasonCode"] == "IO_AMBIGUOUS"), "cleanup scope")
                    names.add(key)
                cleanup = data
            elif kind == "TERMINAL":
                require(pending is None and cleanup is not None and len(payload) == data["receiptSize"]
                        and "sha256:" + digest(bytes(payload)) == data["receiptDigest"]
                        and data["cleanupDigest"] == cleanup["cleanupDigest"], "terminal receipt mismatch")
                require(data["status"] != "COMPLETED" or cleanup["state"] == "CLEAN" and not action_failed,
                        "failed action or pending cleanup is not completed")
                ended = True
            elif kind != "STARTED":
                raise ValueError("aborted/refused transcript cannot complete")
            previous = "sha256:" + digest(canonical(frame))
        require(ended, "terminal frame missing")
        return []
    except (ValueError, TypeError, KeyError, RecursionError, jsonschema.ValidationError):
        return ["invalid DATA_CHECK_ONLY transcript; no native authority"]


class FenceModel:
    """Shared in-memory specification model ONLY, never production admission.

    Methods mutate plain test state so interleavings can be explored. No field
    or result from this model can construct a product protected handle.
    """
    evidenceClass = "DATA_CHECK_ONLY"
    nativeAcceptance = tenantAcceptance = False

    def __init__(self, generation, case_resources):
        require(type(generation) is str and type(case_resources) is dict and set(case_resources) == set(CASES), "model input")
        self.generation, self.resources = generation, {k: frozenset(v) for k,v in case_resources.items()}
        self.consumed, self.active, self.poisoned, self.pending_generation = set(), None, False, None
        self.created, self.used_names, self.effects, self.deletions = {}, set(), [], set()
        self.now, self.deadline = 0, 900

    def admit(self, run, case, generation, persistence="SYNCED"):
        require(type(run) is str and type(case) is str and case in CASES and type(generation) is str,
                "closed model identity")
        require(not self.poisoned and self.now < self.deadline and self.active is None and generation == self.generation
                and (run, case) not in self.consumed, "shared admission denied")
        self.consumed.add((run, case))
        self.active = dict(run=run, case=case, generation=generation, gate=False, reaped=False, invalid=False)
        require(persistence in ("SYNCED", "PARTIAL", "AMBIGUOUS"), "model persistence")
        if persistence != "SYNCED":
            self.poisoned = True
            raise ValueError("ambiguous durable consumption holds capacity")
        self.active["gate"] = True

    def effect(self, run, case, generation, manifest=None, verb=None, uid=None):
        active = self.active
        require(not self.poisoned and self.now < self.deadline and active is not None and active["gate"] and not active["reaped"]
                and not active["invalid"] and (run, case, generation) ==
                (active["run"], active["case"], self.generation), "no active broker execution")
        if manifest is not None:
            require(type(manifest) is str and manifest in self.resources[case] and verb in ("CREATE", "GET", "DELETE"),
                    "resource action outside case")
            if verb == "CREATE":
                require(manifest not in self.used_names, "no adoption or name reuse")
                self.used_names.add(manifest)
                self.created[manifest] = None  # intent is held before a response
            elif verb == "DELETE":
                require(type(uid) is str and self.created.get(manifest) == uid
                        and (manifest, uid) not in self.deletions, "exact recorded UID and no blind retry required")
                self.deletions.add((manifest, uid))
        else:
            require(verb is None and uid is None, "no generic operation")
        self.effects.append((run, case, generation, manifest, verb))

    def created_response(self, manifest, uid):
        require(not self.poisoned and self.active is not None and not self.active["invalid"]
                and self.active["gate"] and type(uid) is str and uid
                and manifest in self.created and self.created[manifest] is None, "unowned create response")
        self.created[manifest] = uid

    def confirmed_absent(self, manifest, uid):
        require(self.active is not None and self.active["gate"] and not self.active["invalid"]
                and type(uid) is str and self.created.get(manifest) == uid
                and (manifest, uid) in self.deletions, "independent exact absence required")
        del self.created[manifest]
        self.deletions.remove((manifest, uid))

    def policy_change(self, generation, urgent=False):
        require(type(generation) is str and generation != self.generation and type(urgent) is bool, "model generation")
        if self.active is not None:
            self.pending_generation = generation
            if urgent:
                self.active.update(gate=False, invalid=True)
            return "DEFERRED"
        self.generation = generation
        return "APPLIED"

    def reap(self):
        require(self.active is not None, "no worker")
        self.active.update(gate=False, reaped=True)

    def finish(self):
        require(not self.poisoned and self.active is not None and self.active["reaped"]
                and not self.active["invalid"] and not self.created, "execution or cleanup unproven")
        self.active = None
        if self.pending_generation is not None:
            self.generation, self.pending_generation = self.pending_generation, None

    def crash(self):
        self.poisoned = True
        if self.active is not None:
            self.active.update(gate=False, invalid=True)

    def advance(self, seconds):
        require(type(seconds) is int and 0 <= seconds <= 900, "monotonic bounded model time")
        self.now += seconds
        if self.now >= self.deadline and self.active is not None:
            self.active.update(gate=False, invalid=True)


def _tests(raw):
    result = []
    def visit(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                result.append(prefix + node.name)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
    visit(ast.parse(raw).body)
    require(len(result) == len(set(result)), "duplicate prior test")
    return result


def load_handoff_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    return record, {p:regular_bytes(root, p) for p in
                    {*record["protectedFiles"], *record["inputFiles"], *record["metaRecipes"]}}


def validate_handoff(packets, record, inputs):
    try:
        pinned(record)
        require(not validate_additions(packets), "broker packet changed")
        pins = {**record["protectedFiles"], **record["inputFiles"],
                **{p:r["afterSha256"] for p,r in record["metaRecipes"].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), "exact input set")
        for p, checksum in pins.items():
            require(type(inputs[p]) is bytes and digest(qualification_history(p, inputs[p])) == checksum, "current input changed: " + p)
        require(all(p in record["protectedFiles"] and digest(qualification_history(p, inputs[p])) == checksum
                    for p, checksum in record["unchangedTests"].items()), "unchanged test pins differ")
        old = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/")}
        require(len(old) == 142 and len(packets) == 194 and set(packets) == old | {"MET-REPAIR-014", "MET-REPAIR-015", "MET-PERF-002", "CONF-PERF-001", "MET-PERF-003", "CONF-PERF-002", "MET-PERF-004", "CONF-PERF-003", "MET-PERF-005", "CONF-PERF-004", "CONF-BENCH-001", "MET-REPAIR-016", "CONF-FIX-006", "MET-ADOPT-001", "MET-PERF-006", "CONF-DIAG-001", "MET-PERF-007", "MET-PERF-008", "CONF-DIAG-002", "MET-ACCEPT-001", "MET-PUBLISH-001", "MET-REPAIR-017", "CONF-FIX-007", "MET-ADOPT-002", "MET-PERF-010", "MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010", "MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}, "exact catalog")
        for name in old | {"MET-REPAIR-014"}:
            require(canonical(packets[name]) == canonical(safe_load(inputs["task-packets/" + name + ".yaml"])), "packet bytes")
        packet = packets["MET-REPAIR-014"]
        previous = packets["MET-REPAIR-013"]["offlineAcceptanceCommands"]
        require(packet["offlineAcceptanceCommands"] == [*previous[:-2],
            ["uv", "run", "--offline", "--frozen", "--no-sync", "python", "scripts/validate_broker_handoff.py"],
            *previous[-2:]] and len(packet["offlineAcceptanceCommands"]) == 22, "cumulative recipe")
        require(packet["allowedPaths"] == record["ownedPaths"], "path grant")
        before = parse(inputs[BEFORE_PATH])
        require(before["baseCommit"] == record["metaBaseline"] and set(before["files"]) == set(record["metaRecipes"]), "before inventory")
        for p, rule in record["metaRecipes"].items():
            raw = before["files"][p].encode()
            require(apply_recipe(raw, rule) == qualification_history(p, inputs[p]), "unreviewed replacement")
            if p.startswith("tests/"):
                require(_tests(raw) == _tests(inputs[p]), "predecessor test identity changed")
        checkpoint = parse(inputs[CHECKPOINT_PATH])
        require(checkpoint["commit"] == record["sourceBaseline"]["commit"]
                and checkpoint["tree"] == record["sourceBaseline"]["tree"]
                and len(checkpoint["files"]) == 127 and sum(map(len, checkpoint["tests"].values())) == 327,
                "source checkpoint changed")
        for name, dispatch in record["dispatch"].items():
            require(packets[name]["allowedPaths"] == dispatch["paths"]
                    and packets[name]["offlineAcceptanceCommands"] == dispatch["commands"], "consumer drift")
        schema, vectors = parse(inputs[SCHEMA_PATH]), parse(inputs[VECTORS_PATH])
        jsonschema.Draft202012Validator.check_schema(schema)
        require(vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["nativeAcceptance"] is False
                and vectors["tenantAcceptance"] is False, "evidence promotion")
        for sample in vectors["positive"]:
            require(not validate_transcript(sample["binding"], sample["request"], sample["frames"], schema), "positive protocol")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError, RecursionError,
            jsonschema.ValidationError, jsonschema.SchemaError, yaml.YAMLError) as exc:
        return ["invalid broker handoff authority: " + (str(exc) if type(exc) is ValueError else type(exc).__name__)]


def main():
    try:
        packets = {p.stem:safe_load(regular_bytes(ROOT, str(p.relative_to(ROOT))))
                   for p in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_handoff(packets, *load_handoff_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        errors = ["broker authority unavailable"]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Broker handoff valid: 194 packets; 127/327 checkpoint; DATA_CHECK_ONLY; product/native NOT_RUN.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
