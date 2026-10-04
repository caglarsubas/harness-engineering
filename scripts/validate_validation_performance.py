#!/usr/bin/env python3
"""Pinned source-only performance authority. No product imports or execution."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import stat
from types import MappingProxyType

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

try:
    from validate_completion_profiling import historical_bytes as profiling_history, current_test_bytes as profiling_current, validate_additions as profiling_additions
except ImportError:
    from scripts.validate_completion_profiling import historical_bytes as profiling_history, current_test_bytes as profiling_current, validate_additions as profiling_additions

try:
    from validate_ci_runner_admission import historical_bytes as runner_history
except ImportError:
    from scripts.validate_ci_runner_admission import historical_bytes as runner_history

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/validation-performance-authority.json"
RECORD_SHA256 = "d914c4bbf00fe3d98a1db63c834203ef4452c10ca185a792c364aef0bbd06db4"
NEW_IDS = ("MET-PERF-010",)
RECORD_FILE_SHA256 = "88e3a3e95b32aa5eee7d34f9124bf60c724c538ba4ebad5a6ed906a0d3e62507"
HISTORY_PATHS = frozenset(["README.md","docs/DEVELOPMENT_STATUS.md","docs/MASTER_DEVELOPMENT_PLAN.md","docs/READINESS_INDEX.md","docs/alpha-2/CANONICAL_REPAIR_PLAN.md","docs/alpha-2/LIVE_BACKEND_READINESS.md","docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md","docs/repositories/00-harness-engineering.md","docs/repositories/12-mas-harness-conformance-labs.md","scripts/validate_backend_timing.py","scripts/validate_broker_handoff.py","scripts/validate_canonical_repair_plan.py","scripts/validate_ci_performance.py","scripts/validate_conformance_completion.py","scripts/validate_conformance_consumer_closure.py","scripts/validate_conformance_performance.py","scripts/validate_conformance_performance_followup.py","scripts/validate_conformance_publication.py","scripts/validate_conformance_reference_measurement.py","scripts/validate_conformance_successor_checkpoint.py","scripts/validate_credential_lifecycle.py","scripts/validate_credential_ordering.py","scripts/validate_custody_handoff.py","scripts/validate_linux_readiness.py","scripts/validate_linux_repair.py","scripts/validate_linux_test_ownership.py","scripts/validate_live_backend_readiness.py","scripts/validate_local_acceptance.py","scripts/validate_model_api_inventory.py","scripts/validate_model_fixture_scope.py","scripts/validate_native_qualification.py","scripts/validate_packet_scalar_repair.py","scripts/validate_policy_observation.py","scripts/validate_provider_adoption.py","scripts/validate_proxy_contract.py","scripts/validate_proxy_diagnostics.py","scripts/validate_readiness.py","scripts/validate_readiness_repairs.py","scripts/validate_research_adoption.py","scripts/validate_reuse.py","scripts/validate_successor_inventory.py","task-packets/README.md","tests/test_alpha2_readiness.py","tests/test_backend_timing.py","tests/test_broker_handoff.py","tests/test_canonical_repair_plan.py","tests/test_ci_performance.py","tests/test_conformance_completion.py","tests/test_conformance_consumer_closure.py","tests/test_conformance_performance.py","tests/test_conformance_performance_followup.py","tests/test_conformance_publication.py","tests/test_conformance_reference_measurement.py","tests/test_conformance_successor_checkpoint.py","tests/test_credential_lifecycle.py","tests/test_credential_ordering.py","tests/test_custody_handoff.py","tests/test_linux_readiness.py","tests/test_linux_repair.py","tests/test_linux_test_ownership.py","tests/test_live_backend_readiness.py","tests/test_local_acceptance.py","tests/test_model_api_inventory.py","tests/test_model_fixture_scope.py","tests/test_native_qualification.py","tests/test_packet_scalar_repair.py","tests/test_policy_observation.py","tests/test_provider_adoption.py","tests/test_proxy_contract.py","tests/test_proxy_diagnostics.py","tests/test_research_adoption.py","tests/test_reuse.py","tests/test_successor_inventory.py","tests/test_task_packets.py"])


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, "duplicate JSON member")
            value[key] = item
        return value
    def nonfinite(_):
        raise ValueError("nonfinite JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def regular_bytes(root, path):
    require(type(path) is str and path and not path.startswith("/")
            and all(x not in ("", ".", "..") for x in path.split("/")), "relative path")
    current = Path(root)
    for part in path.split("/")[:-1]:
        current /= part
        require(stat.S_ISDIR(current.lstat().st_mode), "linked ancestor")
    target = current / path.split("/")[-1]
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= 16777216, "bounded unlinked regular file")
    raw = target.read_bytes()
    after = target.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size, "file changed")
    return raw


def pinned(record):
    require(type(record) is dict and digest(canonical(record)) == RECORD_SHA256, "exact performance authority")


def _record():
    # Fresh read and byte digest every invocation; never cache parsed authority.
    raw = regular_bytes(ROOT, RECORD_PATH)
    require(digest(raw) == RECORD_FILE_SHA256, "exact fresh authority bytes")
    return parse(raw)


def _freeze_projection_rules():
    """Freeze only inverse recipes; current authority bytes are never cached."""
    record = _record()
    require(set(record["metaRecipes"]) == HISTORY_PATHS, "exact historical routing")
    return MappingProxyType({
        path: (
            rule["beforeSha256"],
            rule["afterSha256"],
            tuple((row["before"], row["after"], row["count"])
                  for row in rule["replacements"]),
        )
        for path, rule in record["metaRecipes"].items()
    })


_PROJECTION_RULES = _freeze_projection_rules()


def _checked_projection_rule(path):
    # Preserve a complete fresh regular-file read and SHA on every projection.
    raw = regular_bytes(ROOT, RECORD_PATH)
    require(digest(raw) == RECORD_FILE_SHA256, "exact fresh authority bytes")
    frozen = _PROJECTION_RULES.get(path)
    if frozen is None:
        return None
    before_sha, after_sha, replacements = frozen
    return {
        "beforeSha256": before_sha,
        "afterSha256": after_sha,
        "replacements": [
            {"before": before, "after": after, "count": count}
            for before, after, count in replacements
        ],
    }


def apply_recipe(before, rule):
    require(type(before) is bytes and type(rule) is dict
            and set(rule) == {"beforeSha256", "afterSha256", "replacements"}
            and digest(before) == rule["beforeSha256"], "exact before bytes")
    current = before
    for item in rule["replacements"]:
        require(type(item) is dict and set(item) == {"before", "after", "count"}
                and type(item["before"]) is type(item["after"]) is str
                and item["before"] and item["before"] != item["after"]
                and type(item["count"]) is int and item["count"] > 0, "closed effective replacement")
        old, new = item["before"].encode(), item["after"].encode()
        require(current.count(old) == item["count"], "replacement cardinality")
        current = current.replace(old, new)
    require(digest(current) == rule["afterSha256"], "exact current source")
    return current


def historical_bytes(path, raw):
    raw = profiling_history(path, runner_history(path, raw))
    # A closed code-pinned routing table, not an acceptance/result cache.
    # Unchanged inputs still receive the predecessor caller's exact hash check.
    if path not in HISTORY_PATHS:
        return raw
    rule = _checked_projection_rule(path)
    if rule is None:
        return raw
    require(type(raw) is bytes and digest(raw) == rule["afterSha256"], "current bytes changed: " + path)
    before = raw
    for row in reversed(rule["replacements"]):
        new, old = row["after"].encode(), row["before"].encode()
        require(before.count(new) == row["count"], "inverse cardinality")
        before = before.replace(new, old)
    require(apply_recipe(before, rule) == raw, "unreviewed inverse")
    return before


def current_test_bytes(before):
    require(type(before) is bytes, "test bytes")
    record = _record()
    input_digest = digest(before)
    matches = [r for p, r in record["metaRecipes"].items()
               if p.startswith("tests/") and r["beforeSha256"] == input_digest]
    if not matches:
        require(input_digest in record["unchangedTests"].values(), "unreviewed unchanged test")
        return profiling_current(before)
    require(len(matches) == 1, "unique predecessor")
    return profiling_current(apply_recipe(before, matches[0]))


def validate_additions(packets):
    try:
        record = _record()
        require(type(packets) is dict, "packet mapping")
        for name in NEW_IDS:
            require(digest(canonical(packets.get(name))) == record["packetDigests"][name], "packet substitution")
        return profiling_additions(packets)
    except (ValueError, TypeError, RecursionError):
        return ["missing or changed performance packets"]


def test_ids(raw):
    result = []
    def visit(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                result.append(prefix + node.name)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
    visit(ast.parse(raw).body)
    require(len(result) == len(set(result)), "duplicate test identity")
    return result


SPEC_PATH = "architecture/validation-performance.json"
EXPECTED_SPEC_SHA256 = "7a60958064001545103a5afa12006ff8d9fa6f3b438107ccbab3ed2b90c5f8ac"
EXPECTED_MEMBER_DIGESTS = {"schemaVersion":"0323884afdda87c3f237c77d43e0c802b31456a1fc65dc4dffa3668100adfb77","metaPacketId":"f7768b2a0512a2a4bb988f96b737f55af3ad99e50b5f0ceec9865d3dddd7cfe3","evidenceClass":"e09fa213b382a8b13fb816632566f8c5b0a90fb23105f0950f6d29145e8c4406","baseline":"7f28de39746d8fbc2470b96b4c28243890e4f8bdaed6297dd385ef7ac4f45040","draft":"29a0d8659bddcbc6505a50b965a3ffcea369f77887b9242e103b19f2f6fa830e","budgets":"56045148e11e659aee30068de8353bcf9f68810cf5cc39fbbd245c11503f636d","countCorrection":"af2773f5645cc43b5d93bc476e1dcd141016eaf3bb732141d129932c161fe716","limits":"f01324d1beff56d54760c31fc59b57598554d14c85ae01e980b715fc64dc8eee","oldBudgets":"2d57909c1c5e19f4ef663554ead12c48f2f60a64e838ed53ec9ac3318ca6decb","policies":"d0c5b6ecf0fcc85342792c2a3c0c5465c64d57dd47b65bf90f9255ed1ce2ca13","logicRegions":"22b349decad6bb1d530405511e90c303e88c03ea9f9706000e838fc93721ad06","serializer":"f44a2a9dfbd77971b0fe7912dca2f9e74d6d180f654c2b4f9b5a5ff355391324","testVectors":"a0aceedf597a1ab5937f749ad478cfb14bd924f63f89e9350911cc6299e30cfa","evidence":"89ad4a6536917699fa92ee57e4ff4599dd6425586b69e0892aed65fd149844ee","contractPins":"8251d320903dcd939a57c36f5b3b135d098de635fb81949843244177b1e92d8b"}

def validate_spec(spec, *, bind=True):
    """Exact non-promoting repair limits; no execution or acceptance capability."""
    require(type(spec) is dict and set(spec) == set(EXPECTED_MEMBER_DIGESTS), "closed repair specification")
    if bind:
        require(digest(canonical(spec)) == EXPECTED_SPEC_SHA256, "exact repair specification")
    for key, checksum in EXPECTED_MEMBER_DIGESTS.items():
        require(digest(canonical(spec[key])) == checksum, "repair boundary changed: " + key)
    require(spec["metaPacketId"] == "MET-PERF-010"
            and spec["baseline"]["commit"] == "b2705835139ece8954cf36f66ab0b5e8d8b3c10b"
            and spec["baseline"]["packetCount"] == 166, "accepted independent predecessor")
    require(spec["budgets"] == {"LOCAL": 3, "CI": 2, "LOCAL_EXACT_MAIN": 1,
                                "diagnostic": 0, "transfer": False, "resetOnCommit": False},
            "finite nontransferable allowance")
    require(spec["limits"] == {"nestedSeconds": 420, "hostSeconds": 900,
                              "workflowMinutes": 15, "localGateSeconds": 750,
                              "exactMainGateSeconds": 750}, "unchanged deadlines")
    require(spec["oldBudgets"]["remainingMetaLocal"] == 0
            and spec["oldBudgets"]["remainingDiagnostic"] == 0
            and spec["oldBudgets"]["reset"] is False, "old attempts remain consumed")


def load_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    paths = {*record["protectedFiles"], *record["inputFiles"], *record["metaRecipes"]}
    return record, {p: regular_bytes(root, p) for p in paths}


def validate_authority(packets, record, inputs):
    try:
        pinned(record)
        require(HISTORY_PATHS == set(record["metaRecipes"]), "exact history routing")
        require(validate_additions(packets) == [], "exact repair packet")
        pins = {**record["protectedFiles"], **record["inputFiles"],
                **{p: r["afterSha256"] for p, r in record["metaRecipes"].items()}}
        require(type(inputs) is dict and set(inputs) == set(pins), "fresh complete source inventory")
        for path, checksum in pins.items():
            require(type(inputs[path]) is bytes and digest(profiling_history(path, runner_history(path, inputs[path]))) == checksum,
                    "changed source: " + path)
        old = {Path(p).stem for p in record["protectedFiles"]
               if p.startswith("task-packets/") and p.endswith(".yaml")}
        require(len(old) == 166 and len(packets) == 194
                and set(packets) == old | set(NEW_IDS) | {"MET-PERF-009", "CONF-DIAG-003", "MET-PERF-011", "MET-PERF-012", "CONF-PERF-006", "CONF-BENCH-002", "MET-PERF-013", "CONF-BENCH-003", "MET-REPAIR-018", "CONF-FIX-008", "MET-PERF-014", "CONF-DIAG-004", "MET-PERF-015", "CONF-FIX-009", "MET-PERF-016", "MET-PERF-017", "MET-REPAIR-019", "MET-ENFORCE-001", "MET-PERF-018", "MET-ENFORCE-003", "CONF-FIX-010", "MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}, "166 immutable predecessors plus one repair")
        for name in old | set(NEW_IDS):
            require(canonical(packets[name]) == canonical(safe_load(inputs["task-packets/" + name + ".yaml"])),
                    "raw packet parity")
        packet, prior = packets["MET-PERF-010"], packets["MET-ADOPT-002"]
        require(packet["allowedPaths"] == record["ownedPaths"]
                and packet["predecessors"] == ["MET-ADOPT-002"]
                and packet["repository"] == "Harness-Engineering", "exact independent repair owner")
        commands, previous = packet["offlineAcceptanceCommands"], prior["offlineAcceptanceCommands"]
        require(len(commands) == 37 and commands[:-3] == previous[:-2]
                and commands[-2:] == previous[-2:]
                and commands[-3] == ["uv", "run", "--offline", "--frozen", "--no-sync",
                                     "python", "scripts/validate_validation_performance.py"]
                and packet["offlineExecution"] == prior["offlineExecution"], "full predecessor recipe")
        require(packet["sourceReuse"] == packet["prefetchCommands"] == []
                and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
                and "liveCampaignExecution" not in packet, "no new source/live authority")
        spec = parse(inputs[SPEC_PATH])
        validate_spec(spec)
        for path, checksum in spec["contractPins"].items():
            require(digest(runner_history(path, inputs[path])) == checksum, "unchanged contract or lock")
        for path, rule in record["metaRecipes"].items():
            before = historical_bytes(path, inputs[path])
            require(apply_recipe(before, rule) == profiling_history(path, runner_history(path, inputs[path])), "exact reversible repair")
            if path.startswith("tests/"):
                require(test_ids(before) == test_ids(inputs[path]), "all inherited test identities")
        for path in record["navigationPaths"]:
            require(b"MET-PERF-010" in inputs[path]
                    and b"VALIDATION_PERFORMANCE_REPAIR.md" in inputs[path]
                    and b"WAITING_PREDECESSOR_CORRECTION" in inputs[path]
                    and b"NOT_DUE" in inputs[path], "consistent current navigation")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, SyntaxError,
            RecursionError) as exc:
        return ["invalid validation-performance authority: " + str(exc)]


if __name__ == "__main__":
    packets = {p.stem: safe_load(p.read_bytes()) for p in (ROOT / "task-packets").glob("*.yaml")}
    errors = validate_authority(packets, *load_inputs(ROOT))
    if errors:
        print("\n".join(errors))
        raise SystemExit(1)
    print("Validation-performance authority valid:194 specifications;166 unchanged packets; "
          "bounded digest/fixture repair; no product or acceptance promotion.")
