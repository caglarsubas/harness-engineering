#!/usr/bin/env python3
"""Data-only cumulative inventory authority; never executes product snapshots."""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
import re
import stat

import yaml

try:
    from safe_yaml import safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import safe_load as safe_yaml_load

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/successor-inventory-amendment.json"
RECORD_SHA256 = "491c3ee536b0be231be7f29e3580f357659c7012ec54077268e23aa1f08f48e0"
ADDITIONS = ("MET-REPAIR-008", "CONF-FIX-003")
PACKET_DIGESTS = {"MET-REPAIR-008": "f5dbeed173a73d67e57d7f125ca75de371270b007ad79fdf6cd71176bfbc4740", "CONF-FIX-003": "501835bccacab44ec4961f1c48a15cce76371565b4a8382f65536316eb7ac57c"}
BASELINE_PATH = "architecture/successor-inventory-inputs/baseline.json"
TEST_BEFORE_PATH = "architecture/successor-inventory-inputs/test_packet_scalars.before.txt"
LAUNCHER_BEFORE_PATH = "architecture/successor-inventory-inputs/live_launcher.before.txt"
ROW_FIELDS = {"path", "mode", "size", "sha256", "kind", "nlink", "linkedAncestry"}
PROOF_FIELDS = {"schemaVersion", "evidenceClass", "packetId", "packetSha256", "path", "beforeSha256", "prefixSha256", "suffixSha256", "replacement", "afterSha256"}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def nonfinite(_):
    raise ValueError("nonfinite JSON")


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def regular_bytes(root, relative):
    if type(relative) is not str or not relative or relative.startswith("/"):
        raise ValueError("relative authority path required")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("noncanonical authority path")
    path = root
    for index, part in enumerate(parts):
        path = path / part
        info = path.lstat()
        check = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if not check(info.st_mode) or index == len(parts) - 1 and info.st_nlink != 1:
            raise ValueError("linked or nonregular authority input")
    return path.read_bytes()


def pinned(record):
    if digest(canonical(record)) != RECORD_SHA256:
        raise ValueError("exact reviewed successor authority required")


def load_successor_inputs(root):
    record = parse(regular_bytes(root, RECORD_PATH))
    pinned(record)
    pins = {**record["protectedFiles"], **record["inputFiles"], **record["packetDigests"]}
    return record, {path: regular_bytes(root, path) for path in pins}


def validate_additions(packets):
    if type(packets) is not dict:
        return ["packet mapping required"]
    errors = []
    for packet_id, expected in PACKET_DIGESTS.items():
        try:
            if digest(canonical(packets.get(packet_id))) != expected:
                errors.append("exact cumulative repair packet changed: " + packet_id)
        except (TypeError, ValueError, RecursionError):
            errors.append("malformed cumulative repair packet")
    return errors


def corrected_test(before, record):
    pinned(record)
    change = record["change"]
    if type(before) is not bytes or digest(before) != change["beforeSha256"]:
        raise ValueError("wrong original test bytes")
    current = before
    for hunk in change["hunks"]:
        old, new = hunk["beforeBlock"].encode(), hunk["afterBlock"].encode()
        if current.count(old) != 1:
            raise ValueError("nonunique test hunk")
        prefix, suffix = current.split(old)
        if digest(prefix) != hunk["prefixSha256"] or digest(suffix) != hunk["suffixSha256"]:
            raise ValueError("test context changed")
        current = prefix + new + suffix
    if digest(current) != change["afterSha256"]:
        raise ValueError("wrong corrected test bytes")
    return current


def parse_hook_proof(document):
    if type(document) is not bytes or len(document) > 262144:
        raise ValueError("bounded proof document required")
    marker = b"```harness-launcher-source-proof\n"
    if document.count(marker) != 1:
        raise ValueError("exactly one source proof fence required")
    tail = document.split(marker, 1)[1]
    if b"\n```" not in tail:
        raise ValueError("unterminated source proof")
    raw, closing = tail.split(b"\n```", 1)
    if closing and not closing.startswith(b"\n"):
        raise ValueError("source proof closing fence must end its line")
    if len(raw) > 16384:
        raise ValueError("source proof too large")
    result = parse(raw)
    if type(result) is not dict or set(result) != PROOF_FIELDS or any(type(v) is not str for v in result.values()):
        raise ValueError("closed string-only source proof required")
    return result


def validate_hook(before, after, proof, record):
    pinned(record)
    hook = record["hook"]
    if type(before) is not bytes or type(after) is not bytes or type(proof) is not dict or set(proof) != PROOF_FIELDS:
        raise ValueError("closed source proof and byte strings required")
    if any(type(value) is not str for value in proof.values()) or len(canonical(proof)) > hook["maxProofBytes"]:
        raise ValueError("bounded string-only source proof required")
    expected = {"schemaVersion": hook["proofSchemaVersion"], "evidenceClass": "SOURCE_DELTA_ONLY",
                **{key: hook[key] for key in ("packetId", "packetSha256", "path", "beforeSha256", "prefixSha256", "suffixSha256")}}
    if any(proof[key] != value for key, value in expected.items()):
        raise ValueError("source proof binding mismatch")
    old = hook["beforeBlock"].encode()
    if digest(before) != hook["beforeSha256"] or before.count(old) != 1:
        raise ValueError("wrong historical launcher")
    prefix, suffix = before.split(old)
    replacement = proof["replacement"].encode("ascii")
    if (not replacement or len(replacement) > hook["maxReplacementBytes"] or replacement == old
            or b"\r" in replacement or b"\0" in replacement or not replacement.endswith(b"\n")
            or any(line and not line.startswith(b"        ") for line in replacement.splitlines())):
        raise ValueError("hook must be one bounded indented replacement")
    if (digest(prefix) != hook["prefixSha256"] or digest(suffix) != hook["suffixSha256"]
            or after != prefix + replacement + suffix or digest(after) != proof["afterSha256"]):
        raise ValueError("unreviewed launcher bytes outside exact hook proof")


def validate_composition(rows, record, baseline, test_before, launcher_before, launcher_after, proof=None):
    """Pure metadata/byte oracle. A successful source check grants no execution."""
    pinned(record)
    if type(baseline) is not dict:
        raise ValueError("baseline required")
    regular_baseline_bytes(record, baseline)
    if type(launcher_before) is not bytes or digest(launcher_before) != record["hook"]["beforeSha256"]:
        raise ValueError("exact historical launcher bytes required at every stage")
    if type(rows) is not list:
        raise ValueError("file rows required")
    observed = {}
    for row in rows:
        if type(row) is not dict or set(row) != ROW_FIELDS:
            raise ValueError("closed inventory row required")
        path = row["path"]
        if (type(path) is not str or path.startswith("/") or any(p in ("", ".", "..") for p in path.split("/"))
                or path in observed or row["kind"] != "file" or type(row["nlink"]) is not int or row["nlink"] != 1
                or row["linkedAncestry"] is not False or row["mode"] not in ("100644", "100755")
                or type(row["size"]) is not int or not 0 <= row["size"] <= 16777216
                or type(row["sha256"]) is not str or re.fullmatch("[0-9a-f]{64}", row["sha256"]) is None):
            raise ValueError("invalid, duplicate or linked source row")
        observed[path] = row
    expected_paths = set(baseline["files"]) | set(record["repairPaths"])
    matches = []
    for stage in range(7):
        if stage:
            expected_paths.update(record["stages"][stage - 1]["paths"])
        if set(observed) == expected_paths:
            matches.append(stage)
    if len(matches) != 1:
        raise ValueError("only complete ordered source stages are permitted")
    stage = matches[0]
    if len(observed) != record["stageCounts"][stage]:
        raise ValueError("stage inventory count mismatch")
    corrected = corrected_test(test_before, record)
    if stage < 6:
        if proof is not None or launcher_after != launcher_before:
            raise ValueError("premature launcher change or proof")
    else:
        validate_hook(launcher_before, launcher_after, proof, record)
    for path, expected in baseline["files"].items():
        current = observed[path]
        size, checksum = expected["size"], expected["sha256"]
        if path == record["change"]["path"]:
            size, checksum = len(corrected), digest(corrected)
        elif path == record["hook"]["path"]:
            size, checksum = len(launcher_after), digest(launcher_after)
        if (current["mode"], current["size"], current["sha256"]) != (expected["mode"], size, checksum):
            raise ValueError("predecessor bytes or mode changed: " + path)
    for path in set(observed) - set(baseline["files"]):
        if observed[path]["mode"] != "100644":
            raise ValueError("new source must be non-executable")
    return {"stage": stage, "baselineFiles": 106, "trackedFiles": len(observed),
            "evidenceClass": "SOURCE_INVENTORY_ONLY", "nativeAcceptance": False}


def regular_baseline_bytes(record, baseline):
    # The record pins the exact pretty-printed baseline bytes, not caller paths.
    raw = (json.dumps(baseline, indent=2, sort_keys=True) + "\n").encode()
    if digest(raw) != record["inputFiles"][BASELINE_PATH]:
        raise ValueError("historical baseline changed")
    return raw


@lru_cache(maxsize=256)
def packet_semantics(raw):
    # Key by exact bytes: mutations cannot reuse a predecessor's parsed value.
    return canonical(safe_yaml_load(raw))


def validate_successor_inventory(packets, record, inputs):
    try:
        pinned(record)
        if type(packets) is not dict or type(inputs) is not dict:
            return ["packet and input maps required"]
        errors = validate_additions(packets)
        try:
            from validate_proxy_contract import ADDITIONS as PROXY_ADDITIONS, validate_additions as validate_proxy_additions
        except ImportError:
            from scripts.validate_proxy_contract import ADDITIONS as PROXY_ADDITIONS, validate_additions as validate_proxy_additions
        errors.extend(validate_proxy_additions(packets))
        pins = {**record["protectedFiles"], **record["inputFiles"], **record["packetDigests"]}
        old_ids = {Path(p).stem for p in record["protectedFiles"] if p.startswith("task-packets/")}
        if len(old_ids) != 132 or len(record["protectedFiles"]) != 170 or set(packets) != old_ids | set(ADDITIONS) | set(PROXY_ADDITIONS) | {"MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}:
            errors.append("exact historical 132 plus two inventory and one proxy prerequisite packets required")
        if set(inputs) != set(pins):
            errors.append("exact 188 authority inputs required")
        for path, expected in pins.items():
            raw = inputs.get(path)
            if type(raw) is not bytes or digest(raw) != expected:
                errors.append("immutable authority input changed: " + path)
            elif path.startswith("task-packets/") and canonical(packets.get(Path(path).stem)) != packet_semantics(raw):
                errors.append("packet semantic/byte mismatch: " + path)
        baseline = parse(inputs[BASELINE_PATH])
        if len(baseline["files"]) != 106 or sum(map(len, baseline["tests"].values())) != 150:
            errors.append("106-file/150-test baseline required")
        corrected_test(inputs[TEST_BEFORE_PATH], record)
        for stage in record["stages"]:
            spec = packets[stage["id"]]
            if (spec["allowedPaths"] != stage["paths"] or len(spec["offlineAcceptanceCommands"]) != 8
                    or digest(inputs["task-packets/" + stage["id"] + ".yaml"]) != stage["packetSha256"]):
                errors.append("successor ownership/commands changed")
        if len(record["repairTestIds"]) != 20 or len(set(record["repairTestIds"])) != 20:
            errors.append("twenty exact repair test identities required")
        return errors
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError, UnicodeError, yaml.YAMLError):
        return ["malformed cumulative inventory authority"]


def main():
    try:
        packets = {p.stem: safe_yaml_load(regular_bytes(ROOT, str(p.relative_to(ROOT)))) for p in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_successor_inventory(packets, *load_successor_inputs(ROOT))
    except (OSError, TypeError, ValueError, RecursionError, yaml.YAMLError) as exc:
        errors = ["successor authority unavailable: " + type(exc).__name__]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Successor inventory authority valid: 194 packets; 188 predecessor files unchanged; product correction NOT_RUN; native gate closed.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
