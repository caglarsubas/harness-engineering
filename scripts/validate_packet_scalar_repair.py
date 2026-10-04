#!/usr/bin/env python3
"""Exact data-only parser correction authority; never executes source snapshots."""
from __future__ import annotations

from functools import lru_cache
import hashlib
import json
from pathlib import Path
import stat
from typing import Any

import yaml

try:
    from safe_yaml import safe_load as safe_yaml_load
except ModuleNotFoundError:
    from scripts.safe_yaml import safe_load as safe_yaml_load

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/packet-scalar-amendment.json"
RECORD_SHA256 = "cc083e1bc1b1551ba88a85316074a09434e73d8271355b6011e8f11dbce6a8e0"
ADDITIONS = ("MET-REPAIR-007", "CONF-FIX-002")
PACKET_DIGESTS = {"MET-REPAIR-007":"ac6ee45f518722ced9fa5591775a62ddb29c812417ec798f04bf9bc02c4dc8aa","CONF-FIX-002":"87a1fb0b8dd6093ae32020ecd317e16a66d9e999445529c6e3e8f95c98191582"}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate authority field")
        result[key] = value
    return result


def _constant(_):
    raise ValueError("non-finite authority value")


def regular_bytes(root: Path, relative: str) -> bytes:
    if type(relative) is not str or not relative or relative.startswith("/"):
        raise ValueError("invalid authority path")
    parts = relative.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError("invalid authority component")
    path = root
    for index, part in enumerate(parts):
        path = path / part
        expected = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if not expected(path.lstat().st_mode):
            raise ValueError("authority input must have regular no-link ancestry")
    return path.read_bytes()


def load_scalar_inputs(root: Path):
    record = json.loads(regular_bytes(root, RECORD_PATH), object_pairs_hook=_pairs, parse_constant=_constant)
    if digest(canonical(record)) != RECORD_SHA256:
        raise ValueError("unreviewed scalar amendment")
    pins = {**record["protectedFiles"], **record["inputFiles"], **record["packetDigests"]}
    return record, {path: regular_bytes(root, path) for path in pins}


def validate_additions(packets: Any) -> list[str]:
    errors = []
    if type(packets) is not dict:
        return ["packet mapping required"]
    for packet_id, expected in PACKET_DIGESTS.items():
        try:
            actual = digest(canonical(packets.get(packet_id)))
        except (TypeError, ValueError, RecursionError):
            actual = None
        if actual != expected:
            errors.append("exact scalar repair packet changed: " + packet_id)
    return errors


@lru_cache(maxsize=256)
def _packet_digest(raw: bytes) -> str:
    return digest(canonical(safe_yaml_load(raw)))


def validate_edit(path: str, before: bytes, after: bytes, record: Any) -> list[str]:
    """Byte comparison only: no import, eval, exec or source compilation."""
    try:
        if digest(canonical(record)) != RECORD_SHA256 or type(before) is not bytes or type(after) is not bytes:
            return ["pinned authority and source bytes required"]
        change = record["changes"][path]
        old, new = change["beforeBlock"].encode(), change["afterBlock"].encode()
        if digest(before) != change["beforeSha256"] or before.count(old) != 1:
            return ["incorrect original source"]
        prefix, suffix = before.split(old)
        if (digest(prefix) != change["prefixSha256"] or digest(suffix) != change["suffixSha256"]
                or after != prefix + new + suffix or digest(after) != change["afterSha256"]):
            return ["only the exact whole-file transformation is authorized"]
    except (TypeError, ValueError, KeyError, RecursionError):
        return ["malformed scalar edit"]
    return []


def validate_scalar_repair(packets: Any, record: Any, inputs: Any) -> list[str]:
    try:
        if digest(canonical(record)) != RECORD_SHA256:
            return ["scalar authority must equal the exact reviewed amendment"]
        if type(packets) is not dict or type(inputs) is not dict:
            return ["packet and input mappings required"]
        errors = validate_additions(packets)
        pins = {**record["protectedFiles"], **record["inputFiles"], **record["packetDigests"]}
        if set(inputs) != set(pins):
            errors.append("exact 169-file authority inventory required")
        old_ids = {Path(path).stem for path in record["protectedFiles"] if path.startswith("task-packets/")}
        try:
            from validate_successor_inventory import ADDITIONS as SUCCESSORS, validate_additions as validate_successors
            from validate_proxy_contract import ADDITIONS as PROXY_ADDITIONS, validate_additions as validate_proxy_additions
        except ImportError:
            from scripts.validate_successor_inventory import ADDITIONS as SUCCESSORS, validate_additions as validate_successors
            from scripts.validate_proxy_contract import ADDITIONS as PROXY_ADDITIONS, validate_additions as validate_proxy_additions
        if len(old_ids) != 130 or set(packets) != old_ids | set(ADDITIONS) | set(SUCCESSORS) | set(PROXY_ADDITIONS) | {"MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"}:
            errors.append("exact historical 132 plus three cumulative correction packets required")
        errors.extend(validate_successors(packets))
        errors.extend(validate_proxy_additions(packets))
        for path, expected in pins.items():
            raw = inputs.get(path)
            if type(raw) is not bytes or digest(raw) != expected:
                errors.append("immutable input changed: " + path)
            elif path.startswith("task-packets/"):
                if digest(canonical(packets.get(Path(path).stem))) != _packet_digest(raw):
                    errors.append("packet semantics differ from exact bytes: " + path)
        baseline = json.loads(inputs["architecture/packet-scalar-inputs/baseline.json"])
        if (len(baseline["files"]) != 103 or sum(map(len, baseline["tests"].values())) != 120
                or baseline["commit"] != record["sourceBaseline"]["commit"]):
            errors.append("original conformance inventory changed")
        for path, snapshot in (
            ("ci/run_packet.py", "architecture/packet-scalar-inputs/run_packet.before.txt"),
            ("tests/platform/linux_baseline/test_linux_inventory.py",
             "architecture/packet-scalar-inputs/test_linux_inventory.before.txt"),
        ):
            before = inputs[snapshot]
            change = record["changes"][path]
            after = before.replace(change["beforeBlock"].encode(), change["afterBlock"].encode(), 1)
            errors.extend(validate_edit(path, before, after, record))
            if baseline["files"][path]["sha256"] != "sha256:" + digest(before):
                errors.append("baseline source pin mismatch: " + path)
        for packet_id, text in record["publishedBackendPackets"].items():
            if text.encode() != inputs["task-packets/" + packet_id + ".yaml"]:
                errors.append("backend packet snapshot differs from published bytes")
        return errors
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError, yaml.YAMLError):
        return ["malformed scalar repair authority"]


def main() -> int:
    try:
        packets = {p.stem: safe_yaml_load(regular_bytes(ROOT, str(p.relative_to(ROOT))))
                   for p in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_scalar_repair(packets, *load_scalar_inputs(ROOT))
    except (OSError, TypeError, ValueError, RecursionError, yaml.YAMLError) as exc:
        errors = ["scalar repair authority unavailable: " + type(exc).__name__]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Scalar repair authority valid: 194 packets; historical 132-packet record and 164 predecessor files unchanged.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
