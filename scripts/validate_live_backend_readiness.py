#!/usr/bin/env python3
"""Closed source-only live-backend roadmap authority; never an execution gate."""
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
RECORD_PATH = "architecture/live-backend-roadmap.json"
RECORD_SHA256 = "f2e4bb2ac04b96da29cea06283f2c0e2b800a9209726036cede7383acf68e378"
NEW_IDS = ("MET-LIVE-001", *(f"CONF-LIVE-00{i}" for i in range(1, 7)))
RUNTIME_GATED = ("CTRL-INTEGRATE-001", "MODEL-001", "EXEC-001", "RUN-001")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def regular_bytes(root: Path, relative: str) -> bytes:
    """Local immutable data only; never follow a link in any relative component."""
    if not isinstance(relative, str) or not relative or relative.startswith("/"):
        raise ValueError("invalid roadmap input path")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("invalid roadmap input component")
    path = root
    for index, part in enumerate(parts):
        path = path / part
        mode = path.lstat().st_mode
        expected = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if not expected(mode):
            raise ValueError("roadmap input must have regular no-link ancestry")
    return path.read_bytes()


def _closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate roadmap key")
        output[key] = value
    return output


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite roadmap value: " + value)


def load_live_inputs(root: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    record = json.loads(regular_bytes(root, RECORD_PATH),
                        object_pairs_hook=_closed_pairs, parse_constant=_reject_constant)
    # Verify before trusting even a local record as a path inventory.
    if digest(canonical(record)) != RECORD_SHA256:
        raise ValueError("live-backend roadmap authority changed")
    return record, {path: regular_bytes(root, path) for path in record["protectedFiles"]}


@lru_cache(maxsize=256)
def _packet_semantic_digest(raw: bytes) -> str:
    # Cached immutable digest only, never cache/expose a mutable parsed packet.
    return digest(canonical(safe_yaml_load(raw)))


def validate_live_backend_readiness(
    packets: dict[str, dict[str, Any]], record: Any, inputs: dict[str, bytes],
) -> list[str]:
    errors: list[str] = []
    try:
        if digest(canonical(record)) != RECORD_SHA256:
            return ["live-backend roadmap must equal the exact reviewed source-only authority"]
        if type(packets) is not dict or type(inputs) is not dict:
            return ["live-backend packet/input inventory must be mappings"]
        protected = record["protectedFiles"]
        old_ids = {Path(path).stem for path in protected if path.startswith("task-packets/")}
        if len(old_ids) != 123 or len(protected) != 156:
            errors.append("original 123-packet / 156-file preservation inventory changed")
        try:
            from validate_packet_scalar_repair import ADDITIONS, validate_additions
            from validate_successor_inventory import ADDITIONS as SUCCESSORS, validate_additions as validate_successors
            from validate_proxy_contract import ADDITIONS as PROXY_ADDITIONS, validate_additions as validate_proxy_additions
        except ImportError:
            from scripts.validate_packet_scalar_repair import ADDITIONS, validate_additions
            from scripts.validate_successor_inventory import ADDITIONS as SUCCESSORS, validate_additions as validate_successors
            from scripts.validate_proxy_contract import ADDITIONS as PROXY_ADDITIONS, validate_additions as validate_proxy_additions
        if (set(packets) != old_ids | set(NEW_IDS) | set(ADDITIONS) | set(SUCCESSORS)
                | set(PROXY_ADDITIONS) | {"MET-UNIFY-005", "MET-RUNNER-001", "MET-PERF-028", "MET-LINUX-005", "MET-VERIFY-001", "MET-PERF-029"} or len(packets) != 194):
            errors.append("current roadmap requires exactly 194 named packets; historical authority remains 130")
        errors.extend(validate_additions(packets))
        errors.extend(validate_successors(packets))
        errors.extend(validate_proxy_additions(packets))
        if set(inputs) != set(protected):
            errors.append("missing or extra protected predecessor input")
        for path, expected in protected.items():
            raw = inputs.get(path)
            if type(raw) is not bytes or digest(raw) != expected:
                errors.append("protected predecessor bytes changed: " + path)
                continue
            if path.startswith("task-packets/"):
                packet_id = Path(path).stem
                if digest(canonical(packets.get(packet_id))) != _packet_semantic_digest(raw):
                    errors.append("consumed packet authority changed: " + packet_id)
        for packet_id in NEW_IDS:
            if canonical(packets.get(packet_id)) != canonical(record["packetSpecifications"][packet_id]):
                errors.append("new packet differs from exact reviewed scope: " + packet_id)
        # Independent semantic assertions supplement the whole-record and packet pins.
        specs = record["packetSpecifications"]
        for index, packet_id in enumerate(NEW_IDS[1:]):
            expected = (["MET-LIVE-001", "CONF-LINUX-001", "CON-MODEL-001"]
                        if index == 0 else [NEW_IDS[index]])
            if specs[packet_id]["predecessors"] != expected:
                errors.append("backend source chain is not acyclic and ordered")
        gates = record["gates"]
        if (gates["runtimeBlockedPackets"] != list(RUNTIME_GATED)
                or gates["sourceSuccessIsNativeAcceptance"] is not False
                or gates["unavailableUnblocks"] is not False
                or gates["nextAfterSourceChain"] != "EXTERNAL_NATIVE_QUALIFICATION"):
            errors.append("source completion cannot unlock runtime qualification")
        commands = specs["CONF-LIVE-006"]["offlineAcceptanceCommands"]
        if (len(commands) != 8 or specs["CONF-LIVE-006"]["liveCampaignExecution"]["commands"] != commands
                or gates["manualCommands"] != commands):
            errors.append("manual packet must bind the complete eight-command source inventory")
        if any("liveCampaignExecution" in specs[packet_id] for packet_id in NEW_IDS[:-1]):
            errors.append("only the final backend packet may declare future manual execution")
    except (TypeError, ValueError, KeyError, RecursionError, yaml.YAMLError):
        errors.append("malformed live-backend authority")
    return errors


def main() -> int:
    try:
        packets = {path.stem: safe_yaml_load(regular_bytes(ROOT, str(path.relative_to(ROOT))))
                   for path in (ROOT / "task-packets").glob("*.yaml")}
        errors = validate_live_backend_readiness(packets, *load_live_inputs(ROOT))
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError) as exc:
        errors = ["live-backend authority unavailable: " + type(exc).__name__]
    for error in errors:
        print("ERROR: " + error)
    if not errors:
        print("Live backend roadmap valid: 194 packets; historical 130-packet authority and 156 predecessor files unchanged; source-only, native gate closed.")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
