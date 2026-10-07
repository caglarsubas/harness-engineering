#!/usr/bin/env python3
"""I05 broker-gate channel (W02b): frame envelope, gate state machine and outcome mapping.

DATA_CHECK_ONLY reference model for the private interface between the capacity broker and
the effect gate (HOST-INTERFACE-DRAFT-002 sections 3.2, 6 and 7).

- `check_frame` checks one frame against the closed schema and the envelope bounds.
- `Gate` replays a transcript of broker frames, I04 connection events and failures, and
  returns every gate decision: response payloads, fatal channel closures, forwarding
  decisions with the refusal reason, and the resulting generation state. It encodes
  connection stamping C1-C7, the A1 admission point, the A3 drain fence and A4 urgent
  invalidation.
- `check_agreement` applies the ACTION_OUTCOME to RESOURCE_RESULT mapping table.

None of it opens a socket, forwards a request or grants authority. A gate response is an
observation of gate-owned state, never a capability.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any

FRAME_VERSION = "planeon.internal.effect-gate-frame/v1"
TEMPLATE_VERSION = "planeon.internal.effect-gate-template/v1"
OPERATIONS = ("GENERATION_STATUS", "BIND_EXECUTION", "ARM_ACTION", "ACTION_OUTCOME", "CLOSE_GENERATION")
STATES = ("INSPECTING", "ACTIVE", "DRAINING", "CLOSED", "INVALIDATED", "HELD")
CLOSE_REASONS = ("NORMAL_DRAIN", "REVOCATION", "EXPIRY", "PEER_FAILURE", "STORAGE_FAILURE", "OBSERVATION_FAILURE")
CLASSIFICATIONS = ("NOT_FORWARDED", "DELIVERED_RESULT", "IO_AMBIGUOUS")
RESOURCE_OUTCOMES = ("ABSENT", "CREATED", "PRESENT", "DELETED", "DENIED", "AMBIGUOUS")
CORRELATION_REFUSALS = ("STAMP_NONE", "STAMP_MISMATCH", "CERTIFICATE_MISMATCH", "TEMPLATE_MISMATCH", "ALREADY_CONSUMED")
MAX_FRAME_BYTES = 16384
MAX_SEQUENCE = 2147483647
ZERO_DIGEST = "sha256:" + "0" * 64


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def frame_digest(frame: dict) -> str:
    return sha(canonical(frame))


def template_digest(verb: str, api_version: str, kind: str, namespace: str, name: str, uid: str | None,
                    manifest_digest: str) -> str:
    """The canonical action both the ARM_ACTION template and a parsed I04 request reduce to."""
    return sha(canonical({"schemaVersion": TEMPLATE_VERSION, "verb": verb, "apiVersion": api_version, "kind": kind,
                          "namespace": namespace, "name": name, "uid": uid, "manifestDigest": manifest_digest}))


def _depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


def _has_float(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_has_float(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_float(v) for v in value)
    return type(value) is float


def check_frame(frame: Any, schema: dict) -> None:
    """Exact builtins, closed schema, canonical size and depth bounds (F00-F03)."""
    import jsonschema
    require(not _has_float(frame), "F03 frame contains a non-integer number")
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(frame), key=lambda e: list(e.absolute_path))
    require(not errors, "F00 frame outside the closed schema")
    require(_depth(frame) <= 16, "F01 frame deeper than 16")
    require(len(canonical(frame)) <= MAX_FRAME_BYTES, "F02 frame larger than 16 KiB")


# ---------------------------------------------------------------- outcome mapping

def _row_status(row: dict, status: int | None, exact: bool) -> bool:
    rule = row["httpStatus"]
    if status is None or rule is None:
        return status is None and rule is None
    if exact:
        return type(rule) is int and rule == status
    low, high = {"4xx": (400, 499), "5xx": (500, 599)}.get(rule, (0, -1))
    return type(rule) is str and low <= status <= high


def check_agreement(mapping: dict, verb: str, outcome: dict, result: dict) -> str | None:
    """None when the gate's ACTION_OUTCOME and the server's RESOURCE_RESULT agree; otherwise the
    refusal. The broker treats any refusal as sticky disagreement and holds the generation HELD."""
    if result.get("actionId") != outcome.get("actionId"):
        return "M01 action identifiers differ"
    status = outcome["httpStatus"]
    rows = [row for row in mapping["rows"] if row["verb"] in (verb, "*") and row["classification"] == outcome["classification"]]
    exact = [row for row in rows if _row_status(row, status, True)]
    matched = exact or [row for row in rows if _row_status(row, status, False)]
    if len(matched) != 1:
        return "M02 no mapping row for this outcome"
    row = matched[0]
    if result.get("outcome") not in row["resourceResults"]:
        return "M03 resource result outside the mapped outcomes"
    data = result.get("objectBase64")
    if row["object"] == "NULL" and data is not None:
        return "M04 object reported where the mapping requires none"
    if row["object"] == "UID_MATCH":
        try:
            observed = json.loads(base64.b64decode(data, validate=True))["metadata"]["uid"]
        except (ValueError, TypeError, KeyError):
            observed = None
        if observed is None or observed != outcome["observedUid"]:
            return "M05 reported object UID differs from the gate-observed UID"
    return None


# ---------------------------------------------------------------- gate model

class Gate:
    """Deterministic model of the gate's decisions for one generation and its single I05 channel."""

    def __init__(self, config: dict):
        self.generation = config["generation"]
        self.state = config["state"]
        self.peer = config["peerQualificationDigest"]
        self.manifests = config["manifests"]
        self.executions = config["executions"]
        self.drain_pending = False
        self.channel = "UNOPENED"          # UNOPENED, OPEN, CLOSED
        self.challenge = None
        self.next_sequence = 1
        self.last_digest = ZERO_DIGEST
        self.bound = None                  # executionId
        self.bound_ids: list[str] = []
        self.expired = False
        self.actions: dict[int, dict] = {}  # bound execution's actions
        self.mutation_keys: set[tuple] = set()
        self.backlog: list[str] = []
        self.connections: dict[str, dict] = {}
        self.storage_fails = 0
        self.counters = {"stampsIssued": 0, "consumptions": 0, "correlationRefusals": 0, "flushClosures": 0}
        self.journal: list[Any] = []

    # -- helpers
    def _record(self, entry: Any) -> bool:
        """Durable fsync and readback; False when the store fails (the caller must not proceed)."""
        if self.storage_fails:
            self.storage_fails -= 1
            self.state = "HELD"
            return False
        self.journal.append(copy.deepcopy(entry))
        return True

    def _armed(self) -> dict | None:
        return next((a for a in self.actions.values() if a["status"] == "ARMED"), None)

    def _in_flight(self) -> dict | None:
        return next((a for a in self.actions.values() if a["status"] == "CONSUMED"), None)

    def _close_connections(self, predicate) -> int:
        closed = 0
        for conn in self.connections.values():
            if conn["state"] == "OPEN" and predicate(conn):
                conn["state"] = "CLOSED"
                closed += 1
        self.counters["flushClosures"] += closed
        return closed

    def _deny_armed(self) -> list[int]:
        """Deny every armed but unconsumed action: NOT_FORWARDED, and its stamped connections close."""
        denied = []
        for action in self.actions.values():
            if action["status"] == "ARMED":
                action.update(status="TERMINAL", classification="NOT_FORWARDED")
                self._close_connections(lambda c, a=action: c["stamp"] == a["actionId"] and not c["consumed"])
                self.journal.append(("NOT_FORWARDED", action["actionId"]))
                denied.append(action["actionId"])
        return denied

    def _urgent(self, state: str) -> list[int]:
        """A4: close A1 first, deny unconsumed actions, keep consumed actions recorded."""
        denied = self._deny_armed()
        if self._in_flight() is not None:
            self._in_flight()["afterInvalidation"] = True
        if self.state != "HELD":
            self.state = state
        return denied

    def _fatal(self, reason: str) -> dict:
        self.channel = "CLOSED"
        self._urgent("HELD")
        self.state = "HELD"
        return {"fatal": reason}

    def snapshot(self) -> dict:
        return {"state": self.state, "drainPending": self.drain_pending, "channel": self.channel,
                "boundExecutionId": self.bound,
                "actions": {str(k): {"status": v["status"], "classification": v.get("classification"),
                                     "admittedBeforeInvalidation": v.get("afterInvalidation", False)}
                            for k, v in sorted(self.actions.items())},
                "connections": {k: v["state"] for k, v in sorted(self.connections.items())},
                "counters": dict(self.counters)}

    # -- events
    def handle(self, event: dict, schema: dict) -> dict:
        kind = event["type"]
        if kind == "FRAME":
            return self._frame(event["frame"], schema)
        if kind == "BACKLOG":
            self.backlog.append(event["conn"])
            return {}
        if kind == "ACCEPT":
            return self._accept(event["conn"])
        if kind == "REQUEST":
            return self._request(event)
        if kind == "UPSTREAM_RESPONSE":
            return self._upstream(event, lost=False)
        if kind == "UPSTREAM_LOST":
            return self._upstream(event, lost=True)
        if kind == "STORAGE_FAIL_NEXT":
            self.storage_fails += 1
            return {}
        if kind == "DRAIN_REQUEST":
            return self._drain()
        if kind == "EXPIRE":
            self.expired = True
            return {"denied": self._deny_armed()}
        if kind == "CHANNEL_LOST":
            if self.channel == "OPEN":
                return self._fatal("PEER_LOST")
            return {}
        if kind == "SECOND_CHANNEL":
            require(self.channel != "UNOPENED", "second channel before the first")
            return {"refusedChannel": "CHANNEL_EXISTS" if self.channel == "OPEN" else "GENERATION_CHANNEL_USED"}
        if kind == "PEER_CHANGED":
            return self._fatal("PEER_CHANGED") if self.channel == "OPEN" else {}
        require(kind == "GATE_RESTART", "unknown event")
        # Deny-first restart: no channel, no stamps; a consumed action without a terminal record is ambiguous.
        for action in self.actions.values():
            if action["status"] == "CONSUMED":
                action.update(status="TERMINAL", classification="IO_AMBIGUOUS")
        self._deny_armed()
        for conn in self.connections.values():
            conn["state"] = "CLOSED"
        self.backlog = []
        self.channel = "CLOSED"
        self.state = "HELD"
        return {}

    def _accept(self, conn: str) -> dict:
        require(conn in self.backlog, "accept outside the backlog")
        self.backlog.remove(conn)
        armed = self._armed()
        stamp = armed["actionId"] if armed is not None else None  # C3: gate state, never client data
        self.connections[conn] = {"stamp": stamp, "state": "OPEN", "requests": 0, "consumed": False}
        if stamp is not None:
            self.counters["stampsIssued"] += 1
        return {"stamp": stamp}

    def _request(self, event: dict) -> dict:
        conn = self.connections.get(event["conn"])
        require(conn is not None, "request on an unaccepted connection")

        def refuse(reason: str) -> dict:
            if conn["state"] == "OPEN":
                conn["state"] = "CLOSED"
            if reason in CORRELATION_REFUSALS:
                self.counters["correlationRefusals"] += 1
            return {"decision": "CLOSE", "reason": reason}

        conn["requests"] += 1
        if conn["state"] != "OPEN":
            return refuse("CONNECTION_CLOSED")
        if conn["requests"] > 1:
            return refuse("PROTOCOL_VIOLATION")          # C1: one request per connection
        if self.state != "ACTIVE" or self.drain_pending or self.channel != "OPEN":
            return refuse("NOT_ACTIVE")
        if self.bound is None or self.expired:
            return refuse("EXECUTION_EXPIRED" if self.expired else "NOT_ACTIVE")
        if conn["stamp"] is None:
            return refuse("STAMP_NONE")                   # C5: a 'none' stamp never forwards
        action = self.actions.get(conn["stamp"])
        if action is None or action["status"] != "ARMED":
            return refuse("ALREADY_CONSUMED" if action is not None and action["status"] != "ARMED" else "STAMP_MISMATCH")
        execution = self.executions[self.bound]
        if event["certificateDigest"] != execution["serverCertificateDigest"]:
            return refuse("CERTIFICATE_MISMATCH")
        parsed = event["action"]
        if template_digest(parsed["verb"], parsed["apiVersion"], parsed["kind"], parsed["namespace"], parsed["name"],
                           parsed["uid"], parsed["manifestDigest"]) != action["templateDigest"]:
            return refuse("TEMPLATE_MISMATCH")
        # A1: consume exactly once, fsync and read back, then the first byte goes upstream.
        if not self._record(("CONSUMED", action["actionId"])):
            self._urgent("HELD")
            return refuse("STORAGE_FAILURE")
        action.update(status="CONSUMED", conn=event["conn"])
        conn["consumed"] = True
        self.counters["consumptions"] += 1
        self._close_connections(lambda c: c["stamp"] == action["actionId"] and not c["consumed"])   # C5
        return {"decision": "FORWARD", "actionId": action["actionId"]}

    def _upstream(self, event: dict, lost: bool) -> dict:
        action = next((a for a in self.actions.values() if a["status"] == "CONSUMED" and a["conn"] == event["conn"]), None)
        require(action is not None, "upstream event without a forwarded action")
        if lost:
            action.update(status="TERMINAL", classification="IO_AMBIGUOUS")
            self.state = "HELD"
        else:
            action.update(status="TERMINAL", classification="DELIVERED_RESULT", httpStatus=event["httpStatus"],
                          resultDigest=event["bodyDigest"], observedUid=event["uid"],
                          observedResourceVersion=event["resourceVersion"])
        # The terminal record is durable before any response byte is relayed to the client.
        if not self._record(("TERMINAL", action["actionId"], action["classification"])):
            action.update(status="TERMINAL", classification="IO_AMBIGUOUS")
            self.state = "HELD"
        self._settle_drain()
        return {"classification": action["classification"]}

    def _drain(self) -> dict:
        """I07 WRITE_BEGIN: normal drain; the A3 fence holds once no consumed action lacks a terminal record."""
        if self.state not in ("ACTIVE", "INSPECTING"):
            return {"drain": self.state}
        self.drain_pending = True
        denied = self._deny_armed()
        self.state = "DRAINING"
        self._settle_drain()
        return {"denied": denied, "drain": self.state}

    def _settle_drain(self) -> None:
        if self.drain_pending and self.state == "DRAINING" and self._in_flight() is None:
            ambiguous = any(a.get("classification") == "IO_AMBIGUOUS" for a in self.actions.values())
            self.state = "HELD" if ambiguous else "CLOSED"

    # -- I05 frames
    def _frame(self, frame: Any, schema: dict) -> dict:
        if self.channel == "CLOSED":
            return {"refusedChannel": "GENERATION_CHANNEL_USED"}
        try:
            check_frame(frame, schema)
        except ValueError as exc:
            return self._fatal(str(exc).split(" ", 1)[0] + "_INVALID_FRAME")
        if frame["direction"] != "BROKER_TO_GATE" or frame["sequence"] % 2 != 1:
            return self._fatal("DIRECTION")
        if frame["sequence"] != self.next_sequence or frame["previousDigest"] != self.last_digest:
            return self._fatal("CHAIN_BROKEN")
        if frame["generation"] != self.generation:
            return self._fatal("GENERATION_MISMATCH")
        if self.channel == "UNOPENED":
            if frame["operation"] != "GENERATION_STATUS":
                return self._fatal("OPENING_FRAME_REQUIRED")
            self.channel, self.challenge = "OPEN", frame["challenge"]
        elif frame["challenge"] != self.challenge:
            return self._fatal("CHALLENGE_MISMATCH")
        handler = getattr(self, "_op_" + frame["operation"].lower())
        payload = handler(frame["payload"])
        if payload.get("fatal"):
            return payload
        response = {"schemaVersion": FRAME_VERSION, "generation": self.generation, "challenge": self.challenge,
                    "sequence": frame["sequence"] + 1, "previousDigest": frame_digest(frame),
                    "direction": "GATE_TO_BROKER", "operation": frame["operation"], "payload": payload}
        check_frame(response, schema)
        self.next_sequence = frame["sequence"] + 2
        self.last_digest = frame_digest(response)
        return {"response": payload}

    def _op_generation_status(self, payload: dict) -> dict:
        armed, in_flight = self._armed(), self._in_flight()
        return {"result": "OK", "state": self.state, "drainPending": self.drain_pending,
                "boundExecutionId": self.bound, "armedActionId": armed["actionId"] if armed else None,
                "inFlightActionId": in_flight["actionId"] if in_flight else None,
                "counters": dict(self.counters), "journalDigest": sha(canonical(self.journal))}

    def _refused(self, reason: str) -> dict:
        return {"result": "REFUSED", "reason": reason}

    def _op_bind_execution(self, p: dict) -> dict:
        if p["peerQualificationDigest"] != self.peer:
            return self._fatal("PEER_QUALIFICATION_MISMATCH")
        if self.state != "ACTIVE":
            return self._refused("NOT_ACTIVE")
        if self.drain_pending:
            return self._refused("DRAIN_PENDING")
        if any(a["status"] != "TERMINAL" or not a["sealed"] for a in self.actions.values()):
            return self._refused("ACTION_OUTSTANDING")
        if p["executionId"] in self.bound_ids:
            return self._refused("EXECUTION_REPLAY")
        if p["dispatchGeneration"] != self.generation:
            return self._refused("GENERATION_MISMATCH")
        execution = self.executions.get(p["executionId"])
        if execution is None or any(execution[k] != p[k] for k in (
                "bindingDigest", "reservationDigest", "runNonce", "caseId", "requestDigest", "workerPid", "workerStartTicks")):
            return self._refused("UNKNOWN_BINDING")
        if p["serverCertificateDigest"] != execution["serverCertificateDigest"]:
            return self._refused("CERTIFICATE_MISMATCH")
        if not self._record(("BIND", p["executionId"])):
            self._urgent("HELD")
            return self._refused("STORAGE_FAILURE")
        self.bound, self.expired, self.actions, self.mutation_keys = p["executionId"], False, {}, set()
        self.bound_ids.append(p["executionId"])
        return {"result": "OK", "executionId": p["executionId"],
                "caseManifestSetDigest": sha(canonical(sorted(execution["manifests"])))}

    def _op_arm_action(self, p: dict) -> dict:
        if self.state != "ACTIVE":
            return self._refused("DRAIN_PENDING" if self.drain_pending else "NOT_ACTIVE")
        if self.bound is None or p["executionId"] != self.bound:
            return self._refused("EXECUTION_NOT_BOUND")
        if self.expired:
            return self._refused("EXECUTION_EXPIRED")
        if any(a["status"] != "TERMINAL" or not a["sealed"] for a in self.actions.values()):
            return self._refused("ACTION_OUTSTANDING")
        if p["actionId"] != len(self.actions) + 1:
            return self._refused("ACTION_ID_OUT_OF_ORDER")
        execution = self.executions[self.bound]
        manifest = self.manifests.get(p["manifestDigest"])
        if manifest is None or p["manifestDigest"] not in execution["manifests"]:
            return self._refused("MANIFEST_OUTSIDE_CASE")
        if (p["verb"] == "DELETE") != (p["recordedUid"] is not None):
            return self._refused("UID_RULE")              # only DELETE carries the recorded-UID precondition
        expected = template_digest(p["verb"], manifest["apiVersion"], manifest["kind"], manifest["namespace"],
                                   manifest["name"], p["recordedUid"], p["manifestDigest"])
        if p["requestTemplateDigest"] != expected:
            return self._refused("TEMPLATE_MISMATCH")
        key = ("CREATE", p["manifestDigest"]) if p["verb"] == "CREATE" else ("DELETE", p["recordedUid"]) \
            if p["verb"] == "DELETE" else None
        if key is not None and key in self.mutation_keys:
            return self._refused("MUTATION_KEY_REUSED")   # C7
        # C2: close every unconsumed connection and drain the listen backlog before recording ARM.
        flushed = self._close_connections(lambda c: not c["consumed"])
        for conn in self.backlog:
            self.connections[conn] = {"stamp": None, "state": "CLOSED", "requests": 0, "consumed": False}
        flushed += len(self.backlog)
        self.counters["flushClosures"] += len(self.backlog)
        self.backlog = []
        if not self._record(("ARM", p["actionId"], expected)):
            self._urgent("HELD")
            return self._refused("STORAGE_FAILURE")
        if key is not None:
            self.mutation_keys.add(key)
        self.actions[p["actionId"]] = {"actionId": p["actionId"], "verb": p["verb"], "templateDigest": expected,
                                       "status": "ARMED", "sealed": False}
        return {"result": "OK", "actionId": p["actionId"], "flushedConnections": flushed}

    def _op_action_outcome(self, p: dict) -> dict:
        if self.bound is None or p["executionId"] != self.bound:
            return self._refused("EXECUTION_NOT_BOUND")
        action = self.actions.get(p["actionId"])
        if action is None:
            return self._refused("UNKNOWN_ACTION")
        # Sealing: after this response the action can never be consumed.
        if action["status"] == "ARMED":
            action.update(status="TERMINAL", classification="NOT_FORWARDED")
            self._close_connections(lambda c: c["stamp"] == action["actionId"] and not c["consumed"])
            self.journal.append(("NOT_FORWARDED", action["actionId"]))
        elif action["status"] == "CONSUMED":
            # Still in flight at the seal: the gate aborts the upstream exchange; the outcome is ambiguous.
            action.update(status="TERMINAL", classification="IO_AMBIGUOUS")
            self.state = "HELD"
            self.journal.append(("IO_AMBIGUOUS", action["actionId"]))
            self._settle_drain()
        action["sealed"] = True
        delivered = action["classification"] == "DELIVERED_RESULT"
        return {"result": "OK", "actionId": action["actionId"], "classification": action["classification"],
                "admittedBeforeInvalidation": action.get("afterInvalidation", False) and action["classification"] != "NOT_FORWARDED",
                "httpStatus": action.get("httpStatus") if delivered else None,
                "resultDigest": action.get("resultDigest") if delivered else None,
                "observedUid": action.get("observedUid") if delivered else None,
                "observedResourceVersion": action.get("observedResourceVersion") if delivered else None}

    def _op_close_generation(self, p: dict) -> dict:
        reason = p["reason"]
        if self.state in ("CLOSED", "INVALIDATED", "HELD"):
            return {"result": "OK", "state": self.state, "deniedActionIds": []}
        if reason == "NORMAL_DRAIN":
            if self._in_flight() is not None:
                return self._refused("ACTION_IN_FLIGHT")
            denied = self._deny_armed()
            ambiguous = any(a.get("classification") == "IO_AMBIGUOUS" for a in self.actions.values())
            self.state = "HELD" if ambiguous else "CLOSED"
            return {"result": "OK", "state": self.state, "deniedActionIds": denied}
        denied = self._urgent("INVALIDATED")
        return {"result": "OK", "state": self.state, "deniedActionIds": denied}


ERRORS = (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError)


def _apply(value: Any, ops: list) -> Any:
    value = copy.deepcopy(value)
    for op in ops:
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        else:
            require(op["op"] == "delete", "closed mutation operation")
            del node[last]
    return value


def replay(config: dict, events: list, schema: dict) -> tuple[list, dict]:
    """Replay one transcript; returns every event's output and the final snapshot. A FRAME event
    names the broker's operation and payload; the replay builds the envelope a correct broker
    would send next (sequence, previous digest, generation and channel challenge) and then
    applies the event's mutations, so invalid frames are exact deviations from a valid one."""
    gate = Gate(copy.deepcopy(config))
    outputs = []
    for event in events:
        event = copy.deepcopy(event)
        if event["type"] == "FRAME":
            frame = {"schemaVersion": FRAME_VERSION, "generation": config["generation"],
                     "challenge": config["brokerChallenge"], "sequence": gate.next_sequence,
                     "previousDigest": gate.last_digest, "direction": "BROKER_TO_GATE",
                     "operation": event["operation"], "payload": event["payload"]}
            event = {"type": "FRAME", "frame": _apply(frame, event.get("mutate", []))}
        outputs.append(gate.handle(event, schema))
    return outputs, gate.snapshot()
