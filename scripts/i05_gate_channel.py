#!/usr/bin/env python3
"""I05 broker-gate channel (W02b): frame envelope, gate state machine and outcome mapping.

DATA_CHECK_ONLY reference model for the private interface between the capacity broker and
the effect gate (HOST-INTERFACE-DRAFT-002 sections 3.2, 4.3, 6 and 7).

- `decode_frame` and `check_frame` check one frame: canonical duplicate-free bytes, exact
  builtins, the closed schema and the envelope bounds.
- `render_request` derives the one I04 request an armed action permits (method, path,
  query, headers and body).
- `Gate` replays a transcript of broker frames, I04 connection events, upstream events and
  failures, and returns every gate decision: response payloads, fatal channel closures,
  forwarding decisions with the refusal reason, and the resulting generation state. Every
  state change the gate relies on after a restart is a durable journal record, and a
  restart rebuilds the gate's actions from the journal alone.
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
CLOSE_REASONS = ("NORMAL_DRAIN", "REVOCATION", "EXPIRY", "PEER_FAILURE", "STORAGE_FAILURE", "OBSERVATION_FAILURE",
                 "RECONCILIATION_REQUIRED")
CLASSIFICATIONS = ("NOT_FORWARDED", "DELIVERED_RESULT", "IO_AMBIGUOUS")
# Refusals no reachable interleaving produces in this model; the gate still checks them (defence in depth).
UNREACHABLE_REFUSALS = ("STAMP_MISMATCH", "ALREADY_CONSUMED")
CORRELATION_REFUSALS = ("STAMP_NONE", "CERTIFICATE_MISMATCH", "REQUEST_MISMATCH") + UNREACHABLE_REFUSALS
PLURALS = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}
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
    """The ARM_ACTION request template: the canonical identity of one permitted action."""
    return sha(canonical({"schemaVersion": TEMPLATE_VERSION, "verb": verb, "apiVersion": api_version, "kind": kind,
                          "namespace": namespace, "name": name, "uid": uid, "manifestDigest": manifest_digest}))


def delete_options(uid: str) -> bytes:
    """The only DeleteOptions body a DELETE may carry: the recorded-UID precondition."""
    return canonical({"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}})


def render_request(verb: str, manifest: dict, uid: str | None, endpoint: str) -> dict:
    """The exact I04 request an armed action permits: the request-head bytes and the body digest. A1
    requires the received head bytes and body to equal them byte for byte, and the gate forwards these
    rendered bytes. Any other method, target, query parameter (dryRun, watch, gracePeriodSeconds, ...),
    version, header field, name case, order, duplicate, folding, transfer-coding or body is refused."""
    base = "/api/v1/namespaces/%s/%s" % (manifest["namespace"], PLURALS[manifest["kind"]])
    if verb == "CREATE":
        body_digest, body_length, method, target = manifest["digest"], manifest["size"], "POST", base
    elif verb == "DELETE":
        body = delete_options(uid)
        body_digest, body_length, method, target = sha(body), len(body), "DELETE", base + "/" + manifest["name"]
    else:
        body_digest, body_length, method, target = None, 0, "GET", base + "/" + manifest["name"]
    head = "%s %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\n" % (method, target, endpoint)
    if body_digest is not None:
        head += "Content-Type: application/json\r\nContent-Length: %d\r\n" % body_length
    return {"head": head + "\r\n", "bodyDigest": body_digest}


def outcome_is_final(verb: str, status: int) -> bool:
    """Whether a delivered response settles a mutation. GET never mutates. A CREATE is settled by 201 or a
    rejection (4xx other than 408); a DELETE by 200, 202, 404 or a rejection. Any other status (5xx, 408,
    1xx, 3xx, another 2xx) leaves the outcome unknown: the gate classifies it IO_AMBIGUOUS (Kubernetes API
    conventions: 500 means the outcome is unknown, and a timed-out request may still persist)."""
    if verb == "GET":
        return True
    rejected = 400 <= status <= 499 and status != 408
    return rejected or (status == 201 if verb == "CREATE" else status in (200, 202, 404))


# ---------------------------------------------------------------- frames

def _strict_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "F05 duplicate key")
        result[key] = value
    return result


def _reject_constant(token: str) -> Any:
    raise ValueError("F03 frame contains a non-integer number")


def _depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v)


def check_frame(frame: Any, schema: dict) -> None:
    """Exact builtins, newline-safe strings, closed schema, canonical size and depth bounds."""
    import jsonschema
    require(not any(type(v) is float for v in _walk(frame)), "F03 frame contains a non-integer number")
    # jsonschema's Python patterns let '$' match before a trailing newline; ECMA-262 does not.
    require(not any(type(v) is str and any(ord(c) < 32 or ord(c) == 127 for c in v) for v in _walk(frame)),
            "F04 frame string contains a control character")
    require(not list(jsonschema.Draft202012Validator(schema).iter_errors(frame)), "F00 frame outside the closed schema")
    require(_depth(frame) <= 16, "F01 frame deeper than 16")
    require(len(canonical(frame)) <= MAX_FRAME_BYTES, "F02 frame larger than 16 KiB")


def decode_frame(raw: bytes, schema: dict) -> dict:
    """Bytes as received: at most 16 KiB, UTF-8, duplicate-free, no NaN or Infinity, and exactly the
    canonical encoding, so the next frame's previousDigest is the digest of these very bytes."""
    require(type(raw) is bytes and len(raw) <= MAX_FRAME_BYTES, "F02 frame larger than 16 KiB")
    try:
        frame = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
        encoded = canonical(frame)
    except ValueError as exc:   # also JSONDecodeError, UnicodeDecodeError and over-long integers
        if str(exc).startswith(("F03 ", "F05 ")):
            raise
        raise ValueError("F06 frame is not canonical JSON") from exc
    except UnicodeEncodeError as exc:  # a lone surrogate escape
        raise ValueError("F06 frame is not canonical JSON") from exc
    # Canonical form: sorted keys, no whitespace, UTF-8; for this schema (ASCII strings, integers only) it
    # coincides with RFC 8785.
    require(encoded == raw, "F06 frame is not canonical JSON")
    check_frame(frame, schema)
    return frame


# ---------------------------------------------------------------- outcome mapping

def _row_status(row: dict, status: int | None, exact: bool) -> bool:
    rule = row["httpStatus"]
    if status is None or rule is None:
        return status is None and rule is None
    if exact:
        return type(rule) is int and rule == status
    low, high = {"4xx": (400, 499), "5xx": (500, 599)}.get(rule, (0, -1))
    return type(rule) is str and low <= status <= high


def _decode_object(data: Any) -> dict | None:
    """Strict decode of RESOURCE_RESULT objectBase64: valid base64, duplicate-free JSON, no NaN or
    Infinity, depth at most 16, an object. None when any of that fails."""
    try:
        raw = base64.b64decode(data, validate=True)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
    except (ValueError, TypeError, RecursionError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict) or _depth(value) > 16:
        return None
    return value


def check_agreement(mapping: dict, verb: str, identity: dict, outcome: Any, result: Any) -> str | None:
    """None when the gate's ACTION_OUTCOME and the server's RESOURCE_RESULT agree; otherwise the refusal.
    `identity` is the armed template's apiVersion, kind, namespace and name. The broker treats any
    refusal as sticky disagreement and holds the generation HELD."""
    if type(outcome) is not dict or outcome.get("result") != "OK":
        return "M00 no usable ACTION_OUTCOME"
    if type(result) is not dict or result.get("actionId") != outcome.get("actionId"):
        return "M01 action identifiers differ"
    status = outcome.get("httpStatus")
    rows = [row for row in mapping["rows"] if row["verb"] in (verb, "*") and row["classification"] == outcome.get("classification")]
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
    if row["object"] == "DELETE_BODY_IF_PRESENT" and data is not None and mapping["deleteResponseBody"][identity["kind"]] == "STATUS":
        # Registries that do not return the deleted object answer with a v1 Status (details.kind is the resource).
        value = _decode_object(data)
        details = value.get("details") if value is not None and isinstance(value.get("details"), dict) else None
        if value is None or details is None or (value.get("kind"), value.get("status")) != ("Status", "Success"):
            return "M05 reported object missing or not strictly decodable"
        if (details.get("name"), details.get("kind")) != (identity["name"], PLURALS[identity["kind"]]):
            return "M06 reported object identity differs from the armed action"
        if details.get("uid") != outcome.get("observedUid") or outcome.get("observedResourceVersion") is not None:
            return "M07 reported object UID or resourceVersion differs from the gate's observation"
        return None
    if row["object"] in ("IDENTITY_MATCH", "DELETE_BODY_IF_PRESENT") and (row["object"] == "IDENTITY_MATCH" or data is not None):
        value = _decode_object(data) if data is not None else None
        if value is None:
            return "M05 reported object missing or not strictly decodable"
        meta = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
        if (value.get("apiVersion"), value.get("kind"), meta.get("namespace"), meta.get("name")) != (
                identity["apiVersion"], identity["kind"], identity["namespace"], identity["name"]):
            return "M06 reported object identity differs from the armed action"
        if meta.get("uid") != outcome.get("observedUid") or meta.get("resourceVersion") != outcome.get("observedResourceVersion"):
            return "M07 reported object UID or resourceVersion differs from the gate's observation"
    return None


# ---------------------------------------------------------------- gate model

class Gate:
    """Deterministic model of the gate's decisions for one generation and its single I05 channel."""

    def __init__(self, config: dict):
        self.generation = config["generation"]
        self.state = config["state"]
        self.peer = config["peerQualificationDigest"]
        self.endpoint = config["endpoint"]
        self.manifests = config["manifests"]
        self.runs = config["runs"]
        self.workers = {tuple(w) for w in config["observedWorkers"]}
        # The gate refuses inputs in which a manifest belongs to more than one run (I02 binding rule).
        manifests = [d for run in self.runs.values() for d in run["manifests"]]
        require(len(manifests) == len(set(manifests)), "a manifest digest resolves to more than one run")
        # Bindings of earlier generations stay in the durable journal and are never bound again.
        self.prior_ids = set(config["priorBindings"]["executionIds"])
        self.prior_nonces = set(config["priorBindings"]["runNonces"])
        self._failing = False
        self.drain_pending = False
        self.channel = "UNOPENED"          # UNOPENED, OPEN, CLOSED
        self.challenge = None
        self.next_sequence = 1
        self.last_digest = ZERO_DIGEST
        self.bound = None                  # {"executionId", "runNonce"}
        self.bound_ids: list[str] = []
        self.bound_nonces: list[str] = []
        self.expired = False
        self.actions: dict[int, dict] = {}
        self.mutation_keys: set[tuple] = set()
        self.observed_uids: dict[str, set] = {}
        self.backlog: list[str] = []
        self.connections: dict[str, dict] = {}
        self.storage_fails = 0
        self.counters = {"stampsIssued": 0, "consumptions": 0, "correlationRefusals": 0, "flushClosures": 0}
        self.journal: list[list] = []

    # -- durable journal
    def _record(self, *entry: Any) -> bool:
        """fsync and read back one journal record. A failed write is an urgent STORAGE_FAILURE: A1 closes,
        the generation is HELD, an armed action is denied and an in-flight one is marked admitted before
        invalidation; the caller then refuses or reports what it was doing."""
        if self.storage_fails:
            self.storage_fails -= 1
            self._storage_failure()
            return False
        self.journal.append(list(entry))
        return True

    def _storage_failure(self) -> None:
        if self._failing:
            return
        self._failing = True
        self.state = "HELD"
        in_flight = self._in_flight()
        if in_flight is not None:
            in_flight["afterInvalidation"] = True
        self._record("INVALIDATED", "STORAGE_FAILURE", "HELD")
        self._deny_armed()
        self._failing = False

    def _rebuild(self) -> str:
        """Restart: the gate's actions are what the durable journal says, nothing more. Returns the state the
        gate restarts in: the recorded CLOSED or INVALIDATED when every action is sealed and terminal and
        none is ambiguous, otherwise HELD."""
        actions: dict[int, dict] = {}
        state = "HELD"
        for entry in self.journal:
            kind = entry[0]
            if kind in ("INVALIDATED", "CLOSED"):
                state = entry[2]
            elif kind == "DRAINED":
                state = entry[1]
            if kind == "BIND":
                actions = {}
            elif kind == "ARM":
                actions[entry[1]] = {"actionId": entry[1], "status": "ARMED", "sealed": False}
            elif kind == "CONSUMED":
                actions[entry[1]].update(status="CONSUMED", afterInvalidation=False)
            elif kind in ("INVALIDATED", "EXPIRED"):
                for action in actions.values():
                    if action["status"] == "CONSUMED":
                        action["afterInvalidation"] = True
            elif kind == "TERMINAL":
                actions[entry[1]].update(status="TERMINAL", classification=entry[2], afterInvalidation=entry[3])
            elif kind == "DENIED":
                actions[entry[1]].update(status="TERMINAL", classification="NOT_FORWARDED")
            elif kind == "SEALED":
                actions[entry[1]].update(status="TERMINAL", classification=entry[2], sealed=True,
                                         afterInvalidation=entry[3] and entry[2] != "NOT_FORWARDED")
        clean = all(a["status"] == "TERMINAL" and a["sealed"] and a.get("classification") != "IO_AMBIGUOUS"
                    for a in actions.values())
        for action in actions.values():
            # Admitted without a terminal record: ambiguous, and admitted before the restart (C6, base 5).
            if action["status"] == "CONSUMED":
                action.update(status="TERMINAL", classification="IO_AMBIGUOUS", afterInvalidation=True)
            elif action["status"] == "ARMED":
                action.update(status="TERMINAL", classification="NOT_FORWARDED")
        self.actions = actions
        return state if clean and state in ("CLOSED", "INVALIDATED") else "HELD"

    # -- helpers
    def _armed(self) -> dict | None:
        return next((a for a in self.actions.values() if a["status"] == "ARMED"), None)

    def _in_flight(self) -> dict | None:
        return next((a for a in self.actions.values() if a["status"] == "CONSUMED"), None)

    def _stamp_of(self, action: dict) -> dict:
        return {"executionId": self.bound["executionId"], "actionId": action["actionId"]}

    def _close_connections(self, predicate) -> int:
        closed = 0
        for conn in self.connections.values():
            if conn["state"] == "OPEN" and predicate(conn):
                conn["state"] = "CLOSED"
                closed += 1
        self.counters["flushClosures"] += closed
        return closed

    def _deny_armed(self) -> list[int]:
        """Deny every armed, unconsumed action: its stamped connections close, then NOT_FORWARDED is
        recorded. The deny holds in memory even if the record fails (the generation is then HELD)."""
        denied = []
        for action in self.actions.values():
            if action["status"] == "ARMED":
                stamp = self._stamp_of(action)
                self._close_connections(lambda c, s=stamp: c["stamp"] == s and not c["consumed"])
                action.update(status="TERMINAL", classification="NOT_FORWARDED")
                self._record("DENIED", action["actionId"])
                denied.append(action["actionId"])
        return denied

    def _urgent(self, state: str, reason: str) -> list[int]:
        """A4: close A1 first (in memory, independent of storage), record the invalidation, deny
        unconsumed actions, keep consumed actions recorded."""
        if self.state != "HELD":
            self.state = state
        in_flight = self._in_flight()
        if in_flight is not None:
            in_flight["afterInvalidation"] = True
        self._record("INVALIDATED", reason, self.state)
        return self._deny_armed()

    def _fatal(self, reason: str) -> dict:
        self.channel = "CLOSED"
        self._urgent("HELD", reason)
        self.state = "HELD"
        return {"fatal": reason}

    def _orderly(self) -> bool:
        return (self.state in ("CLOSED", "INVALIDATED") and self._in_flight() is None
                and all(a["status"] == "TERMINAL" and a["sealed"] for a in self.actions.values()))

    def snapshot(self) -> dict:
        return {"state": self.state, "drainPending": self.drain_pending, "channel": self.channel,
                "boundExecutionId": self.bound["executionId"] if self.bound else None,
                "actions": {str(k): {"status": v["status"], "classification": v.get("classification"),
                                     "admittedBeforeInvalidation": v.get("afterInvalidation", False),
                                     "sealed": v["sealed"]}
                            for k, v in sorted(self.actions.items())},
                "connections": {k: v["state"] for k, v in sorted(self.connections.items())},
                "counters": dict(self.counters), "journal": copy.deepcopy(self.journal)}

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
            return self._expire()
        if kind == "CHANNEL_LOST":
            if self.channel == "UNOPENED":      # a connection that ends before its first frame uses the channel
                self.channel = "CLOSED"
                self._record("CHANNEL_ENDED", "BEFORE_FIRST_FRAME")
                return {"channelEnd": "UNUSED"}
            if self.channel != "OPEN":
                return {}
            if self._orderly():
                self.channel = "CLOSED"
                self._record("CHANNEL_ENDED", "ORDERLY")
                return {"channelEnd": "ORDERLY"}
            return self._fatal("PEER_LOST")
        if kind == "SECOND_CHANNEL":
            require(self.channel != "UNOPENED", "second channel before the first")
            return {"refusedChannel": "CHANNEL_EXISTS" if self.channel == "OPEN" else "GENERATION_CHANNEL_USED"}
        if kind == "PEER_CHANGED":
            return self._fatal("PEER_CHANGED") if self.channel == "OPEN" else {}
        require(kind == "GATE_RESTART", "unknown event")
        # Deny-first restart: no channel, no stamps, no connections; actions and state come from the journal.
        self.state = self._rebuild()
        for conn in self.connections.values():
            conn["state"] = "CLOSED"
        self.backlog = []
        self.channel = "CLOSED"
        self.drain_pending = False
        return {"restartState": self.state}

    def _expire(self) -> dict:
        """The bound execution's signed lifetime ended: as with the EXPIRY close for that execution, an
        in-flight action is reported admitted before invalidation and an armed one is denied."""
        if self.bound is None or self.expired:
            return {"denied": []}
        self.expired = True
        in_flight = self._in_flight()
        if in_flight is not None:
            in_flight["afterInvalidation"] = True
        self._record("EXPIRED", self.bound["executionId"])
        return {"denied": self._deny_armed()}

    def _accept(self, conn: str) -> dict:
        require(conn in self.backlog, "accept outside the backlog")
        self.backlog.remove(conn)
        armed = self._armed()
        stamp = self._stamp_of(armed) if armed is not None else None  # C3: gate state, never client data
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
        # The observed policy generation is current exactly while the generation is ACTIVE with no
        # pending drain: I07 is the only policy writer, and any write first drains the generation.
        if self.state != "ACTIVE" or self.drain_pending or self.channel != "OPEN" or self.bound is None:
            return refuse("NOT_ACTIVE")
        if self.expired:
            return refuse("EXECUTION_EXPIRED")
        if conn["stamp"] is None:
            return refuse("STAMP_NONE")                   # C5: a 'none' stamp never forwards
        if conn["stamp"]["executionId"] != self.bound["executionId"]:
            return refuse("STAMP_MISMATCH")
        action = self.actions.get(conn["stamp"]["actionId"])
        if action is None or action["status"] != "ARMED":
            return refuse("ALREADY_CONSUMED" if action is not None else "STAMP_MISMATCH")
        run = self.runs[self.bound["runNonce"]]
        if event["certificateDigest"] != run["serverCertificateDigest"]:
            return refuse("CERTIFICATE_MISMATCH")
        manifest = self.manifests[action["manifestDigest"]]
        if {"head": event["head"], "bodyDigest": event["bodyDigest"]} != render_request(
                action["verb"], manifest, action["uid"], self.endpoint):
            return refuse("REQUEST_MISMATCH")             # C4: exact bytes, not a reduction
        # A1: consume exactly once, fsync and read back, then the first byte goes upstream.
        if not self._record("CONSUMED", action["actionId"]):
            return refuse("STORAGE_FAILURE")
        action.update(status="CONSUMED", conn=event["conn"], afterInvalidation=False)
        conn["consumed"] = True
        self.counters["consumptions"] += 1
        stamp = self._stamp_of(action)
        self._close_connections(lambda c: c["stamp"] == stamp and not c["consumed"])   # C5
        return {"decision": "FORWARD", "actionId": action["actionId"]}

    def _upstream(self, event: dict, lost: bool) -> dict:
        action = next((a for a in self.actions.values() if a.get("conn") == event["conn"] and a["status"] != "ARMED"), None)
        require(action is not None, "upstream event without a forwarded action")
        if action["status"] == "TERMINAL":
            # The seal aborted this exchange: a late response is never relayed and never changes the seal.
            self._record("LATE_UPSTREAM", action["actionId"])
            return {"lateUpstream": "NOT_RELAYED"}
        reconciliation = {}
        if lost:
            classification, details = "IO_AMBIGUOUS", {}
        elif not outcome_is_final(action["verb"], event["httpStatus"]):
            # Unknown mutation outcome: ambiguous; status and digest are kept for reconciliation only.
            classification, details = "IO_AMBIGUOUS", {}
            reconciliation = {"httpStatus": event["httpStatus"], "resultDigest": event["bodyDigest"]}
        else:
            classification = "DELIVERED_RESULT"
            details = {"httpStatus": event["httpStatus"], "resultDigest": event["bodyDigest"], "observedUid": event["uid"],
                       "observedResourceVersion": event["resourceVersion"]}
        after = action.get("afterInvalidation", False)
        # The terminal record, qualifier included, is durable before any response byte is relayed.
        recorded = self._record("TERMINAL", action["actionId"], classification, after, details or reconciliation)
        if not recorded:
            classification, details = "IO_AMBIGUOUS", {}
        action.update(status="TERMINAL", classification=classification, **details)
        if classification == "IO_AMBIGUOUS":
            self.state = "HELD"
        elif action["verb"] in ("CREATE", "GET") and details["httpStatus"] == (201 if action["verb"] == "CREATE" else 200) \
                and details["observedUid"] is not None:
            self.observed_uids.setdefault(action["manifestDigest"], set()).add(details["observedUid"])
        self.connections[event["conn"]]["state"] = "CLOSED"  # one response per connection, then close
        self._settle_drain()
        # A response is relayed only after its terminal record is durable; a lost exchange relays nothing.
        return {"classification": classification, "relayed": recorded and not lost}

    def _drain(self) -> dict:
        """I07 WRITE_BEGIN: normal drain; the A3 fence holds once no consumed action lacks a terminal record."""
        if self.state not in ("ACTIVE", "INSPECTING"):
            return {"drain": self.state}
        self.drain_pending = True
        self.state = "DRAINING"
        self._record("DRAIN_STARTED")
        denied = self._deny_armed()
        self._settle_drain()
        return {"denied": denied, "drain": self.state}

    def _settle_drain(self) -> None:
        if self.drain_pending and self.state in ("DRAINING", "HELD") and self._in_flight() is None:
            ambiguous = any(a.get("classification") == "IO_AMBIGUOUS" for a in self.actions.values())
            self.state = "HELD" if ambiguous or self.state == "HELD" else "CLOSED"
            self.drain_pending = False
            self._record("DRAINED", self.state)

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
        payload = getattr(self, "_op_" + frame["operation"].lower())(frame["payload"])
        if payload.get("fatal"):
            return payload
        response = {"schemaVersion": FRAME_VERSION, "generation": self.generation, "challenge": self.challenge,
                    "sequence": frame["sequence"] + 1, "previousDigest": frame_digest(frame),
                    "direction": "GATE_TO_BROKER", "operation": frame["operation"], "payload": payload}
        check_frame(response, schema)
        self.next_sequence = frame["sequence"] + 2
        self.last_digest = frame_digest(response)
        return {"response": payload}

    def _refused(self, reason: str) -> dict:
        return {"result": "REFUSED", "reason": reason}

    def _op_generation_status(self, payload: dict) -> dict:
        armed, in_flight = self._armed(), self._in_flight()
        return {"result": "OK", "state": self.state, "drainPending": self.drain_pending,
                "boundExecutionId": self.bound["executionId"] if self.bound else None,
                "armedActionId": armed["actionId"] if armed else None,
                "inFlightActionId": in_flight["actionId"] if in_flight else None,
                "counters": dict(self.counters), "journalDigest": sha(canonical(self.journal))}

    def _op_bind_execution(self, p: dict) -> dict:
        if p["peerQualificationDigest"] != self.peer:
            return self._fatal("PEER_QUALIFICATION_MISMATCH")
        if self.state != "ACTIVE":
            return self._refused("NOT_ACTIVE")
        if any(a["status"] != "TERMINAL" or not a["sealed"] for a in self.actions.values()):
            return self._refused("ACTION_OUTSTANDING")
        if p["executionId"] in self.bound_ids or p["runNonce"] in self.bound_nonces \
                or p["executionId"] in self.prior_ids or p["runNonce"] in self.prior_nonces:
            return self._refused("EXECUTION_REPLAY")     # durable across generations
        if p["dispatchGeneration"] != self.generation:
            return self._refused("GENERATION_MISMATCH")
        run = self.runs.get(p["runNonce"])
        if run is None or any(run[k] != p[k] for k in ("bindingDigest", "caseId", "requestDigest")):
            return self._refused("UNKNOWN_BINDING")
        if p["serverCertificateDigest"] != run["serverCertificateDigest"]:
            return self._refused("CERTIFICATE_MISMATCH")
        if (p["workerPid"], p["workerStartTicks"]) not in self.workers:
            return self._refused("WORKER_NOT_OBSERVED")
        if not self._record("BIND", p["executionId"], p["runNonce"], p["reservationDigest"]):
            return self._refused("STORAGE_FAILURE")
        self.bound = {"executionId": p["executionId"], "runNonce": p["runNonce"]}
        self.expired, self.actions, self.mutation_keys, self.observed_uids = False, {}, set(), {}
        self.bound_ids.append(p["executionId"])
        self.bound_nonces.append(p["runNonce"])
        return {"result": "OK", "executionId": p["executionId"],
                "caseManifestSetDigest": sha(canonical(sorted(run["manifests"])))}

    def _op_arm_action(self, p: dict) -> dict:
        if self.state != "ACTIVE":
            return self._refused("DRAIN_PENDING" if self.drain_pending else "NOT_ACTIVE")
        if self.bound is None or p["executionId"] != self.bound["executionId"]:
            return self._refused("EXECUTION_NOT_BOUND")
        if self.expired:
            return self._refused("EXECUTION_EXPIRED")
        if any(a["status"] != "TERMINAL" or not a["sealed"] for a in self.actions.values()):
            return self._refused("ACTION_OUTSTANDING")
        if p["actionId"] != len(self.actions) + 1:
            return self._refused("ACTION_ID_OUT_OF_ORDER")
        run = self.runs[self.bound["runNonce"]]
        manifest = self.manifests.get(p["manifestDigest"])
        if manifest is None or p["manifestDigest"] not in run["manifests"]:
            return self._refused("MANIFEST_OUTSIDE_CASE")
        if (p["verb"] == "DELETE") != (p["recordedUid"] is not None):
            return self._refused("UID_RULE")              # only DELETE carries the recorded-UID precondition
        if p["verb"] == "DELETE" and p["recordedUid"] not in self.observed_uids.get(p["manifestDigest"], set()):
            return self._refused("UID_NOT_OBSERVED")      # the UID must come from the gate's own delivered result
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
        if not self._record("ARM", p["actionId"], p["verb"], p["manifestDigest"], p["recordedUid"], expected):
            return self._refused("STORAGE_FAILURE")
        if key is not None:
            self.mutation_keys.add(key)
        self.actions[p["actionId"]] = {"actionId": p["actionId"], "verb": p["verb"], "manifestDigest": p["manifestDigest"],
                                       "uid": p["recordedUid"], "templateDigest": expected, "status": "ARMED",
                                       "sealed": False}
        return {"result": "OK", "actionId": p["actionId"], "flushedConnections": flushed}

    def _op_action_outcome(self, p: dict) -> dict:
        if self.bound is None or p["executionId"] != self.bound["executionId"]:
            return self._refused("EXECUTION_NOT_BOUND")
        action = self.actions.get(p["actionId"])
        if action is None:
            return self._refused("UNKNOWN_ACTION")
        if not action["sealed"]:
            # Sealing: from here on the action can never be consumed, and its classification never changes.
            if action["status"] == "ARMED":
                stamp = self._stamp_of(action)
                self._close_connections(lambda c: c["stamp"] == stamp and not c["consumed"])
                action.update(status="TERMINAL", classification="NOT_FORWARDED")
            elif action["status"] == "CONSUMED":
                # Still in flight: the gate aborts the upstream exchange and closes the server connection.
                self.connections[action["conn"]]["state"] = "CLOSED"
                action.update(status="TERMINAL", classification="IO_AMBIGUOUS")
                self.state = "HELD"
            if not self._record("SEALED", action["actionId"], action["classification"], action.get("afterInvalidation", False)):
                return self._refused("STORAGE_FAILURE")
            action["sealed"] = True
            self._settle_drain()
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
            if reason == "RECONCILIATION_REQUIRED" and self.state != "HELD":
                self.state = "HELD"
                self._record("INVALIDATED", reason, "HELD")
            return {"result": "OK", "state": self.state, "deniedActionIds": self._deny_armed()}
        if reason == "NORMAL_DRAIN":
            if self._in_flight() is not None:
                return self._refused("ACTION_IN_FLIGHT")
            ambiguous = any(a.get("classification") == "IO_AMBIGUOUS" for a in self.actions.values())
            self.state = "HELD" if ambiguous else "CLOSED"
            self._record("CLOSED", reason, self.state)
            denied = self._deny_armed()
            return {"result": "OK", "state": self.state, "deniedActionIds": denied}
        # The broker's own disagreement or missing outcome ends the gate's generation HELD as well.
        denied = self._urgent("HELD" if reason == "RECONCILIATION_REQUIRED" else "INVALIDATED", reason)
        return {"result": "OK", "state": self.state, "deniedActionIds": denied}


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
