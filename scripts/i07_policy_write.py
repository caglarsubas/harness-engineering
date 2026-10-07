#!/usr/bin/env python3
"""I07 policy writer channel (W02c): frame envelope, closed policy-kind table and gate decisions.

DATA_CHECK_ONLY reference model for the private interface between the enrolled policy-writer
artifact and the effect gate (HOST-INTERFACE-DRAFT-002 sections 2.3, 2.4, 3.2 A3/A4, 4.3 and 5.5).

- `check_write` applies the closed policy-kind table to one WRITE_OBJECT request: which kinds,
  scopes and operations the writer identity may change, and the exact object shape.
- `render_write` derives the one Kubernetes request a write permits (method, path, headers and
  body), including the uid and resourceVersion preconditions the apiserver enforces.
- `PolicyGate` extends the reviewed W02b gate model (`i05_gate_channel.Gate`, unchanged) with the
  I07 channel. A WRITE_BEGIN asks for the gate's normal drain; maintenance opens only when the A3
  fence holds, which this model computes from the gate's own state and never from a drain reply
  (W02b review finding P1). Every write is journalled durably before its first upstream byte and
  its terminal classification before its response.

None of it opens a socket, forwards a request or grants authority.
"""
from __future__ import annotations

import copy
from typing import Any

try:
    import i05_gate_channel as i05
except ImportError:
    from scripts import i05_gate_channel as i05

FRAME_VERSION = "planeon.internal.policy-write-frame/v1"
OPERATIONS = ("MAINTENANCE_STATUS", "WRITE_BEGIN", "WRITE_OBJECT", "WRITE_END")
MAINTENANCE_STATES = ("NONE", "PENDING", "OPEN", "HELD", "ENDED")
WRITE_OPERATIONS = ("CREATE", "UPDATE", "DELETE")
SCOPES = ("QUALIFICATION_NAMESPACE", "QUALIFICATION_NAMESPACE_OBJECT", "CLUSTER")
SUCCESS_STATUSES = {"CREATE": (201,), "UPDATE": (200, 201), "DELETE": (200, 202)}
METADATA_KEYS = ("annotations", "labels", "name", "namespace", "resourceVersion", "uid")
MAX_WRITES = 256
CLASSIFICATIONS = ("DELIVERED_RESULT", "IO_AMBIGUOUS")
ZERO_DIGEST = i05.ZERO_DIGEST
canonical, sha, require, frame_digest = i05.canonical, i05.sha, i05.require, i05.frame_digest
check_frame, decode_frame = i05.check_frame, i05.decode_frame


# ---------------------------------------------------------------- closed policy-kind table

def api_version(entry: dict) -> str:
    return entry["group"] + "/" + entry["version"] if entry["group"] else entry["version"]


def classify_resource(kinds: dict, resource: dict) -> tuple[dict | None, str | None]:
    """The table entry for a requested resource, or the refusal. Writable kinds match group, version and
    resource exactly; effect kinds and non-writable policy kinds match by group and resource at any version;
    everything else is outside the table."""
    key = (resource["group"], resource["version"], resource["resource"])
    for entry in kinds["writable"]:
        if (entry["group"], entry["version"], entry["resource"]) == key:
            return entry, None
    loose = (resource["group"], resource["resource"])
    if any((e["group"], e["resource"]) == loose for e in kinds["effectKinds"]):
        return None, "EFFECT_KIND"
    if any((e["group"], e["resource"]) == loose for e in kinds["notWritable"]):
        return None, "POLICY_KIND_NOT_WRITABLE"
    return None, "KIND_OUTSIDE_TABLE"


def _string_map(value: Any) -> bool:
    return type(value) is dict and all(type(v) is str for v in value.values())


def check_write(kinds: dict, namespace: str, p: dict) -> str | None:
    """None when the WRITE_OBJECT request is inside the closed table, otherwise the refusal reason.
    The gate never forwards an effect kind, a policy kind outside the writer's closure or any other kind."""
    entry, reason = classify_resource(kinds, p["resource"])
    if entry is None:
        return reason
    op = p["operation"]
    if op not in entry["operations"]:
        return "VERB_NOT_ALLOWED"
    scope = entry["scope"]
    if scope == "QUALIFICATION_NAMESPACE":
        in_scope = p["namespace"] == namespace
    elif scope == "QUALIFICATION_NAMESPACE_OBJECT":
        in_scope = p["namespace"] is None and p["name"] == namespace
    else:
        in_scope = p["namespace"] is None
    if not in_scope:
        return "SCOPE_MISMATCH"
    if (op == "CREATE") != (p["prior"] is None):
        return "PRIOR_RULE"               # CREATE expects absence; UPDATE and DELETE name the exact prior object
    if (op == "DELETE") != (p["object"] is None):
        return "OBJECT_RULE"
    if op == "DELETE":
        return None
    obj = p["object"]
    meta = obj.get("metadata")
    allowed = {"apiVersion", "kind", "metadata"} | set(entry["topLevelKeys"])
    if not (set(obj) <= allowed and obj.get("apiVersion") == api_version(entry) and obj.get("kind") == entry["kind"]
            and type(meta) is dict and set(meta) <= set(METADATA_KEYS) and meta.get("name") == p["name"]):
        return "OBJECT_RULE"
    if scope == "QUALIFICATION_NAMESPACE":
        if meta.get("namespace") != namespace:
            return "OBJECT_RULE"
    elif "namespace" in meta:
        return "OBJECT_RULE"
    if any(key in meta and not _string_map(meta[key]) for key in ("labels", "annotations")):
        return "OBJECT_RULE"
    if op == "CREATE":
        if "uid" in meta or "resourceVersion" in meta:
            return "OBJECT_RULE"
    elif (meta.get("uid"), meta.get("resourceVersion")) != (p["prior"]["uid"], p["prior"]["resourceVersion"]):
        return "OBJECT_RULE"              # an UPDATE carries the prior object's uid and resourceVersion itself
    return None


def render_write(entry: dict, p: dict, namespace: str, authority: str) -> dict:
    """The exact Kubernetes request one write permits: head bytes and body digest. The gate forwards these
    bytes with the writer identity. CREATE posts the object (the apiserver refuses an existing name), UPDATE
    puts the object with its uid and resourceVersion, DELETE carries only uid and resourceVersion
    preconditions; a stale prior object is refused by the apiserver itself (409)."""
    base = "/api/" + entry["version"] if not entry["group"] else "/apis/%s/%s" % (entry["group"], entry["version"])
    if entry["scope"] == "QUALIFICATION_NAMESPACE":
        collection = "%s/namespaces/%s/%s" % (base, namespace, entry["resource"])
    else:
        collection = "%s/%s" % (base, entry["resource"])
    op = p["operation"]
    if op == "CREATE":
        method, target, body = "POST", collection, canonical(p["object"])
    elif op == "UPDATE":
        method, target, body = "PUT", collection + "/" + p["name"], canonical(p["object"])
    else:
        method, target = "DELETE", collection + "/" + p["name"]
        body = canonical({"apiVersion": "v1", "kind": "DeleteOptions",
                          "preconditions": {"resourceVersion": p["prior"]["resourceVersion"], "uid": p["prior"]["uid"]}})
    head = ("%s %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nContent-Type: application/json\r\n"
            "Content-Length: %d\r\n\r\n" % (method, target, authority, len(body)))
    return {"head": head, "bodyDigest": sha(body)}


def write_outcome_is_final(op: str, status: int) -> bool:
    """Whether a delivered response settles a write: its success statuses or a rejection (4xx other than
    408, such as 409 for an existing name or a stale precondition). Any other status (5xx, 408, 1xx, 3xx,
    another 2xx) leaves the outcome unknown, so the write is IO_AMBIGUOUS."""
    return status in SUCCESS_STATUSES[op] or (400 <= status <= 499 and status != 408)


# ---------------------------------------------------------------- gate model

class PolicyGate(i05.Gate):
    """The W02b gate with its I07 channel: one writer session at a time and one maintenance per
    generation, owned by the session that began it."""

    def __init__(self, config: dict, kinds: dict):
        super().__init__(config)
        writer = config["policyWriter"]
        self.kinds = kinds
        self.namespace = writer["qualificationNamespace"]
        self.authority = writer["apiserverAuthority"]
        self.maintenance = "NONE"
        self.maintenance_reason = None
        self.session: dict | None = None
        self.writes: dict[int, dict] = {}
        self.write_counters = {"sessions": 0, "writesForwarded": 0, "writesRefused": 0}

    # -- the A3 fence for I07
    def _fence(self) -> str:
        """OPEN when the generation is CLOSED or INVALIDATED and no action admitted under it lacks a durable
        terminal classification; HELD when the generation is HELD (an ambiguous outcome or a failure);
        otherwise PENDING. Computed from gate state, never from a drain reply."""
        if self.state == "HELD":
            return "HELD"
        if self.state not in ("CLOSED", "INVALIDATED") or self._in_flight() is not None:
            return "PENDING"
        return "OPEN"

    def _settle_maintenance(self) -> None:
        if self.maintenance == "PENDING" and self._fence() == "OPEN":
            if self._record("MAINT_OPEN", self.state):
                self.maintenance = "OPEN"
        if self.maintenance in ("PENDING", "OPEN") and self._fence() == "HELD":
            self.maintenance = "HELD"
            self._record("MAINT_HELD", self.state)

    def _ambiguous_writes(self) -> list[int]:
        return [w for w, r in sorted(self.writes.items()) if r["classification"] == "IO_AMBIGUOUS"]

    def _end_maintenance(self, reason: str) -> None:
        self.maintenance, self.maintenance_reason = "ENDED", reason
        self._record("MAINT_ENDED", reason, len(self.writes), self._ambiguous_writes())

    def _rebuild(self) -> str:
        """Restart: I05 actions as in W02b; every write forwarded without a terminal record is ambiguous and
        the gate restarts HELD. A maintenance the restart interrupted never resumes."""
        state = super()._rebuild()
        writes: dict[int, dict] = {}
        begun, ended = False, None
        for entry in self.journal:
            kind = entry[0]
            if kind == "WRITE_FORWARDED":
                writes[entry[1]] = {"status": "FORWARDED", "classification": None}
            elif kind == "WRITE_TERMINAL":
                writes[entry[1]] = {"status": "TERMINAL", "classification": entry[2]}
            elif kind == "MAINT_REQUESTED":
                begun = True
            elif kind == "MAINT_ENDED":
                ended = entry[1]
        for record in writes.values():
            if record["status"] == "FORWARDED":
                record.update(status="TERMINAL", classification="IO_AMBIGUOUS")
        self.writes = writes
        self.maintenance = "ENDED" if begun else "NONE"
        self.maintenance_reason = None if not begun else ended or "GATE_RESTART"
        return "HELD" if self._ambiguous_writes() else state

    def snapshot(self) -> dict:
        view = super().snapshot()
        view.update(maintenance=self.maintenance, maintenanceReason=self.maintenance_reason,
                    writerSession=self.session["state"] if self.session else None,
                    writes={str(k): dict(v) for k, v in sorted(self.writes.items())},
                    writeCounters=dict(self.write_counters))
        return view

    # -- events
    def handle(self, event: dict, schemas: dict) -> dict:
        kind = event["type"]
        if kind.startswith("W_"):
            out = self._writer_event(event, schemas["i07"])
        else:
            out = super().handle(event, schemas["i05"])
            if kind == "GATE_RESTART":
                self.session = None       # deny-first: no writer session survives a restart
                out["maintenance"] = self.maintenance
        self._settle_maintenance()
        return out

    def _writer_event(self, event: dict, schema: dict) -> dict:
        kind = event["type"]
        if kind == "W_CONNECT":
            if self.session is not None:
                return {"refusedSession": "SESSION_EXISTS"}
            self.session = {"state": "UNOPENED", "challenge": None, "next": 1, "last": ZERO_DIGEST, "owner": False}
            self.write_counters["sessions"] += 1
            return {"session": "CONNECTED"}
        if self.session is None:
            require(kind in ("W_CHANNEL_LOST", "W_PEER_CHANGED"), "writer frame without a session")
            return {}
        if kind == "W_FRAME":
            return self._w_frame(event, schema)
        if kind == "W_CHANNEL_LOST":
            return self._end_session("ENDED")
        require(kind == "W_PEER_CHANGED", "unknown writer event")
        # Something other than the qualified writer holds the session: an enforcement breach.
        self._urgent("HELD", "WRITER_PEER_DEVIATION")
        self.state = "HELD"
        out = self._end_session("FATAL")
        out["fatal"] = "PEER_CHANGED"
        return out

    def _end_session(self, how: str) -> dict:
        owner = self.session["owner"]
        self.session = None
        self._record("WRITER_SESSION_ENDED", how)
        if owner and self.maintenance != "ENDED":
            self._end_maintenance("SESSION_" + how)
        return {"sessionEnd": how, "maintenance": self.maintenance}

    def _w_fatal(self, reason: str) -> dict:
        out = self._end_session("FATAL")
        out["fatal"] = reason
        return out

    def _w_frame(self, event: dict, schema: dict) -> dict:
        s, frame = self.session, event["frame"]
        try:
            check_frame(frame, schema)
        except ValueError as exc:
            return self._w_fatal(str(exc).split(" ", 1)[0] + "_INVALID_FRAME")
        if frame["direction"] != "WRITER_TO_GATE" or frame["sequence"] % 2 != 1:
            return self._w_fatal("DIRECTION")
        if frame["sequence"] != s["next"] or frame["previousDigest"] != s["last"]:
            return self._w_fatal("CHAIN_BROKEN")
        if s["state"] == "UNOPENED":
            if frame["operation"] != "MAINTENANCE_STATUS":
                return self._w_fatal("OPENING_FRAME_REQUIRED")
            s["state"], s["challenge"] = "OPEN", frame["challenge"]
        elif frame["challenge"] != s["challenge"]:
            return self._w_fatal("CHALLENGE_MISMATCH")
        payload = getattr(self, "_w_op_" + frame["operation"].lower())(frame["payload"], event)
        if payload.get("gateCrashed"):
            return payload
        response = {"schemaVersion": FRAME_VERSION, "challenge": s["challenge"], "sequence": frame["sequence"] + 1,
                    "previousDigest": frame_digest(frame), "direction": "GATE_TO_WRITER",
                    "operation": frame["operation"], "payload": payload}
        check_frame(response, schema)
        s["next"], s["last"] = frame["sequence"] + 2, frame_digest(response)
        return {"response": payload}

    def _refused(self, reason: str) -> dict:
        return {"result": "REFUSED", "reason": reason}

    def _w_op_maintenance_status(self, p: dict, event: dict) -> dict:
        in_flight = self._in_flight()
        return {"result": "OK", "generation": self.generation, "gateState": self.state, "maintenance": self.maintenance,
                "inFlightActionId": in_flight["actionId"] if in_flight else None, "writes": len(self.writes),
                "ambiguousWriteIds": self._ambiguous_writes(), "journalDigest": sha(canonical(self.journal))}

    def _w_op_write_begin(self, p: dict, event: dict) -> dict:
        if p["expectedGeneration"] != self.generation:
            return self._refused("GENERATION_MISMATCH")
        if self.maintenance == "ENDED":
            return self._refused("MAINTENANCE_ENDED")
        denied: list[int] = []
        if self.maintenance == "NONE":
            if not self._record("MAINT_REQUESTED", self.generation):
                return self._refused("STORAGE_FAILURE")
            self.session["owner"], self.maintenance = True, "PENDING"
            denied = self._drain().get("denied", [])     # the W02b normal drain; its reply is not the fence
            self._settle_maintenance()
        # A repeated WRITE_BEGIN in the owning session reports the maintenance state (polling).
        return {"result": "OK", "maintenance": self.maintenance, "gateState": self.state, "deniedActionIds": denied}

    def _w_op_write_object(self, p: dict, event: dict) -> dict:
        if self.maintenance != "OPEN":
            self.write_counters["writesRefused"] += 1
            return self._refused("MAINTENANCE_HELD" if self.maintenance == "HELD" else "MAINTENANCE_NOT_OPEN")
        if p["writeId"] != len(self.writes) + 1:
            self.write_counters["writesRefused"] += 1
            return self._refused("WRITE_ID_OUT_OF_ORDER")
        reason = check_write(self.kinds, self.namespace, p)
        if reason is not None:
            self.write_counters["writesRefused"] += 1
            return self._refused(reason)
        entry, _ = classify_resource(self.kinds, p["resource"])
        request = render_write(entry, p, self.namespace, self.authority)
        request_digest = sha(canonical(request))
        # Durable before the first upstream byte, like A1's consumption record.
        if not self._record("WRITE_FORWARDED", p["writeId"], p["operation"], api_version(entry), entry["kind"],
                            p["namespace"], p["name"], request_digest, p["prior"]):
            return self._refused("STORAGE_FAILURE")
        self.writes[p["writeId"]] = {"status": "FORWARDED", "classification": None}
        self.write_counters["writesForwarded"] += 1
        upstream = event["upstream"]
        if upstream == "GATE_CRASH":
            # The gate dies after forwarding: deny-first restart from the journal alone.
            out = self.handle({"type": "GATE_RESTART"}, {"i05": None, "i07": None})
            return {"gateCrashed": True, **out}
        reconciliation, details = {}, {}
        if upstream == "LOST":
            classification = "IO_AMBIGUOUS"
        elif not write_outcome_is_final(p["operation"], upstream["httpStatus"]):
            classification = "IO_AMBIGUOUS"
            reconciliation = {"httpStatus": upstream["httpStatus"], "resultDigest": upstream["bodyDigest"]}
        else:
            classification = "DELIVERED_RESULT"
            details = {"httpStatus": upstream["httpStatus"], "resultDigest": upstream["bodyDigest"],
                       "observedUid": upstream["uid"], "observedResourceVersion": upstream["resourceVersion"]}
        if event.get("terminalRecordFails"):
            self.storage_fails += 1
        if not self._record("WRITE_TERMINAL", p["writeId"], classification, details or reconciliation):
            classification, details = "IO_AMBIGUOUS", {}
        self.writes[p["writeId"]] = {"status": "TERMINAL", "classification": classification}
        if classification == "IO_AMBIGUOUS":
            self.state = "HELD"         # an unknown write outcome holds the generation, as an ambiguous action does
        self._settle_maintenance()
        delivered = classification == "DELIVERED_RESULT"
        return {"result": "OK", "writeId": p["writeId"], "classification": classification, "requestDigest": request_digest,
                "httpStatus": details.get("httpStatus") if delivered else None,
                "resultDigest": details.get("resultDigest") if delivered else None,
                "observedUid": details.get("observedUid") if delivered else None,
                "observedResourceVersion": details.get("observedResourceVersion") if delivered else None}

    def _w_op_write_end(self, p: dict, event: dict) -> dict:
        if self.maintenance == "NONE":
            return self._refused("MAINTENANCE_NOT_BEGUN")
        if self.maintenance == "ENDED":
            return self._refused("MAINTENANCE_ENDED")
        if not self._record("MAINT_ENDED", "WRITE_END", len(self.writes), self._ambiguous_writes()):
            return self._refused("STORAGE_FAILURE")
        self.maintenance, self.maintenance_reason = "ENDED", "WRITE_END"
        # The gate stays CLOSED: the old generation never resumes, a new one needs fresh observation.
        return {"result": "OK", "maintenance": "ENDED", "gateState": self.state, "writes": len(self.writes),
                "ambiguousWriteIds": self._ambiguous_writes()}


def replay(config: dict, events: list, schemas: dict, kinds: dict) -> tuple[list, dict]:
    """Replay one transcript of I05 and I07 events. FRAME events build the next valid I05 broker frame and
    W_FRAME events the next valid writer frame of the open session (with the W_CONNECT event's challenge);
    then the event's mutations apply, so invalid frames are exact deviations from a valid one."""
    gate = PolicyGate(copy.deepcopy(config), copy.deepcopy(kinds))
    outputs, challenge = [], None
    for event in events:
        event = copy.deepcopy(event)
        if event["type"] == "FRAME":
            frame = {"schemaVersion": i05.FRAME_VERSION, "generation": config["generation"],
                     "challenge": config["brokerChallenge"], "sequence": gate.next_sequence,
                     "previousDigest": gate.last_digest, "direction": "BROKER_TO_GATE",
                     "operation": event["operation"], "payload": event["payload"]}
            event = {"type": "FRAME", "frame": i05._apply(frame, event.get("mutate", []))}
        elif event["type"] == "W_CONNECT":
            challenge = event["challenge"]
        elif event["type"] == "W_FRAME":
            session = gate.session or {"next": 1, "last": ZERO_DIGEST}
            frame = {"schemaVersion": FRAME_VERSION, "challenge": challenge, "sequence": session["next"],
                     "previousDigest": session["last"], "direction": "WRITER_TO_GATE",
                     "operation": event["operation"], "payload": event["payload"]}
            event = {**event, "frame": i05._apply(frame, event.get("mutate", []))}
        outputs.append(gate.handle(event, schemas))
    return outputs, gate.snapshot()
