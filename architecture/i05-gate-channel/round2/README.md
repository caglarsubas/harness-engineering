# I05 broker-gate channel — W02b (MET-ENFORCE-007), round 2

Status: **CONTRACT_CANDIDATE**, awaiting the round-2 independent review. Round 1 (`review-round1.json`, reviewed bytes
in `round1/`) returned CHANGES_REQUIRED with 3 MAJOR, 8 MINOR and 1 NOTE findings; each is answered below. DATA_CHECK_ONLY:
no socket is opened, no request is forwarded, nothing is installed, and all E01-E12 stay OPEN_UNPROVEN.

This part formalizes I05, the private channel from the capacity broker to the effect gate, as the reviewed W01 design
(HOST-INTERFACE-DRAFT-002 §3.2 A1-A4, §4.3, §6 C1-C7 and §7) left it for W02:

- the frame envelope: canonical duplicate-free JSON bytes, strict request/response lockstep, sequence and hash chain bound
  to the generation and to the broker's opening challenge;
- the closed schema for the five operations and their responses;
- the gate state machine as an executable model: connection stamping, the exact request rendering checked at the A1
  admission point, the durable journal, the A3 drain fence and A4 urgent invalidation;
- the ACTION_OUTCOME to RESOURCE_RESULT mapping table;
- transcript, replay, duplicate and byte-level vectors, including counterexamples 17, 18, 21 and 22.

## Files

| File | Content |
|---|---|
| `channel.schema.json` | Draft 2020-12 schema `planeon.internal.effect-gate-frame/v1`: ten frame variants (five requests, five responses) |
| `outcome-mapping.json` | ACTION_OUTCOME to I02 RESOURCE_RESULT agreement rows, object rules and rules |
| `vectors.json` | 65 transcripts, 31 agreement cases, 26 frame checks and 8 byte-level frame checks, each with its exact expected output |
| `scripts/i05_gate_channel.py` | Reference model: `decode_frame`, `check_frame`, `render_request`, `template_digest`, `Gate`, `replay`, `check_agreement` |

## Channel

1. **One channel per gate generation.** The broker connects to the candidate path
   `/run/planeon/live-proxy/effect-admission.sock` (AF_UNIX/SOCK_SEQPACKET, root:root 0600) after it has qualified the gate
   as a peer (§4.3). The gate refuses a second connection while the channel is open and any connection after it closed:
   there is no reconnect.
2. **Custody on every frame (round-1 F10).** On every received frame the gate verifies the broker's kernel peer identity:
   SO_PEERCRED and the frame's SCM_CREDENTIALS, the retained pidfd and PID/start identity, executable, label and cgroup
   (base §3, §4.3). Any deviation is fatal. The BIND_EXECUTION peer-qualification digest adds a cross-check of the mutual
   qualification record; it does not replace the per-frame checks.
3. **Opening and lockstep.** The first broker frame is GENERATION_STATUS with sequence 1, an all-zero previous digest, the
   gate's generation and a fresh 256-bit broker challenge; every later frame carries the same generation and challenge. Odd
   sequences are broker requests, even sequences gate responses, one response per request, no unsolicited gate frames.
   `previousDigest` is the SHA-256 of the exact bytes of the frame before it.
4. **Bytes (round-1 F8).** A received datagram is at most 16 KiB, UTF-8, duplicate-free JSON without NaN or Infinity, and
   exactly the canonical encoding (sorted keys, no whitespace), so the bytes digested are the bytes received
   (`decode_frame`). Then: exact builtins (no floats; booleans are not integers), no control character in any string (the
   schema patterns are ECMA-262 patterns; a trailing newline is refused), the closed schema, depth at most 16. Each request
   is answered within 2 seconds, inside the execution's signed lifetime and the 900-second limit. No descriptor passing, no
   command, URL, path or program selector.
5. **Fatal versus refused.** A frame that fails any of item 4, breaks the chain, claims the gate's direction (a response
   shape or an even sequence), carries another generation or challenge, or does not open with GENERATION_STATUS closes the
   channel without a response; so does a peer deviation or a BIND whose peer-qualification digest differs. A well-formed
   request the gate will not honour gets REFUSED with a closed reason and changes no gate state, except that a storage
   failure holds the generation.
6. **Channel end (round-1 F5).** Broker EOF when the generation is CLOSED or INVALIDATED, every action sealed and none in
   flight, is an orderly end: the state stays. Any other loss is peer failure: unsealed actions are denied and the
   generation is HELD. W01 §2.4 WRITE_END therefore leaves the gate CLOSED.

The broker verifies the gate's frames the same way and treats any deviation as peer failure.

## Operations

| Operation | Request | OK response | Refusal reasons |
|---|---|---|---|
| GENERATION_STATUS | `{}` | state, drainPending, bound execution, armed and in-flight action, counters, journal digest | none |
| BIND_EXECUTION | executionId, bindingDigest, reservationDigest, runNonce, caseId, requestDigest, dispatchGeneration, serverCertificateDigest, worker PID and start ticks, peerQualificationDigest | executionId and the gate-resolved case manifest-set digest | NOT_ACTIVE, ACTION_OUTSTANDING, EXECUTION_REPLAY, GENERATION_MISMATCH, UNKNOWN_BINDING, CERTIFICATE_MISMATCH, WORKER_NOT_OBSERVED, STORAGE_FAILURE |
| ARM_ACTION | executionId, actionId, verb, manifestDigest, requestTemplateDigest, recordedUid | actionId and the number of connections the C2 flush closed | NOT_ACTIVE, DRAIN_PENDING, EXECUTION_NOT_BOUND, EXECUTION_EXPIRED, ACTION_OUTSTANDING, ACTION_ID_OUT_OF_ORDER, MANIFEST_OUTSIDE_CASE, UID_RULE, UID_NOT_OBSERVED, TEMPLATE_MISMATCH, MUTATION_KEY_REUSED, STORAGE_FAILURE |
| ACTION_OUTCOME | executionId, actionId | classification, admittedBeforeInvalidation, HTTP status, result digest, observed UID and resourceVersion | EXECUTION_NOT_BOUND, UNKNOWN_ACTION, STORAGE_FAILURE |
| CLOSE_GENERATION | reason | resulting state and the actions this close denied | ACTION_IN_FLIGHT (normal drain only) |

### Where each request value comes from (round-1 F1)

| Value | Source at the gate | Effect |
|---|---|---|
| runNonce, bindingDigest, caseId, requestDigest | RESOLVED: the gate's own copy of the signed release and capacity inputs for this run nonce | Must equal the resolution (UNKNOWN_BINDING) |
| serverCertificateDigest | RESOLVED: the run certificate the gate enrolled for this run | Must equal it; A1 requires the same certificate (CERTIFICATE_MISMATCH) |
| case manifest set, manifest identity, request rendering | RESOLVED: the signed profile and exact kubernetesApiRules | Bounds every ARM_ACTION |
| workerPid, workerStartTicks | KERNEL: a live member of the broker's probe-worker cgroup with that PID and start time | Must be observed (WORKER_NOT_OBSERVED) |
| peerQualificationDigest | KERNEL: the gate's own mutual qualification record | Must equal it (fatal) |
| dispatchGeneration | GATE: its own generation | Must equal it (GENERATION_MISMATCH) |
| recordedUid (DELETE) | GATE: a UID the gate itself recorded from a DELIVERED_RESULT (CREATE 201 or GET 200) for the same manifest in this execution | Must be one of them (UID_NOT_OBSERVED) |
| executionId, reservationDigest | LABEL: broker-assigned; no independent source | Confers no authority; journalled; an executionId or run nonce binds once per generation (EXECUTION_REPLAY) |
| actionId, verb, manifestDigest, requestTemplateDigest | LABEL checked against RESOLVED data | A request to arm; the gate re-derives the template and refuses any mismatch |

## Decisions

1. **ACTION_OUTCOME seals.** After its response the action can never be consumed and its classification never changes. An
   armed, unconsumed action becomes NOT_FORWARDED and its stamped connections close. A terminal action returns its record.
   An action still in flight is aborted: the gate closes the upstream exchange and the consumed server connection, records
   IO_AMBIGUOUS and holds the generation (A3). A late upstream response after a seal is never relayed and never changes the
   seal; it is journalled as a reconciliation note (round-1 F4). The broker asks after the server's RESOURCE_RESULT, and
   the gate records every terminal classification durably before relaying any response byte, so a normal result is
   recorded by then.
2. **One outstanding action, sealed before the next.** ARM_ACTION and the next BIND_EXECUTION are refused until every action
   of the bound execution is terminal and sealed. One execution is bound at a time (one worker). The broker's I02
   transcript advances only after it holds both the gate's ACTION_OUTCOME and the server's RESOURCE_RESULT and they agree.
3. **Action identifiers.** actionId is the I02 RESOURCE_ACTION actionId, contiguous from 1 within the execution (1-256). The
   broker emits RESOURCE_ACTION only after ARM_ACTION returned OK. A connection stamp is (executionId, actionId).
4. **Exact request rendering (round-1 F2).** From the armed template and the signed profile the gate renders the one I04
   request the action permits (`render_request`): method (POST, GET or DELETE), path
   (`/api/v1/namespaces/<ns>/<plural>[/<name>]`), an empty query string, exactly the headers Host (the signed endpoint
   authority), Accept `application/json` and, with a body, Content-Type `application/json` and Content-Length, and the body:
   the signed manifest bytes for CREATE, the canonical DeleteOptions carrying only the recorded-UID precondition for DELETE,
   none for GET. At A1 the parsed request must equal the rendering exactly. Any other query parameter (dryRun, watch,
   resourceVersion, gracePeriodSeconds, ...), DeleteOptions field, header, method, path or body byte is refused as
   REQUEST_MISMATCH. HTTP/2, CONNECT, upgrade, redirect and generic proxying stay refused (base §4).
5. **C2 flush and C3 stamp.** In the ARM_ACTION transaction, under the generation lock and before the ARM record, the gate
   closes every accepted connection that has not consumed an action and accepts and closes every connection in its listen
   backlog. A connection accepted later is stamped with the armed action, or with none. ACCEPT, ARM_ACTION, A1, sealing and
   closing serialize on the generation lock.
6. **A1.** A request passes only when the generation is ACTIVE with no pending drain (I07 is the only policy writer and any
   write first drains, so the observed policy generation is current exactly then; round-1 F12), the execution is bound and
   not expired, the connection's stamp equals the armed, unconsumed action of the bound execution, its client certificate
   equals the bound run certificate and the request equals the rendering. The gate records the consumption (fsync and read
   back), then sends the first byte upstream. One request per connection (C1); the gate closes the connection after relaying
   its one response. After the consumption every other connection stamped with that action closes (C5). STAMP_MISMATCH and
   ALREADY_CONSUMED are checked but unreachable in the model (defence in depth).
7. **C7 by construction.** At ARM the gate refuses a CREATE whose manifest it already armed in this execution and a DELETE
   whose recorded UID it already armed, even if the earlier action was never forwarded. GETs may repeat.
8. **Closing.** Normal drain is refused while an action is in flight; otherwise it records the close, denies an armed action
   and ends CLOSED, or HELD if any action of the generation is IO_AMBIGUOUS. Urgent reasons (revocation, expiry, peer,
   storage or observation failure) close A1 at once in memory, independent of storage, record the invalidation, deny an
   armed action and end INVALIDATED (HELD if the record fails); an action already admitted may still complete and is
   recorded with `admittedBeforeInvalidation` (A4). An I07 WRITE_BEGIN is the gate's own normal drain: ARM is refused with
   DRAIN_PENDING, BIND with NOT_ACTIVE, an armed action is denied, and the generation becomes CLOSED once no consumed action
   lacks a terminal record (the A3 fence), or HELD if one is ambiguous.
9. **Execution expiry (round-1 F6).** When the bound execution's signed lifetime ends, the gate records the expiry, denies an
   armed action, refuses ARM and A1 (EXECUTION_EXPIRED), and an action already in flight completes but is reported
   `admittedBeforeInvalidation`, as under the EXPIRY close.
10. **Cleanup admission (round-1 F11).** Every I04 request, cleanup and absence confirmation included, must be a broker-armed
    RESOURCE_ACTION of the bound execution, or it is refused (STAMP_NONE). Absence is confirmed by GET (repeatable); a
    DELETE needs a UID the gate observed in this execution and is armed once per UID (C7). An INVALIDATED or HELD gate
    forwards nothing, cleanup included: resources stay CLEANUP_PENDING until externally authorized reconciliation, and a
    later generation re-observes a UID by GET before deleting it.
11. **States.** INSPECTING, ACTIVE, DRAINING, CLOSED, INVALIDATED and HELD are the base conceptual states, carried only on
    this private channel. GENERATION_STATUS is constrained in the schema: at most one outstanding action, none without a
    bound execution, an armed action only while ACTIVE, no pending drain while ACTIVE, a pending drain while DRAINING, and
    nothing bound while INSPECTING (round-1 F8).

## Durable journal (round-1 F3)

The gate relies after a restart only on these records. Each is written with fsync and read back before the effect named.
A failed write holds the generation; the in-memory decision that denies or closes still applies.

| Record | Content | Durable before |
|---|---|---|
| BIND | executionId, runNonce, reservationDigest | the BIND_EXECUTION response |
| ARM | actionId, verb, manifestDigest, recordedUid, template digest | the ARM_ACTION response (after the C2 flush) |
| CONSUMED | actionId | the first byte sent upstream (A1) |
| TERMINAL | actionId, classification, admittedBeforeInvalidation, status, result digest, observed UID and resourceVersion | the first response byte relayed to the server |
| SEALED | actionId, classification, admittedBeforeInvalidation | the ACTION_OUTCOME response |
| DENIED | actionId | the response or event that denied it |
| INVALIDATED | reason | the CLOSE_GENERATION response (A1 closes first, in memory) |
| CLOSED, DRAIN_STARTED, DRAINED | reason or resulting state | the response, or the I07 reply |
| EXPIRED | executionId | any later decision for that execution |
| LATE_UPSTREAM | actionId | reconciliation only |

A restart starts denied and HELD, with no channel, stamps or connections, and rebuilds the actions from the journal alone:
a consumed action without a terminal record is IO_AMBIGUOUS, an armed one without a terminal record is NOT_FORWARDED, and
the A4 qualifier comes back from the TERMINAL and INVALIDATED records (T25, T27). The storage format stays open.

## Outcome mapping

`outcome-mapping.json` maps each gate classification to the I02 RESOURCE_RESULT outcomes that agree with it; an exact HTTP
status row takes precedence over a status-class row, and only an OK ACTION_OUTCOME is usable.

| Verb | Gate classification | HTTP status | RESOURCE_RESULT | Object |
|---|---|---|---|---|
| CREATE | DELIVERED_RESULT | 201 | CREATED | identity match required |
| CREATE | DELIVERED_RESULT | 4xx / 5xx | DENIED / AMBIGUOUS | not compared |
| GET | DELIVERED_RESULT | 200 | PRESENT | identity match required |
| GET | DELIVERED_RESULT | 404 / other 4xx / 5xx | ABSENT / DENIED / AMBIGUOUS | not compared |
| DELETE | DELIVERED_RESULT | 200, 202 | DELETED | identity match when present |
| DELETE | DELIVERED_RESULT | 404 / other 4xx (incl. 409) / 5xx | ABSENT / DENIED / AMBIGUOUS | not compared |
| any | NOT_FORWARDED | none | DENIED or AMBIGUOUS | none |
| any | IO_AMBIGUOUS | none | AMBIGUOUS | none |

An identity match (round-1 F7) decodes objectBase64 strictly (valid base64, duplicate-free JSON, no NaN, depth at most 16)
and requires apiVersion, kind, metadata.namespace and metadata.name equal to the armed template and metadata.uid and
metadata.resourceVersion equal to the gate's observation. Object content beyond that is not verified. Any other status has
no row. Disagreement, a missing or refused ACTION_OUTCOME or a missing RESOURCE_RESULT is sticky failure: the broker holds
the generation HELD and never advances its I02 transcript past the action. `admittedBeforeInvalidation` keeps the mapped
outcome, but such an execution never ends COMPLETED. NOT_FORWARDED agrees with both DENIED and AMBIGUOUS, because a server
that saw its connection closed cannot tell a refusal from a lost send. I02 is unchanged and no outcome enum is overloaded.

Conservative outcomes, stated rather than hidden (round-1 F12): a server whose I04 timeout is shorter than the gate's
upstream wait reports AMBIGUOUS, the seal then aborts the exchange (IO_AMBIGUOUS) and the generation is HELD; a
DELIVERED_RESULT whose relay the server lost disagrees with its AMBIGUOUS and is HELD as well. `flushClosures` counts every
gate-initiated closure of an unconsumed connection: the C2 flush, C5, seals and denies.

## Counterexamples

| Counterexample | Vector |
|---|---|
| 17: a byte-identical duplicate of completed GET A buffered before ARM(B) | T02 (on an earlier connection and in the backlog), T03 (connection stamped none) |
| 18: a policy write while an admitted CREATE is in flight | T30, T31 |
| 21: gate restart mid-execution | T25, T27 |
| 22: a connection opened while A was armed, used after B is armed | T08 (closed by C5 at A's consumption), T64 (closed by A's seal) |

The §6.3 residual stays as stated there: a server that opens a new connection after ARM(B) and sends exactly B's request
gets B forwarded once; misattribution shows as disagreement (HELD), not as an unarmed effect.

## Round-1 findings and dispositions

| Finding | Disposition in round 2 |
|---|---|
| F1 MAJOR, DELETE UID as broker authority | UID_NOT_OBSERVED: a DELETE UID must be one the gate recorded from its own delivered CREATE 201 or GET 200 for that manifest in this execution (T12, T45, T47); per-field source table; WORKER_NOT_OBSERVED and run-nonce replay (T13) |
| F2 MAJOR, lossy canonical action | `render_request` exact rendering; A1 compares method, path, query, headers and body (T48-T56) |
| F3 MAJOR, A4 and seals not durable | Every record through fsync and readback, enumerated above; restart rebuilds from the journal (T25, T27); storage failure at seal and urgent close defined (T57, T58) |
| F4 MINOR, late response after a seal | Seal immutable; abort closes upstream and the server connection; late response not relayed (T33) |
| F5 MINOR, every generation ended HELD | Orderly channel end (T01, T59); otherwise HELD (T26, T60) |
| F6 MINOR, in-flight action at expiry | Reported admittedBeforeInvalidation and recorded (T61) |
| F7 MINOR, lax agreement decoding | Strict decode, identity, UID and resourceVersion match, M00 for a refused outcome, DELETE object rule (A24-A31) |
| F8 MINOR, status combinations, newline, bytes | Schema constraints (G21-G26), control characters refused (T65, G18), `decode_frame` (B01-B08), dead BIND reason removed |
| F9 MINOR, vectors not reaching their reason | T19 and T63 reach DIRECTION, T62 A1 EXECUTION_EXPIRED, request-bound checks G13-G20, T64 for counterexample 22, unreachable reasons marked |
| F10 MINOR, per-frame custody | Channel item 2 |
| F11 MINOR, cleanup admission | Decision 10, T46 |
| F12 NOTE | Decision 6 (observed policy generation), stamps (executionId, actionId), connections closed after the relay, conservative outcomes and the counter documented |

## Spec mapping

| Spec | Encoded by |
|---|---|
| Base §3 I05 rules (custody, bounds, no selectors) | Channel 1-5, schema, `decode_frame` |
| Base §4 step 4 (gate derives route and body) | Decision 4 |
| §7 BIND_EXECUTION additions | dispatchGeneration, peerQualificationDigest |
| §7 ARM_ACTION additions | Decisions 5 and 7, DRAIN_PENDING |
| §7 ACTION_OUTCOME additions | admittedBeforeInvalidation, durable journal, outcome mapping |
| §7 CLOSE_GENERATION additions | Decision 8 |
| §7 GENERATION_STATUS additions | Counters and constraints in the status response |
| §3.2 A1, A3, A4 | Decisions 6, 8 and 9, durable journal |
| §6 C1-C7 | Decisions 3-7, T02-T10, T64 |
| §2.4 WRITE_END | Channel item 6 |

## Still open

- All E01-E12 and T01-T08; C2/C3 behaviour under load and restart is native T02/T03 work.
- The I07 wire schema and the policy-writer drain handshake (W02c).
- The gate's HTTP/TLS substrate and how it implements stamping and exact rendering (the Envoy candidate stays unselected).
- The journal's storage format.
