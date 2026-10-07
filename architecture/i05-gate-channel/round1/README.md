# I05 broker-gate channel — W02b (MET-ENFORCE-007), round 1

Status: **CONTRACT_CANDIDATE**, awaiting independent review. DATA_CHECK_ONLY: no socket is opened, no
request is forwarded, nothing is installed, and all E01-E12 stay OPEN_UNPROVEN.

This part formalizes I05, the private channel from the capacity broker to the effect gate, as the
reviewed W01 design (HOST-INTERFACE-DRAFT-002 §3.2 A1-A4, §4.3, §6 C1-C7 and §7) left it for W02. It
gives:

- the frame envelope: canonical JSON, strict request/response lockstep, sequence and hash chain bound to
  the generation and to the broker's opening challenge;
- the closed schema for the five operations and their responses;
- the gate state machine as an executable model: connection stamping, the A1 admission point, the A3
  drain fence and A4 urgent invalidation;
- the ACTION_OUTCOME to RESOURCE_RESULT mapping table;
- transcript, replay and duplicate vectors, including counterexamples 17, 18, 21 and 22.

## Files

| File | Content |
|---|---|
| `channel.schema.json` | Draft 2020-12 schema `planeon.internal.effect-gate-frame/v1`: ten frame variants (five requests, five responses) |
| `outcome-mapping.json` | ACTION_OUTCOME to I02 RESOURCE_RESULT agreement rows and rules |
| `vectors.json` | 44 transcripts, 23 agreement cases and 12 frame checks, each with its exact expected output |
| `scripts/i05_gate_channel.py` | Reference model: `check_frame`, `Gate`, `replay`, `check_agreement`, `template_digest` |

## Channel

1. **One channel per gate generation.** The broker connects to the existing candidate path
   `/run/planeon/live-proxy/effect-admission.sock` (AF_UNIX/SOCK_SEQPACKET, root:root 0600) after it has
   qualified the gate as a peer (§4.3). The gate refuses a second connection while the channel is open
   and any connection after it closed: there is no reconnect. Channel loss (broker EOF, peer change or a
   fatal frame) is peer failure and holds the generation HELD.
2. **Opening.** The first broker frame is GENERATION_STATUS with sequence 1, an all-zero previous digest,
   the gate's generation and a fresh 256-bit broker challenge. Every later frame in either direction
   carries the same generation and challenge.
3. **Lockstep.** Odd sequences are broker requests, even sequences gate responses; each request gets
   exactly one response before the next request. There are no unsolicited gate frames, so the hash chain
   has a single order. Each frame's `previousDigest` is the SHA-256 of the exact canonical bytes of the
   frame before it.
4. **Frames.** Canonical duplicate-free JSON, exact builtins (no floats; booleans are not integers),
   depth at most 16, at most 16 KiB canonical bytes, no unknown fields or operations. Each request must be
   answered within 2 seconds and every exchange stays inside the execution's signed lifetime and the
   900-second limit (unchanged base rules). No descriptor passing, no command, URL, path or program
   selector.
5. **Fatal versus refused.** A frame that fails the schema, breaks the chain, claims the gate's direction,
   carries another generation or challenge, or does not open with GENERATION_STATUS closes the channel
   without a response; so does a BIND_EXECUTION whose peer-qualification digest differs. A well-formed
   request the gate will not honour gets a REFUSED response with a closed reason and changes no gate
   state (except storage failure, which holds the generation).

The broker verifies the gate's frames the same way and treats any deviation as peer failure.

## Operations

| Operation | Request | OK response | Refusal reasons |
|---|---|---|---|
| GENERATION_STATUS | `{}` | state, drainPending, bound execution, armed and in-flight action, counters (stamps issued, consumptions, correlation refusals, flush closures), journal digest | none |
| BIND_EXECUTION | executionId, bindingDigest, reservationDigest, runNonce, caseId, requestDigest, dispatchGeneration, serverCertificateDigest, worker PID and start ticks, peerQualificationDigest | executionId and the gate-resolved case manifest-set digest | NOT_ACTIVE, DRAIN_PENDING, ACTION_OUTSTANDING, EXECUTION_REPLAY, GENERATION_MISMATCH, UNKNOWN_BINDING, CERTIFICATE_MISMATCH, STORAGE_FAILURE |
| ARM_ACTION | executionId, actionId, verb, manifestDigest, requestTemplateDigest, recordedUid | actionId and the number of connections the C2 flush closed | NOT_ACTIVE, DRAIN_PENDING, EXECUTION_NOT_BOUND, EXECUTION_EXPIRED, ACTION_OUTSTANDING, ACTION_ID_OUT_OF_ORDER, MANIFEST_OUTSIDE_CASE, UID_RULE, TEMPLATE_MISMATCH, MUTATION_KEY_REUSED, STORAGE_FAILURE |
| ACTION_OUTCOME | executionId, actionId | classification, admittedBeforeInvalidation, HTTP status, result digest, observed UID and resourceVersion | EXECUTION_NOT_BOUND, UNKNOWN_ACTION |
| CLOSE_GENERATION | reason | resulting state and the actions this close denied | ACTION_IN_FLIGHT (normal drain only) |

Every value in a request is a cross-check, never authority. The gate resolves the execution's binding,
case manifest set, run certificate and deadline from its own independently loaded release and capacity
inputs; BIND_EXECUTION fields must equal that resolution (base §3). The peer-qualification digest is the
SHA-256 of the mutual qualification record (both artifacts, labels, cgroups, PID/start and pidfd
identities) that each side computes from its own peer checks (§4.3).

## Decisions

1. **ACTION_OUTCOME is a broker request that seals the action.** After its response the action can never
   be consumed: an armed, unconsumed action becomes NOT_FORWARDED and its stamped connections close; a
   terminal action returns its recorded classification; an action still in flight is aborted upstream and
   becomes IO_AMBIGUOUS, which holds the generation (A3). The broker asks after the server's
   RESOURCE_RESULT, and the gate records each terminal classification durably before relaying any response
   byte to the server, so a normal result is always recorded by then.
2. **One outstanding action, sealed before the next.** ARM_ACTION is refused until every earlier action of
   the execution is terminal and sealed; BIND_EXECUTION of the next execution has the same precondition.
   One execution is bound at a time (one worker). The broker's I02 transcript advances only after it has
   both the gate's ACTION_OUTCOME and the server's RESOURCE_RESULT and they agree.
3. **Action identifiers.** actionId is the I02 RESOURCE_ACTION actionId, contiguous from 1 within the
   execution (1-256). The broker emits RESOURCE_ACTION only after ARM_ACTION returned OK.
4. **Canonical action.** The gate derives the request template from its signed profile entry for the
   manifest: `template_digest` over verb, apiVersion, kind, namespace, name, recorded UID and manifest
   digest. ARM_ACTION's requestTemplateDigest must equal it, and at A1 the parsed I04 request must reduce
   to the same digest (C4). Only DELETE carries a recorded UID (its precondition); CREATE and GET carry
   none.
5. **C2 flush and C3 stamp.** In the ARM_ACTION transaction, under the generation lock and before the ARM
   record, the gate closes every accepted connection that has not consumed an action and accepts and
   closes every connection in its listen backlog. A connection accepted later is stamped with the armed
   action, or with none. ACCEPT, ARM_ACTION and A1 serialize on the generation lock.
6. **A1.** A request passes only when the generation is ACTIVE with no pending drain, the execution is
   bound and not expired, the connection's stamp equals the armed, unconsumed action, its client
   certificate equals the bound run certificate and its canonical action equals the template. The gate
   then records the consumption (fsync and read back) and only then sends the first byte upstream. One
   request per connection (C1). After the consumption every other connection stamped with that action
   closes (C5). A failed record forwards nothing and holds the generation.
7. **C7 by construction.** At ARM the gate refuses a CREATE whose manifest it already armed in this
   execution, and a DELETE whose recorded UID it already armed, even if the earlier action was never
   forwarded. GETs may repeat; C2-C5 keep them apart.
8. **Closing.** Normal drain is refused while an action is in flight; otherwise it denies an armed action
   and ends CLOSED, or HELD if any action of the generation is IO_AMBIGUOUS. Urgent reasons (revocation,
   expiry, peer, storage or observation failure) close A1 at once, deny an armed action and end
   INVALIDATED; an action already admitted may still complete and is reported with
   `admittedBeforeInvalidation` (A4). An I07 WRITE_BEGIN is the gate's own normal drain: ARM is refused
   with DRAIN_PENDING, an armed action is denied, and the generation becomes CLOSED once no consumed
   action lacks a terminal record (the A3 fence), or HELD if one is ambiguous. The I07 wire schema is
   W02c.
9. **Restart and loss.** A gate restart starts denied and HELD, with no channel and no stamps; a consumed
   action without a terminal record is IO_AMBIGUOUS (C6, base §5). Tombstones stay in the journal.
10. **States.** INSPECTING, ACTIVE, DRAINING, CLOSED, INVALIDATED and HELD are the base conceptual states,
    carried only on this private channel.

## Outcome mapping

`outcome-mapping.json` maps each gate classification to the I02 RESOURCE_RESULT outcomes that agree with
it. An exact HTTP status row takes precedence over a status-class row.

| Verb | Gate classification | HTTP status | RESOURCE_RESULT | Object |
|---|---|---|---|---|
| CREATE | DELIVERED_RESULT | 201 | CREATED | UID must equal the gate-observed UID |
| CREATE | DELIVERED_RESULT | 4xx | DENIED | any |
| CREATE | DELIVERED_RESULT | 5xx | AMBIGUOUS | any |
| GET | DELIVERED_RESULT | 200 | PRESENT | UID must equal the gate-observed UID |
| GET | DELIVERED_RESULT | 404 | ABSENT | any |
| GET | DELIVERED_RESULT | other 4xx / 5xx | DENIED / AMBIGUOUS | any |
| DELETE | DELIVERED_RESULT | 200, 202 | DELETED | any |
| DELETE | DELIVERED_RESULT | 404 | ABSENT | any |
| DELETE | DELIVERED_RESULT | other 4xx (incl. 409 UID precondition) / 5xx | DENIED / AMBIGUOUS | any |
| any | NOT_FORWARDED | none | DENIED or AMBIGUOUS | none |
| any | IO_AMBIGUOUS | none | AMBIGUOUS | none |

Any other status (1xx, 3xx, another 2xx) has no row. Disagreement, a missing ACTION_OUTCOME or a missing
RESOURCE_RESULT is sticky failure: the broker holds the generation HELD and never advances its I02
transcript past the action. `admittedBeforeInvalidation` keeps the mapped outcome, but such an execution
never ends COMPLETED and its resources stay owned for exact-UID cleanup. A server that saw its connection
closed cannot tell a gate refusal from a lost send, so NOT_FORWARDED agrees with both DENIED and
AMBIGUOUS. `resultDigest` is the gate's digest of the exact relayed body, kept for reconciliation;
agreement does not ask the server to reproduce it, because RESOURCE_RESULT carries bounded observed-object
data. I02 is unchanged and no outcome enum is overloaded.

## Counterexamples

| Counterexample | Vector |
|---|---|
| 17: a byte-identical duplicate of completed GET A buffered before ARM(B) | T02 (duplicate on an earlier connection and in the backlog), T03 (connection stamped none) |
| 18: a policy write while an admitted CREATE is in flight | T30, T31 |
| 21: gate restart mid-execution | T25 |
| 22: a connection opened while A was armed, used after B is armed | T02, T08 (closed by C5 at A's consumption, or by the C2 flush) |

The §6.3 residual stays as stated there: a server that opens a new connection after ARM(B) and sends
bytes identical to B gets B forwarded once; misattribution then shows as disagreement (HELD) in the
mapping, not as an unarmed effect.

## Spec mapping

| Spec | Encoded by |
|---|---|
| Base §3 I05 rules (custody, bounds, no selectors) | Channel 1-5, schema |
| §7 BIND_EXECUTION additions | dispatchGeneration, peerQualificationDigest |
| §7 ARM_ACTION additions | Decisions 5 and 7, DRAIN_PENDING |
| §7 ACTION_OUTCOME additions | admittedBeforeInvalidation, outcome mapping |
| §7 CLOSE_GENERATION additions | Decision 8 |
| §7 GENERATION_STATUS additions | Counters in the status response |
| §3.2 A1, A3, A4 | Decisions 6 and 8 |
| §6 C1-C7 | Decisions 5-7, T02-T10 |

## Still open

- All E01-E12 and T01-T08; C2/C3 behaviour under load and restart is native T02/T03 work.
- The I07 wire schema and the policy-writer drain handshake (W02c).
- The gate's HTTP/TLS substrate and how it implements stamping (the Envoy candidate stays unselected).
- The journal's storage format; this contract fixes only what each record must contain and when it is
  durable.
