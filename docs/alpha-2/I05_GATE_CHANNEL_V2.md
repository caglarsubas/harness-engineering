# Alpha 2A — W02b-F I05 broker-gate channel v2 (MET-ENFORCE-011)

> Current-status page for the W02b-F part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and
> phase status; the adopted v1 channel is described in its [README](../../architecture/i05-gate-channel/README.md).

W02b-F: **ADOPTED_DATA_CONTRACT.** The successor channel contract `planeon.internal.effect-gate-frame/v2` passed its
independent source-only review (round 1, PASS_FOR_SOURCE_PUBLICATION). It closes every finding the v1 round-3 review
carried to W02b-F (P1-P8). The v1 contract and model, and the I07 contract that extends the v1 model, are byte-identical.
It is DATA_CHECK_ONLY: no socket is opened, nothing is forwarded or installed, and all E01-E12 remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/i05-gate-channel-v2/README.md): what v2 changes and why, the channel, operations, decisions,
  durable journal and failure marker, outcome mapping and the dispositions of P1-P8.
- [Schema](../../architecture/i05-gate-channel-v2/channel.schema.json): `urn:planeon:internal:effect-gate-frame:v2`.
- [Outcome mapping](../../architecture/i05-gate-channel-v2/outcome-mapping.json): agreement rows with the 408 exclusion and
  the Kubernetes v1.37.1 sources pinned by commit and file digest.
- [Vectors](../../architecture/i05-gate-channel-v2/vectors.json): 106 transcripts (T01-T86 carried from v1),
  42 agreement cases, 33 frame checks, 14 byte-level checks and 3 configuration refusals.
- Reference model `scripts/i05_gate_channel_v2.py`, written as reviewed edits of the unchanged v1 model.

Key rules:
- **Drain (P1):** an I07 WRITE_BEGIN is answered from the A3 fence in every state: PENDING while a consumed action lacks a
  terminal record, then OPEN (CLOSED or INVALIDATED) or HELD, on the event that settles it.
- **Cleanup ownership (P2):** a DELETE needs a UID from this execution's own CREATE 201; a manifest digest or identity
  belongs to one run, across runs and generations (MANIFEST_REUSED).
- **Reported denies (P3):** close, expiry and drain report every action they denied, also through a storage failure.
- **Restart (P4):** a failure marker on a separate failure domain and torn-record detection make a restart HELD after any
  write failure; the double-fault residual is stated.
- **Mapping and decoding (P5-P7):** 408 excluded from the mutation 4xx rows, pinned upstream sources, depth checked first
  and a distinct code for non-bytes input.

## Independent review

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | PASS_FOR_SOURCE_PUBLICATION (6 NOTE) | `review-round1.json` | current files |

The reviewer was a separate agent that did not author the contract. It worked read-only against the exact bytes, replayed
every vector independently, re-ran the v1 round-3 probes, ran randomized and bounded exhaustive searches with an
oracle, replayed source mutants and checked the Kubernetes citations at the pinned commit. The
[status record](../../architecture/i05-gate-channel-v2/status.json) derives the adoption state from the verdict, and
`scripts/validate_i05_gate_channel_v2.py` replays the contract and checks that derivation.

## Carried findings (none blocking)

- **V1** (NOTE) → W02b-F2: add vectors for a drain pending across GATE_RESTART, a repeated WRITE_BEGIN while pending (one DRAIN_STARTED) and a DELETE armed with a UID created for another manifest; give STORAGE_FAIL_NEXT a skip count and pin DRAINED-failure and DENIED-after-record failures, or state the injection limit
- **V2** (NOTE) → W02c-F and W02b-F2: a HELD generation answers a drain HELD at once (Decision 8 wording); OPEN is a point-in-time answer, the generation can become HELD afterwards, and the I07 writer keeps evaluating the fence after OPEN
- **V3** (NOTE) → W02b-F2 and W02c-F (R1): state the P4 residual's exact precondition (two consecutive journal failures, one marker failure, no torn record, no later state record), that it covers the gate's own storage-failure HELD, and that a WRITE_BEGIN after such a restart is answered OPEN
- **V4** (NOTE) → W02b-F2 and W03: bound the forwarded upstream exchange (signed lifetime, 900-second limit) after which it is lost (IO_AMBIGUOUS, HELD), or require the broker to seal by its own deadline; liveness only
- **V5** (NOTE) → W02b-F2: restore or name as carried the v1 README clauses v2 dropped (conservative outcomes, flushClosures definition, stock client refused fail-closed, durability before relay, NOT_FORWARDED agreeing with DENIED and AMBIGUOUS)
- **V6** (NOTE) → W02b-F2: word the identity refusal as more than one manifest (also within one run), refuse a priorBindings object without manifestDigests or manifestIdentities explicitly, order byteFrames B12-B14

## Still open

All E01-E12 and T01-T08. The I07 move onto v2 and the restart rule for a fresh maintenance (W02c-F). The upstream
exchange bound, the journal and marker storage formats, the HTTP/TLS substrate and the distribution re-check (W03).
W03-W07 remain gated. Alpha2 remains open; model-effort transition NOT_DUE.
