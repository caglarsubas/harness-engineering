# Alpha 2A — W02b I05 broker-gate channel (MET-ENFORCE-007)

> Current-status page for the W02b part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and
> phase status; W02g is recorded on the [W02g page](I06_BACKEND_PROFILE.md).

W02b: **ADOPTED_DATA_CONTRACT.** The closed wire contract `planeon.internal.effect-gate-frame/v1` for I05, the private
channel from the capacity broker to the effect gate, passed its third independent source-only review with verdict
PASS_FOR_SOURCE_PUBLICATION. It formalizes the reviewed W01 design (§3.2 A1-A4, §4.3, §6 C1-C7, §7). The contract is
DATA_CHECK_ONLY: no socket is opened, nothing is forwarded or installed, and all E01-E12 remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/i05-gate-channel/README.md): channel, per-field sources, decisions 0-11, durable journal,
  outcome mapping, counterexamples and the round-1 and round-2 dispositions.
- [Frame schema](../../architecture/i05-gate-channel/channel.schema.json): ten closed variants (five requests, five
  responses) with constrained GENERATION_STATUS.
- [Outcome mapping](../../architecture/i05-gate-channel/outcome-mapping.json): ACTION_OUTCOME to I02 RESOURCE_RESULT, with
  per-kind DELETE bodies; I02 unchanged.
- [Vectors](../../architecture/i05-gate-channel/vectors.json): 86 transcripts (counterexamples 17, 18, 21 and 22
  included), 38 agreement cases, 26 frame checks, 10 byte-level frame checks and 1 configuration refusal: 161 checks.
- Reference model `scripts/i05_gate_channel.py`: frame decoding, exact request rendering, the gate state machine with its
  durable journal, and the agreement check.

Key rules: one lockstep, hash-chained channel per generation with per-frame peer custody; ACTION_OUTCOME seals; A1 admits
only the armed action's exact rendered request bytes on a connection stamped with it; a DELETE needs a UID the gate itself
observed; a CREATE or DELETE whose response does not settle its outcome is IO_AMBIGUOUS and holds the generation; every
state the gate relies on after a restart is a durable record.

## Independent review

Three rounds, each by a separate agent that did not author the contract, read-only, with the reviewed bytes kept unchanged:

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | CHANGES_REQUIRED (3 MAJOR, 8 MINOR, 1 NOTE) | `review-round1.json` | `round1/` |
| 2 | CHANGES_REQUIRED (1 MAJOR, 5 MINOR, 4 NOTE; all round-1 findings closed) | `review-round2.json` | `round2/` |
| 3 | PASS_FOR_SOURCE_PUBLICATION (3 MINOR, 5 NOTE) | `review-round3.json` | current files |

The round-3 reviewer replayed all vectors with two harnesses, ran a 3.76M-event randomized campaign with an independent
shadow oracle and a depth-7 exhaustive search of 2.19M states, and found no interleaving that forwards an unarmed or
twice-armed request, forwards after invalidation, or reports a false classification. The
[status record](../../architecture/i05-gate-channel/status.json) derives the adoption state from the final verdict, and
`scripts/validate_i05_gate_channel.py` checks that derivation.

## Carried findings (none blocking)

- **P1** → W02c and W02b-F: the gate-side drain must settle in every state, and a WRITE_BEGIN after an urgent close must
  wait for the A3 fence or be treated by I07 as "no write".
- **P2** → W02b-F: bind a DELETE UID to this execution's own CREATE, or make manifest identity unique across every run the
  gate has bound.
- **P3** → W02b-F: report the storage-failure path's denies in deniedActionIds and the EXPIRE/DRAIN outputs.
- **P4-P8** → W02b-F (P6 also W03): restart after an unrecordable write failure, the 408 mapping rows, pinned upstream
  sources and the finalizer DELETE body, decode error codes, two vector intents.

## Still open

All E01-E12 and T01-T08; C2/C3 under load and restart (native T02/T03). The I07 wire schema (W02c), now unblocked. The
exact I04 request head as a requirement on the I04 client (R01, CONF-LIVE-003). The gate's HTTP/TLS substrate and the
journal storage format. W03-W07 remain gated. Alpha2 remains open; model-effort transition NOT_DUE.
