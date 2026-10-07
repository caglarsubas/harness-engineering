# Alpha 2A — W02c I07 policy writer channel (MET-ENFORCE-008)

> Current-status page for the W02c part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and
> phase status; W02b is recorded on the [W02b page](I05_GATE_CHANNEL.md).

W02c: **ADOPTED_DATA_CONTRACT.** The closed wire contract `planeon.internal.policy-write-frame/v1` for I07 passed its
first independent source-only review with verdict PASS_FOR_SOURCE_PUBLICATION. I07 is the private channel from the
enrolled policy-writer artifact to the effect gate, and the contract formalizes the reviewed W01 design (§2.3, §2.4,
§3.2 A3/A4, §4.3, §5.5). It is DATA_CHECK_ONLY: no socket is opened, nothing is forwarded or installed, and all E01-E12
remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/i07-policy-write/README.md): channel, operations, per-field sources, the closed
  policy-kind table, decisions 0-8, durable journal, W02b finding P1, counterexamples.
- [Frame schema](../../architecture/i07-policy-write/channel.schema.json): eight closed variants (four requests, four
  responses).
- [Policy-kind table](../../architecture/i07-policy-write/policy-kinds.json): nine writable kinds derived from the W02g
  `planeon:policy-writer` grants (`patch` never used, Namespace UPDATE only), three effect kinds and nine policy kinds
  outside the writer closure, all refused.
- [Vectors](../../architecture/i07-policy-write/vectors.json): 77 kind checks, 7 exact renderings, 22 outcome checks,
  20 frame checks, 9 byte-level checks and 45 transcripts, 180 checks in all.
- Reference model `scripts/i07_policy_write.py`: the kind table, exact write rendering with uid and resourceVersion
  preconditions, and `PolicyGate`, which extends the unchanged W02b gate model.

Key rules:
- WRITE_BEGIN asks for the gate's normal drain. Maintenance opens only when the A3 fence holds, computed from gate
  state and never from a drain reply (W02b P1, write side).
- One maintenance per generation, owned by the session that began it. It never resumes after a restart.
- The writer identity is used only for the closed table and only while maintenance is OPEN.
- A write with an unknown outcome holds the generation.
- Every write is journalled before its first upstream byte and its outcome before its response.

## Independent review

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | PASS_FOR_SOURCE_PUBLICATION (4 MINOR, 4 NOTE) | `review-round1.json` | current files |

The reviewer was a separate agent that did not author the contract. It worked read-only, and the reviewed bytes were kept
unchanged. It replayed all vectors and checked the table derivation independently. It ran 600,000 randomized events
against an independent oracle, injected storage failures at every record point of every transcript, and seeded ten
mutants. It found no interleaving that forwards a write before the fence holds, outside an open maintenance, without a
durable record or for a kind outside the table. The [status record](../../architecture/i07-policy-write/status.json)
derives the adoption state from the final verdict, and `scripts/validate_i07_policy_write.py` checks that derivation.

## Carried findings (none blocking)

- **R1** → W02b-F and W02c-F: W02b P4 reaches I07. After two unrecorded write failures and a restart, a fresh
  maintenance could open in a generation the gate had held in memory.
- **R2** → W02c-F and W02f: refuse unexpected ValidatingAdmissionPolicy and binding names once the A2 names are pinned.
  This fulfils the W02g README obligation.
- **R3** → W02c-F: conditional response-schema constraints.
- **R4** → W02c-F and W03: events during an outstanding write, and no successor generation while a write is
  unterminated or unreconciled.
- **R5-R8** → W02c-F and W02b-F: requestDigest input and observed fields on rejections, Decision 2 wording, the
  deniedActionIds case of W02b P3, and the 317-character key bound.

## Still open

All E01-E12 and T01-T08. The writer's per-frame custody under load (native). The gate's HTTP/TLS client and the journal
format (W03). The A2 policy names and field allowlists (W02f). The I05-side drain bookkeeping and W02b P2-P8 (W02b-F).
W03-W07 remain gated. Alpha2 remains open; model-effort transition NOT_DUE.
