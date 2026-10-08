# Alpha 2A — W02c-F I07 policy writer channel v2 (MET-ENFORCE-014)

> Current-status page for the W02c-F part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and
> phase status; the adopted v1 writer channel is described in its [README](../../architecture/i07-policy-write/README.md).

W02c-F: **ADOPTED_DATA_CONTRACT.** The successor writer channel `planeon.internal.policy-write-frame/v2` passed its
independent source-only review (round 1, PASS_FOR_SOURCE_PUBLICATION). It moves the I07 model onto the I05 v2 gate, seals
the admission-policy kinds per W02f, splits a write's upstream outcome into its own event, and answers the v1 review
findings R1-R8. The v1 contract, the I05 v2 contract and the W02f contract are byte-identical. It is DATA_CHECK_ONLY: no
socket is opened, nothing is forwarded or installed, and all E01-E12 remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/i07-policy-write-v2/README.md): what v2 changes, the channel, operations, the closed table,
  decisions, the journal additions and the dispositions of R1-R8.
- [Schema](../../architecture/i07-policy-write-v2/channel.schema.json): `urn:planeon:internal:policy-write-frame:v2`.
- [Policy kinds](../../architecture/i07-policy-write-v2/policy-kinds.json): seven writable kinds from the W02g closure, the two
  admission kinds sealed (W02f).
- [Vectors](../../architecture/i07-policy-write-v2/vectors.json): 79 kind, 7 render, 22 outcome,
  38 frame, 9 byte and 58 transcript cases.
- Reference model `scripts/i07_policy_write_v2.py`, extending `scripts/i05_gate_channel_v2.py`.

Key rules:
- **Fence:** maintenance follows the I05 v2 gate's own fence after every event; OPEN can become HELD and never reopens.
- **Restart:** a generation rebuilt after a restart never opens a maintenance.
- **Sealed kinds:** ValidatingAdmissionPolicy and its binding are refused ADMISSION_OBJECT_SEALED; no name is writable.
- **Outstanding writes:** the upstream outcome is its own event; an abort is recorded before the session or maintenance ends;
  a late outcome is never relayed; lockstep is enforced.

## Independent review

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | PASS_FOR_SOURCE_PUBLICATION (4 findings, none blocking or major) | `review-round1.json` | current files |

The reviewer was a separate agent that did not author the contract. It worked read-only against the exact bytes, replayed
every vector, re-ran the v1 probes, and ran randomized, failpoint and mutant campaigns with an independent oracle. The
[status record](../../architecture/i07-policy-write-v2/status.json) derives the adoption state from the verdict, and
`scripts/validate_i07_policy_write_v2.py` replays the contract and checks that derivation.

## Carried findings (none blocking)

- **W1** (MINOR) → W02c-F2: schema constraints MAINTENANCE_STATUS ENDED => gateState not ACTIVE/INSPECTING, PENDING => inFlightActionId integer, gateState CLOSED => inFlightActionId null, WRITE_END ambiguousWriteIds non-empty => HELD, with G vectors; or narrow the README R3 row and list the unexpressible ambiguousWriteIds/writes bound
- **W2** (NOTE) → W02c-F2: reword the restart reason (recorded MAINT_ENDED reason, else GATE_RESTART if begun, else GENERATION_REBUILT); state whether the 10-second upstream expiry is LOST (relayed) or an abort ({aborted: UPSTREAM_TIMEOUT}) and pin it with a vector
- **W3** (NOTE) → W02c-F2: state that a WRITE_BEGIN refused STORAGE_FAILURE (MAINT_REQUESTED record) may have denied an armed I05 action, reported only through ACTION_OUTCOME
- **W4** (NOTE) → W02c-F2: add architecture/i06-backend-profile/README.md with its digest to predecessorInputs; remove or mark unreachable the CLUSTER scope branches

## Still open

All E01-E12 and T01-T08. Enrollment refusing a successor generation while a write is unterminated (W03); the writer
artifact, socket, substrate and storage formats (W03). W03-W07 remain gated. Alpha2 remains open; model-effort transition
NOT_DUE.
