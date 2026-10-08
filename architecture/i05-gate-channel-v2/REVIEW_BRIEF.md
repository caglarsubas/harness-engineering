# Independent review brief — W02b-F I05 broker-gate channel v2, round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

v2 is the successor of the adopted v1 contract `../i05-gate-channel/` (three review rounds; round 3
`review-round3.json` PASS_FOR_SOURCE_PUBLICATION with findings P1-P8 carried to W02b-F). The v1 bytes stay unchanged.
README.md ("What v2 changes", "v1 round-3 findings and dispositions") states how v2 answers P1-P8.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, the frame schema, the outcome
mapping, the vectors and the reference model `scripts/i05_gate_channel_v2.py`. Check them against the predecessor inputs
listed there: the v1 contract and model, the v1 round-3 review, the base W01 candidate (I05 section), the reviewed W01
resolution (§2.4, §3.2, §4.3, §5.5, §6, §7), the I02 broker channel schema and protocol (RESOURCE_ACTION,
RESOURCE_RESULT, cleanup ownership), and the I07 contract that consumes the drain (W02c). The v1-to-v2 diff of the
reference model is the main review surface.

Nothing else in the working tree is part of the subject.

## Questions to answer

0. **Carried findings.** For each of P1-P8, is the README disposition true in the v2 bytes? Give CLOSED, PARTIAL or OPEN
   under `openItemStatus`. Probes PA, PA3, Q3 (P1), PD, PE (P2), PB, PB2, PB3 (P3), PC (P4) and PH (P6) of the v1 round-3
   review should now behave as the README says.
1. **Successor fidelity.** Does v2 keep every v1 property the v1 review confirmed (the v1 round-3 Q1/Q2 answers), changing
   only what the README discloses? Is anything weakened? Is the v1 contract still byte-identical?
2. **Drain and fence (P1).** Can any interleaving of broker frames, I04 connection events, upstream events, drain
   requests, urgent or normal closes, restarts, storage or marker failures, or peer loss produce an OPEN answer while a
   consumed action lacks a terminal record or the generation is HELD, leave a drain pending after its fence is decided,
   settle a drain without an answer (other than at a restart), or answer PENDING for a drain that will never settle? Is the
   answer usable by W02c-F as stated?
3. **Cleanup ownership (P2).** Can a run arm a DELETE for a UID it did not create, or create, observe for deletion or delete
   an object of another run (same or earlier generation) through I05? Is MANIFEST_REUSED derivable from durable records as
   stated?
4. **Restart after unrecorded failures (P4).** Apart from the disclosed double-fault residual (T103), can a restart come back
   CLOSED or INVALIDATED although the gate was HELD in memory? Is the residual stated accurately against base §5?
5. **Mapping, schema, envelope (P5-P7).** Are the agreement rows, the pinned sources and the new status-schema constraints
   correct and complete? Are the decode codes as stated?
6. **Vectors.** Does each transcript, agreement case, frame, byte and configuration check produce exactly its stated result
   for its stated reason? Do the carried vectors that changed say so?
7. **Overclaims.** Does anything claim an installed gate, a journal or marker implementation, native stamping, a selected
   HTTP/TLS substrate or Kubernetes distribution, the I07 move to v2, or any E01-E12 proof?

## How to check

You may run the v1 and v2 reference models read-only from the repository root with the locked environment
(`uv run --offline --frozen --no-sync python`): import `scripts/i05_gate_channel.py` and `scripts/i05_gate_channel_v2.py`.
Do not run the repository test suite or validators, and do not modify any repository file; scratch files go outside the
repository.

## Result

Return one JSON object: `schemaVersion` `"planeon.internal.i05-gate-channel-v2-review/v1"`, `round` 1, `reviewDate`,
`verdict` (PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED), `subjectSha256` (subject file name to digest),
`findings` (each with `id`, `severity` BLOCKING / MAJOR / MINOR / NOTE, `location`, `finding`, `requiredChange`),
`openItemStatus` (P1-P8), `questionAnswers` (Q0-Q7), `modelExecution`, `sourcesRead`, `actions` (booleans
`filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`, `repositoryValidatorsRun`, `runnerActivated`,
`testsRun`, `warmSourcesAccessed`) and `reviewLimit`. A PASS is not an installed gate, native qualification or
authorization for anything installed.

Rules: separate agent from the author; read-only; no repository edits, no tests or validators, no runner, native, cloud or
GitHub actions, no warm-source access. Public documentation and upstream source may be read; list what you read.
