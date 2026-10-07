# Independent review brief — W02c I07 policy writer channel, round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, the frame schema, the policy-kind
table, the vectors and the reference model `scripts/i07_policy_write.py`. Check them against the predecessor inputs
listed there:
- the reviewed W01 resolution (§2.3, §2.4, §3.2 A3/A4, §4.3, §5.3, §5.5, counterexamples 18 and 23) and its review;
- the reviewed W02g identity closure (`planeon:policy-writer`) and its status;
- the adopted W02b I05 contract: README, schema, status, the round-3 review with finding P1, and the W02b model
  `scripts/i05_gate_channel.py`, which the W02c model imports unchanged.

The working tree also contains this packet's mechanical history-chain edits (catalog counts, successor bridges, a new
layer validator and test, the packet YAML). They are outside this subject, are checked by the required verify suite, and
will not change while you review.

## Questions to answer

1. **Fidelity.** Does the contract encode the reviewed I07 design without weakening it? Consider W01 §2.4 (WRITE_BEGIN
   drains and replies only after the A3 fence; HELD if ambiguous; WRITE_OBJECT one policy-kind write with the expected
   prior; WRITE_END leaves the gate CLOSED), §2.3 (writer identity only while CLOSED for maintenance), §3.2 A3/A4, §4.3
   (per-frame writer custody) and §5.5 M2/M4. Are the README decisions disclosed and justified where the design left room?
   Those are: grant versus drain reply, one maintenance per generation owned by one session, no resume after restart,
   preconditions instead of a gate-side read, ambiguous writes holding the generation, and a writer peer deviation
   invalidating the generation.
2. **Protocol soundness.** Can any interleaving of writer frames, I05 broker frames, I04 connection events, upstream
   events, storage failures, restarts, session loss or peer change produce any of the following?
   - a write forwarded while an action admitted under the generation lacks a durable terminal classification;
   - a write forwarded outside an OPEN maintenance, or after its end;
   - a write forwarded without a durable WRITE_FORWARDED record;
   - an A1 admission after maintenance began;
   - a false write classification;
   - a maintenance resumed after a restart;
   - a second session writing.

   Probe in particular W02b finding P1 (urgent close with an action in flight, drain pending before an urgent close, a
   failed seal record), counterexample 18, and storage failure at every record point.
3. **Policy-kind table.** Is the writable table exactly the POLICY_WRITE grants of `planeon:policy-writer` in the W02g
   closure, with only `patch` unused? Are effect kinds, policy kinds outside the closure and every other kind refused at
   every version? Is the refusal order sound, and is anything the writer identity could do through I07 missing from the
   table or its refusals?
4. **Schema and envelope.** Is every frame closed and bounded? Do the object-value rules (printable ASCII strings and
   member names, integers within ±(2^53−1)) keep the canonical form equal to RFC 8785? Do the response variants forbid
   impossible combinations?
5. **Vectors.** Does each kind check, rendering, outcome check, frame check, byte check and transcript produce exactly its
   stated result for its stated reason?
6. **Overclaims.** Does anything claim an installed gate or writer, a selected HTTP/TLS client, native custody, the A2
   policy objects, a fix of the I05-side P1 bookkeeping or of P2-P8, or any E01-E12 proof?

## How to check

You may run the reference models read-only from the repository root with the locked environment
(`uv run --offline --frozen --no-sync python`): import `scripts/i07_policy_write.py` (it imports
`scripts/i05_gate_channel.py`). Do not run the repository test suite or validators, and do not modify any file.

## Result

Return one JSON object:
- `schemaVersion` `"planeon.internal.i07-policy-write-review/v1"`, `round` 1, `reviewDate`;
- `verdict`: PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED;
- `subjectSha256`: subject file name to digest;
- `findings`, each with `id`, `severity` (BLOCKING / MAJOR / MINOR / NOTE), `location`, `finding` and `requiredChange`;
- `questionAnswers` (Q1-Q6), `modelExecution`, `sourcesRead`;
- `actions`, booleans: `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
  `repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`;
- `reviewLimit`.

A PASS is not an installed gate, native qualification or authorization for anything installed.

Rules: separate agent from the author; read-only; no repository edits, no tests or validators, no runner, native, cloud
or GitHub actions, no warm-source access. Public documentation may be read; list what you read.
