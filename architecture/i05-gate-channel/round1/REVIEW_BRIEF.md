# Independent review brief — W02b I05 broker-gate channel, round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this
brief. It is not a verdict.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, the frame
schema, the outcome mapping, the vectors and the reference model `scripts/i05_gate_channel.py`. Check
them against the predecessor inputs listed there: the base W01 candidate (I05 section), the reviewed
W01 resolution (§3.2, §4.3, §6, §7) and its review, and the existing I02 broker channel schema and
protocol (RESOURCE_ACTION, RESOURCE_RESULT).

The working tree also contains this packet's mechanical history-chain edits (catalog counts,
successor bridges, a new layer validator and test, the packet YAML). They are outside this subject,
are checked by the required verify suite, and will not change while you review.

## Questions to answer

1. **Fidelity.** Does the contract encode the reviewed I05 design (§7 additions, A1/A3/A4, C1-C7,
   §4.3 peer qualification, base §3 bounds) without weakening it? Are the README decisions disclosed
   and justified where the design left room (channel lifetime, sealing by ACTION_OUTCOME, lockstep,
   fatal versus refused)?
2. **Protocol soundness.** Can any interleaving of broker frames, I04 connection events, upstream
   events, restarts, storage failures or peer loss make the gate forward a request that was not armed,
   forward one armed action twice, forward after invalidation, lose an admitted action's ownership, or
   report a terminal classification that is false? Probe in particular counterexample 17 and its
   variants, backlog and accept ordering, sealing races, drain and urgent close with an action in
   flight, and replayed or reordered frames.
3. **Mapping.** Is the ACTION_OUTCOME to RESOURCE_RESULT table complete and safe against the I02
   outcome vocabulary, without overloading it? Is the UID-match rule sufficient where byte equality is
   not required?
4. **Schema and envelope.** Is every frame closed and bounded (exact builtins, depth, size, no
   selectors)? Do the response variants forbid impossible combinations?
5. **Vectors.** Does each transcript, agreement case and frame check produce exactly its stated
   result for its stated reason?
6. **Overclaims.** Does anything claim an installed gate, native stamping, a selected HTTP/TLS
   substrate, the I07 schema or any E01-E12 proof?

## How to check

You may run the reference model read-only from the repository root with the locked environment
(`uv run --offline --frozen --no-sync python`): import `scripts/i05_gate_channel.py`. Do not run the
repository test suite or validators, and do not modify any file.

## Result

Return one JSON object: `schemaVersion` `"planeon.internal.i05-gate-channel-review/v1"`, `round` 1,
`reviewDate`, `verdict` (PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED), `subjectSha256`
(subject file name to digest), `findings` (each with `id`, `severity` BLOCKING / MAJOR / MINOR / NOTE,
`location`, `finding`, `requiredChange`), `questionAnswers` (Q1-Q6), `modelExecution`, `sourcesRead`,
`actions` (booleans `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
`repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`) and `reviewLimit`.
A PASS is not an installed gate, native qualification or authorization for anything installed.

Rules: separate agent from the author; read-only; no repository edits, no tests or validators, no
runner, native, cloud or GitHub actions, no warm-source access. Public documentation may be read; list
what you read.
