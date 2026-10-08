# Independent review brief — W02c-F I07 policy writer channel v2, round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

v2 is the successor of the adopted I07 contract `../i07-policy-write/` (review round 1 PASS with R1-R8 carried). The v1
bytes stay unchanged. README.md ("What v2 changes", "v1 review findings and dispositions") states how v2 answers R1-R8, the
W02b-F note V2 and the W02f sealing decision.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, the frame schema, the policy-kind
table, the vectors and the reference model `scripts/i07_policy_write_v2.py`. Check them against the predecessor inputs
listed there: the v1 I07 contract, model and review; the I05 v2 contract and model (the base gate); the W02f contract
(sealed admission objects and the guard); the W02g identity closure; the W01 resolution (§2.3, §2.4, §3.2, §5.5).

## Questions to answer

0. **Carried findings.** For each of R1-R8, is the README disposition true in the v2 bytes? Give CLOSED, PARTIAL or OPEN
   under `openItemStatus`. Re-run the v1 review's probes (PA, PA2, PB, P3-I07) against v2.
1. **Successor fidelity.** Does v2 keep every v1 property the v1 review confirmed, changing only what the README discloses?
   Is the move onto the I05 v2 gate correct (fence, drain answer, denies, restart, failure marker), and is anything weakened?
2. **Outstanding writes (R4).** Can any interleaving of writer frames, writer EOF or peer deviation, W_UPSTREAM outcomes,
   I05 frames and events, storage failures (including STORAGE_FAIL_AFTER) and restarts let a policy write commit while an
   admitted I05 action lacks a durable terminal classification, forward a write outside OPEN, lose a forwarded write's
   classification, relay an outcome after an abort, end a session or maintenance before an outstanding write is recorded,
   or open a maintenance in a rebuilt generation?
3. **Sealed admission kinds.** Is the derivation of the table from the W02g closure plus the W02f decision exact, and are
   the two kinds refused at every version and before every scope or object rule?
4. **Schema (R3, R8).** Do the conditional constraints forbid exactly the combinations the gate cannot produce, and does
   the gate never produce a frame they refuse?
5. **Vectors.** Does each case produce exactly its stated result for its stated reason? Do the carried v1 cases that
   changed say so?
6. **Overclaims.** Does anything claim an installed gate or writer, a selected substrate, enrollment rules (W03) or any
   E01-E12 proof?

## How to check

You may run the v1 and v2 reference models read-only from the repository root with the locked environment
(`uv run --offline --frozen --no-sync python`): import `scripts/i07_policy_write_v2.py` (it imports
`scripts/i05_gate_channel_v2.py`). Do not run the repository test suite or validators, and do not modify any repository
file; scratch files go outside the repository.

## Result

Return one JSON object: `schemaVersion` `"planeon.internal.i07-policy-write-v2-review/v1"`, `round` 1, `reviewDate`,
`verdict` (PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED), `subjectSha256` (subject file name to digest),
`findings` (each with `id`, `severity` BLOCKING / MAJOR / MINOR / NOTE, `location`, `finding`, `requiredChange`),
`openItemStatus` (R1-R8), `questionAnswers` (Q0-Q6), `modelExecution`, `sourcesRead`, `actions` (booleans `filesEdited`,
`githubMutated`, `nativeActions`, `referenceModelExecuted`, `repositoryValidatorsRun`, `runnerActivated`, `testsRun`,
`warmSourcesAccessed`) and `reviewLimit`. A PASS is not an installed gate or writer.

Rules: separate agent from the author; read-only; no repository edits, no tests or validators, no runner, native, cloud or
GitHub actions, no warm-source access. Public documentation may be read; list what you read.
