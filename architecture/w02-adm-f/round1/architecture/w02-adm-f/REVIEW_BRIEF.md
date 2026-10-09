# Independent review brief — W02-ADM-F combined successor revisions, round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

W02-ADM-F folds three follow-ups into one packet under one review (owner decision, 2026-10-08):
- **I05 v3** (`../i05-gate-channel-v3/`, `planeon.internal.effect-gate-frame/v3`) answers V1 and V3-V6, and the Decision 8
  wording of V2, from the I05 v2 review (`../i05-gate-channel-v2/review-round1.json`).
- **POLICY-ADMISSION-SEMANTICS/v3** (`../admission-semantics-v3/`) answers R2-F1..F5 from the W02f round-2 review
  (`../admission-semantics-v2/review-round2.json`). The sealed A2 manifest file stays byte-identical to v2's.
- **I07 v3** (`../i07-policy-write-v3/`, `planeon.internal.policy-write-frame/v3`) extends the I05 v3 gate and answers
  W1-W4 from the I07 v2 review (`../i07-policy-write-v2/review-round1.json`).

The three v2 contracts are adopted and frozen by later layers; they stay byte-identical. Each v3 README has a "What v3
changes" table and a findings-and-dispositions table.

## Subject

The exact bytes listed under `subject` in `source-index.json`: this brief, the three v3 contract directories (README,
schemas or allowlists, mapping or kind table, sealed manifest file, vectors) and the three v3 reference models. Check them
against the predecessor inputs listed there: the three v2 contracts with their models, status files and review records,
the I05 v1 README (for V5), the W02g README, identity closure and criteria (for W4 and R2-F2), and the reviewed W01
resolution. The v2-to-v3 diffs of the three reference models are the main review surface:
`scripts/i05_gate_channel_v2.py` → `scripts/i05_gate_channel_v3.py`, `scripts/admission_semantics_v2.py` →
`scripts/admission_semantics_v3.py`, `scripts/i07_policy_write_v2.py` → `scripts/i07_policy_write_v3.py`.

Nothing else in the working tree is part of the subject.

## Questions to answer

0. **Carried findings.** For each of V1-V6, R2-F1..R2-F5 and W1-W4, is the README disposition true in the v3 bytes? Give
   CLOSED, PARTIAL or OPEN under `openItemStatus`. The original reviewers' probes (V1 four mutants and the reviewer
   injection; V3 PC-*; V6 identity and priorBindings; R2 probes PG, PH, PN, PI, PJ, PB2, PB3; W1 combinations; W2 restart
   reason; W3 probe) should now behave as the READMEs say.
1. **Successor fidelity.** Does each v3 keep every v2 property its review confirmed, changing only what its README
   discloses? Are the carried vectors' expected outputs unchanged apart from the version strings and the digests and bytes
   that follow from them (and the K02 refusal text)? Are the v2 contracts byte-identical, and is v3's
   `planeon-a2.json` byte-identical to v2's?
2. **Upstream bound (V4, W2).** I05 aborts an expired exchange without relaying anything; I07 aborts it and answers the
   writer IO_AMBIGUOUS. Can an UPSTREAM_TIMEOUT or a TIMEOUT outcome leave a drain pending, open a maintenance, relay a
   late response, or classify anything other than IO_AMBIGUOUS with the generation HELD? Is the I05/I07 difference
   (relayed to the writer, not to the server) sound?
3. **Failure injection (V1).** Does `STORAGE_FAIL_AFTER` in the base gate behave as stated, alone and combined with
   STORAGE_FAIL_NEXT and MARKER_FAIL_NEXT, and does I07 still use it the same way (T56)? Is the injection limit now
   gone, or is a remaining limit stated?
4. **Residual (V3).** Is the stated precondition exact: can the restart trust the last clean record under any other
   combination of journal, marker and torn-record failures? Is T116-T118's description accurate?
5. **Admission (R2-F1..F4).** Do MC39 and MC40 rule out every pod-level resource and label-key merge delta reachable on
   CREATE in v1.37.1 with W02g's pinned gates? Are the env defaults modelled as upstream sets them, and is any other
   create-path delta still without a disposition? Do C03, C12 and C27 refuse exactly what the README says? Does the
   allowlists file match the README (dispositions, coverage, publisher wording)?
6. **Schema (W1).** Does the I07 v3 schema now refuse exactly the four combinations, without refusing any frame the gate
   can send? Is the unexpressible ambiguousWriteIds bound stated correctly?
7. **Vectors.** Does each vector produce exactly its stated result for its stated reason?
8. **Overclaims.** Does anything claim an installed gate, writer, journal, marker or admission configuration, a selected
   substrate or distribution, a signer, or any E01-E12 proof?

## How to check

You may run the v2 and v3 reference models read-only from the repository root with the locked environment
(`uv run --offline --frozen --no-sync python`, with `UV_PROJECT_ENVIRONMENT` set as your prompt says). Run one process at a
time, each at most 60 seconds; no parallel campaigns. Do not run the repository test suite or validators, and do not
modify any repository file; scratch files go outside the repository. Stop at once when asked to pause, and continue only
when told to resume.

## Result

Return one JSON object: `schemaVersion` `"planeon.internal.w02-adm-f-review/v1"`, `round` 1, `reviewDate`, `verdict`
(PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED), `subjectSha256` (subject file name to digest), `findings`
(each with `id`, `contract` I05 / ADMISSION / I07, `severity` BLOCKING / MAJOR / MINOR / NOTE, `location`, `finding`,
`requiredChange`), `openItemStatus` (V1-V6, R2-F1..R2-F5, W1-W4), `questionAnswers` (Q0-Q8), `modelExecution`,
`sourcesRead`, `actions` (booleans `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
`repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`) and `reviewLimit`. A PASS is not an
installed component, native qualification or authorization for anything installed.

Rules: separate agent from the author; read-only; no repository edits, no tests or validators, no runner, native, cloud or
GitHub actions, no warm-source access. Public documentation and upstream source may be read; list what you read.
