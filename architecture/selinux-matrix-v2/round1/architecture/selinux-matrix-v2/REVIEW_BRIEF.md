# Independent review brief — W02e-F SELinux matrix v4, round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

v4 is the successor of the adopted matrix `../selinux-matrix/` (`planeon.internal.selinux-matrix/v3`; review round 3
`review-round3.json` PASS_FOR_SOURCE_PUBLICATION with K1-K6 carried). The v3 bytes stay unchanged. README.md ("What v4
changes", "Round-3 findings and dispositions in v4") states how v4 answers K2, K3, K4 and K6; K1 and K5 are carried
elsewhere and are not part of this subject's claims.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, `matrix.json`, `vectors.json` and
the reference evaluator `scripts/selinux_matrix_v2.py`. Check them against the predecessor inputs listed there: the
adopted v3 matrix, vectors, README, evaluator and its three review records, and the reviewed W01 resolution. The v3-to-v4
diffs of `matrix.json`, `vectors.json` and the evaluator are the main review surface.

Nothing else in the working tree is part of the subject.

## Questions to answer

0. **Carried findings.** For K2, K3, K4 and K6, is the README disposition true in the v4 bytes? Give CLOSED, PARTIAL or
   OPEN under `openItemStatus`. Re-run the round-3 probes for K2 (the gate-to-server, gate-to-containment and
   broker-to-maintenance `procAccess` mutations) and K3 (init_t `load_policy` before the seal).
1. **Successor fidelity.** Is v4 the v3 matrix plus exactly the disclosed changes (the A59 statement, A59.<target>, A66,
   S11, M34, M45, M51-M55, the appended access checks)? Is every other v3 vector unchanged? Is v3 byte-identical?
2. **Per-target assertions (K2).** Does each A59.<target> allow exactly that target's `procAccess` peers? Can any
   mutation that grants a pair outside `procAccess` (to a planeon target) pass all 109 assertions?
3. **Policy load (K3).** Together with A21, A22 and A23, do the assertions now pin that the reviewed policy is the only
   one loaded throughout the enrolled boot and that enforcing mode never changes? Is anything vacuous?
4. **cgroup2 statements (K4).** Are the corrected kernfs, `SE_SBGENFS`, `cgroup_seclabel` and `dir create` statements
   true for the pinned kernel line, and is S11 now the access the kernel checks?
5. **Vectors.** Does every access and mutation check produce exactly its stated result for its stated reason? Do the 109
   assertions all hold on the v4 matrix?
6. **Overclaims.** Does anything claim a policy module, a compiled or loaded policy, a selected distribution, or any
   E01-E12 proof?

## How to check

You may run the v3 and v4 evaluators read-only from the repository root with the locked environment
(`uv run --offline --frozen --no-sync python`, with `UV_PROJECT_ENVIRONMENT` set as your prompt says). Run one process at
a time, each at most 60 seconds. Do not run the repository test suite or validators, and do not modify any repository
file; scratch files go outside the repository. Stop at once when asked to pause, and continue only when told to resume.

## Result

Return one JSON object: `schemaVersion` `"planeon.internal.selinux-matrix-v2-review/v1"`, `round` 1, `reviewDate`,
`verdict` (PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED), `subjectSha256` (subject repository path to
digest), `findings` (each with `id`, `severity` BLOCKING / MAJOR / MINOR / NOTE, `location`, `finding`,
`requiredChange`), `openItemStatus` (K2, K3, K4, K6), `questionAnswers` (Q0-Q6), `modelExecution`, `sourcesRead`,
`actions` (booleans `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`, `repositoryValidatorsRun`,
`runnerActivated`, `testsRun`, `warmSourcesAccessed`) and `reviewLimit`. A PASS is not a policy module, a loaded policy or
native qualification.

Rules: separate agent from the author; read-only; no repository edits, no tests or validators, no runner, native, cloud or
GitHub actions, no warm-source access. Public kernel and SELinux documentation and upstream source may be read; list what
you read.
