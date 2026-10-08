# Independent review brief — I06 backend profile v2 (W02g-F), round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, `criteria.json`, `vectors.json` and
the reference model `scripts/i06_backend_profile_v2.py`. Check them against the predecessor inputs listed there:
- the adopted I06 profile v1: README, criteria, vectors, status, model, the frozen identity closure, writer inventory,
  upstream facts and bootstrap RBAC, and its verbatim round-2 review (findings N1-N6);
- the adopted W02a v3 contract: README, schema, vectors, status and model (`check_record`, `check_qualification`);
- the W02a v2 vectors and status (the v1 backend for the cross-version cases, and the P7 carry).

The v2 model imports the v1 model and W02a v3's model and adds rules before or after the v1 checks. Its review surface
is the whole file, about 100 lines.

The working tree may also contain later mechanical history-chain edits. They are outside this subject.

## Questions to answer

1. **N1.** Does `check_evidence` now accept only evidence that names, by digest, a record that W02a v3's `check_record`
   accepts, with the evidence's identity and test-only state equal to that record's backend? Is applying `check_record`
   inside the check (rather than as a caller obligation) sound, and does it examine `cgroupPath`, `apiIdentities` and
   `filePaths` as the round-2 type sweep required? Is the digest well defined (canonical form, no prefix)? Is the
   statement that no production evidence can be accepted until a reviewed W02a revision adds a production backend
   profile correct, and is that an acceptable answer to round 2's request for non-fixture accepted variants? Give
   CLOSED, PARTIAL or OPEN under `openItemStatus`.
2. **N2.** Is every RBAC rule on User `system:apiserver` refused, including non-policy ones, and is the snapshot format
   rightly left at v1?
3. **N3.** Are shared and nested backend cgroups refused (G07, G08), and does a prefix-sharing sibling stay accepted
   (A09)? Is the P7 carry chain stated correctly against the W02a v2 and v3 status records?
4. **No regression.** Does every v1 rule still hold in v2? Are the ten changed replay refusals (README "Replayed v1
   cases") correct, each for the stated reason? Is it right not to replay the closure and inventory vectors?
5. **Probes.** Try evidence, backends and snapshots beyond the vectors: can a v2 check accept evidence whose backend W02a
   v3 refuses, evidence naming a record other than the one passed, a test-only backend outside a fixture call, or any
   rule on the loopback user?
6. **Vectors.** Does each case produce exactly its stated result for its stated reason? Are the cross-version cases
   accurate?
7. **Overclaims.** Does anything claim a cluster or distribution observation, a selected distribution, a production
   backend profile or an E01-E12 proof?

## How to check

You may run the reference models read-only from the worktree root with the shared locked environment:
`UV_PROJECT_ENVIRONMENT=/Users/caglarsubasi/Desktop/prometa/pocs/harness-engineering/harness-onion/.venv uv run --offline --frozen --no-sync python`.
Set the environment variable inline on every command, and never let uv create a `.venv` in the worktree. Add `scripts`
to `sys.path` and import `i06_backend_profile_v2`, `i06_backend_profile` and `native_qualification_v3`. The vectors' ops
use v1's mutation format; backend operations apply to the W02a v3 record, after which the evidence names the mutated
record unless its own operations change the reference. Do not run the repository test suite or validators, and do not
modify any file.

## Result

Return one JSON object:
- `schemaVersion` `"planeon.internal.i06-backend-profile-v2-review/v1"`, `round` 1, `reviewDate`;
- `verdict`: PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED;
- `subjectSha256`: subject file name to digest;
- `findings`, each with `id`, `severity` (BLOCKING / MAJOR / MINOR / NOTE), `location`, `finding` and `requiredChange`;
- `openItemStatus` (N1-N6), `questionAnswers` (Q1-Q7), `modelExecution`, `sourcesRead`;
- `actions`, booleans: `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
  `repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`;
- `reviewLimit`.

A PASS is not a distribution selection or authorization for anything installed.

Rules: you are a separate agent from the author; read-only; no repository edits, no tests or validators, and no runner,
native, cloud or GitHub actions; no warm-source access. Public Kubernetes documentation and source may be read; list what
you read.
