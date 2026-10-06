# Independent review brief — W02g I06 backend profile, round 2

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. The authoring agent
wrote this brief. It is not a verdict.

Round 1 (`review-round1.json`) returned CHANGES_REQUIRED. The bytes it reviewed are kept in
`round1/`. `upstream-facts-v1.37.1.json` is unchanged and is not copied there. README.md
("Round-1 findings and dispositions") states how round 2 answers F1-F12.

## Subject

The subject is the exact bytes listed under `subject` in `source-index.json`:

- README.md and this brief;
- the criteria, writer inventory and identity closure;
- the upstream bootstrap RBAC and upstream facts;
- the vectors;
- the reference model `scripts/i06_backend_profile.py`.

Check them against the predecessor inputs listed there: the W01 spec and review, and the
W02a status, schema and vectors. The evidence vectors bind to the W02a unit-distribution
positive.

The working tree also contains this packet's mechanical history-chain edits: catalog
counts, successor bridges, a new layer validator and test, and the packet YAML. They are
outside this subject, the required verify suite checks them, and they will not change
while you review.

## Questions to answer

1. **Round-1 closure.** For each round-1 finding F1-F12, is the README disposition true
   in the round-2 bytes? Give CLOSED, PARTIAL or OPEN under `openItemStatus`.
2. **Fidelity.** Does the contract encode W01 spec §2.1-§2.6 (P1-P10, the §2.3 closure,
   the §2.5 dispositions) without weakening them? Are its narrowings and extensions
   disclosed and justified?
3. **Upstream accuracy.** Do the inventory, the bootstrap RBAC derivation, the
   referenced `system:kubelet-api-admin` rules and the cited facts match Kubernetes
   v1.37.1? This includes the facts new in round 2:
   - the service-account signing endpoint and verification keys;
   - `staticPodURL`;
   - emulated and minimum-compatibility versions and runtime-config;
   - the kubelet log and checkpoint handlers.
4. **Closure completeness.** Can any identity obtain a policy write, or another identity's
   authority, outside the closure? Probe again, including the paths round 1 listed and
   any the record still cannot express.
5. **Model soundness.** Can a violating evidence record (with its W02a backend), RBAC
   snapshot, closure or inventory still pass? Look in particular at:
   - the PROFILE pinning;
   - the dormant rule;
   - the W02a binding and the canonical, distinct executables;
   - the exact sealed set;
   - the strict type checks.
6. **Vectors.** Does each negative fail for its stated reason? Are the accepted variants
   right?
7. **F1 and P7.** Is W01 finding F1 closed (`f1Closed`)? For W02a finding P7, answer two
   fields:
   - `p7Closed`: is the whole finding closed?
   - `p7I06PartClosed`: does the I06 evidence path refuse the fixture as a production
     backend, with every remaining part of P7 explicitly carried to a named successor?
8. **Overclaims.** Does anything claim an observed cluster, a selected distribution, an
   installed profile, W02e/W02c/W02f content or any E01-E12 proof?

## How to check

You may run the reference model read-only from the repository root with the locked
environment: `uv run --offline --frozen --no-sync python` and import
`scripts/i06_backend_profile.py`. You may read the public Kubernetes source at tag
v1.37.1. Do not run the repository test suite or validators, and do not modify any file.

## Result

Return one JSON object with these keys:

- `schemaVersion`: `"planeon.internal.i06-backend-profile-review/v1"`
- `round`: 2
- `reviewDate`
- `verdict`: PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED
- `subjectSha256`: subject file name to digest
- `findings`: a list; each finding has `id`, `severity` (BLOCKING, MAJOR, MINOR or
  NOTE), `location`, `finding` and `requiredChange`
- `openItemStatus`: F1-F12
- `questionAnswers`: Q1-Q8
- `f1Closed`, `p7Closed`, `p7I06PartClosed`
- `modelExecution`
- `sourcesRead`
- `actions`: booleans `filesEdited`, `githubMutated`, `nativeActions`,
  `referenceModelExecuted`, `repositoryValidatorsRun`, `runnerActivated`, `testsRun`,
  `warmSourcesAccessed`
- `reviewLimit`

A PASS is not a selected distribution, an observed cluster or authorization for anything
installed.

Rules:

- You are a separate agent from the author, and the review is read-only.
- No repository edits, tests or validators.
- No runner, native, cloud or GitHub actions.
- No warm-source access.
- You may read public documentation and upstream source; list what you read.
