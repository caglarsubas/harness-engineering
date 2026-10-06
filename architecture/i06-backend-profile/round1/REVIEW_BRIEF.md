# Independent review brief — W02g I06 backend profile, round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring
agent wrote this brief. It is not a verdict.

## Subject

The subject is the exact bytes listed under `subject` in `source-index.json`:

- README.md and this brief;
- the criteria, writer inventory and identity closure;
- the upstream bootstrap RBAC and upstream facts;
- the vectors;
- the reference model `scripts/i06_backend_profile.py`.

Check them against the predecessor inputs listed there: the W01 spec and review,
and the W02a status and contract.

The working tree also contains this packet's mechanical history-chain edits:
catalog counts, successor bridges, a new layer validator and test, and the packet
YAML. They are outside this subject, the required verify suite checks them, and
they will not change while you review.

## Questions to answer

1. **Fidelity.** Does the contract encode W01 spec §2.1-§2.6 (P1-P10, the §2.3
   closure and the §2.5 dispositions) without weakening them? Are its narrowings
   and extensions disclosed and justified in README decisions 1-11 and the
   closure section?
2. **Upstream accuracy.** Do the inventory, the bootstrap RBAC derivation and the
   cited facts match Kubernetes v1.37.1? Sample controllers, apiserver writers,
   bootstrap roles and the facts behind the SPECIAL and WORKLOAD categories:
   - constrained impersonation verbs and resources;
   - the `nodes/proxy` verb mapping;
   - the websocket exec authorization gate;
   - the PodCertificateRequest and ClusterTrustBundle signers;
   - the front-proxy request-header authenticator.
3. **Closure completeness.** Can any identity obtain a policy write, or another
   identity's authority, outside the closure? Consider at least:
   - impersonation, both legacy and constrained;
   - token minting;
   - CSR and PodCertificateRequest signing;
   - legacy token Secrets;
   - pod creation with a service account, exec, attach and ephemeral containers;
   - `nodes/proxy` and the kubelet API;
   - front-proxy and external authentication;
   - aggregated ClusterRoles, `escalate` and `bind`;
   - the Node authorizer;
   - controller accounts created later (dormant bindings).
4. **Model soundness.** Can a violating evidence record, RBAC snapshot, closure or
   inventory still pass? Check the RBAC matching, the scope handling (including
   `QUALIFICATION_NAMESPACE`), the dormant rule and the writer constraints.
5. **Vectors.** Does each negative fail for its stated reason? Are the accepted
   variants right?
6. **F1 and P7.** Does the contract close W01 finding F1 (its required change is
   quoted in the README) and W02a finding P7? Answer `f1Closed` and `p7Closed`.
7. **Overclaims.** Does anything claim an observed cluster, a selected
   distribution, an installed profile, W02e/W02c/W02f content or any E01-E12
   proof?

## How to check

You may run the reference model read-only from the repository root with the locked
environment: `uv run --offline --frozen --no-sync python` and import
`scripts/i06_backend_profile.py`. You may read the public Kubernetes source at tag
v1.37.1. Do not run the repository test suite or validators, and do not modify any
file.

## Result

Return one JSON object with these keys:

- `schemaVersion`: `"planeon.internal.i06-backend-profile-review/v1"`
- `round`: 1
- `reviewDate`
- `verdict`: PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED
- `subjectSha256`: subject file name to digest
- `findings`: a list; each finding has `id`, `severity` (BLOCKING, MAJOR, MINOR
  or NOTE), `location`, `finding` and `requiredChange`
- `questionAnswers`: Q1-Q7
- `f1Closed`, `p7Closed`
- `modelExecution`
- `sourcesRead`
- `actions`: booleans `filesEdited`, `githubMutated`, `nativeActions`,
  `referenceModelExecuted`, `repositoryValidatorsRun`, `runnerActivated`,
  `testsRun`, `warmSourcesAccessed`
- `reviewLimit`

A PASS is not a selected distribution, an observed cluster or authorization for
anything installed.

Rules:

- You are a separate agent from the author, and the review is read-only.
- No repository edits, tests or validators.
- No runner, native, cloud or GitHub actions.
- No warm-source access.
- You may read public documentation and upstream source; list what you read.
