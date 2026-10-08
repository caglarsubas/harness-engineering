# Independent review brief — W02f POLICY-ADMISSION-SEMANTICS/v2 and A2 allowlists, round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, `allowlists.json`,
`admission-manifests/planeon-a2.json`, `vectors.json` and the reference model `scripts/admission_semantics_v2.py`. Check
them against the predecessor inputs listed there: the reviewed W01 resolution (§3 G05, §2.4, §5.5) and its review, the
pinned v1 sentence in `docs/alpha-2/POLICY_OBSERVATION_READINESS.md`, the W02g I06 backend profile (admission plugin
allowlist SC05, OR06, OR08, SC12, the identity closure), the I05 v2 contract (A1 and the drain answer) and the I07
contract (W02c R2). The owner's decision recorded in the README (sealed static manifest directory, run-independent) is
an input, not a subject.

## Questions to answer

1. **Semantics.** Does the v2 text carry W01 §3.2 A1-A4 faithfully, amending only the A2 placement as the owner decided?
   Is the v1 sentence correctly pinned and refused? Does `check_claim` support exactly the claims the text supports?
2. **Allowlist completeness.** For Pod, immutable ConfigMap and ClusterIP Service on CREATE in Kubernetes v1.37.1, is
   every field that scheme defaulting, the request handler, BeforeCreate, Service allocation or an admission plugin of the
   W02g allowlist can set listed, with a correct disposition? Check the citations at the pinned commit.
3. **Soundness of A2.** Given A1's byte check and the closed mutator set, can any enabled mutator, under any cluster
   state (LimitRange, PriorityClass, RuntimeClass, ServiceAccount, Node, flags), change the persisted object beyond the
   allowlisted deltas while every A2 validation passes? Is the shape echo argument sound, and is its bound stated?
4. **CEL.** Is each rendered validation valid CEL for the v1.37 ValidatingAdmissionPolicy environment, and does
   `check_final` read it faithfully (including absent fields, empty lists and omitted empty values)? Is the guard policy
   correct and safe (does it block anything the platform needs)?
5. **Static directory.** Are the structural rules (`check_a2_objects`) and the loader hash (`manifest_directory_hash`)
   correct against the upstream loader?
6. **Vectors.** Does each case produce exactly its stated result for its stated reason?
7. **Overclaims.** Does anything claim an installed admission configuration, compiled CEL, a selected distribution, the
   I07 change, or any E01-E12 proof?

## How to check

You may run the reference model read-only from the repository root with the locked environment
(`uv run --offline --frozen --no-sync python`): import `scripts/admission_semantics_v2.py`. Do not run the repository
test suite or validators, and do not modify any repository file; scratch files go outside the repository.

## Result

Return one JSON object: `schemaVersion` `"planeon.internal.admission-semantics-v2-review/v1"`, `round` 1, `reviewDate`,
`verdict` (PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED), `subjectSha256` (subject file name to digest),
`findings` (each with `id`, `severity` BLOCKING / MAJOR / MINOR / NOTE, `location`, `finding`, `requiredChange`),
`questionAnswers` (Q1-Q7), `modelExecution`, `sourcesRead`, `actions` (booleans `filesEdited`, `githubMutated`,
`nativeActions`, `referenceModelExecuted`, `repositoryValidatorsRun`, `runnerActivated`, `testsRun`,
`warmSourcesAccessed`) and `reviewLimit`. A PASS is not an installed admission configuration or authorization for
anything installed.

Rules: separate agent from the author; read-only; no repository edits, no tests or validators, no runner, native, cloud or
GitHub actions, no warm-source access. Public documentation and upstream source may be read; list what you read.
