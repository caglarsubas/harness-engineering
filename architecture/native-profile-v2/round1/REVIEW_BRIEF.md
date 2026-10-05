# Independent review brief — W02a native qualification record v2

Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. Written by the authoring
agent; not a verdict.

## Subject

The exact bytes listed under `subject` in `source-index.json`: this README, the v2
schema, the v2 vectors, and the reference model `scripts/native_qualification_v2.py`.
Check them against the predecessor inputs listed there, in particular the reviewed
W01 candidate (HOST_INTERFACE_SPEC.md §2, §4, §5), its review record (findings F1-F3)
and the unchanged v1 schema, vectors and reference model.

## Questions to answer

1. **Fidelity.** Does the v2 schema plus model encode the reviewed G06/G07 design
   (spec §4.1-§4.4, §5.1-§5.3) without weakening it? List anything the spec requires
   that the record cannot express or does not check. List anything the record adds
   that the spec does not support. The four decisions in README "Decisions made in
   this contract" are in scope.
2. **F3.** Are the v2 cgroup paths exact, consistent with spec §4.2, and is v1/v2
   mutual rejection shown for both records and captures?
3. **Rejection coverage.** Do the negatives cover every rejection case in spec §4.4?
   Does each negative fail for its stated reason (the `refusal` field) and not for
   an incidental one? Are there important refusals with no vector (for example
   duplicated pins, lifecycle-subject code loaded by a resident role, a backend
   component sharing a role artifact)?
4. **Model soundness.** Can a record or capture that violates the spec still pass
   `check_record` / `check_capture` / `check_lifecycle_capture` /
   `check_migration`? Look at ordering (schema before semantics), the
   endpoint/capability coupling, code-inventory ownership and the capture
   equality checks.
5. **Overclaims.** Does anything claim native observation, an installed profile, a
   selected Kubernetes distribution, closure of F1/F2, or any E01-E12 proof?
6. **v1 preservation.** Are v1 schema, vectors and reference model bytes unchanged,
   and does v2 avoid reinterpreting v1 data?

## How to check

You may run the reference model on the vectors (read-only, offline) with the
repository's locked environment, for example
`uv run --offline --frozen --no-sync python -c "..."` from the repository root.
Importing `scripts/native_qualification_v2.py` and calling its functions on
`vectors.json` is allowed. Do not run the repository's test suite or validators,
and do not modify any file.

## Result

Return PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED with numbered
findings (BLOCKING / MAJOR / MINOR / NOTE). Give an explicit answer per question. A
PASS is not native qualification, an installed profile or authorization for anything
installed.

Rules: separate agent from the author; read-only; no repository edits, no tests or
validators, no runner, native, cloud or GitHub actions, no warm-source access. Public
documentation and upstream source may be read; list what you read.
