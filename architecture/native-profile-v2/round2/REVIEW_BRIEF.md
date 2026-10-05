# Independent review brief — W02a native qualification record v2, round 2

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. Written by the
authoring agent; not a verdict.

Round 1 (`review-round1.json`) returned CHANGES_REQUIRED with 7 MAJOR, 9 MINOR and 3
NOTE findings. The reviewed round-1 bytes are kept in `round1/`. README.md lists how
round 2 answers each finding.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief,
the v2 schema, the v2 vectors and the reference model `scripts/native_qualification_v2.py`.
Check them against the predecessor inputs listed there: the reviewed W01 candidate
(HOST_INTERFACE_SPEC.md §2, §4, §5), its review record, the unchanged v1 schema,
vectors and reference model, the proxy profile contract, the round-1 subject and the
round-1 verdict.

The working tree also contains this packet's mechanical history-chain edits (about
110 files of catalog counts and successor bridges, a new layer validator and test, and
the packet YAML). They are outside this subject, are checked by the required verify
suite, and will not change while you review.

## Questions to answer

1. **Round-1 closure.** For each round-1 finding F1-F19, is the README disposition
   true in the round-2 bytes? Is anything still open, or only partly fixed?
2. **Fidelity.** Does the contract encode spec §4.1-§4.4 and §5.1-§5.3 without
   weakening them? List spec requirements the record cannot express or does not
   check, and additions the spec does not support. README decisions 1-8 are in scope.
3. **Model soundness.** Can a record, capture, lifecycle capture, backend capture or
   full qualification bundle that violates the spec still pass? Try new probes, in
   particular around cgroup membership, capability sets, code ownership by content,
   backend separation, migration nonce scanning and the seal-marker binding.
4. **Vectors.** Does each negative fail for its stated reason? Are the schema-level
   refusals single-error? Are the accepted variants really acceptable under the spec?
   Are the cross-version expectations right for both readers?
5. **Overclaims.** Does anything claim native observation, an installed profile, a
   selected distribution, closure of W01 findings F1/F2, or any E01-E12 proof?
6. **v1 preservation.** Are the v1 schema and vectors byte-identical, and is the v1
   reference model's record and capture logic unchanged?

## How to check

You may run the reference model read-only from the repository root with the locked
environment: `uv run --offline --frozen --no-sync python`. Importing
`scripts/native_qualification_v2.py` and calling its functions on `vectors.json` is
allowed. So is importing `scripts/validate_proxy_contract.py` for its pure
`validate_profile` and `load_proxy_inputs`. Do not run the repository test suite or
validators, and do not modify any file.

## Result

Return PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED with numbered
findings (BLOCKING / MAJOR / MINOR / NOTE), an answer per question, and a per-finding
status for round-1 F1-F19 (CLOSED, PARTIAL or OPEN). A PASS is not native
qualification, an installed profile or authorization for anything installed.

Rules: separate agent from the author; read-only; no repository edits, no tests or
validators, no runner, native, cloud or GitHub actions, no warm-source access. Public
documentation and upstream source may be read; list what you read.
