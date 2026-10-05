# Independent review brief — W02a native qualification record v2, round 3

Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**. Written by the
authoring agent; not a verdict.

Round 1 (`review-round1.json`) and round 2 (`review-round2.json`) returned
CHANGES_REQUIRED. Their reviewed bytes are kept in `round1/` and `round2/`. README.md
lists how round 3 answers each open item: round-1 partials F3, F7, F15, F16 and F18,
and round-2 findings N1-N16. It also records the owner's decision D5 (worker
capability rule, finding N7).

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief,
the v2 schema, the v2 vectors and the reference model `scripts/native_qualification_v2.py`.
Check them against the predecessor inputs listed there and the earlier rounds' records.

The working tree also contains this packet's mechanical history-chain edits (catalog
counts, successor bridges, a new layer validator and test, the packet YAML). They are
outside this subject, are checked by the required verify suite, and will not change
while you review.

## Questions to answer

1. **Closure.** For each open item (round-1 F3, F7, F15, F16, F18; round-2 N1-N16), is
   the README disposition true in the round-3 bytes? Give CLOSED, PARTIAL or OPEN.
2. **Owner decision D5.** Is the redefined WORKER capability rule encoded exactly as
   stated, and is it no weaker than the README claims?
3. **Fidelity.** Does the contract encode spec §4.1-§4.4 and §5.1-§5.3 (as amended by
   D5) without weakening them? Are README decisions 1-11 disclosed and justified?
4. **Model soundness.** Can a violating record, capture, lifecycle capture, backend
   capture or full qualification bundle still pass? Probe in particular: the slice
   census and host-wide counts, subtree and membership rules, worker descent,
   the confined-type allow-list and implementation profiles, content-distinct role
   executables, the seal-marker binding, and migration with an attested empty history.
5. **Vectors and overclaims.** Does each negative fail for its stated reason, as a
   single schema error where it is schema-level? Are the accepted variants right? Are
   the cross-version facts right? Does anything claim native observation, an installed
   profile, a selected distribution, W01 F1/F2 closure or any E01-E12 proof?
6. **v1 preservation.** v1 schema and vectors byte-identical; v1 `validate_record` and
   `validate_capture` and the proxy contract's `validate_profile` unchanged?

## How to check

You may run the reference model read-only from the repository root with the locked
environment (`uv run --offline --frozen --no-sync python`): import
`scripts/native_qualification_v2.py` and, for its pure functions only,
`scripts/validate_proxy_contract.py`. Do not run the repository test suite or
validators, and do not modify any file.

## Result

Return PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED with numbered findings
(BLOCKING / MAJOR / MINOR / NOTE), an answer per question, and statuses for the open
items listed in question 1. A PASS is not native qualification, an installed profile
or authorization for anything installed.

Rules: separate agent from the author; read-only; no repository edits, no tests or
validators, no runner, native, cloud or GitHub actions, no warm-source access. Public
documentation and upstream source may be read; list what you read.
