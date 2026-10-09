# Independent review brief — CATALOG-BANK v2 sector catalog overlay, round 1

The authoring agent wrote this brief. It is not a verdict.

## Subject

The commit named in the review request, on branch `codex/met-sector-002-catalog-overlay`, on accepted main `da81730`
(217 packets). Read it with `git show <subject>:<path>` or `git diff da81730 <subject>`, and record the tree hash. The
subject consists of:
- `architecture/sector-catalog/overlay.json`, `README.md` and this brief;
- `scripts/sector_catalog.py`;
- the notice and the DIST-004 pointer in `docs/repositories/11-mas-harness-distribution.md`.

## Context

- Owner decision SECTOR-D1 made banking the first release sector. MET-SECTOR-001 (`architecture/sector-direction.json`)
  listed eight exact `catalogFollowUps`.
- v1 applied them in place, and its content review passed (rounds 1-2). The build then failed: five older validators
  read `providers.yaml` and `services.yaml` from disk as immutable inputs, and about 33-35 records pin them.
- The owner chose this overlay: the catalogs stay byte-identical, and a reviewed record plus a reference module give
  the banking-era view.
- v1's review content carries over: the follow-up mapping, the reason for the deferral and the R11 text. Re-check it
  anyway.

## Questions to answer

1. **Exactness.**
   - Does `overlay.json` cover exactly the eight `catalogFollowUps` (same path, current and proposed)?
   - Are the occurrence counts, the base digests and the effective digests correct for the current tree?
   - Does `effective_bytes` refuse a changed base, a wrong count, a target already present, or a wrong effective digest?
   - Can replacement order or overlapping substrings make the result ambiguous?
2. **Completeness.** Do the effective catalogs contain no white-goods term (SECTOR-001's detection pattern) except the
   deferred pack path? Are all 12 base matches covered?
3. **Deferral.** Is the deferred binding (artifact.platform.industry-pack → IND-WG-005, deliverable 0) checked
   exactly? Does `check()` refuse once IND-BANK-005 is published? Is the reason still accurate?
4. **No catalog change.** Are `providers.yaml`, `services.yaml` and `PROVIDER_MODULE_CATALOG.md` byte-identical to main?
   Can any older validator observe a difference?
5. **R11 notice.**
   - Is the text as reviewed in v1?
   - Is the DIST-004 pointer written without backticks?
   - Does `check()` verify the notice?
   - Will the packet's inverse authority cover the doc for the older validators, as it did for MET-ENFORCE-003?
6. **Module safety.**
   - Does it read only regular files, within a size limit, through a structurally closed record?
   - Does it import only `safe_yaml`?
   - Can a malformed overlay pass?
7. **Consumer rule and guard plan.** Is "banking-era consumers read only through `sector_catalog`, older validators
   keep the base" a sound and enforceable rule for the layer test's guard? What should the guard cover?
8. **Overclaims.** Are the non-claims accurate?

## How to check

Run Python read-only with the shared environment:
`UV_PROJECT_ENVIRONMENT=/Users/caglarsubasi/Desktop/prometa/pocs/harness-engineering/harness-onion/.venv uv run --offline --frozen --no-sync python ...`
from the worktree root, for example `python scripts/sector_catalog.py`, or by importing the module and probing it with
mutated inputs in memory. Run single validators one process at a time. Never let uv create a `.venv` in the worktree.
Do not run the full suite, modify any file, run git commands that write, or access the network.

## Result

Return one JSON object:
- `schemaVersion` `"harness.planeon.ai/sector-catalog-review/v1"`, `round`, `reviewDate`;
- `subjectCommit`, `subjectTree`;
- `verdict`: PASS_FOR_SOURCE_PUBLICATION or CHANGES_REQUIRED;
- `findings`, each with `id`, `severity` (BLOCKING / MAJOR / MINOR / NOTE), `location`, `finding` and `requiredChange`;
- `questionAnswers`, `checksRun`, `sourcesRead`;
- `actions`: booleans `filesEdited`, `githubMutated`, `fullSuiteRun`, `networkAccessed`.
