# Independent review brief — W04-0 enforcement test plan, round 3

Status: **AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a verdict.

## Subject

Branch `codex/w04-0-test-plan` in the worktree `/Users/caglarsubasi/Desktop/prometa/pocs/harness-engineering/harness-onion-w04`,
as a diff against main `195c4c9`. Subject files with digests: `architecture/enforcement-test-plan/source-index.json`. Builder (outside the repository,
read-only): `~/.local/state/harness-onion-ci/tools/w04/build_w04_0.py`.

Inputs: the later verification matrix (`architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md:74-81`), the T08
additions (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md` section 4.4) and its section 8 gate map,
the obligation ledger (`docs/alpha-2/ENFORCEMENT_FEASIBILITY.md:156-177`), the acceptance items
(`docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md:320-336` and 143-150), `docs/alpha-2/ENFORCEMENT_INTEGRATION.md`
(lines 89-143) and the adopted W02 contracts. One W03 record is allowed as input, the distribution selection
(`git show 104b115:architecture/backend-distribution/selection.json`); read nothing else of W03.

## Questions

0. Does every test group carry exactly the matrix's cases and evidence class, and is every T08 addition present?
1. Is the TG-to-E map right and complete: does each group cover the obligations its cases test, and no others? Is E09's
   placement outside the groups justified? Does each obligation's gate list match the resolved spec's section 8?
2. Is the W04/W06 split right: does any group with native evidence run before W06, or does any offline-runnable group
   wait needlessly? Are the acceptance items mapped correctly (A01 the register; A07-A09 outside W04)?
3. Are the contract inputs the adopted ones, pinned to the exact bytes on main? Is anything missing that a group needs?
4. Does the observation-window schema force an exhaustive register for one exact revision with every field
   OBSERVATION_ENFORCEMENT_DESIGN.md:143-150 requires? Do the independence rules hold? Does anything overclaim?

## How to check

Read-only. One process at a time, each at most 60 seconds, from the worktree root with plain `python3`. The W03
selection record reaches main only with packet 221; until then, run `check` with a reader that serves
`architecture/backend-distribution/selection.json` from `git show 104b115:architecture/backend-distribution/selection.json`
and every other path from the worktree. No repository
edits, no git state changes, no other worktrees; scratch in `/private/tmp/claude-501/w04-0-review-r3/`. Stop at once on
PAUSE (or when that directory has a `PAUSE` file). Never send personal data (email, names, account ids) in any network
request, header, User-Agent or query; no network access is needed.

## Result

Write one JSON object to `/private/tmp/claude-501/w04-0-review-r3/review-round3.json`: `schemaVersion`
`"planeon.internal.enforcement-test-plan-review/v1"`, `round` 3, `reviewDate`, `verdict` (PASS_FOR_SOURCE_PUBLICATION,
CHANGES_REQUIRED or BLOCKED), `subjectCommit`, `subjectSha256` (path -> sha256 of every subject file in the source index),
`findings` (`id`, `severity` BLOCKING/MAJOR/MINOR/NOTE, `location`, `finding`, `requiredChange`), `questionAnswers`
(Q0-Q4), `sourcesRead`, `actions` (booleans `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
`repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`) and `reviewLimit`.

Rules: separate agent from the author; read-only; no runner, native, cloud or GitHub actions.
