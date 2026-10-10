# Independent review brief — W02d successor v3 (seccomp-allowlists-v3), round 2

Status: **AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a verdict.

## Subject

Branch `codex/w02d-v3` in the worktree `/Users/caglarsubasi/Desktop/prometa/pocs/harness-engineering/harness-onion-w02d-v3`,
as a diff against `195c4c9` (main after MET-ENFORCE-018, which adopts v2). Subject files with digests:
`architecture/seccomp-allowlists-v3/source-index.json`. Builder sources (outside the repository, read-only):
`~/.local/state/harness-onion-ci/tools/w02dv3/{make_v3.py,build_v3.py,write_docs.py}`, which derive from the reviewed v2
builder `~/.local/state/harness-onion-ci/tools/w01amend/build_v2.py`; upstream sources under
`~/.local/state/harness-onion-ci/tools/w01amend/research/` (musl-1.2.5/, rust/) and the v6.12 kernel files under
`~/.local/state/harness-onion-ci/tools/w02d/research/src/linux-v6.12/`.

Owner decision W02d-V3 (2026-10-10, via the lane monitor): NATIVE_STATIC adds mremap only with flags == MREMAP_MAYMOVE,
prctl only with arg0 == PR_SET_NAME, and tkill; setresuid/setresgid threaded signalling, available_parallelism reads and
units starting roles with fds 0-2 open are W03 trace items.

## Questions

0. Is v3 exactly v2 plus the decision: diff the v2 and v3 data and models; does anything else differ (other roles, other
   rules, constants, citations)? Do SERVER's and WORKER's programs equal v2's?
1. Are the three rules right and narrow at the cited versions: musl mallocng's mremap flags, Rust std's and musl's thread
   naming path (self only, so prctl, not /proc/self/task/<tid>/comm), musl abort/raise using tkill, and the constants
   (PR_SET_NAME 15, MREMAP_MAYMOVE 1, mremap's flags in arg 3)? Would MREMAP_FIXED, MREMAP_DONTUNMAP or any other prctl
   option be admitted anywhere they should not?
2. Do all v3 vectors replay through the v3 model (reference decision == compiled filter), the worker stack checks hold,
   every mutation (including M16-M18) is refused with its recorded message, and the digests are the compiled programs'?
   Do the two new model checks refuse what they claim and admit the broker's coverage and PR_SET_NO_NEW_PRIVS?
3. Does the README overclaim, and are the W03 carry items stated correctly?

## How to check

Read-only. One process at a time, each at most 60 seconds, from the worktree root with plain `python3` (the models are
stdlib-only). You may import the models and run the builders' logic in a scratch copy, never writing into the repository.
No repository edits, no git state changes, no other worktrees; scratch in `/private/tmp/claude-501/w02dv3-review-r2/`. Stop
at once on PAUSE (or when that directory has a `PAUSE` file) until resume.

## Result

Write one JSON object to `/private/tmp/claude-501/w02dv3-review-r2/review-round2.json`: `schemaVersion`
`"planeon.internal.seccomp-allowlists-v3-review/v1"`, `round` 2, `reviewDate`, `verdict` (PASS_FOR_SOURCE_PUBLICATION,
CHANGES_REQUIRED or BLOCKED), `subjectCommit`, `subjectSha256` (path -> sha256 of every subject file in the source index),
`findings` (`id`, `severity` BLOCKING/MAJOR/MINOR/NOTE, `location`, `finding`, `requiredChange`), `questionAnswers`
(Q0-Q3), `sourcesRead`, `actions` (booleans `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
`repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`) and `reviewLimit`.

Rules: separate agent from the author; read-only; no tests or validators of the repository suite, no runner, native,
cloud or GitHub actions.
