# Independent review brief — W01-AMEND (W01 amendment + W02d successor v2), round 2

Round 1 (`review-round1.json`, its subject bytes in `round1/`) returned CHANGES_REQUIRED (R1-1 MAJOR, R1-2..R1-6 MINOR,
R1-7..R1-10 NOTE). The amendment README's "Round-1 findings and dispositions" answers each; round 2 checks those
answers and the whole changed subject. Round 2 also takes over parts of a stopped draft by the primary lane (BROKER
stacking, the WORKER SELinux row, the section 5.3 note pointer, the W4 sentence, section 11 and the obligations).

Status: **AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a verdict.

## Subject

Branch `codex/w01-amend-p` in the worktree `/Users/caglarsubasi/Desktop/prometa/pocs/harness-engineering/harness-onion-w01amend-p`,
as a diff against main `b8ce77b` (packet 219, W02d merged). Subject files are listed with digests in
`architecture/host-interface-amendment-w02d/source-index.json`.

1. `architecture/host-interface-amendment-w02d/`: `amendment.json` (`planeon.internal.host-interface-amendment/v1`), the published amended specification
   `HOST_INTERFACE_SPEC.md`, `README.md`, and the model `scripts/host_interface_amendment.py`. The resolved W01 spec
   (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md`) is byte-identical; items A1-A7 are exact counted
   replacements in it.
2. `architecture/seccomp-allowlists-v2/`: the W02d successor (`syscalls.json`, `allowlists.json`, `vectors.json`, `README.md`) and
   `scripts/seccomp_allowlists_v2.py`. Builder sources (outside the repository, read-only for you):
   `~/.local/state/harness-onion-ci/tools/w01amend/{make_v2.py,build_v2.py,build.py}` and the reviewed v1 builder
   `~/.local/state/harness-onion-ci/tools/w02d/build_w02d.py`; kernel sources under
   `~/.local/state/harness-onion-ci/tools/w02d/research/src/linux-v6.12/`.

Owner decisions (via the lane monitor): W02d-Q1, QA, QB, QC (2026-10-09; recorded in `architecture/seccomp-allowlists/status.json` and README),
and for this item QW1 = cgroup.kill only (drop the unused pidfd_send_signal grant), QW2 = the broker runs with no
supplementary groups and W3 checks the child's Groups: line lists none, QW3 = M-a: memfd flags MFD_CLOEXEC |
MFD_NOEXEC_SEAL (not a vm.memfd_noexec pin). The pidfd_send_signal drop in v2 is approved (monitor, 2026-10-10).

## Questions

0. Does each amendment item A1-A7 say exactly what its owner decision and W02d's `carriedToW01` item require, with
   nothing more? Is any carried item missing (W02d `status.json` `carriedToW01` lists six)? Is the amended specification
   internally consistent (BROKER row vs W6; SERVER row vs the v2 allowlists; W3/W4 vs QW2)?
1. Is the kernel reasoning right at v6.12: MFD_NOEXEC_SEAL semantics and its interaction with vm.memfd_noexec
   (`mm/memfd.c`), CAP_KILL for pidfd_send_signal across uids (`kernel/signal.c`), and that the sysctl can be lowered in
   the init namespace (`kernel/pid_sysctl.h`)?
2. Is the v2 successor exactly v1 plus the two disclosed changes: compare `architecture/seccomp-allowlists/` and
   `-v2/` and the two models; does every v2 vector replay through the v2 model (decide == compiled filter), are the
   digests the compiled programs', and are M09's and the memfd check's messages right? Is anything else different?
3. Does `scripts/host_interface_amendment.py` refuse a changed base, a missing or doubled current text, an
   undecided owner decision, an item citing an unknown decision, and a published effective file that differs from the
   applied result?
4. Does any README overclaim (DATA_CHECK_ONLY; no filter, sysctl or unit; E01-E12 open)?

## How to check

Read-only. One process at a time, each at most 60 seconds, from the worktree root with plain `python3` (the models are
stdlib-only). You may import the models and run the builders' logic in a scratch copy, never writing into the repository.
No repository edits, no git state changes; scratch in `/private/tmp/claude-501/w01amend-review-r2/`. Stop at once on
PAUSE (or when that directory has a `PAUSE` file) until resume.

## Result

Write one JSON object to `/private/tmp/claude-501/w01amend-review-r2/review-round2.json`: `schemaVersion`
`"planeon.internal.w01-amendment-review/v1"`, `round` 2, `reviewDate`, `verdict` (PASS_FOR_SOURCE_PUBLICATION,
CHANGES_REQUIRED or BLOCKED), `subjectCommit`, `subjectSha256` (path → sha256 of every subject file in the source index),
`findings` (`id`, `severity` BLOCKING/MAJOR/MINOR/NOTE, `location`, `finding`, `requiredChange`), `questionAnswers`
(Q0-Q4), `sourcesRead`, `actions` (booleans `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
`repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`) and `reviewLimit`.

Rules: separate agent from the author; read-only; no tests or validators of the repository suite, no runner, native,
cloud or GitHub actions.
