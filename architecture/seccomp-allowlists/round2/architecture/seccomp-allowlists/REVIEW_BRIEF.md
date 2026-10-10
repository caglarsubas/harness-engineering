# Independent review brief — W02d seccomp allowlists, round 2

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

Round 1 (`review-round1.json`; the round-1 bytes of the files changed since are in `round1/`) returned CHANGES_REQUIRED.
The owner decided W02d-QA..QD (README, "Owner decisions"); README "Round-1 findings and dispositions" gives each answer.
Check each disposition, re-run your round-1 probes (W5 under the worker filter, the stacked broker and worker filters,
glibc clone3, the broker's W3/W5 calls) and confirm nothing regressed.

W02d turns the seccomp shape of the reviewed W01 design (section 5.3 per-role table, section 5.1 bpf command limit,
section 5.4 worker pre-exec steps) into exact x86_64 and aarch64 allowlists for the seven roles, under three owner
decisions recorded in README.md (W02d-Q1..Q3 and, after round 1, W02d-QA..QD).

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, `syscalls.json`, `allowlists.json`,
`vectors.json` and the reference model `scripts/seccomp_allowlists.py`. Check them against the predecessor inputs listed
there (the W01 resolution, the native-profile v3 record schema with the `seccompFilterDigest` slot, the readiness note on
membarrier) and against the pinned kernel sources: Linux v6.12, commit `adc218676eef25575469234709c2d87185ca223a` (public;
the author's research copies are in `~/.local/state/harness-onion-ci/tools/w02d/research/src/`, each recorded by sha256 in
`.../research/w02d-facts.json`; you may fetch your own).

## Questions to answer

0. **Owner decisions and round-1 findings.** Are F1-F12 answered as README states? Does the contract implement W02d-QA..QD, W02d-Q1 (the worker allowlist from its duties, the W01 row amendment
   carried), W02d-Q2 (duty calls from each row plus one closed runtime base; W03 must fit) and W02d-Q3 (the digest is the
   SHA-256 of the little-endian `sock_filter` array the reference compiler emits) as decided?
1. **Numbers and constants.** Is every syscall number in `syscalls.json` the v6.12 number for the stated ABI (x86_64:
   common and 64; aarch64: `scripts/syscall.tbl` with the arm64 ABIs), and every constant (audit arches, x32 bit, socket,
   clone, memfd, open flags on both arches, AT_EMPTY_PATH, P_PIDFD, SIGKILL, PR_SET_NO_NEW_PRIVS, SECCOMP_SET_MODE_FILTER,
   the ioctl numbers including FS_IOC_ENABLE_VERITY) right for both arches?
2. **Derivation.** Is each role's allowlist exactly its W01 row (plus its base), with nothing missing that the row names
   and nothing added that no row, step or owner decision supports? Are the argument filters right (argument positions per
   arch, low-32-bit sufficiency, masks)? Are the runtime bases plausible and closed, and is anything in them that a row
   forbids?
3. **Denials.** Does `check_policy` refuse everything W01 sections 5.1 and 5.3 deny (execve and execveat, clone3, clone
   without CLONE_THREAD, the mount family, setns, unshare, ptrace, process_vm_*, module and kexec calls, bpf outside
   {7, 15, 16})? Is the list of the mount family and module calls complete for v6.12?
4. **Compiler and digest.** Is `compile_filter` a correct classic-BPF seccomp program for `decide` (architecture check,
   x32 refusal, jump arithmetic, conditional bodies, default action), and deterministic? Would the kernel accept it
   (`seccomp_check_filter`: only permitted instructions, aligned loads within `struct seccomp_data`, forward jumps, a
   return at the end)? Is the digest definition sound?
5. **Vectors.** Does every decision check and policy mutation produce exactly its stated result for its stated reason? Do
   the decision checks exercise every grant and every alternative on both arches?
6. **Findings and overclaims.** Are the README's W01/W03 findings right (W6's pidfd kill without CAP_KILL; setgroups;
   the two-filter worker)? Does anything overclaim?

## How to check

Read-only. One process at a time, each at most 60 seconds, from the worktree root with
`UV_PROJECT_ENVIRONMENT=/Users/caglarsubasi/Desktop/prometa/pocs/harness-engineering/harness-onion/.venv
PYTHONDONTWRITEBYTECODE=1 uv run --offline --frozen --no-sync python`. No repository edits, no git state changes, no test
suite or repository validators; scratch in `/private/tmp/claude-501/w02d-review-r2/`. Stop at once on PAUSE (or when
`/private/tmp/claude-501/w02d-review-r2/PAUSE` exists) until resume.

## Result

Return one JSON object written to `/private/tmp/claude-501/w02d-review-r2/review-round2.json`: `schemaVersion`
`"planeon.internal.seccomp-allowlists-review/v1"`, `round` 2, `reviewDate`, `verdict` (PASS_FOR_SOURCE_PUBLICATION,
CHANGES_REQUIRED or BLOCKED), `subjectSha256` (subject repository path to digest), `findings` (`id`, `severity`
BLOCKING / MAJOR / MINOR / NOTE, `location`, `finding`, `requiredChange`), `questionAnswers` (Q0-Q6), `modelExecution`,
`sourcesRead`, `actions` (booleans `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
`repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`) and `reviewLimit`.

Rules: separate agent from the author; read-only; no tests, runner, native, cloud or GitHub actions. Public kernel
sources and documentation may be read; list what you read.
