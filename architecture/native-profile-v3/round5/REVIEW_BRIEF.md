# Independent review brief — native qualification record v3 (W02a-F), round 5

Status: **CONTRACT_CANDIDATE_ROUND5_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

Rounds 1 to 4 (`review-round1.json` to `review-round4.json`) returned CHANGES_REQUIRED; their reviewed bytes are kept in
`round1/` to `round4/`. Round 4 closed every earlier finding and raised R4-1 (MINOR) and R4-2 (NOTE). README "Round-4
findings and dispositions" states how round 5 answers them: the boot command line now has a closed grammar.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, `qualification.schema.json`,
`vectors.json` and the reference model `scripts/native_qualification_v3.py`. Check them against the predecessor inputs
listed there:
- the adopted v2 contract: README, schema, vectors, model, status and its three verbatim reviews, especially round-3
  findings P1-P7;
- the W02g identity closure and its round-2 review (P7 carries, the network-policy agent identity);
- the W02e SELinux matrix README and status (label slots, owner decision E1 and its census, K1);
- the reviewed W01 resolution (§4, §5.2, §5.5).

The v2 model is the base of the v3 model. `diff scripts/native_qualification_v2.py scripts/native_qualification_v3.py`
is the model's review surface.

The working tree may also contain this packet's mechanical history-chain edits. They are outside this subject, are
checked by the required verify suite, and will not change while you review.

## Questions to answer

0. **Earlier findings.** For R4-1 and R4-2, is the README disposition true in the round-5 bytes? Does the closed grammar
   leave any quote-free word through which the command line selects, adds, masks or overrides a unit, or hands init an
   environment or arguments? Does it refuse a legitimate enrolled or maintenance entry that W03 could not reasonably
   avoid? Give CLOSED, PARTIAL or OPEN under `openItemStatus`, and confirm that no CLOSED item reopened.
1. **Carried findings.** For P1, P3, P4, P5, P6, P7(a), P7(b) and P7(c), the network-policy agent identity, the W02e
   label slots, E1's census and K1: does v3 close the finding as it was required? Give CLOSED, PARTIAL or OPEN under
   `openItemStatus`.
2. **No regression.** Does every v2 rule still hold in v3? Are the four changed replay refusals (README "Replayed v2
   cases") correct, and is the subsumed identity-disjointness rule truly subsumed? Does any v3 rule refuse a legitimate
   host, for example a shared library between native roles (A05), a leftover unpopulated scope (A06) or another node
   name (A07)?
3. **Kernel facts.** Check that:
   - the 22 census attach types plus the 7 hooks are exactly the cgroup attach types of Linux v6.12;
   - `BPF_PROG_QUERY` with `BPF_F_QUERY_EFFECTIVE` reports the effective set, including inherited `BPF_F_ALLOW_MULTI`
     programs, and for `BPF_LSM_CGROUP` across its slots;
   - `pids.current` counts tasks;
   - `/proc/<pid>/exe` names the interpreter for an interpreted program.

   The README cites the v6.12 source files and their digests.
4. **K1.** Does recording the enrolled and maintenance boot entries, and requiring captures to observe the enrolled one,
   give the record-level discriminator W02e's K1 asked for? Is the README's statement (loader-reported, not measured;
   the maintenance domain is a trusted installer) accurate and sufficient?
5. **Census and closure soundness.** Can a bundle still carry its own observation of a foreign cgroup, process or
   program and qualify? Can a role still run another role's or an interpreter's code? Try probes beyond the vectors.
6. **Vectors.** Does each case produce exactly its stated result for its stated reason? Are the positives
   kernel-plausible?
7. **Overclaims.** Does anything claim a native observation, a measured boot, a selected distribution, seccomp filters
   or an E01-E12 proof?

## How to check

You may run the reference model read-only from the worktree root with the shared locked environment:
`UV_PROJECT_ENVIRONMENT=/Users/caglarsubasi/Desktop/prometa/pocs/harness-engineering/harness-onion/.venv uv run --offline --frozen --no-sync python`.
Set the environment variable inline on every command, and never let uv create a `.venv` in the worktree. Import
`scripts/native_qualification_v3.py`. Do not run the repository test suite or validators, and do not modify any file.

## Result

Return one JSON object:
- `schemaVersion` `"planeon.internal.native-profile-v3-review/v1"`, `round` 5, `reviewDate`;
- `verdict`: PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED;
- `subjectSha256`: subject file name to digest;
- `findings`, each with `id`, `severity` (BLOCKING / MAJOR / MINOR / NOTE), `location`, `finding` and `requiredChange`;
- `openItemStatus`, `questionAnswers` (Q0-Q7), `modelExecution`, `sourcesRead`;
- `actions`, booleans: `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
  `repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`;
- `reviewLimit`.

A PASS is not a native qualification or authorization for anything installed.

Rules: you are a separate agent from the author; read-only; no repository edits, no tests or validators, and no runner,
native, cloud or GitHub actions; no warm-source access. Public documentation and kernel source may be read; list what you
read.
