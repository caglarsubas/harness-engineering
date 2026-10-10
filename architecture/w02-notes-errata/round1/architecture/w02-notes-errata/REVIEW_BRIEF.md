# Independent review brief — W02 notes errata (W02a-F2, W02g-F2, PERF-032-F), round 1

Status: **ERRATA_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

## Subject

The exact bytes listed under `subject` in `source-index.json`:
- this directory: README, this brief, both errata records, the R6-3 vector file and `effective/`;
- `scripts/contract_errata.py` and `scripts/perf032_followup.py`;
- the F13 wording edits in `scripts/schema_unique.py`, `scripts/validate_verify_headroom.py`,
  `tests/test_verify_headroom.py` and `docs/MASTER_DEVELOPMENT_PLAN.md`.

`git diff 5fab673` against the subject commit is the whole change surface. The adopted inputs are the native-profile-v3
round-6 review (`architecture/native-profile-v3/review-round6.json`), the I06 v2 round-2 and round-3 reviews, and the
MET-PERF-032 round-3 review (F12-F15). The owner decisions are:
- Q-S = A: review notes only; the rule changes become W02-PROD;
- Q-F = A: errata records with no version ripple. For native-profile-v3, counted replacements answer R6-1 and R6-2, and
  an added negative-vector file answers R6-3, replayed against the unchanged v3 model. For I06 v2, the README answers
  R3-1 and R3-2, and R2-4 is answered by its documented alternative; the verityDigest rule and R3-3 move to W02-PROD.
  PERF-032-F is ordinary code edits.

## Questions

1. Does every replacement answer its finding's required change exactly and truthfully? Check each against the cited
   systemd v256 and Linux v6.12 behaviour where it states a fact (R6-1a to R6-1d, R6-2a). Do the effective files read
   correctly in place?
2. Is every R6-3 vector refused by the rule its intent names, through `native_qualification_v3.check_record`
   unchanged? Replay them. Do the bound pairs make each grammar and lockdown case single-defect? Does each mutant in the
   README table pass the 207 adopted negatives and 9 accepted cases, while changing the listed errata cases?
3. Is the stated overlap of the maintenance-grammar and maintenance-target rules exact?
4. Does `check_errata` refuse a wrong adopted digest, a wrong count, a non-comment model change and an effective file
   that differs? Is the comment-only rule (AST equality) sound?
5. Is the R2-4 alternative true: does `check_backend_capture` refuse a record whose backend `verityDigest` contradicts
   the observed `measuredVerity`?
6. Do F12, F14 and F15 refuse the round-3 probes, and accept the current tree? Are the F13 edits exact?
7. Does anything here change an adopted contract, rule, vector, model or version, or claim more than it shows?

## How to run

Use the repository's uv environment. Each command must be single-process and take ≤60 s:

```
UV_PROJECT_ENVIRONMENT=<repo>/.venv PYTHONDONTWRITEBYTECODE=1 uv run --offline --frozen --no-sync python -c '...'
```

- `contract_errata.check_errata(parse(read(record)), read)` for each record;
- `contract_errata.replay_vectors(parse(read(vectors)), read)`, which returns 39;
- `perf032_followup.validate_perf032_followup(read, <the route tests>)`, which returns 806 for 31 files;
- `tests/test_verify_headroom.py` is expected to fail on this contract commit with "unreviewed current source" and
  "reviewed schema_unique bytes": the history chain refuses edited sources until the packet's bridge layer projects
  them back, which is built after this review. Check the F13 edits by reading them.

Write probes and mutants only in a scratch directory, never in the worktree.

## Rules for the reviewer

- Single process, at most 60 s per command. Stop while a `PAUSE` file exists in the scratch directory.
- Never send personal data (email, name or account IDs) in any network request, header or query. Use a generic
  User-Agent such as `harness-onion-review` when one is needed.
- Return a JSON verdict (`PASS_FOR_SOURCE_PUBLICATION` or `CHANGES_REQUIRED`) with findings (id, severity, location,
  finding, requiredChange), `questionAnswers`, `sourcesRead` and `actions`.
