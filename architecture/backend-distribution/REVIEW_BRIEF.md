# Review brief — W03-0, round 3

Subject: `architecture/backend-distribution/` (README.md, selection.json), `architecture/w03-plan/` (README.md, plan.json),
`scripts/backend_distribution.py` and `scripts/w03_plan.py`.

Round 2 (`review-round2.json`, bytes in `round2/`) returned CHANGES_REQUIRED. Since then, owner decisions Q-S (S-b: W02d v3
adds mremap with MREMAP_MAYMOVE, prctl with PR_SET_NAME and tkill to NATIVE_STATIC) and Q-L2 (L2-a: an OR-choice rule and
exact entries for the GCC runtime and the nft library closure). Please check:
1. Each round-2 finding's disposition (README, "Round-2 findings and dispositions").
2. The license reviews: one per expression, each with its election, each attached to the right part, sandbox image or host
   dependency, and consistent with Q-L and Q-L2. Is any part of the closure still outside them?
3. The plan: W02D-V2 and W02D-V3 as preconditions; TR-SETXID (musl v1.2.5 `src/unistd/setxid.c:32`,
   `src/thread/synccall.c:67, :82`); the corrected citations; the selection's open items registered.
4. Both check modules: re-run your round-2 probes.
5. Anything else that would mislead W04 (which receives `selection.json`) or the owner.

Read-only. Network reads of public sources are fine; avoid large downloads. No test suites (another lane may be running a
dry run or verify). No sudo, no edits.
