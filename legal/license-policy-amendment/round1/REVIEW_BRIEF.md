# Review brief — LIC-HOST-A1, round 1

Subject: `legal/license-policy-amendment/` (README.md, amendment.json, vectors.json) and `scripts/license_amendment.py`,
on main `195c4c9`.

Please check:
1. The amendment matches the owner decisions Q-L, Q-L2 and Q-L3. The decision texts are in `amendment.json`, and the W03-0
   selection's license reviews are on branch `codex/w03-0-backend-distribution`, `architecture/backend-distribution/`.
   Look for anything broader than the decisions, and for anything they cover that is missing.
2. The amendment never weakens the base policy (`legal/third-party-license-policy.yaml`): exact base entries keep their
   outcomes, and denied, unknown, placeholder and unapproved review terms still block.
3. The parser: SPDX precedence (WITH, then AND, then OR), parentheses, and malformed input refused.
4. The election rule, and whether the 24 vectors cover the cases that matter, including the W03-0 selection's
   expressions.
5. The explicit-review decision records against the base `optionalExplicitReviewRule.requiredDecisionFields`.
6. The overlay rationale: confirm that the base policy is pinned by the records the README names and by `validate_reuse`.

Read-only. Network reads of public sources are fine. Never put the user's email address or any personal data in a request
(User-Agent, URL, query string or body); use a generic User-Agent. No test suites. No sudo, no edits.
