# License-policy amendment LIC-HOST-A1 (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. Round 1 (`review-round1.json`, bytes in `round1/`) returned CHANGES_REQUIRED (L1-L4 MAJOR, L5-L9 MINOR, L10 NOTE); each finding is answered below.

The owner decided three questions for the W03 backend distribution (`architecture/backend-distribution/`, W03-0). All
three were decided on 2026-10-10, via the lane monitor:
- Q-L (L-a): keep the official upstream binaries, pinned, under a reviewed class for host-OS and statically linked system
  libraries.
- Q-L2 (L2-a): an OR-choice rule, plus exact entries for the GCC runtime and nft's library closure.
- Q-L3 (L3-a): an AND-term rule, and legacy "A/B" crate strings read as "A OR B".

## Why an overlay

`legal/third-party-license-policy.yaml` is pinned by digest in 32 architecture files (`git grep -l <sha256> -- architecture/`), and `scripts/validate_reuse.py`
pins its identity (`policyVersion` 0.3.0). An in-place edit would break the validators that read it as an immutable input,
as CATALOG-BANK's first design found for the catalogs. So the base policy stays byte-identical. This directory holds the
reviewed amendment, and `scripts/license_amendment.py` gives the effective classification.

## Files

| File | Content |
|---|---|
| `amendment.json` | `planeon.internal.license-policy-amendment/v1`: the base pin, the three owner decisions, the host-OS class, the three rules and their precedence, and two explicit-review decision records |
| `vectors.json` | 24 classification cases with expected outcomes and elections |
| `../../scripts/license_amendment.py` | an SPDX expression parser (OR, AND, WITH, parentheses), `classify`, `effective_policy`, `check` |

## The amendment

**Component-scoped classification.** `classify(policy, expression, component)` takes the component's name, kind and
custody, and whether the expression is a legacy crate field. It returns the outcome, the canonical expression, every
leaf's category and the structured elections.

**HOST_OS_SYSTEM_LIBRARY class.** It has four exact terms:
- LGPL-2.1-or-later (glibc, libmnl);
- LGPL-2.1-only (libseccomp);
- GPL-3.0-or-later WITH GCC-exception-3.1 (the GCC runtime);
- GPL-2.0-or-later (libnftnl).

None of them appears in any base category. A class term is accepted only for a component of kind HOST_OS_PROGRAM,
HOST_OS_LIBRARY or STATIC_SYSTEM_LIBRARY in UPSTREAM_PINNED custody, including inside compounds. Elsewhere it is
OUT_OF_SCOPE, which ranks with UNKNOWN.

**Explicit-review decision records.** GPL-2.0-only and LGPL-3.0-or-later are base explicit-review expressions, so they are
decision records rather than class entries. A class term must not overlap a base category; W03-0's wording listed nft
under the class.
- GPL-2.0-only covers nft and libnftables (Q-L).
- LGPL-3.0-or-later covers gmp (Q-L2).

Each record carries every required base field, plus its subjects and deciding question, under one digest. An approval
applies only to its named subjects (OPTIONAL_EXPLICIT_REVIEW_APPROVED, the base's name). For any other component the term
stays OPTIONAL_EXPLICIT_REVIEW. Open content is accepted only for an ARTIFACT, as the base limits it.

**Rules.**
- Canonical form: nested operators are flattened, operands are sorted and spaces are single. A compound listed exactly in
  the base keeps its base outcome however it is spelled.
- OR-choice (Q-L2): an OR expression is accepted when one alternative is accepted for the component. The election ranks
  the alternatives: Apache-2.0, then default-allowed, then an allowed exception, then open content, then the class, then
  an approved review, with ties broken by canonical text. The owner-named elections are pinned for their components
  whatever the term order: libpathrs electing MPL-2.0 (Q-L) and gmp electing LGPL-3.0-or-later (Q-L2).
- AND-term (Q-L3): a compound is accepted when every term is accepted for the component, and its obligations are the union
  of the leaves'.
- Legacy slash (Q-L3): a crate field "A/B" is read as "A OR B".
- Precedence: an AND with a blocking term takes the most restrictive blocking outcome under the base
  `evaluation.precedence`. An OR with no accepted alternative takes its least restrictive alternative's outcome. Neither
  depends on term order, and no rule weakens the base `deniedRule`.

**Release admission** is stated for each amendment outcome: the class, an approved review, an AND compound (the union of
the leaves' obligations) and an OR expression (the elected alternatives' obligations, with the elections recorded).

**Parser** (SPDX 2.3 Annex D):
- id strings of letters, digits, `.` and `-`, an optional trailing `+`, and `LicenseRef-` forms;
- operators AND, OR and WITH, in uppercase only;
- ASCII spaces only;
- at most 512 characters and 16 levels of nesting.
Anything else is refused with a ValueError.

`check` pins the decided content: the class, its kinds and custody, the decisions with their subjects and questions, and
the owner elections. It verifies the decision digests and the base digest, and confirms there is no overlap with base
categories. All 63 vectors must classify as expected and cover every outcome, refusal included.

## Consumers

The W03 license gate (HE-001 for the Rust modules, HE-008 for the host image) classifies every SBOM entry with
`classify` and records the elections and normalisations. W02g-F2 replaces I06 SC13's single-license check with a reference
to this closure. The base policy's own consumers are unchanged.

## Round-1 findings and dispositions

| Finding | Disposition |
|---|---|
| L1 MAJOR, scopes not enforced | `classify` takes the component; class, approval and open-content terms are scoped, inside compounds too; leaves and their categories are returned; subjects and question inside the decision digest |
| L2 MAJOR, exact entries bypassed | canonical form before the exact lookup; reordered, parenthesised, nested and flattened variants keep the base outcome (vectors) |
| L3 MAJOR, order-dependent blocking | AND takes the most restrictive blocking outcome under base precedence; OR with no accepted alternative takes the least restrictive; both orders in the vectors |
| L4 MAJOR, election ranking | ranked election; the owner-named elections are pinned per component, independent of order; structured elections (canonical group, elected alternative) |
| L5 MINOR, decided content not pinned | the class, kinds, custody, decisions (expression, subjects, question) and owner elections are pinned by the check |
| L6 MINOR, parser | SPDX Annex D id strings, uppercase operators only, ASCII spaces, length and depth bounds, refusal vectors |
| L7 MINOR, vectors | 63 vectors covering every outcome including refusal, default-allowed, open content, placeholders and approvals; unique; a legacy crate field |
| L8 MINOR, outcome names and admission | OPTIONAL_EXPLICIT_REVIEW_APPROVED (the base's name); release admission stated per amendment outcome |
| L9 MINOR, pin count | 32 architecture files, with the command |
| L10 NOTE | GPL-2.0-only's decision record explained; libnftables stays in the host-image packet's shipped-package check |

## Not claimed

The base policy keeps its outcomes for every expression it lists. Nothing is released by this record, and it is not legal
advice: the owner's decisions are the approving authority.
