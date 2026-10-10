# License-policy amendment LIC-HOST-A1 (DATA_CHECK_ONLY)

Status: **ADOPTED_FOR_SOURCE_PUBLICATION** (review round 4 PASS on `c12fa44`; `status.json`). Before that: Rounds 1 to 3 (`review-round1.json` to `review-round3.json`, bytes in `round1/` to `round3/`) returned CHANGES_REQUIRED; each finding is answered below.

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
| `vectors.json` | 88 classification cases (schema v2): expression, component, expected outcome and elections, refusals included |
| `../../scripts/license_amendment.py` | an SPDX expression parser (OR, AND, WITH, parentheses), `classify`, `effective_policy`, `check` |

## The amendment

**Component-scoped classification.** `classify(policy, expression, component)` takes the component's name, kind,
custody and, for a static system library, the binary it is linked into. It also takes whether the expression is a legacy
crate field. It returns the outcome, the canonical expression, every
leaf's category and the structured elections.

**HOST_OS_SYSTEM_LIBRARY class.** It has four exact terms:
- LGPL-2.1-or-later (glibc, libmnl);
- LGPL-2.1-only (libseccomp);
- GPL-3.0-or-later WITH GCC-exception-3.1 (the GCC runtime);
- GPL-2.0-or-later (libnftnl).

None of them appears in any base category. A class term is accepted only for a component the owner decisions name,
under that component's decided term, in one of its decided kinds and in UPSTREAM_PINNED custody, including inside
compounds. A static library also has to be linked into one of its decided pinned official upstream binaries:

| Component | Decided term | Kinds | Binaries (static) | Decision |
|---|---|---|---|---|
| glibc | LGPL-2.1-or-later | host library, static library | containerd, pause, runc | Q-L |
| libseccomp | LGPL-2.1-only | static library | runc | Q-L |
| libgcc, libgcc_eh | GPL-3.0-or-later WITH GCC-exception-3.1 | static library | containerd, pause, runc | Q-L2 |
| libnftnl | GPL-2.0-or-later | host library | — | Q-L2 |
| libmnl | LGPL-2.1-or-later | host library | — | Q-L2 |

Elsewhere the term is OUT_OF_SCOPE, which ranks with UNKNOWN. That includes any other term for these components (for
example glibc under GPL-2.0-or-later), libseccomp in containerd or pause, and glibc or libgcc linked into a planeon binary,
none of which the owner decisions cover. glibc as a host library is read as part of Q-L2's nft library closure: nft and
its libraries load the host libc.

**Explicit-review decision records.** GPL-2.0-only and LGPL-3.0-or-later are base explicit-review expressions, so they are
decision records rather than class entries. A class term must not overlap a base category; W03-0's wording listed nft
under the class.
- GPL-2.0-only covers nft and libnftables (Q-L).
- LGPL-3.0-or-later covers gmp (Q-L2).

Each record carries every required base field, plus its subjects, its decided kinds and its deciding question, under
one digest. An approval applies only to its named subjects, in their decided kinds and upstream-pinned custody
(OPTIONAL_EXPLICIT_REVIEW_APPROVED, the base's name):
- nft and libnftables, as a host program and a host library;
- gmp, as a host library, dynamically linked.

For any other component, kind or custody the term stays OPTIONAL_EXPLICIT_REVIEW. The owner elections are bound in the
same way: libpathrs as a static library linked into runc, gmp as a host library. Elsewhere the ranking decides. Open content is accepted only for an ARTIFACT, as the base
limits it. NOASSERTION and NONE are whole-field values and are refused inside an expression.

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

**Release admission** is stated for each amendment outcome: the class, an approved review, an AND compound and an OR
expression. A compound's obligations are the union of its effective leaves: the AND terms and each OR group's elected
alternative, which is what `classify` returns. A compound listed exactly in the base returns no leaves and `baseEntry:
true`, so the base entry's own release outcome applies.

**Parser** (SPDX 2.3 Annex D):
- id strings of letters, digits, `.` and `-`, an optional trailing `+`, and `LicenseRef-` forms;
- operators AND, OR and WITH, in uppercase only;
- ASCII spaces only;
- at most 512 characters and 16 levels of nesting.
Anything else is refused with a ValueError.

`check` pins the decided content: the class, its kinds and custody, each class component's term, kinds and binaries, the
decisions with their subjects and questions, and the owner elections with their binaries. It verifies the decision digests and the base digest, and confirms there is no overlap with base
categories. All 88 vectors must classify as expected and cover every outcome, refusal included. `effective_policy` builds the
policy from the same base bytes whose digest `check` verified.

## Consumers

The W03 license gate (HE-001 for the Rust modules, HE-008 for the host image) classifies every SBOM entry with
`classify` and records the elections and normalisations. W02g-F2 replaces I06 SC13's single-license check with a reference
to this closure. The base policy's own consumers are unchanged.

Two limits for those consumers:
- Components are identified by their upstream names. SBOM generators report distribution package names or purls (for
  example libc6, libseccomp2, libgmp10), so the host-image packet needs a reviewed mapping or purl identity. Until it
  exists, a mismatch fails closed (OUT_OF_SCOPE or OPTIONAL_EXPLICIT_REVIEW).
- The native modules are fully static musl builds (Q3), so no glibc or GCC runtime is linked into planeon binaries. A
  `*-linux-gnu` build would come out OUT_OF_SCOPE and need a further owner decision. HE-001's license gate enumerates the
  musl target's self-contained objects.

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

## Round-2 findings and dispositions

| Finding | Disposition |
|---|---|
| L11 MAJOR, approvals by bare name | each approval and owner election is bound to its subjects, decided kinds and upstream-pinned custody; the kinds are inside the decision digest; vectors for nft as a crate or planeon source, libnftables static, gmp as a crate, static or repository-built, and gmp's OR group for a crate |
| L12 MAJOR, class scope | option (i): the class reaches only the named components in their decided kinds; a static library needs `linkedInto` one of the pinned official upstream binaries; vectors for glibc and libgcc_eh in planeon binaries and for unnamed host libraries |
| L13 MINOR, placeholder in compounds | NOASSERTION and NONE are refused inside an expression (SPDX 2.3) |
| L14 MINOR, leaves | only the effective leaves are returned; release admission is defined over them; base entries return `baseEntry: true` |
| L15 MINOR, double read | `effective_policy` builds the policy from the verified base bytes |
| L16 MINOR, files row | 80 v2 cases |
| L17 NOTE | (5) legacy fields with spaces are read too; (2) an invalid vector component is refused before classification; (1) the amendment record will be pinned by digest in the packet's authority; (3), (4), (6) and (7) noted |

## Round-3 findings and dispositions

| Finding | Disposition |
|---|---|
| L18 MAJOR, class terms not bound | each class component is bound to its decided term, kinds and, for a static library, its decided binaries (the table above); `check` pins them; the libpathrs election is bound to runc, and elsewhere the ranking decides; OUT_OF_SCOPE vectors for glibc under GPL-2.0-or-later, glibc under the GCC runtime term, glibc host with "GPL-2.0-or-later OR LGPL-2.1-only", libnftnl under LGPL-2.1-or-later, libseccomp in containerd, in pause and as a host library; a vector for libpathrs in containerd |
| L19 NOTE | (6) HOST_OS_PROGRAM removed from the class kinds; (5) the glibc host-library reading is stated; (3) and (4) are stated as limits for consumers; (1), (2), (7) and (8) noted, and (7) stays with the packet authority's digest pin |

## Not claimed

The base policy keeps its outcomes for every expression it lists. Nothing is released by this record, and it is not legal
advice: the owner's decisions are the approving authority.
