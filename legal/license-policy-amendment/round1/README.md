# License-policy amendment LIC-HOST-A1 (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**.

The owner decided three questions for the W03 backend distribution (`architecture/backend-distribution/`, W03-0). All
three were decided on 2026-10-10, via the lane monitor:
- Q-L (L-a): keep the official upstream binaries, pinned, under a reviewed class for host-OS and statically linked system
  libraries.
- Q-L2 (L2-a): an OR-choice rule, plus exact entries for the GCC runtime and nft's library closure.
- Q-L3 (L3-a): an AND-term rule, and legacy "A/B" crate strings read as "A OR B".

## Why an overlay

`legal/third-party-license-policy.yaml` is pinned by digest in 35 architecture records, and `scripts/validate_reuse.py`
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

**HOST_OS_SYSTEM_LIBRARY class.** It has four exact expressions:
- LGPL-2.1-or-later (glibc, libmnl);
- LGPL-2.1-only (libseccomp);
- GPL-3.0-or-later WITH GCC-exception-3.1 (the GCC runtime);
- GPL-2.0-or-later (libnftnl).

None of them appears anywhere in the base policy. The class covers host-OS programs and libraries, and system libraries
statically linked into a pinned upstream binary, under upstream-pinned custody only. It never covers planeon-authored
source, code copied into a planeon repository, or a component that owner decisions do not name. A release must carry the
corresponding source offer from the pinned source, the license text, the SBOM and the NOTICE.

**Explicit-review decision records.** The base policy lists GPL-2.0-only and LGPL-3.0-or-later for explicit review, with
required decision fields. The amendment records the owner's two decisions with every required field and a digest over
them:
- GPL-2.0-only, for nft and libnftables, which kube-proxy executes;
- LGPL-3.0-or-later, gmp's election.

**Rules.**
- OR-choice (Q-L2): an OR expression is accepted when one alternative is accepted on its own. The election is
  Apache-2.0, the core license, when that is accepted; otherwise it is the first accepted alternative. The election is
  recorded per component.
- AND-term (Q-L3): a compound is accepted when every AND term is accepted, so compiler_builtins resolves to MIT + Apache-2.0
  WITH LLVM-exception + an Apache-2.0 election.
- Legacy slash (Q-L3): a crate field "A/B" is read as "A OR B", for crate metadata only.
- Precedence: an expression listed exactly in the base policy keeps its base outcome. A denied, unknown, placeholder or
  unapproved review term still blocks an AND compound, and no rule weakens the base `deniedRule`.

`check` verifies these properties:
- the base policy's digest is unchanged;
- the class overlaps no base category;
- each decision answers a base explicit-review expression, and its digest matches;
- each rule names the owner decision behind it;
- every vector classifies as expected;
- the vectors cover every kind of outcome.

## Consumers

The W03 license gate (HE-001 for the Rust modules, HE-008 for the host image) classifies every SBOM entry with
`classify` and records the elections and normalisations. W02g-F2 replaces I06 SC13's single-license check with a reference
to this closure. The base policy's own consumers are unchanged.

## Not claimed

The base policy keeps its outcomes for every expression it lists. Nothing is released by this record, and it is not legal
advice: the owner's decisions are the approving authority.
