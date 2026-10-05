# Independent review brief — W01 gate resolutions (HOST-INTERFACE-DRAFT-002)

Status: **RESOLVED_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. The design agent
wrote this file. It is not a verdict. The base candidate's review
(`../independent-review.json`) covers DRAFT-001 only. It does not extend to the
resolutions here.

## What to review

The exact bytes listed in `source-index.json` (`subject` entries), against the
listed predecessor inputs. For each of G04, G05, G06, G07 and G09, decide whether
the candidate meets the RESOLVED_DESIGN definition in HOST_INTERFACE_SPEC.md §0:
a concrete mechanism is selected, and every property only an installed host can
show is named as residual native or source evidence. Also check that nothing
claims native enforcement, an adopted wire ABI, an installed gate, a selected
Kubernetes distribution or an E01-E12 proof.

| Gate | Candidate disposition | What would make it fail |
|---|---|---|
| G04 | RESOLVED_DESIGN: sealed single-node control plane (P1-P10), API-path closure, identity closure, I07 sole writer, autonomous-writer table, writer-family mapping | An unlisted path that changes a policy fact; a listed identity with policy-kind write; a mechanism that relies on cooperation; tenant clusters silently required to surrender control-plane ownership |
| G05 | RESOLVED_DESIGN: versioned amendment A1-A4 | A1-A3 claimed as an atomic end-to-end transaction; A2 unable to see the post-defaulting object; A4 hidden instead of recorded; accepted bytes edited |
| G06 | RESOLVED_DESIGN: record v2, closed resident roles + lifecycle subjects + backend components, v1/v2 mutual rejection | Gate accepted under an old role; mode-dependent parser branch; new root key or signing role; reinterpretation of v1 data |
| G07 | RESOLVED_DESIGN: §5.1 kernel findings, boot/seal S1-S6, per-role table, worker W1-W6, reboot-only M1-M5 | A blanket CAP_SYS_ADMIN; a step that depends on a process staying cooperative after it exits; a stated v6.12 fact that the source does not support; a syscall row that cannot generate a closed allowlist |
| G09 | RESOLVED_DESIGN: connection stamping C1-C7 on unchanged I04 | A buffered/queued duplicate path that still reaches A1 for a later armed action; reliance on a caller-supplied identifier; a hidden new header or field |

## Questions the reviewer should answer explicitly

1. Does C2 (flush on arm) plus C3 (stamp at accept) actually exclude counterexample
   17 for every place a duplicate can be buffered? Consider: the kernel accept
   queue, TLS records inside an accepted connection, gate parser queues, and a
   connection whose TLS handshake finishes after ARM.
2. Is §6.3's residual (an application-level resend identical to B while B is
   armed) correctly bounded, i.e. no unarmed effect and at most one B effect?
3. Do the §5.1 v6.12 kernel claims match the source? This covers GET_FD_BY_ID
   needing CAP_SYS_ADMIN, query needing CAP_NET_ADMIN, info redaction, legacy-mode
   detach without a program fd, O_PATH cgroup fds, and `selinux_bpf` checking only
   MAP_CREATE and PROG_LOAD. Fetch the source yourself; do not rely on the author.
4. Is A2 (in-apiserver ValidatingAdmissionPolicy after mutating admission) a sound
   pre-persist position for "actual post-mutation manifest", and is A4 honestly
   weaker rather than presented as equivalent?
5. Does the §2.3 closure include every identity able to reach the apiserver, given
   P2, P8 and P9? Is the §2.5 autonomous-writer table plausible as a starting
   inventory, with distribution-specific additions deferred to W02?
6. Is the cgroup "single slice" refinement of MET-ENFORCE-001 decision 2 acceptable,
   or does it need to be a single delegated service?
7. Are the residual native items in §8 complete, i.e. is any RESOLVED_DESIGN claim
   actually resting on an unlisted native assumption?

## Counterexamples

Counterexamples 1-17 in the base brief
(`../corrected/REVIEW_BRIEF.md`) still apply. Each needs a disposition under v2.
Counterexamples 18-28 are in HOST_INTERFACE_SPEC.md §9.

## Result requirements

Return PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED with numbered
findings, and a per-gate disposition (RESOLVED_DESIGN or OPEN, with reason). A
PASS can still mark any gate OPEN. A PASS is not W01 native completion, coding
readiness, an adopted wire ABI or authorization for anything installed.

The reviewer must be a separate agent from the author. The review is read-only:
no edits to repository files, no tests, no repository code execution, no runner
activation, no warm-source access, no native or cloud actions and no GitHub
mutation. Reading public upstream source or documentation is allowed. Record
which ones were read.
