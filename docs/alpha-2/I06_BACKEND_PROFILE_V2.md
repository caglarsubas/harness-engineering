# Alpha 2A — W02g-F I06 backend profile v2 (MET-ENFORCE-012)

> Current-status page for the W02g-F part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and
> phase status; the adopted v1 profile is described in its [README](../../architecture/i06-backend-profile/README.md).

W02g-F: **ADOPTED_DATA_CONTRACT.** The successor I06 backend profile v2 passed its independent source-only review
(round 3, PASS_FOR_SOURCE_PUBLICATION). It closes the W02g round-2 findings carried to W02g-F (N1-N3). The v1 profile,
its identity closure, writer inventory and upstream inputs, and the W02a v2 and v3 contracts are byte-identical. It is
DATA_CHECK_ONLY: no cluster, distribution, host or kernel is observed, no distribution is selected, and all E01-E12
remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/i06-backend-profile-v2/README.md): why a successor, what changes, replayed v1 cases,
  cross-version cases and the dispositions of every review finding.
- [Criteria](../../architecture/i06-backend-profile-v2/criteria.json): v1's criteria with SC00, SC08 and IC03 restated.
- [Vectors](../../architecture/i06-backend-profile-v2/vectors.json): 7 accepted evidence and
  5 accepted snapshot variants, 91 evidence negatives (all 71 v1 negatives replayed),
  38 snapshot negatives (all 35 v1 negatives replayed) and 6 cross-version cases.
- Reference model `scripts/i06_backend_profile_v2.py`, which reuses the unchanged v1 model and W02a v3's `check_record`.

Key rules:
- **W02a binding (N1):** an evidence record names one W02a v3 record by its qualification digest, and W02a v3's
  `check_record` must accept that record; the evidence's identity and test-only state equal the backend's, and a
  test-only backend qualifies only in an explicit fixture call. No production evidence is possible until a reviewed
  W02a revision adds a production backend profile and an I06 successor binds to it.
- **Loopback user (N2):** the apiserver's loopback user `system:apiserver` holds no resource rule of any kind.
- **Backend cgroups (N3):** shared and nested backend cgroups are refused through W02a v3's rules.
- **Code distinctness:** W02a v3 lets backend components share code, so I06 keeps its own rule that components run
  distinct executables with distinct content.

## Independent review

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | CHANGES_REQUIRED (1 MINOR, 7 NOTE) | `review-round1.json` | `round1/` |
| 2 | PASS_FOR_SOURCE_PUBLICATION (5 NOTE) | `review-round2.json` | `round2/` |
| 3 | PASS_FOR_SOURCE_PUBLICATION (3 NOTE) | `review-round3.json` | current files |

The reviewers were separate agents that did not author the contract. Each worked read-only against the exact bytes,
replayed every vector independently and probed beyond them (type sweeps over the evidence and the backend, digest
spellings, import modes). The author opened round 3 after the round-2 pass to fix the model's package import; no rule
changed. The [status record](../../architecture/i06-backend-profile-v2/status.json) derives the adoption state from the
final verdict, and `scripts/validate_i06_backend_profile_v2.py` replays the contract and checks that derivation.

## Carried findings (none blocking)

- **R3-1** → W02g-F2: give the README's two 'Round-2 findings and dispositions' sections distinct names (W02g N1-N6; W02g-F R2-1 to R2-5 and round-3 changes) and update the pointers in the README status paragraph and the brief
- **R3-2** → W02g-F2: add review-round2.json/round2/ (and the later rounds) to the README Files table and list the R2-4 carry under 'Still open'
- **R3-3** → W02g-F2 (optional): narrow the import fallback to ModuleNotFoundError for the two bare predecessor names
- **R2-4** → W02g-F2 or W03: backend content distinctness compares SHA-256 only; either also require distinct verityDigest values for backend executables (as W02a does for role executables) or state that SHA-256 distinctness relies on the observed backend captures in the W03 composition
- **R2-5** → Fulfilled by this record: the R1-4, R1-5 and R1-7 carries below are written next to the P7 chain and N4-N6
- **R1-4** → W03: production evidence needs a reviewed W02a revision with a production backend profile AND an I06 successor bound to that revision (v2 fixes W02A_VERSION and W02a pins its schema digest); this holds for every W02a successor, including W02a-F2
- **R1-5** → W03: evidence binds to one W02a record and is re-issued per record; callers compose check_evidence with check_qualification's acceptance of the same record and keep W02a v3 caller obligations 1 (pinned proxy profile contract) and 4 (test_fixture only for fixtures)
- **R1-7** → W03 observer: a non-resource-URL rule bound to User system:apiserver is never dropped; the observer refuses to produce the snapshot
- **N4** → W02e and W03, unchanged from the I06 v1 status: file-level sealing map and apiserver-to-kubelet serving-certificate verification
- **N5** → W03, unchanged from the I06 v1 status: kubernetesVersion is the gitVersion every component reports; unmodified v1.37.1 builds or a reviewed vendor patch set
- **N6** → W02f and W02e, unchanged from the I06 v1 status: PodSecurity at least baseline in every namespace, refusal of hostPath and local PersistentVolumes, container domains unable to read component credentials

## Still open

All E01-E12 and T01-T08. A production backend profile (W03, with a reviewed W02a revision and an I06 successor),
the observer, the file-level sealing map and the kubelet serving-certificate check (W02e, W03), PodSecurity defaults
(W02f). W03-W07 remain gated. Alpha2 remains open; model-effort transition NOT_DUE.
