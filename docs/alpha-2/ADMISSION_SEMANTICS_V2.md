# Alpha 2A — W02f POLICY-ADMISSION-SEMANTICS/v2 and A2 admission allowlists (MET-ENFORCE-013)

> Current-status page for the W02f part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and
> phase status; the v1 sentence stays in [POLICY_OBSERVATION_READINESS.md](POLICY_OBSERVATION_READINESS.md).

W02f: **ADOPTED_DATA_CONTRACT.** POLICY-ADMISSION-SEMANTICS/v2 and the A2 per-kind allowlists passed their independent
source-only review (round 2, PASS_FOR_SOURCE_PUBLICATION). Owner decision (2026-10-08): the A2 ValidatingAdmissionPolicy
objects live in a sealed static admission manifest directory and are run-independent; they are not written through I07.
It is DATA_CHECK_ONLY: nothing contacts an apiserver, compiles CEL or installs an admission configuration, and all
E01-E12 remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/admission-semantics-v2/README.md): the pinned v1 sentence (met by no boundary), the v2
  checks A1-A4, manifest constraints, allowed differences per kind, other creators in the namespace, the sealed directory
  and the dispositions of the round-1 findings.
- [Allowlists](../../architecture/admission-semantics-v2/allowlists.json): every field Kubernetes v1.37.1 can set on CREATE
  for Pod, immutable ConfigMap and ClusterIP Service, with source, value, citation, disposition and constraint coverage.
- [Sealed directory file](../../architecture/admission-semantics-v2/admission-manifests/planeon-a2.json): three per-kind
  A2 policies, a guard that denies API writes of admission objects, and their Deny bindings.
- [Vectors](../../architecture/admission-semantics-v2/vectors.json): 30 manifest-constraint, 17 end-to-end,
  24 final-object, 9 policy-object, 4 directory-hash and 18 semantics-claim cases.
- Reference model `scripts/admission_semantics_v2.py`.

Key rules:
- **A2 placement:** static policies (names ending `.static.k8s.io`), failurePolicy Fail, binding action Deny, no paramKind,
  matchConditions or objectSelector; the observer compares the loaded directory hash with the pinned one before ACTIVE.
- **A2 soundness:** every field an enabled in-tree mutator can set is an allowed fixed value, an allowed server-chosen value
  or ruled out by a manifest constraint (re-checked by A2 or guaranteed by the signer); a Pod's shape echo catches added
  containers, volumes and changed images.
- **Other creators:** only the root-CA publisher's `kube-root-ca.crt`, from its own identity and in its fixed shape.
- **Guard:** admission policies, bindings and webhook configurations cannot be written through the API, so I07 writes none.

## Independent review

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | CHANGES_REQUIRED (2 MAJOR, 2 MINOR, 3 NOTE) | `review-round1.json` | `round1/` |
| 2 | PASS_FOR_SOURCE_PUBLICATION (5 findings, none blocking or major) | `review-round2.json` | current files |

The reviewers were separate agents that did not author the contract. They worked read-only against the exact bytes,
replayed every vector, probed the model and checked the cited Kubernetes v1.37.1 sources at the pinned commit. The
[status record](../../architecture/admission-semantics-v2/status.json) derives the adoption state from the final verdict,
and `scripts/validate_admission_semantics_v2.py` replays the contract and checks that derivation.

## Carried findings (none blocking)

- **R2-F1** (MINOR) → W02f-F and W03 (T03): give pod-level resource defaulting, the matchLabelKeys/mismatchLabelKeys selector merges and the env fieldRef/fileKeyRef defaults a disposition (ALLOWED_FIXED and modelled in final_object, or a new MC code); deterministic deltas of the A1 bytes, not a cluster-state lever
- **R2-F2** (MINOR) → W02f-F and W03 (signer): encode the disabled-gate rule (fields of gates the W02g profile pins off) as an MC code or a separate A2 claim evidence key with a vector
- **R2-F3** (MINOR) → W02f-F: mark MC00 and MC02 SIGNER_GUARANTEED (A2 scoped by its match rules and C26), correct the MC03 reason, and reword the model docstring to match README A2 item 1
- **R2-F4** (MINOR) → W02f-F: add A1 claim evidence for the bound, unexpired execution, run certificate and the stamp equal to the armed action, or state that the existing keys imply them, with a refusal vector
- **R2-F5** (NOTE) → W02f-F: README code range MC00-MC38, vector range F01-F19, the ConfigMap rendered order, and 'admits, from exactly that identity and only under that name, an object of the publisher's shape' (or pin !has(object.immutable))

## Still open

All E01-E12 and T01-T08. The native A2 test against the selected distribution with compiled CEL, the distribution's sealed
values and `staticManifestsDir`, the observer's hash check and the manifest signer (W03, R12). W02c-F removes the
admission-object rows from I07's writable kinds. W03-W07 remain gated. Alpha2 remains open; model-effort transition
NOT_DUE.
