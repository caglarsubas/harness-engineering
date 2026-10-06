# Alpha 2A — W02g I06 backend profile (MET-ENFORCE-006)

> Current-status page for the W02g part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md)
> gives packet and phase status; W02a is recorded on the [W02a page](NATIVE_PROFILE_V2.md).

W02g: **ADOPTED_DATA_CONTRACT.** The I06 backend profile for
`SEALED_SINGLE_NODE_CONTROL_PLANE_V1` on Kubernetes v1.37.1 passed its second independent
source-only review with verdict PASS_FOR_SOURCE_PUBLICATION. It closes W01 review finding F1:
the apiserver's loopback identity in `system:masters` and the bootstrap-roles reconciler are
enumerated, and full authority belongs only to `system:masters`. The contract is DATA_CHECK_ONLY:
no cluster was observed, nothing is installed, no distribution is selected, and all E01-E12
remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/i06-backend-profile/README.md): grant categories, decisions
  1-11, the identity closure, the round-1 dispositions and the spec mapping.
- [Criteria](../../architecture/i06-backend-profile/criteria.json):
  - SC00-SC15: the distribution evidence record, bound to its W02a backend profile;
  - CL: closure derivation;
  - IC01-IC05: the effective-RBAC snapshot;
  - OR01-OR08: observer and operational rules.
- [Writer inventory](../../architecture/i06-backend-profile/writer-inventory.json): 49
  controller-manager controllers and 21 in-process apiserver writers, each with a disposition.
  Ten controllers are required-disabled.
- [Identity closure](../../architecture/i06-backend-profile/identity-closure.json): 24
  identities. Upstream entries equal the grants derived from the upstream golden RBAC fixtures.
  The five planeon identities are a closed set with fixed names and grants.
- [Vectors](../../architecture/i06-backend-profile/vectors.json): two positives, 11 accepted
  variants and 127 negatives, each pinned to its exact refusal.
- Reference model `scripts/i06_backend_profile.py`.

## Independent review

Two rounds, each by a separate agent that did not author the contract, read-only, with the
reviewed bytes kept unchanged:

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | CHANGES_REQUIRED (3 MAJOR, 5 MINOR, 4 NOTE) | `review-round1.json` | `round1/` (facts file unchanged, reviewed in place) |
| 2 | PASS_FOR_SOURCE_PUBLICATION (1 MINOR, 5 NOTE; F1-F11 closed, F12 partial) | `review-round2.json` | current files |

The round-2 reviewer fetched 20 upstream files at the tag. All were byte-identical to the
tree the contract was derived from. The reviewer re-derived the 56 bootstrap subjects,
replayed all 143 vector expectations and ran its own probes. The
[status record](../../architecture/i06-backend-profile/status.json) derives the adoption state
from the final verdict, and `scripts/validate_i06_backend_profile.py` checks that derivation.

## W02a finding P7

Status `I06_PART_CLOSED_REMAINDER_CARRIED`. I06 evidence binds to its W02a backend profile and
refuses the `unit-distribution` fixture identity as a production backend. W02a's own bytes are
frozen in this packet, so the rest is carried to W02a-F, and to W03 when it adds its profile:

- W02a's schema still accepts the fixture like a production profile.
- The type-name wording is still to be corrected (P7(b)).
- Nested backend cgroups are still accepted (P7(c)).
- The fixture's network-policy agent identity differs from the closure's user
  `planeon:netpol-agent`.

## Carried findings (none blocking)

- **N1** → W02g-F and W03. The evidence binding compares only implementationId, component keys,
  labels, executables and digests. It does not apply W02a's backend rules, so two accepted
  variants use backends that W02a's adopted schema refuses. The README's "names its W02a backend
  profile" overstates the reviewed binding.
- **N2** → W02g-F. IC03 refuses policy-relevant grants bound to `system:apiserver` but accepts
  non-policy rules. The README's "refuses any" overstates it.
- **N3** → W02a-F and W02g-F. The P7(b) and P7(c) carry chain. Optionally, refuse nested or
  shared backend cgroups under SC08.
- **N4** → W02e and W03. File-level sealing map: the client CA bundles, the kubelet
  `--config-dir` drop-ins and the egress selector file. Also verification of the apiserver's
  kubelet serving certificate.
- **N5** → W03. `kubernetesVersion` is every component's reported gitVersion, and components are
  unmodified v1.37.1 builds or a reviewed vendor patch set.
- **N6** → W02f and W02e. PodSecurity defaults of at least baseline, refusal of hostPath and local
  PersistentVolumes, and container domains unable to read component credentials.

## Still open

- All E01-E12 and T01-T08.
- The SELinux matrix and port and socket types, including W01 finding F2 (W02e).
- The I07 wire schema (W02c).
- Admission field allowlists (W02f).
- The distribution choice (W03).

W03-W07 remain gated. Alpha2 remains open; model-effort transition NOT_DUE.
