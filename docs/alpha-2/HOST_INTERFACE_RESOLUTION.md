# Alpha 2A — W01 gate resolutions (MET-ENFORCE-004)

> Current-status page for W01. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md)
> gives packet and phase status. The earlier [W01 candidate publication](HOST_INTERFACE_PUBLICATION.md)
> stays as the record of MET-ENFORCE-003.

W01: **DESIGN_RESOLVED_REVIEWED.** G04, G05, G06, G07 and G09 are resolved at design
level, and a separate agent independently reviewed the resolution with verdict
PASS_FOR_SOURCE_PUBLICATION. This adopts the resolved candidate as the design-level
host interface that W02 must formalize. It is not an installed ABI, native
enforcement, coding readiness for W03-W07 or tenant acceptance. All E01-E12 remain
OPEN_UNPROVEN.

## Subject and review

- [Resolved candidate HOST-INTERFACE-DRAFT-002](../../architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md),
  SHA256 `8a3a09bb5dbc08804dbea06dd0700a14648a9cdbc8efd62112dc64ba0b6ba1b4`;
  [review brief](../../architecture/host-interface-inputs/resolved/REVIEW_BRIEF.md),
  [scope](../../architecture/host-interface-inputs/resolved/scope.json) and
  [source index](../../architecture/host-interface-inputs/resolved/source-index.json).
- [Independent review, round 1](../../architecture/host-interface-inputs/resolution-review-round1.json),
  stored verbatim, SHA256 `619b7ac456097e1312fc0e42c2bf67911b7a1cc044119862724606b189b4861f`.
  The verdict is PASS_FOR_SOURCE_PUBLICATION and every gate is RESOLVED_DESIGN.
  The reviewer confirmed all 19 cited Linux v6.12 and Kubernetes facts against
  upstream source. It was read-only: no repository edits, tests, code execution,
  GitHub, native or runner actions.
- [Status record](../../architecture/host-interface-inputs/resolution-status.json): W01
  state, gate dispositions and carried findings. Each is derived from the final
  review and checked by `scripts/validate_host_interface_resolution.py`.

The base candidate (DRAFT-001), its CHANGES_REQUIRED/PASS verdict and the closed
MET-ENFORCE-003 plan are unchanged. The accepted contract documents are unchanged.
The G05 amendment is recorded as versioned design text for W02.

## Owner decisions (October 5, 2026)

| Gate | Decision | Resolution in the candidate |
|---|---|---|
| G04 | Dedicated sealed qualification control plane | I06 = `SEALED_SINGLE_NODE_CONTROL_PLANE_V1` (P1-P10): loopback apiserver with a labelled port, an AF_UNIX datastore, no `system:masters` or minting path, a sealed configuration and admission chain, an identity closure, I07 as the only policy writer through the gate, and a table of autonomous writers. Resource-bearing live qualification is UNAVAILABLE on tenant-managed clusters |
| G05 | Versioned amendment | `POLICY-ADMISSION-SEMANTICS/v2`: gate consume-then-forward (A1), in-apiserver ValidatingAdmissionPolicy before persistence (A2), drain fence for policy writers (A3), and urgent invalidation recorded as ADMITTED_BEFORE_INVALIDATION (A4). No end-to-end atomic claim |
| G06 | (design) | Record `native-qualification/v2`, profile `SELINUX_FSVERITY_CGROUP_BPF_V2`. Five resident roles including EFFECT_GATE, two lifecycle subjects and closed backend components. v1 and v2 reject each other. No new root key or signing role |
| G07 | Reboot-only host maintenance | v6.12 finding: the v1 inspection command set needs CAP_SYS_ADMIN, so v2 replaces it with BPF_OBJ_GET on sealed pins plus CAP_NET_ADMIN/CAP_BPF and helper-free programs. Also: MULTI attachment and labelled cgroups, the boot/seal sequence with `secure_mode_policyload`, a per-role privilege table, and the original-parent worker sequence through a frozen cgroup |
| G09 | Connection stamping | On unchanged I04, the gate flushes on arm, stamps each connection at accept with the armed action, and allows one consumption per stamp. Mutations are unique by construction. The application-level resend residual is bounded and becomes HELD on disagreement |

## Carried to W02 (review findings, none blocking)

- F1 (MINOR): enumerate the apiserver's in-process loopback `system:masters` client
  and the `rbac/bootstrap-roles` reconciler in the §2.3 identity closure as sealed,
  configuration-pinned TCB identities. Counterexample 4 is partially covered until then.
- F2 (MINOR): state that the cgroup control in §5.1 and counterexample 28 is the
  SELinux open/label denial plus denying CAP_DAC_READ_SEARCH to the confined admin
  domain. Search denial alone does not stop `open_by_handle_at` on cgroup2.
- F3 (NOTE): carry the exact v2 cgroup paths and the v1/v2 rejection vectors into W02.

## Still open

All E01-E12 and T01-T08. Completeness of writer mediation on a real host. The
v6.12 facts on the enrolled kernel and policy. Behaviour of flush/stamp under load
and restart. Admission field allowlists against real defaulting. Kubernetes
distribution selection. Wire schemas, per-architecture syscall allowlists and
exact cgroup paths. W02-W07 stay work labels until their own packets. CONF-FIX-010
stays BLOCKED_SAFE_DESIGN. No product attempt, installation or native proof is
created here. Alpha2 remains open; model-effort transition NOT_DUE.
