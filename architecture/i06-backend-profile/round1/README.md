# I06 backend profile — W02g (MET-ENFORCE-006), round 1

Status: **CONTRACT_CANDIDATE**, awaiting independent review. DATA_CHECK_ONLY: no
cluster was observed, nothing is installed and no distribution is selected. All
E01-E12 stay OPEN_UNPROVEN.

This part makes the I06 backend of `SEALED_SINGLE_NODE_CONTROL_PLANE_V1` (W01 spec
§2.1-§2.6, HOST-INTERFACE-DRAFT-002) concrete for the Kubernetes v1.37 baseline. It
gives:

- the selection criteria a distribution must meet (W03 selects);
- an inventory of every upstream controller and in-process apiserver writer, each
  with a disposition;
- the closed identity closure, including W01 review finding F1 (the apiserver's
  loopback identity in `system:masters`).

It also marks the W02a `unit-distribution` profile test-only (W02a finding P7).

## Files

| File | Content |
|---|---|
| `criteria.json` | SC00-SC15 (evidence record), CL (closure derivation), IC01-IC05 (RBAC snapshot), OR01-OR07 (observer and operational rules) |
| `writer-inventory.json` | 49 kube-controller-manager controllers and 21 apiserver writers with profile, disposition and source line |
| `identity-closure.json` | 24 identities with their exact allowed grants and derivation |
| `upstream-bootstrap-rbac-v1.37.1.json` | Effective bootstrap RBAC of all 56 bound subjects, derived from the upstream golden fixtures |
| `upstream-facts-v1.37.1.json` | Facts read from the v1.37.1 source with file and line citations; open points under `unverified` |
| `vectors.json` | One evidence and one snapshot positive, 8 accepted variants and 88 negatives, each negative pinned to its exact refusal |
| `scripts/i06_backend_profile.py` | Reference model: `check_inventory`, `check_closure`, `check_evidence`, `check_rbac_snapshot` |

## Baseline and sources

The baseline is Kubernetes tag v1.37.1 (commit `f78e722310e50bcaca9276be22276d9e91d91308`).
Facts come from static reading of that tree, with method and caveats in
`upstream-facts-v1.37.1.json` (`meta`, `unverified`). Bootstrap RBAC is computed from
the six default-feature-gate golden fixtures under
`plugin/pkg/auth/authorizer/rbac/bootstrappolicy/testdata/`, which upstream unit
tests assert against the code. Their SHA-256 digests are recorded. Each subject
receives the rules of every ClusterRoleBinding (scope `CLUSTER`) and RoleBinding
(scope = its namespace) that names it. Non-resource-URL rules are dropped.

## Policy-relevant grants

The model classifies each effective RBAC rule using upstream matching semantics:
`*` covers every resource and subresource, `*/x` covers any `<r>/x`, and verb `*`
covers special verbs. There are four categories:

- **POLICY_WRITE**: create, update, patch, delete or deletecollection on a policy
  kind. These are the §2.3 kinds plus `namespaces/finalize`,
  MutatingAdmissionPolicy and its binding, FlowSchema and
  PriorityLevelConfiguration.
- **STATUS_WRITE**: writes to the status of ResourceQuota, Namespace,
  ValidatingAdmissionPolicy, APIService, CustomResourceDefinition, FlowSchema or
  PriorityLevelConfiguration.
- **SPECIAL**: verbs that escalate or take over another identity:
  - `escalate` and `bind` on Roles and ClusterRoles.
  - Legacy `impersonate` on core users, groups and serviceaccounts. Constrained
    `impersonate:<mode>` on `authentication.k8s.io` users, groups, serviceaccounts
    and nodes, plus `uids` and `userextras/<key>`. ConstrainedImpersonation is
    beta and on by default since 1.36.
  - `create` on `serviceaccounts/token`.
  - `approve`, `sign` and `attest` on signers, and `attest` on
    `admissionReviewAPIGroups`.
  - get, create, update, patch or delete on `nodes/proxy`, and `proxy` on nodes.
    These reach the kubelet API, including exec over a websocket GET.
  - `create` on `pods/exec` and `pods/attach`.
- **WORKLOAD**: create, update or patch on pods, ephemeral containers,
  ReplicationControllers, Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs
  or CronJobs, at cluster scope or in `kube-system`. A new pod can run as any
  service account of its namespace. `kube-system` is the only namespace that holds
  closure service accounts.

## Decisions

1. **v1.37 baseline only (SC14, SC15).** The inventory and the exec/attach rule
   hold for v1.37.x with default feature gates. Pre-releases are refused. A new
   minor release needs a new inventory revision.
2. **Webhook admission off (SC05).** Spec P6 requires only that the webhook and
   mutating-policy objects are absent. The profile also disables
   ValidatingAdmissionWebhook, MutatingAdmissionWebhook, MutatingAdmissionPolicy,
   ImagePolicyWebhook, NamespaceAutoProvision and AlwaysAdmit, and the observer
   still checks that the objects are absent (OR07). Enabled plugins must come from
   a closed allowlist: the v1.37 default-on set minus the forbidden plugins,
   NodeRestriction, and four off-by-default plugins that only restrict requests.
   NodeRestriction, CertificateApproval and CertificateSigning are required.
3. **Signing key for the apiserver only (SC03).** P4 allowed the apiserver and
   controller-manager domains. The controller-manager needs the private key only
   for the legacy token controller, which this profile disables. Per-controller
   credentials use TokenRequest, which the apiserver signs. This narrows P4.
4. **Authentication closure (SC03).** P3 is extended: front-proxy request-header
   authentication is off and its CA key is absent, because a front-proxy client
   certificate can assert any user and group, `system:masters` included. External
   JWT and webhook authenticators are off. No cluster-admin credential exists on
   the host: none for `system:masters` and none for any subject bound to
   `cluster-admin`.
5. **Required-disabled controllers (SC06).** Ten controllers are disabled, each
   with its reason in the inventory:
   - the CSR signing, approving and cleaner controllers, which share one account;
   - the bootstrap signer and token cleaner;
   - the legacy service-account token controller and its cleaner;
   - ClusterRole aggregation, the only controller holding `escalate`;
   - the storage-version migrator, which has wildcard list and patch;
   - the ClusterTrustBundle publisher, which holds `attest`.

   Per-controller credentials are required. Upstream defaults to the shared
   controller-manager identity.
6. **Dispositions of the allowed policy-kind writers.**
   - `namespace-controller` and `serviceaccount-controller` are
     I07_TRIGGERED_ONLY.
   - `resourcequota-controller` and `validatingadmissionpolicy-status-controller`
     are STATUS_ONLY.
   - `garbage-collector-controller` is OWNERREF_RULE. Spec §2.5 says the garbage
     collector acts only on admitted objects, but it holds wildcard patch, update
     and delete. OR02 therefore adds that policy-kind objects carry no
     ownerReferences, and the observer checks it.

   Apiserver writers:
   - `rbac/bootstrap-roles` (F1) is STARTUP_BEFORE_INSPECTING. Its role set is
     compiled into the pinned apiserver binary (SC13). It runs once per start and
     only adds rules. OR01 makes any apiserver restart during ACTIVE invalidate
     the generation.
   - The system-namespace and authentication-info controllers are
     SYSTEM_NAMESPACES_ONLY.
   - API Priority and Fairness configuration is AVAILABILITY_ONLY (OR04).
   - Autoregistration is LOCAL_APISERVICES_ONLY.
   - The apiextensions controllers are ABSENT_BY_PROFILE, because CRDs are
     forbidden.
7. **Components (SC08).** Each component is a separate process with a distinct
   executable, so each has its own SELinux entry type. It runs in its W02a
   confined type; the model mirrors the W02a type names. This refuses
   single-binary distributions.
8. **Sealed configuration (SC12).** P5's list is sealed, including the component
   definitions and, when used, the admission manifest directory. The apiserver
   reloads that directory on change. Auto-apply directories must be empty and
   sealed.
9. **In-cluster clients (SC10).** Every in-cluster client is a closure identity
   with no policy-relevant grant, and no token is automounted (P8).
10. **Network-policy agent.** SC09 forbids CRDs, so W03 can pick only an agent that
    uses built-in APIs alone.
11. **`unit-distribution` is test-only (SC00, W02a P7).** It must carry
    `testOnly: true` and never qualifies a production backend.

## Identity closure

Closure entries have one of four derivations. CL checks each derivation.

- **F1_LOOPBACK**: full authority, allowed only for Group `system:masters` and
  User `system:apiserver`. `system:apiserver` is the apiserver's in-process
  loopback client: a per-process random bearer token, groups
  `system:authenticated` and `system:masters`. Every apiserver writer in the
  inventory runs as this identity. Both identities are sealed-TCB. P2 makes them
  unreachable from unlisted domains. The observer re-verifies effective RBAC in
  every observation. This closes F1's required change.
- **BOOTSTRAP_SUBJECT**: the grants must equal the grants derived from the
  subject's upstream bootstrap rules.
  - `system:kube-controller-manager` holds `serviceaccounts/token` create at
    cluster scope. It mints tokens for every service account, so it is
    TCB-equivalent to all of them.
  - The scheduler and kube-proxy hold no policy-relevant grant.
  - Thirteen controller accounts hold grants. Upstream finding: the wildcard
    verbs of `generic-garbage-collector` (get, patch, update, delete) and
    `namespace-controller` (get, delete) cover `nodes/proxy`. Both accounts can
    reach the kubelet API. They run inside the sealed controller-manager.
  - Accounts used only by required-disabled controllers are excluded.
- **PROFILE**: the planeon identities.
  - **Policy writer**: its kinds and scopes are fixed in the model. It may write
    Roles, RoleBindings, ResourceQuotas, LimitRanges, ServiceAccounts and
    NetworkPolicies in the qualification namespace. It may update and patch
    that namespace object. It may write ValidatingAdmissionPolicies and bindings
    at cluster scope. It may use `escalate` and `bind` only on the named Roles
    `planeon-gate-effect` and `planeon-policy-observer` (IC04).
  - **Effect gate**: no policy-relevant grant. Its pod creation in the
    qualification namespace is not policy-relevant, because that namespace holds
    no closure service account.
  - **Observer**: reads the policy kinds by name. A get on every resource would
    include `nodes/proxy`.
  - **Apiserver kubelet client**: holds the rules of the upstream
    `system:kubelet-api-admin` role.
  - **Network-policy agent account**.
  - W03 fixes the exact names of the last two.
- **NODE_AUTHORIZER**: `system:nodes` holds no RBAC grant. The Node authorizer
  limits node `serviceaccounts/token` create to accounts of pods bound to that
  node. CSR create is not graph-limited, but it is inert while signing and
  approval are disabled.

The writer is narrower than §2.3's list of kinds. It writes no ClusterRoles,
ClusterRoleBindings, webhook configurations, APIServices, CRDs or CSR approvals.
Those exist only from reboot maintenance or never. RBAC cannot restrict the
creation of a cluster-scoped ValidatingAdmissionPolicy by name. W02c's
WRITE_OBJECT and the W02f observer must refuse unexpected names.

**Dormant bindings (IC02).** Bootstrap binds every controller role, but the
controller-manager creates `kube-system/<name>` only for controllers it starts. A
binding of a controller account that does not exist is dormant. If the account
appears, IC01 or IC03 applies. Only service accounts can be absent.

**Snapshot rules (IC00-IC05).** The qualification namespace must be dedicated and
must not be a system namespace. Service-account usernames must use kind
`ServiceAccount`. A cluster-scope allowance covers the same grant in any namespace.
A namespaced grant on a cluster-scoped kind is treated as a grant, so it is
refused unless allowed.

## Spec mapping

| Spec | Encoded by |
|---|---|
| P1 | SC01; the datastore socket type is W02e |
| P2 | SC02; the apiserver port type and `name_connect` matrix are W02e |
| P3 | SC03, SC04 (Node then RBAC from the sealed structured file; the binary default is AlwaysAllow) |
| P4 | SC03, SC06, SC07; IC01 for `serviceaccounts/token` |
| P5 | SC12 |
| P6 | SC05, OR07 |
| P7 | SC09 |
| P8 | SC10, closure |
| P9 | SC11 |
| P10 | Unchanged runtime rule, not a selection criterion |
| §2.3 | CL, IC01-IC05, closure |
| §2.5 | Inventory dispositions, OR02, OR03 |
| F1 | Closure F1_LOOPBACK entries, inventory `rbac/bootstrap-roles`, OR01 |

## Still open

- All E01-E12 and T01-T08.
- The SELinux matrix and port and socket types, including F2 (W02e).
- The I07 wire schema (W02c).
- Admission field allowlists; OR06 recommends sealed file-based admission
  manifests for the A2 policies (W02f).
- The distribution choice and the exact names of the network-policy agent account
  and the apiserver kubelet-client subject (W03).
- OR01-OR07 are operational rules for the observer and runtime. The model does not
  check them.
