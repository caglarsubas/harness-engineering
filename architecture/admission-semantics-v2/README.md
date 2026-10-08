# POLICY-ADMISSION-SEMANTICS/v2 and A2 admission field allowlists — W02f contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-08. Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. Round 1 (`review-round1.json`,
reviewed bytes in `round1/`) returned CHANGES_REQUIRED with 2 MAJOR, 2 MINOR and 3 NOTE findings; each is answered in
"Round-1 findings and dispositions" at the end.

W02f carries the G05 amendment of the reviewed W01 resolution (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md`
§3) into its owning contract, and fixes the A2 per-kind allowlists that §3.2 left to W02. The accepted
`docs/alpha-2/POLICY_OBSERVATION_READINESS.md` is not changed: its v1 sentence is quoted and pinned below, and this
directory is where POLICY-ADMISSION-SEMANTICS/v2 is stated. Nothing here contacts an apiserver, compiles CEL, installs
an admission configuration or grants anything; all E01-E12 stay OPEN_UNPROVEN.

Accepted base: main `487eca6809eca9fd5b2647f79522d107dee8d814` (MET-ENFORCE-011, 210 packets).

## Owner decision (2026-10-08)

The A2 ValidatingAdmissionPolicy objects live in a **sealed admission manifest directory** (static policies, upstream
`ManifestBasedAdmissionControlConfig`, recommended by W02g OR08), and they are **run-independent**. This amends the W01
§3.2 wording "Its policy objects are policy kinds (written only through I07)": A2 is not written through I07 at all. It
changes only in the maintenance boot (W01 §5.5 M1), with the rest of the sealed control-plane configuration (W02g SC12
lists the admission manifest directory). The alternatives were API objects written through I07 (run-independent or per
run). They were not chosen because API-registered policies take effect through a cache refreshed about every second with
no activation barrier, and they cannot guard the admission objects themselves.

## Files

| File | Content |
|---|---|
| `README.md` | This text, including POLICY-ADMISSION-SEMANTICS/v2 |
| `allowlists.json` | Per kind (Pod, immutable ConfigMap, ClusterIP Service): every field the create path or an enabled mutator can set, with source, value, presence at the policy and citation (Kubernetes v1.37.1, commit `f78e722310e50bcaca9276be22276d9e91d91308`, 95 cited files with digests); its disposition (allowed fixed value, allowed server-chosen value, or ruled out by a manifest constraint); the A2 validations that check it; the create-path order; the unverified points |
| `admission-manifests/planeon-a2.json` | The one file of the sealed directory: a v1 List of four static ValidatingAdmissionPolicy objects and their four bindings, canonical JSON, rendered for the vector's sealed values |
| `vectors.json` | 30 manifest-constraint cases, 17 end-to-end cases (manifest and cluster facts to the final object to A2), 24 final-object cases (19 mutations, 5 root-CA publisher cases), 9 policy-object refusals, 4 directory-hash cases, 18 semantics claims |
| `../../scripts/admission_semantics_v2.py` | Reference model: `check_manifest`, `final_object`, `check_final`, `a2_objects`, `check_a2_objects`, `manifest_file_bytes`, `manifest_directory_hash`, `check_claim` |

## POLICY-ADMISSION-SEMANTICS/v1 (pinned, not met)

`docs/alpha-2/POLICY_OBSERVATION_READINESS.md` (SHA-256
`65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c`), lines 139-141:

> Before committing a mutation, its immutable admission guard rechecks current namespace/UID, effective RBAC, quotas,
> network policy and actual post-mutation manifest under the broker's serialized admission transaction.

No boundary of this design meets that sentence literally: a gate outside the apiserver cannot make an upstream storage
commit atomic with unrelated policy changes (W01 §3.1). A consumer claim citing v1 is refused (`check_claim` C01).

## POLICY-ADMISSION-SEMANTICS/v2

"Before committing a mutation" becomes three named checks at named positions (A1-A3), plus A4, which is kept separate
because it is explicitly weaker.

- **A1 Gate admission (pre-forward linearization point).** Under the gate's generation lock the gate verifies the current
  generation ACTIVE, scope, deadline, observed policy generation and the stamped armed action (W01 §3.2). In I05 v2 terms
  (Decisions 4-6): ACTIVE with no pending drain is the observed policy generation (I07 is the only policy writer and any
  write first drains), the bound and unexpired execution and its run certificate are scope and deadline, and the stamp
  equals the armed action whose exact rendered request bytes arrive. It records the consumption (fsync and read
  back) and only then sends the first byte upstream. Nothing earlier is the admission event: not socket accept, TLS, the
  ARM_ACTION acknowledgement or a worker report.
- **A2 In-chain persist check (pre-persist).** Inside the sealed apiserver, after mutating admission and before
  persistence, the static ValidatingAdmissionPolicy for the object's kind runs. Its failurePolicy is Fail and its binding
  action is Deny. It sees the decoded final object, never the request bytes, and its CEL has no hash, so it does not
  compare bytes. It enforces "final object = the manifest A1 admitted + allowlisted server deltas" this way:
  1. Every field an enabled in-tree mutator can set on CREATE is one of these:
     - an allowed difference whose fixed value A2 checks where it is checkable;
     - an allowed server-chosen value (uid, creationTimestamp, managedFields, the Service allocation inside the sealed
       service CIDR);
     - ruled out by a manifest constraint. A2 re-checks some constraints on the final object; the others hold only
       because the signer enforced `check_manifest` and A1 admitted exactly the signed bytes.
       `allowlists.json` `constraintCoverage` says which is which (RECHECKED_BY_A2 or SIGNER_GUARANTEED). A2's guarantee
       therefore depends on the signer (W03, R12), and an A2 claim needs that evidence (`check_claim` C25).
  2. The set of mutators is closed: W02g allows only the in-tree admission plugins, and the observer checks that no
     webhook or mutating-policy object exists (W02g SC05, OR06).
  3. A Pod also carries a shape echo: its container names and images, init containers and volume names, as annotations.
     A1 proves the echo is the signed one, and A2 compares it with the final object. An added container, init container
     or volume, or a changed image, fails A2 even though no allowed mutator makes such a change.

  The built-in quota and LimitRanger admission re-evaluate usage in the same chain. A2 replaces "actual post-mutation
  manifest" in the v1 sentence. The bound is this design's mutator set: a mutator that rewrote a field and its echo
  together would have to be one W02g's allowlist and OR06 exclude.
- **A3 Drain fence for policy writers.** No I07 WRITE_OBJECT, and no other writer of W01 §2, commits while any action
  admitted under the current generation lacks a durable terminal classification. The I05 v2 drain answer OPEN is that
  fence. PENDING means wait and HELD means no write. OPEN is a point-in-time answer, and the writer keeps evaluating the
  fence after it. An IO_AMBIGUOUS action holds the generation HELD.
- **A4 Urgent invalidation (explicitly weaker, recorded).** Revocation, peer death, storage failure or observation loss
  closes A1 immediately and does not wait for A3. An action already admitted may still be persisted after the
  invalidating change. It is recorded ADMITTED_BEFORE_INVALIDATION with its terminal or ambiguous outcome, never
  relabelled unadmitted, never retried, and its resources stay owned for exact-UID cleanup.

Resulting guarantee for normal operation: if a mutation reached DELIVERED_RESULT, no mediated policy write committed
between its A1 event and its upstream response. The final object it persisted differs from the signed manifest only by
the allowlisted deltas. What v2 does not claim: a distributed transaction, persistence before a lost response (that is
IO_AMBIGUOUS), ordering for controller side effects outside W01 §2.5, or byte equality at A2.

`check_claim` encodes which consumer claims v2 supports (vectors Q01-Q16):
- A1 only at the effect gate, with the durable consumption first;
- A2 only at the apiserver, with the loaded static-manifest hash equal to the sealed directory's, no webhook or
  mutating-policy objects, only allowlisted plugins, A1, the signer's constraint check, and the sealed qualification
  namespace;
- A3 only with the drain answer OPEN;
- A4 never as strict ordering.

## Manifest constraints (signed qualification manifests)

`check_manifest`. Each constraint removes a mutation, or a server-chosen value, that A2 could not tell apart from the
signed content (codes MC00-MC37):

| Kind | Constraint | Rules out |
|---|---|---|
| all | explicit DNS-label `metadata.name` and the qualification namespace; no generateName, uid, resourceVersion, generation, timestamps, managedFields, ownerReferences, finalizers, selfLink; no label or annotation key under `kubernetes.io/` or `k8s.io/` (or a subdomain); no status | name generation, namespace defaulting, metadata wipes, plugin labels and annotations |
| ConfigMap | `immutable: true` | — (no mutator touches a ConfigMap on CREATE) |
| Service | explicit `type: ClusterIP`; no clusterIP(s), ipFamilies, ipFamilyPolicy, external, node-port or load-balancer field, sessionAffinityConfig or trafficDistribution; sessionAffinity and internalTrafficPolicy omitted or the defaults | external exposure and pinned addresses; the allocation is server-chosen and checked by A2 |
| Pod | `automountServiceAccountToken: false` | the ServiceAccount token volume and mounts |
| Pod | no nodeName, nodeSelector, runtimeClassName, overhead, priority, priorityClassName, preemptionPolicy, tolerations, imagePullSecrets, ephemeralContainers, schedulingGates, resourceClaims, host namespaces or deprecated serviceAccount | PodTopologyLabels, RuntimeClass, Priority's class lookup, DefaultTolerationSeconds against manifest tolerations, ServiceAccount pull-secret copy |
| Pod | every image pinned by digest with `imagePullPolicy: Always`; every container states equal requests and limits | AlwaysPullImages, pull-policy defaulting, LimitRanger defaults, requests copied from limits |
| Pod | no mount at the token path and no `kube-api-access-*` volume | a look-alike token volume |
| Pod | no image volume (MC38) | AlwaysPullImages rewriting an image volume's pull policy (alwayspullimages/admission.go:76-81) |
| ConfigMap | not named `kube-root-ca.crt` (MC11) | a gate-created object with the publisher's reserved name |
| Pod | the shape echo annotations `planeon.ai/a2-containers`, `planeon.ai/a2-init-containers`, `planeon.ai/a2-volumes` equal the spec (`name=image` and volume names, comma-joined, in order; empty when none) | — (input to A2) |

The constraints are checked when manifests are signed and enrolled (W03, R12). The fields of disabled feature gates are
dropped silently by the apiserver before A2, so they are a signer obligation, not an A2 check: the signer refuses fields
of feature gates the W02g profile pins off (`constraintCoverage` DISABLED_GATE_FIELDS).

## Other creators in the qualification namespace

A per-kind A2 policy matches every CREATE of its kind in the namespace, whoever creates it. W01 §2.5 lists one non-gate
creator of a matched kind there: kube-controller-manager's root-CA publisher, which keeps one ConfigMap,
`kube-root-ca.crt`, in every namespace (pkg/controller/certificates/rootcacertpublisher/publisher.go). Its object carries
the reserved annotation `kubernetes.io/description` and is not immutable. W02g SC06 requires per-controller credentials,
so its creator is `system:serviceaccount:kube-system:root-ca-cert-publisher`. The ConfigMap policy's first validation,
A2-CM-PUBLISHER, admits exactly that object from exactly that creator:
- the name `kube-root-ca.crt`;
- only the data key `ca.crt`;
- no binaryData and no labels;
- at most the description annotation.

Any other creator using the name is refused, and the publisher identity gets no exemption for any other name (P01-P05).
The other ConfigMap validations skip only that name. No other non-gate creator of a Pod, ConfigMap or Service in the
qualification namespace is admitted.

## Allowed differences per kind

`allowlists.json` lists every upstream field with its disposition. In short:
- **Pod.** Fixed: generation 1; scheme defaults (dnsPolicy, restartPolicy, securityContext `{}`, terminationGracePeriodSeconds 30,
  schedulerName, enableServiceLinks, terminationMessagePath/Policy, port protocol, probe and volume defaults); quantities
  re-emitted in canonical form; serviceAccountName `default` when omitted and its alias; the two default NoExecute
  tolerations with the sealed seconds; priority 0 and PreemptLowerPriority; status phase Pending and qosClass. Server-chosen:
  uid, creationTimestamp, managedFields.
- **ConfigMap.** Server-chosen uid, creationTimestamp, managedFields; `data: {}` when nil (invisible to the policy).
- **Service.** Fixed: sessionAffinity None, internalTrafficPolicy Cluster, port protocol TCP, targetPort = port,
  ipFamilyPolicy SingleStack, ipFamilies = the sealed family, `status.loadBalancer {}`. Server-chosen: uid,
  creationTimestamp, managedFields, one clusterIP equal to clusterIPs[0] inside the sealed service CIDR.

resourceVersion is set by storage after the policy and is not part of A2.

## The sealed directory (`admission-manifests/planeon-a2.json`)

`a2_objects` renders the objects from four sealed values: the qualification namespace, the service IP family and CIDR,
and the default toleration seconds. Those values come from the distribution's sealed configuration (W03); the vectors
use `planeon-qual`, IPv4, `10.96.0.0/12` and 300.

- One policy per kind: `planeon-a2-pod.static.k8s.io`, `planeon-a2-configmap.static.k8s.io` and
  `planeon-a2-service.static.k8s.io`. Each matches CREATE of its v1 resource in the qualification namespace
  (namespaceSelector on `kubernetes.io/metadata.name`) with matchPolicy Exact. It has no objectSelector (requester-
  controlled), no matchConditions (a false one skips the policy) and no paramKind, and failurePolicy is Fail. Each
  validation's message is its A2 code.
- `planeon-a2-admission-objects.static.k8s.io` denies every API CREATE, UPDATE and DELETE of validating and mutating
  admission policies, their bindings and both webhook configurations. Static policies run for all six; API-registered
  policies never run for the four admission-policy resources (generic/plugin.go:58-65). The status subresource is not
  matched, so the validatingadmissionpolicy status controller is unaffected. So admission objects can no longer be written through the API, I07 included. This
  closes the W02g note that RBAC cannot restrict ValidatingAdmissionPolicy names. W02c-F removes the
  ValidatingAdmissionPolicy and binding rows from I07's writable kinds, and W02c R2 (a name allowlist for I07 policy
  writes) becomes "no name is writable".
- One binding per policy, named `<policy>-binding.static.k8s.io`, with `validationActions: [Deny]` and no paramRef or
  matchResources.

`check_a2_objects` refuses any other structure (S01-S06), including any change to a rendered validation.
`manifest_directory_hash` reproduces the loader's directory hash (in file-name order, each non-empty `.yaml`, `.yml` or
`.json` file followed by a NUL byte). The apiserver exports that hash as
`apiserver_manifest_admission_config_controller_last_config_info` (ALPHA). The observer compares it with the pinned
hash before a generation becomes ACTIVE (claim Q06 versus Q07). The directory is reloaded on a filesystem event and at least every
minute (util/filesystem/watchuntil.go); a failed load keeps the previous configuration and its hash. Sealing and the
maintenance boot (W01 §5.5) are what keep it unchanged.

`check_final` is the reference reading of the CEL validations, in rendered order (A2-RESERVED, then the kind's checks).
The CEL text is data for the native tests: the model does not compile or run CEL. Each validation avoids the CEL forms
the research could not confirm (schemaless list equality, mixed int/double equality). It uses sizes, `exists_one`,
`all`, `has`, `matches`, `join`, `request.userInfo.username` and the CIDR library. Where a CEL expression dereferences a
field without a `has()` guard, the reference reading requires the field: its absence is a runtime error, which
failurePolicy Fail denies (F17). Integers and booleans are compared by exact type (F18), and a malformed address is a
refusal (F19).

## Vectors

- **manifest** (N01-N30): each constraint, refused with its MC code.
- **endToEnd**:
  - E01-E04: each positive manifest under the plain sealed cluster; A2 admits.
  - E05-E12: cluster facts that make a mutator act:
    - outside the allowlist, A2 refuses: pull secrets copied from the ServiceAccount, a global default PriorityClass, a
      LimitRange default (its annotation), different toleration seconds, an address outside the CIDR, another family;
    - harmlessly, A2 admits: AlwaysPullImages with a manifest that already pulls Always, and a ServiceAccount
      automount overridden by the Pod field.
  - U01-U05: what an unconstrained manifest would let the mutators do; A2 refuses each.
- **finalObject** (F01-F15): changes an unexpected mutator could make (an injected sidecar, init container or volume,
  a changed image, automount on, added or changed tolerations, a node selector, a reserved label, a changed priority,
  immutability removed, a NodePort, two cluster IPs, ClientIP affinity, a removed echo, an image volume, no ports, a
  boolean priority, a malformed address). Each is refused for its A2 code. P01-P05: the root-CA publisher's object and its
  look-alikes.
- **objects** (S01-S06b): structural refusals of the sealed directory.
- **directoryHash** (H01-H04): the loader hash rules.
- **claims** (Q01-Q18): the v1 sentence refused at every boundary; v2 A1-A4 claims supported or refused.

`final_object` reproduces the upstream create path for the fields the allowlist lists, from the cited facts. It is a
reference simulation, not the apiserver: managedFields carry no fieldsV1 content (an unverified point), and the token
volume shape is abridged. The native tests (W03, T03) compare it against a real apiserver of the selected distribution.

## What stays open

- All E01-E12; the native A2 test against a real apiserver of the selected distribution, including CEL compilation and
  the unverified points in `allowlists.json` (W03).
- The distribution's sealed values (namespace, service family and CIDR, toleration seconds) and the admission
  configuration's `staticManifestsDir` (W03).
- The observer's check of the loaded manifest hash before ACTIVE (W03, R12).
- W02c-F: I07 writes no admission objects; the guard policy denies them.
- The signer and enrollment of manifests under these constraints (W03, R12).

## Round-1 findings and dispositions

| Finding | Disposition in round 2 |
|---|---|
| F1 MAJOR, AlwaysPullImages rewrites image volumes | Image volumes forbidden in manifests (MC38) and on the final object (A2-POD-IMAGE-VOLUME); `final_object` applies the upstream volume rewrite; allowlist disposition added (N29, U05, F16) |
| F2 MAJOR, the root-CA publisher's ConfigMap | A2-CM-PUBLISHER admits exactly `kube-root-ca.crt` from the publisher's per-controller identity with its fixed shape; the name is reserved for gate manifests (MC11); section "Other creators" (N30, P01-P05) |
| F3 MINOR, constraints A2 does not re-check | A2 item 1 reworded; `constraintCoverage` marks each constraint RECHECKED_BY_A2 or SIGNER_GUARANTEED; disabled-gate fields are a signer obligation; the A2 claim needs `manifestConstraintsMetAtSigning` (C25, Q17) |
| F4 MINOR, A1 wording | A1 restores scope, deadline and the observed policy generation and maps them to the I05 v2 conditions; "three named checks plus A4" |
| F5 NOTE, API hooks and webhook resources | The exemption sentence is limited to the four admission-policy resources |
| F6 NOTE, reload timing | Reloaded on a filesystem event and at least every minute; a failed load keeps the previous hash |
| F7 NOTE, reference reading on unreachable inputs | Required dereferenced fields, exact integer and boolean types, address parse errors refused (F17-F19); the A2 claim binds the sealed namespace (C26, Q18) |
