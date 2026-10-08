# I06 backend profile v2 — W02g-F, round 1

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: no cluster, distribution, host or
kernel is observed, nothing is installed and no distribution is selected. All E01-E12 stay OPEN_UNPROVEN.

This is the successor of the adopted I06 backend profile (`architecture/i06-backend-profile/`, W02g, MET-ENFORCE-006,
main fe50b57). It answers the round-2 findings that W02g carried to W02g-F (`review-round2.json` there): N1 (bind the
evidence record to a backend that W02a accepts), N2 (no RBAC rule of any kind on the loopback user) and N3 (shared or
nested backend cgroups).

## Why a successor

The v1 bytes cannot change:
- `identity-closure.json` is a frozen input of the W02e SELinux matrix, the I07 policy-write contract and the W02a v3
  qualification record;
- the v1 model `scripts/i06_backend_profile.py` is imported by later layers and their tests (`validate_native_profile_v2`,
  `validate_verify_headroom` and the native-profile, I05, SELinux and projection-reuse tests).

So v2 adds this directory and `scripts/i06_backend_profile_v2.py`. v1's writer inventory, identity closure, upstream
facts, upstream bootstrap RBAC and model stay byte-identical. v2 reads them and reuses the v1 checks, adding rules only
in front of or after them.

## Files

| File | Content |
|---|---|
| `criteria.json` | v1's criteria with SC00, SC08 and IC03 restated (`planeon.internal.i06-selection-criteria/v2`) |
| `vectors.json` | evidence and snapshot positives, 7 accepted evidence variants, 5 accepted snapshot variants, 89 evidence negatives (all 71 v1 negatives replayed, plus G01-G18), 38 snapshot negatives (all 35 v1 negatives replayed, plus H01-H03) and 6 cross-version cases |
| `scripts/i06_backend_profile_v2.py` | the reference model: `check_evidence`, `check_rbac_snapshot`; `check_inventory` and `check_closure` are v1's |
| `REVIEW_BRIEF.md` | the brief for the independent review |
| `source-index.json` | digests of the subject and of the predecessor inputs at the base main a29c93c |

## What changes

### N1: evidence bound to an accepted W02a v3 record (SC00, SC08)

An evidence record (`planeon.internal.i06-distribution-evidence/v2`) adds one field, `w02aRecord`:
`{"schemaVersion": "planeon.internal.native-qualification/v3", "sha256": <hex>}`. The digest is SHA-256 over W02a's
canonical JSON form of the record (`native_qualification_v3.canonical`: sorted keys, no whitespace, UTF-8). The record
thereby names its backend; v1 only compared `implementationId` with whatever backend the caller passed.

`check_evidence(record, inventory, w02a_record, w02a_profile, w02a_endpoints, w02a_schema, test_fixture=False)`
checks, in this order:
1. the closed v2 record, its version and the closed reference with version v3;
2. W02a v3's `check_record` accepts `w02a_record` with its profile, endpoints and schema. Its refusal is reported as
   `SC00 W02a v3 refuses the backend record: <W02a rule>`;
3. the reference digest equals the digest of `w02a_record`;
4. the evidence's `testOnly` equals the backend's `backendProfile.testOnly`;
5. a test-only backend is accepted only when `test_fixture` is True. This mirrors W02a v3's `check_qualification`
   (P7(a));
6. v1's `check_evidence` on the v1 projection: the record without `w02aRecord`, under v1's version, against the backend's
   profile, implementationId and componentKeys and its `backendComponents`, with `production = not test_fixture`.

Step 2 brings in every W02a v3 backend rule that v1 never examined. The round-2 type sweep accepted 606 of 1341
substitutions because `cgroupPath`, `apiIdentities` and `filePaths` were not checked. The rules it brings in:
- each component's process label is its W02e slot constant;
- each component has its own domain, cgroup and API identity, and API identities are within the W02g closure for that
  component;
- every backend file is owned and listed in W02a's artifact custody;
- cgroups are outside the planeon slice, never shared and never nested.

**No production evidence yet.** W02a v3's schema admits exactly one backend profile: the test-only `unit-distribution`
fixture with its eight components. Every production call (`test_fixture=False`) is therefore refused, at step 5 or by
v1's production rules. Production evidence becomes possible only when W03 adds a production backend profile through
a reviewed W02a revision. Until then, v2 has no non-fixture accepted variant, and none can exist. The production rules
in step 6 stay in place for that revision. Round 2 asked for non-fixture accepted variants; this is the reason v2 has
none. G09 and G10 pin the refusal of the two v1 accepted variants whose backends W02a never accepted, and X03 and X04
compare them across versions.

### N2: the loopback user holds no RBAC rule (IC03)

`check_rbac_snapshot` runs v1's check and then refuses any non-empty `effectiveRules` on User `system:apiserver`
(`IC03 the loopback user system:apiserver holds an RBAC rule`). v1 refused only policy-relevant grants on that name.
H01-H03 pin the round-2 probes (configmap and secret reads in kube-system, `nodes/stats`) and a workload grant. B05
accepts the user listed with no rules. The snapshot record format is unchanged (`planeon.internal.i06-rbac-snapshot/v1`):
only the check is stricter.

### N3: shared and nested backend cgroups

These are refused by W02a v3's `check_record` (`backend components share a cgroup`, `backend cgroup nested in another
backend cgroup`), which N1 applies to every evidence check: G07 and G08. A09 accepts a sibling whose name only extends
the kubelet's unit name, so the nesting test is per path component. The P7 carry chain is now closed:
- W02a v2's frozen status assigned P7 to "W02g and W03";
- W02g carried P7(b) and P7(c) to W02a-F;
- W02a-F closed P7(a)-(c) (`architecture/native-profile-v3/status.json` closedFindings.P7).

The v2 status record states this when the contract is adopted.

## Replayed v1 cases

Every v1 evidence and snapshot negative is replayed under v2 with its v1 operations. A v1 `production` flag becomes
`testFixture = not production`. Backend operations apply to the W02a v3 record, and the evidence then names the mutated
record. 61 evidence negatives and all 35 snapshot negatives keep their v1 refusal. Ten evidence negatives now stop at
an earlier rule; `v1Refusal` keeps the old text:

| Vector | v1 refusal | v2 refusal | Why |
|---|---|---|---|
| E06 | SC08 component outside its confined type | W02a v3 schema, `processLabel` const | W02a v3 pins each backend label to its W02e slot constant |
| E35 | SC00 test-only profile cannot qualify production | test-only backend only in a fixture call | step 5 runs before v1's production rule; same outcome |
| E36 | SC00 unit-distribution is a test-only profile | evidence and backend disagree on test-only | step 4 runs first; same outcome |
| E38, E56 | SC08 distinct executables with distinct content | W02a v3 artifact custody | changing a backend executable or digest breaks W02a's custody listing |
| E55 | SC08 executable must be canonical | W02a v3 artifact custody | as E38 |
| E60, E61 | SC00 fixture identity in production; identifier pattern | W02a v3 schema, `implementationId` const | W02a v3 admits only the fixture profile |
| E70, E71 | SC10 API client; SC08 component set | W02a v3 schema, `componentKeys` const | W02a v3 admits only the eight-component fixture |

The v1 accepted variants A01, A03, A04, A06 and A07 are replayed as accepted fixture calls. A02 and A05 moved to the
cross-version cases (X03, X04). Closure and inventory vectors are not replayed: their inputs and checks are v1's,
unchanged, and the v1 layer still replays them.

## Cross-version cases

| Case | v1 model | v2 model |
|---|---|---|
| X01: each version's positive under the other version | refuses (closed record) | refuses (closed record) |
| X02: each version's positive under its own version | accepts | accepts |
| X03: v1 A02, a production profile renamed `selected-distribution` | accepts | refuses: W02a v3 schema |
| X04: v1 A05, a six-component fixture | accepts | refuses: W02a v3 schema |
| X05, X06: the round-2 N2 probes | accept | refuse: IC03 |

No adopted v1 evidence or snapshot exists outside these vectors, so there is nothing to migrate.

## Round-2 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| N1 W02a binding | MINOR | Applied inside `check_evidence` (steps 1-5), not as a caller obligation; SC00, SC08 restated; G01-G18, A08, A09, X03, X04 |
| N2 loopback user | NOTE | Any rule refused; IC03 restated; H01-H03, B05, X05, X06 |
| N3 nested or shared cgroups | NOTE | Refused through W02a v3's check_record (G07, G08); P7 carry chain recorded above and in the status at adoption |
| N4 sealed file vocabulary | NOTE | Unchanged carry to W02e and W03 |
| N5 kubernetesVersion as reported gitVersion | NOTE | Unchanged carry to W03 |
| N6 workload paths outside kube-system | NOTE | Unchanged carry to W02f and W02e |

## Not claimed

- No cluster, distribution, host or kernel observation, and no selected distribution.
- No production backend profile: W03 adds it through a reviewed W02a revision.
- All E01-E12 stay OPEN_UNPROVEN.
- The v1 profile and its inputs, the W02a v2 and v3 contracts, the W02e matrix and the W01 resolution stay
  byte-identical.

## Still open

- Production evidence needs W03's production backend profile in a reviewed W02a revision.
- N4 (W02e, W03), N5 (W03) and N6 (W02f, W02e), as carried by W02g.
