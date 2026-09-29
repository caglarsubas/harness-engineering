# Source development and native qualification — MET-UNIFY-008

This is a source-only amendment to the accepted `MET-UNIFY-005` roadmap at
`945de93f89c94f42f1d63bff7997e3d0fa704fc4`. It changes when native Linux
AMD64 evidence is required for four existing product packets. It does not record
native execution, installation, deployment, release or tenant acceptance.

## Retained failed candidates

`MET-UNIFY-006` was a separate, unpublished local attempt from the same accepted
baseline. Its exact packet, authority and policy hashes are retained in the
[item-level backlog](../../architecture/unified-roadmap-backlog.json) with local
commit `2e705d421b0bef21b0bc37fa62e4b5a6b63c468d`. LOCAL1 failed before
product validation because the fresh worktree lacked the pinned offline Python
environment. LOCAL2 used the preinstalled exact toolchain, passed the network
canary and YAML measurement, then stopped at 21 inherited history/test-identity
readiness errors. Both LOCAL slots were consumed; there was no PR, CI, merge or
exact-main acceptance.

`MET-UNIFY-007` was a second separate unpublished local candidate from the same
accepted baseline. Its retained commit is
`47e775afd87443e9826e2f2e496cf2eae768399f`, packet SHA-256 is
`f4ae338db253af3d25c11568c5574808bbec5ef9df1258c1e0caecab960f3599`,
and authority SHA-256 is
`9652193ef581f740f1aec5f0270efd7705d1b6b4281fbaf005af6254b60fa83f`.
LOCAL1 stopped at the historical status validator's handling of the retained
unpublished 006 ID; LOCAL2 passed the earlier history/custody checks and
stopped at document-repair raw packet parity; LOCAL3 stopped at host-interface
current-source drift on `CTRL-INTEGRATE-001`. All three LOCAL slots are consumed;
there was no PR, CI, merge or exact-main acceptance.

`MET-UNIFY-008` is a corrective replacement directly from accepted
`MET-UNIFY-005`, not a retry or accepted successor of either failed candidate.
It has its own finite LOCAL3, CI2 and exact-main1 budget. No allowance or PASS
transfers from 006 or 007.

Its isolated LOCAL1 passed the first 50 direct source validators, including the
network-denial canary and historical inverse checks. Command 51, the outer
pytest suite, failed: five failed, 5096 passed and ten skipped. Command 52,
the zero-bill scan, was not reached. One pytest failure was the
nested predecessor-suite derivative; the other four were stale raw-history or
YAML-corpus-count assertions. The four underlying assertions and their
negative-test count target were corrected within the packet's allowed paths.
At that checkpoint LOCAL1 was consumed; LOCAL2 and LOCAL3 remained. There was
no CI, merge or exact-main PASS for 008.

LOCAL2 subsequently passed all 52 declared commands inside the same isolated
process tree: 5101 outer tests passed, ten existing skips were reported, and
the final zero-bill scan passed. The source-status synchronization in this
paragraph uses the final LOCAL3 slot for exact-byte revalidation; LOCAL2's PASS
does not transfer to changed bytes. CI, merge and exact-main remain distinct.

## Effective source gate

`CTRL-INTEGRATE-001`, `MODEL-001`, `EXEC-001` and `RUN-001` retain their packet
IDs, path grants, contracts and exact offline commands. Their current predecessor
lists omit `CONF-LINUX-001`. Each may begin clean-room source coding and complete
its declared isolated offline acceptance, CI and merge after **all of its other
predecessors** close. macOS ARM64 is a valid development host for that source
work. Its output remains source evidence, even when all those checks pass.

The original `MET-LINUX-001` policy, `MET-LIVE-001` roadmap, `CONF-LINUX-001`
and `CONF-LIVE-006` packet records remain exact historical authorities for their
own publication and campaign contracts. Their statements requiring native PASS
*before coding* are superseded only for the four packet IDs above. The new
amendment does not change their campaign commands, ten mandatory AMD64 cases,
signatures, freshness, protected backend, capacity or billing conditions.

## Qualification and release gate

Fresh, independently verified `CONF-LINUX-001` native AMD64 PASS for the selected
foundation is required before Linux release deployment or promotion. Every new
product artifact must also earn native evidence bound to its exact source and
image digests, target OS/architecture/libc, toolchain and cache, host/isolation,
trust state, tenant/environment and validity window. Foundation PASS cannot
qualify a subsequently changed image. A missing required case, changed binding,
expired or revoked authority, or `NOT_RUN_ENV_UNAVAILABLE` blocks qualification;
source tests, emulation and fixtures cannot fill the gap. ARM64 has its own native
gate before an ARM64 support or release claim.

Campaign-scoped test deployments used to collect native evidence run only under
the signed live-campaign authority. They are not release deployment or promotion.

No Linux environment may be called `PLATFORM_DEPLOYABLE` or
`PLATFORM_CERTIFIED`, and no tenant acceptance may be claimed, until the exact
release has the separately required artifact, signature, deployment, runtime,
security, assurance and tenant evidence. The release lock's generic evidence
axes alone do not identify native Linux cases; the owning qualification and
promotion work must verify their exact native references before promoting. The
current native AMD64 and ARM64 states remain `NOT_RUN_ENV_UNAVAILABLE`.

Before a promotion claim, R12 conformance must publish an exact product-native
qualification packet and independently verify the selected R04 control, R05
runtime, R06 model and R08 execution artifact bindings after their source
merges. R11 distribution must publish a separately bounded release-lock
verification packet that rejects missing or stale R12 native evidence for any
selected artifact. Both are `WAITING_EXACT_PACKET`, not authorization to run a
campaign or a claim that foundation `CONF-LINUX-001` alone qualifies new images.

Live campaigns remain manual and post-merge through the external root-owned
launcher, independently signed release and tenant envelopes, capacity-operator
authorization, pre-existing zero-incremental-cost capacity and server-side
admission. Missing backend, signer or target is unavailable. Offline runs remain
in the declared deny-all-outbound single process tree with warm sources denied.

`W01` still has G04–G07/G09 and E01–E12 open. `CONF-FIX-010` remains
`BLOCKED_SAFE_DESIGN` with zero product attempts. This amendment grants neither
an interface adoption nor a conformance repair attempt. Alpha 2 remains open.
