# Sol-High Execution Rules

0. One initial planning-publication bootstrap is permitted before packet work:
   seed the public default branch with this non-product planning corpus, pinned
   self-hosted workflow, and offline runner contract. It may not implement any
   product packet or copy warm-source material. After this one-time seed, the
   one-packet/one-branch/one-PR rule applies without exception.
1. Implement exactly one task packet from `task-packets/` per coding run and PR.
2. Touch only `allowedPaths` from that packet. The meta repository may be touched
   together with one product repository only for an explicit release/reuse lock update.
3. Read and honor every predecessor contract and source lock before editing.
4. Never modify a warm-start repository. All current source paths are reference-
   only; implement clean-room. A future import requires path-level legal evidence,
   `COPY_AUTHORIZED`, an approved authorizationId/mapping, a revised packet, and
   the matching destination `PORTING.yaml` record.
5. Do not introduce cloud provisioning into product or repository implementation,
   hosted runners, paid APIs, API-key requirements, runtime downloads, mutable
   artifact references, or external telemetry defaults. MET-RUNNER-001 documents
   one externally operated, separately cost-authorized disposable development-CI
   Linux guest; its source publication grants no provisioning or runner authority.
6. Run only declared direct-argv `prefetchCommands` as the first phase inside
   the same deny-all-outbound OS-isolated process tree as acceptance. Set
   `HARNESS_TASK_PACKET` to the hash-pinned YAML path and execute the exact
   `offlineExecution.wrapperArgv`; it must transport and run both phases in one
   process tree, hide the packet path from children, and recheck its digest after
   every command. Never invoke a shell, parse a command string, or run an
   offline command separately.
   The trusted launcher receives every canonical warm-snapshot root through the
   newline-delimited `HARNESS_WARM_SOURCE_ROOTS` runner setting, applies OS-level
   read/metadata/write denial, and removes that setting before any packet child.
   An undeclared detected snapshot or unavailable isolation backend blocks the run.
7. Preserve source, CI, merge, artifact, deployment, runtime, assurance, and tenant
   acceptance as separate evidence states.
8. Create a `codex/<packet-id>-<slug>` branch, open a PR, monitor required self-hosted
   checks, apply bounded fixes, and merge only when every required check is green.
9. Stop when a missing decision would change a public contract, tenant isolation,
   destructive-data behavior, licensing disposition, or billing boundary.
10. Product implementation runs must not mount, open, or receive paths to any
    warm-start checkout. Packet `sourceReuse` entries are historical provenance
    and clean-room parity requirements only. New source observation requires a
    separately authorized observation packet and execution identity.
11. The sole pre-checkout exception is an externally installed, root-owned
    nonwritable exact-job admission hook and verifier with signed one-shot
    authority, image-pinned public-key trust, atomic nonce reservation and a
    hard timeout. The external controller binds the numeric GitHub job ID to a
    signed unique run/attempt/workflow/job-context tuple; a controlled live
    Linux host test must prove that the pinned hook authenticates every required
    observable tuple field before registration. It fails a wrong assignment
    before checkout; shared runner labels never establish job identity. No
    checked-out repository code runs in
    that hook. CI then performs
    only the pinned credential-free checkout and invokes the
    preinstalled absolute host launcher `/opt/planeon/bin/harness-offline-launch`.
    Repository shell/Python begins only after it establishes isolation. The
    ephemeral self-hosted runner and root-owned launcher contain no ambient cloud
    credentials, SSH agent, kubeconfig, Docker/containerd socket, or billable broker.
12. Never run live campaign argv directly. Live execution is manual and
    post-merge through only the external root-owned
    `/opt/planeon/bin/harness-live-campaign-launch`, under
    `docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`. Its only packet-declared
    input is `HARNESS_LIVE_EXECUTION_ENVELOPE`; fixed trust mounts are
    `/etc/planeon/trust/release-trust-bundle.json` and
    `/etc/planeon/trust/tenant-trust-bundle.json`. It must verify independent
    `PLATFORM_RELEASE` and `TENANT_LIVE_EXECUTION` signatures over the same RFC
    8785 payload, every referenced digest and embedded endpoint, the separate
    digest-bound `CAPACITY_OPERATOR` authorization, proxy scope, and server-side
    zero-cost mutation admission before checked-out code, probes or mutations run.
    MET-REPAIR-013 is the sole credential-ordering exception: after independent
    signatures, isolation, durable nonce reservation and retained custody checks,
    the campaign-client mTLS credential may authenticate only to its pinned
    proxy. This grants no execution; fresh server observation and transactional
    admission remain mandatory before effects or upstream credential access.
    See docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md. A missing authority/backend/target is
    `NOT_RUN_ENV_UNAVAILABLE`; never bypass it, invoke the inner repository
    launcher directly, broaden egress, or let a campaign sign tenant acceptance.
13. A product bootstrap packet is the sole owner of `Makefile` and
    `ci/run_make_target.py`. A later Make-using packet owns only its exact
    `ci/targets/<lowercase-packet-id>.json` descriptor and may not edit
    `Makefile`; the conformance campaign/evidence/acceptance rules are the closed
    `CONF-001` exception. Preserve every predecessor handler and reject unknown,
    duplicate, ambiguous, undeclared-variable, or shell-based dispatch. The sole
    bootstrap-handler corrections are `CTRL-FIX-001` and `DIST-FIX-001`.
    `CTRL-FIX-001` may edit only the control plane's `AGENTS.md`,
    `ci/handlers/prefetch.py`, its exact descriptor, and its bootstrap regression
    test so later packet PR merge commits remain admissible without weakening the
    exact empty-root or bootstrap dependency pins. `DIST-FIX-001` may edit only
    the distribution repository's `AGENTS.md`, `Makefile`, and bootstrap dispatch
    regression test so future packet descriptors are reachable through the
    already-closed dispatcher; it may not change the dispatcher, existing target
    argv, source locks, PORTING ledger, toolchain, or zero-bill boundary.
14. Only a product bootstrap packet may seed the inert `PORTING.yaml` ledger.
    No current reference/discovery-only packet may edit it. A later revision may
    add that path only with a legally approved `PORT_CANDIDATE` and exact mapping.
