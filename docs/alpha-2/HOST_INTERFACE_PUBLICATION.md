# Alpha 2 — independently reviewed W01 interface candidate

> Current-status note for MET-UNIFY-003: this is a retained W01 source-review subject, not an adopted host ABI or native enforcement result. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives the current packet and phase status. PR #138 recorded the MET-ENFORCE-003 source publication on accepted main; G04–G07/G09 and E01–E12 remain open.

MET-ENFORCE-003 · ONGOING_SOURCE_PUBLICATION. W01 remains ONGOING_DESIGN.

## Current position

| Phase | ID | Status | Description |
|---|---|---|---|
| Phase0 / Alpha1 | Existing foundations | DONE_RECORDED | Historical source/offline evidence, not universal native acceptance |
| Alpha2 | MET-ENFORCE-001 | DONE_SOURCE_GATES | PR135 / cdb71ae; LOCAL, required CI and exact-main separately retained |
| Alpha2 | W01 independent draft review | DONE_SOURCE_REVIEW | One unsupported correlation claim corrected and independently rereviewed |
| Alpha2 | MET-PERF-018 | DONE_SOURCE_GATES | PR137 / fe771b2; LOCAL, required CI and exact-main separately retained |
| Alpha2 | MET-ENFORCE-002 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Draft PR136 stays unaccepted; both LOCAL attempts retained |
| Alpha2 | MET-ENFORCE-003 | ONGOING_SOURCE_PUBLICATION | Reconcile reviewed snapshots on accepted repaired main with explicit new finite allowance |
| Alpha2 | W01 HOST_INTERFACE_SPEC | ONGOING_DESIGN | G04-G07 and G09 must be concretely resolved before adoption |
| Alpha2 | W02-W07 | WAITING_EXACT_SUCCESSOR | Versioned ABI, implementation, packaging and native evidence remain gated |
| Alpha2 | CONF-FIX-009 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | All previous reservations and failures preserved |
| Alpha2 | CONF-FIX-010 | BLOCKED_SAFE_DESIGN | Zero attempts; not a dispatch target |
| Alpha2 | CONF-LIVE-004/005/006; CONF-A2-001 | WAITING | Qualified integrated read-only profile not achieved |
| Alpha3 / Alpha4 | Governed actions / enterprise qualification | WAITING | Existing roadmap; no phase-end effort transition |

## Exact reviewed subject and finding

Read the [corrected candidate](../../architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md),
[review brief](../../architecture/host-interface-inputs/corrected/REVIEW_BRIEF.md),
[independent verdict](../../architecture/host-interface-inputs/independent-review.json)
and [closed current plan](../../architecture/host-interface-plan.json).
The original and corrected snapshots are immutable historical subjects. Their
pre-review flags describe when they were written; the separate verdict records
the subsequent independent review. Do not rewrite reviewed bytes to claim a pass.

Original draft SHA256: `6b6568ab2a0dfa1cd86fd302f6f75411839be8f6ba8d92bd54ba46bb26f30533`.
Verdict CHANGES_REQUIRED: a run certificate, digest and sole outstanding action
cannot necessarily distinguish a delayed duplicate of completed action A from a
later byte-identical action B in the same generation.

Corrected draft SHA256: `1b0bee7e46e3cd730b3f878179ac36d0f062ce70ed6c843788ab634aead16ef0`.
Verdict PASS_FOR_SOURCE_PUBLICATION: the unsupported claim was removed; G09,
counterexample17 and T02 explicitly retain the correlation gap. This is a corrected
specification, not a runtime fix or demonstrated replay defense.

The independent reviewer verified all five draft files and23 predecessor inputs.
Review was read-only and performed no tests, repository execution, native actions,
warm-source access, runner activation or GitHub mutation. An agent review is not
an external certification or independent tenant acceptance.

## Unresolved adoption gates

- G04: concrete current policy backend and complete mediation/exclusion of writers.
- G05: explicit admission-versus-storage-commit semantics without weakening the
  accepted contract through a gateway acknowledgement.
- G06: versioned native role/manifest enrollment for the proposed gate.
- G07: exact syscall, capability, MAC, seal and original-parent lifecycle policy.
- G09: demonstrated request-to-action correlation, or an explicit reviewed protocol
  amendment. No new header now; caller-supplied action identifiers are not authority.

I01-I04 remain unchanged. I05 is proposed, not an installed private socket; I06 is
unresolved, not an implicit daemon. All E01-E12 remain OPEN_UNPROVEN. W01 is not
coding-ready; W02-W07 are work labels, not executable task packets. Current temporal
checks, failed product evidence, irreversible nonce consumption and cleanup
ownership remain intact. No product attempt or native proof is created here.

R10 remains accountable for four separate host modules, outside the nonroot
Kubernetes controller; R12 independently qualifies and R11 packages released
artifacts. R01 owns any later public-contract changes. Thirteen repositories,
four planes and16 harnesses remain unchanged, as do all typed dependency graphs.

The candidate evaluates maintained upstream HTTP/TLS support before bespoke code.
`envoyproxy/envoy` remains a candidate, not a selected release, dependency or
qualified enforcement mechanism. Preserve the
[all16 harness-paper-OSS map](HARNESS_PAPER_REPOSITORY_MAP.md). Require **at least
one qualified baseline for every released harness capability** at first enterprise
release. Publication does not add a qualified baseline.

## Bounded source publication

One META packet/branch/PR from accepted main
`fe771b213a96bb6f0c1c9e3d1c47c18d21881cde` (MET-PERF-018 / PR137).
All187 previous packet YAML and preexisting architecture data remain byte-identical.
The new catalog has188 specifications; MET-ENFORCE-002 is not imported into it.
Old scripts/tests change only for exact current-catalog integration, checked
reversible history and the new predecessor's private-local/single-successor link.
Retain fresh authority reads, exact refusals and every inherited test identity.
No historical code execution or cached acceptance. Keep all49 predecessor commands
and add one data validator for50, both full test replays, ten inherited skips and
the frozen exact case accounting in the plan.

### Explicit reconciliation and historical allowance

PR136 head `3bf938b9fc435bf8899a3f348288f73c77129557` remains unaccepted.
Its LOCAL1 input-closure failure and LOCAL2 full-replay timeout consumed2/2 LOCAL;
CI0/2 and exact-main0/1 were unused but are not transferable. Its immutable stop
record has SHA256
`bce5dce885b53f2af8499b8c80a423fc9aa4a6fa3f6de86febdd7ab592a39d88`.
This is an explicit successor after a separately accepted algorithmic repair,
not another002 retry. Record both old failures and their original identities in
[the reconciliation ledger](../../architecture/host-interface-inputs/reconciliation.json).

Distinct003 allowance: LOCAL2 / CI2 / LOCAL_EXACT_MAIN1; prior lineage LOCAL2
already consumed, maximum cumulative lineage LOCAL4. Zero product, diagnostic or
benchmark executions. Reserve before activation; refusal, failure, interruption
or timeout consumes the slot. No resets, pooled allowance or hidden retries.
Retain750s local/main,420s nested,900s trusted and15min CI bounds. Prior exact-main
701.1914s is historical evidence, not a guarantee that the new candidate fits.

### Preserve the actual reviewed inputs

All original/corrected snapshots and indexes remain exact, reviewed at cdb71ae.
Bind all23 current input paths. Three reviewed documents changed in the accepted
repair: the master plan, enforcement-integration guide and operator repository
guide. Verify current003 bytes, invert only the exact new authority's recipes to
fe771b2, then invert the three exact accepted repair recipes to cdb71ae. The entire
bridge authority file is pinned to SHA256
`c84888a7fe3fd955922cdc4e45fab7308b1fcf02ba4273173c9e534c42e82169`.
Check both endpoint hashes and inverse cardinality. This is data projection only:
no circular imports, retargeted source indexes or execution of historical code.

Use only the existing signed isolated localhost runner; no root/key/policy/admin,
workflow/toolchain/dispatcher changes, hosted execution, downloads, artifact uploads,
cloud provisioning, paid API, API-key requirement or external telemetry default.
Source, CI, merge, exact-main, artifact, installed/native/runtime, assurance and
tenant acceptance remain distinct. Source rollback is a reviewed revert before
consumption or scoped successor afterwards; no history or consumed authority reset.

Alpha2 remains open; model-effort transition **NOT_DUE**.
