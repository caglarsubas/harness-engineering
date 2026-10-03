# Harness-Onion — unified development roadmap

## Current checkpoint — MET-PERF-029 source preparation, October 4, 2026

Alpha2 OPEN. MET-VERIFY-001 passed its required verify through the owner's App
(55/55, 750.4 s in the trusted launcher, activation391) and PR #147 merged as
main 8172538 with no administrator exception. Its run showed suite time growing
about50s per packet because composed layers re-read every newer authority
quadratically. MET-PERF-029 is the sole194th specification: each route still
freshly reads every newer authority, now exactly once.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 performance | MET-PERF-029 | SOURCE_PREPARED | Linear authority rechecks as194th packet; verify from the owner's App |
| Alpha2 CI | MET-VERIFY-001 | VERIFY_PASSED_MERGED | Owner-operated required check; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed Linux host, fresh native AMD64 and integrated read-only acceptance |

Keep56argv, both full suites, 420/750/900s/15min and32MiB. No cloud, runner
registration, live/native/tenant or model-effort changes. Phase-end effort
transition NOT_DUE. Prior checkpoints below are history only.

## Historical VERIFY-001 source checkpoint — MET-VERIFY-001 source preparation, October 3, 2026

Alpha2 OPEN. MET-LINUX-005 reached LOCAL_PASS_ONLY (54/54, 671.395 s,
activation390; independent terminal review confirmed) and PR #146 was merged as
main e4e0beb under a second consumed one-time administrator exception. The owner
then replaced the unavailable runner path: required verify is now reported only
by the owner's GitHub App from the installed trusted launcher on an
owner-operated host (docs/alpha-2/OWNER_OPERATED_VERIFIER.md). MET-VERIFY-001 is
the sole193rd specification and the first PR checked through that path.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 CI | MET-VERIFY-001 | SOURCE_PREPARED | Owner-operated required-check contract as193rd packet; verify from the owner's App |
| Alpha2 runner | MET-LINUX-005 | LOCAL_PASS_MERGED_BY_EXCEPTION | LOCAL pass confirmed; exact-main and native Linux NOT_RUN |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed Linux host, fresh native AMD64 and integrated read-only acceptance |

Keep55argv, both full suites, 420/750/900s/15min and32MiB. No cloud, runner
registration, live/native/tenant or model-effort changes. A GCP Linux verifier is
a later, separately approved successor. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical005 source checkpoint — MET-LINUX-005 source preparation, October 3, 2026

Alpha2 OPEN. MET-PERF-028 reached LOCAL_PASS_ONLY (53/53, 600.586 s,
activation389; independent terminal review confirmed) and PR #145 was merged as
main f7af83e under a consumed one-time administrator exception; its required
verify did not run because no self-hosted runner exists. MET-LINUX-005 is the
sole192nd specification: it carries the reviewed MET-LINUX-004 nested-checkout
and system-alias runner-contract repair onto that main.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 runner | MET-LINUX-005 | SOURCE_PREPARED_AWAITING_REVIEW | Runner-contract repair as192nd packet; independent review and separately authorized full acceptance remain |
| Alpha2 readiness | MET-PERF-028 | LOCAL_PASS_MERGED_BY_EXCEPTION | LOCAL pass confirmed; CI and exact-main NOT_RUN |
| Alpha2 runner | MET-LINUX-004 / PR144 | SUPERSEDED_SOURCE | LOCAL1/2/3 consumed and retained; not a predecessor |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

This packet grants LOCAL0/CI0/exact-main0. Keep54argv, both full suites,
420/750/900s/15min and32MiB. No cloud, root, runner registration,
live/native/tenant or model-effort changes. Phase-end effort transition NOT_DUE.
Prior checkpoints below are history only.

## Historical028 source checkpoint — MET-PERF-028 source preparation, October 2, 2026

Alpha2 OPEN. Accepted main0314a684 retains190 immutable packets;028 is the
sole191st specification. Same-host measurement of frozen027 outside the trusted
launcher (no allowance consumed) showed the full predecessor suite at485.15s,
over the420s nested limit. Profiling attributed most of the heaviest tests to
per-call full SHA-256 of three large history authorities and about4s per
validate_reuse call to quadratic uniqueItems over3868 path-index objects.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-028 | SOURCE_PREPARED_AWAITING_REVIEW | Exact-bytes authority recheck reuse, linear uniqueItems and additive regressions; independent review and separately authorized full acceptance remain |
| Alpha2 readiness | MET-PERF-027 | FAILED_LOCAL_FROZEN | 750.277658s timeout;52/53 commands; nested420.012s timeout; independently confirmed cleanup |
| Alpha2 readiness | MET-PERF-019–026 | FAILED_LOCAL_FROZEN | Every previous allowance and failure preserved; no replay |
| Alpha2 runner | MET-LINUX-004 / PR144 | WAITING | Separate three consumed attempts; CI/capacity/exact-main unresolved |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

Every authority call still freshly reads complete bytes through unchanged
custody checks; only a byte-identical read under the identical pin skips a
repeated digest. uniqueItems keeps the pinned verdict and message wherever the
pinned check completes; sortable arrays still use it unchanged. Ten lineage
allowances plus separatePR1443 remain consumed. This packet grants
LOCAL0/CI0/exact-main0. Keep53argv, both full suites,420/750/900s/15min and32MiB.
No cloud, root, runner registration, live/native/tenant or model-effort changes.
Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

## Historical027 source checkpoint — MET-PERF-027 source preparation, October 2, 2026

Alpha2 OPEN. Accepted main0314a684 retains190 immutable packets;027 is the
sole191st specification. Two historical recipe readers reuse immutable decoded
recipe data only. Every call retains fresh full reads/hash checks, explicit
overridden-reader semantics, original failure ordering and fresh mutable views.
No function-level speedup or sufficient headroom has been measured.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-027 | SOURCE_PREPARED_AWAITING_REVIEW | Two recipe projections and additive regressions; final frozen-source review and separately authorized full acceptance remain |
| Alpha2 readiness | MET-PERF-026 | FAILED_LOCAL_FROZEN | 750.261581s timeout;52/53 commands; independently confirmed cleanup |
| Alpha2 readiness | MET-PERF-019–025 | FAILED_LOCAL_FROZEN | Every previous allowance and failure preserved; no replay |
| Alpha2 runner | MET-LINUX-004 / PR144 | WAITING | Separate three consumed attempts; CI/capacity/exact-main unresolved |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

026 nested5128passed/10skipped and7/7 commands completed; outer4981passed with
zero observed failures had no final report. Its51snapshot/42semantic regression
passes are partial observations, not acceptance. Final scan did not run. Nine
lineage allowances plus separatePR1443 remain consumed. This packet grants
LOCAL0/CI0/exact-main0. Keep53argv, both full suites,420/750/900s/15min and32MiB.
No cloud, root, runner registration, live/native/tenant or model-effort changes.
Phase-end effort transition NOT_DUE. Prior checkpoints below are history only.

Data-only inspection reconciles111 exact owned paths,90 accepted-file inverses,
18 new-file pins and3 closure objects. All190 accepted packets and192 protected
files remain unchanged. The13 repository guides,191-entry index and412 ordered
predecessor edges agree;48 accepted test identity inventories are preserved.
New regression source declares18 functions/50 literal decorator cases;17 use a
two-module fixture. These are syntax observations, not collection or test results.
Independent preliminary core/test review found no concrete blocker. Final exact
commit/tree/history review is separate and remains required before any run.

## Historical026 source checkpoint — MET-PERF-026 source preparation, October 2, 2026

Alpha2 remains OPEN. Accepted main0314a684 has190 immutable YAML; this branch
adds026 only. The sole new optimization is lazy immutable decoding of one
pinned290177-byte historical snapshot. Each call still rereads and hashes the
file, checks the current record and returns a fresh map; other data preserves
the original parser and refusal order. No measured speedup or timing PASS.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-026 | SOURCE_PREPARED_AWAITING_REVIEW | One snapshot decode projection and additive regressions; final exact-source review and every execution gate remain |
| Alpha2 readiness | MET-PERF-025 | FAILED_LOCAL_FROZEN | Outer750.224819s and nested420.016669s timeout,52/53 commands; cleanup independently confirmed |
| Alpha2 readiness | MET-PERF-019–024 | FAILED_LOCAL_FROZEN | All previous allowances/evidence preserved; no replay or transfer |
| Alpha2 runner | MET-LINUX-004 / PR144 | WAITING | Separate three attempts consumed; capacity/CI/exact-main unresolved |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed host enforcement, fresh native AMD64 and integrated read-only acceptance |

025 outer3134passed calls/one failed enclosing call and nestedINCOMPLETE27873
records/zero observed failed phases are partial observations. The final scan
did not run. Prior019-025 and separatePR144 remain immutable; cumulative8
lineage allowances are consumed. This packet grants LOCAL0/CI0/exact-main0.
Keep53argv, both full suites and420/750/900s/15min limits. No cloud, root,
runner registration, live/native or tenant effects. Exact-source/helper review
and finite authority are required before a future full run. Phase-end effort
transition NOT_DUE; prior checkpoints below are history, not execution grants.

Data-only source inspection reconciles108 exact owned paths,89 accepted-file
inverses,16 new-file pins and3 closure objects. All190 accepted YAML and192
protected files are unchanged. The13 repository guides,191 current/indexed
packets and412 predecessor edges agree;48 accepted test identity inventories
are preserved. New snapshot regression source declares12 functions/51 literal
cases, not collected or executed tests. Preliminary independent core/test
review found no concrete blocker; final frozen-source/history review remains.

## Historical025 source checkpoint — MET-PERF-025 source preparation, October 2, 2026

Alpha2 remains open. Fresh remote main0314a684 retains190 immutable packet YAML;
this candidate adds only025 for191. Reuse the existing exact-byte-keyed immutable
canonical serializer at one CI-performance call site under an explicit narrow
amendment. Preserve interleaved fresh authority/projection/digest checks, every
inherited test, fixed parser semantics and existing256-entry bound. No changed
shared helper/parser, two-pass rewrite, cached verdict or new acceptance grant.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha2 readiness | MET-PERF-025 | SOURCE_PREPARED_AWAITING_REVIEW | One canonical-byte delegation and additive regressions; independent review and finite full acceptance remain |
| Alpha2 readiness | MET-PERF-024 | FAILED_LOCAL_FROZEN | 750.259927s deadline,52/53, no final scan; diagnostic repairs narrowly exercised, cleanup confirmed |
| Alpha2 readiness | MET-PERF-019–023 | FAILED_LOCAL_FROZEN | Every prior allowance and evidence retained; no replay/reset/transfer |
| Alpha2 runner preparation | MET-LINUX-004 / PR144 | WAITING | Separate three LOCAL attempts consumed; CI/capacity/exact-main distinct |
| Alpha2 qualification | W01 / CONF-LINUX-001 / CONF-A2-001 | WAITING_PREREQUISITES | Installed enforcement, fresh native AMD64 and integrated read-only evidence |

024 nested suite returned0 in385.898376s with COMPLETE30271records,0failed/drop
and10recorded skips; all seven nested commands passed. Outer4676 passed calls
and0observed failed phases are incomplete observations, not acceptance. Exact
failure/cleanup pins are in architecture/packet-schema-performance-inputs/prior-024-terminal.json.

Whole-run timing remains unresolved. Repeated YAML-to-canonical conversion is
a source-confirmed opportunity, not measured speedup. Fixed pinned parser
semantics are required; warm cache entries do not detect arbitrary runtime
parser replacement. Preserve53argv, both full suites,420/750/900s,15min and32MiB.
Cumulative7 and PR144 separate3 remain consumed. NewLOCAL0/CI0/exact-main0;
no helper/signing/activation, cloud, root-policy, runner or native/tenant effect.
Model/effort unchanged; phase-end transition NOT_DUE. Earlier checkpoints below
are retained history, not current implementation or execution authority.

Author data-only inspection reconciles106 owned paths,89 exact inverses and14
new-file pins plus the three closure objects; all190 accepted packets and192
protected files remain unchanged. The13 repository guides,191-entry index and
412 ordered predecessor edges agree. All48 changed accepted test modules retain
ordered identities. The additive semantic module declares15 test functions and
42 literal parameter cases, not collected or executed tests. Pre-freeze review
caught three AST fingerprints generated with system Python3.9; corrected hashes
are bound to pinned3.12.14. Import fixtures restore introduced aliases and observe
the actual loaded authority chain. Independent final review remains required.

## Historical024 source checkpoint — MET-PERF-024 source preparation, October 2, 2026

Alpha 2 remains open. Accepted main `0314a684` retains 190 immutable packet YAML;
this unaccepted source adds only `MET-PERF-024`, for 191. Preserve the schema,
freshness, separate semantic-test ownership and historical reconstruction work.
Correct short explicit IDs for invalid-node fixtures without changing inputs,
and explicitly raise the existing nonzero failure payload without pytest
assertion rewriting. No recorder-limit or strict regression relaxation.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 readiness | MET-PERF-024 | SOURCE_PREPARED_AWAITING_REVIEW | Diagnostic corrections and static regression source prepared; independent review and separately authorized complete acceptance remain |
| Alpha 2 readiness | MET-PERF-023 | FAILED_LOCAL_FROZEN | LOCAL1/1 consumed; 750-second timeout, invalid diagnostic completion, no final scan |
| Alpha 2 readiness | MET-PERF-019 / MET-PERF-020 / MET-PERF-021 / MET-PERF-022 | FAILED_LOCAL_FROZEN | All old allowances remain consumed; no replay, reset or transfer |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Three consumed LOCAL attempts; CI/capacity and exact-main remain separate |
| Alpha 2 qualification | W01 / native Linux / CONF-A2-001 | WAITING_PREREQUISITES | Host enforcement, target qualification and integrated read-only evidence |

Latest023 reached 52/53 commands. Its nested stdout reports 5,019 passed and10
declared skips, but return1 reflects INVALID_NODE and4,680 dropped diagnostic
records. Four outer failed call phases are retained, not a final complete
report. The negative fixture created a65,633-character real node ID; three exact
payload regressions conflict with pinned pytest assertion rewriting. The first
cause is source/log confirmed; the second is a reviewed source-grounded inference
without a retained final traceback. Actual cleanup and unchanged source/history
are independently confirmed. Preserve evidence in
`architecture/packet-schema-performance-inputs/prior-023-terminal.json`.

Whole-run timing is still unresolved. Keep all53 argv, both full suites, nested
420 / local750 / trusted900 seconds, workflow15minutes and32MiB output. This
source grants ZERO attempts; the old shared2/2 plus four separate1/1 allowances
remain consumed at cumulative6. No source/helper execution, CI, merge, cloud,
runner registration, privilege or native/tenant acceptance follows. Model-effort
transition remains NOT_DUE. Prior checkpoints below are historical records.

Author data-only inspection found 104 exact changed paths, 190 unchanged accepted
packets, 191 current entries, 192 protected files, 13 owner guides and 412 ordered
predecessor edges. All 48 changed accepted test modules retain ordered function
identities. The new diagnostic-repair module declares seven functions and 16
literal cases; these are source observations, not executed or collected tests.

## Historical023 source checkpoint — MET-PERF-023 source preparation, October 2, 2026

Alpha 2 remains open. Accepted main `0314a684` has 190 immutable packet YAML;
this unaccepted candidate adds only `MET-PERF-023`, for 191. Move the four new
semantic test functions (14 static cases) into a separate owned module while
restoring the protected file's ten historical identities and bodies. Keep the
canonical owner/root fixes and all unaccepted schema/freshness/diagnostic work.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 preparation | MET-PERF-023 | SOURCE_PREPARED_AWAITING_REVIEW | Exact historical identities restored and semantic coverage separated; independent review and separately authorized full acceptance remain |
| Alpha 2 preparation | MET-PERF-019 / MET-PERF-020 / MET-PERF-021 / MET-PERF-022 | FAILED_LOCAL_FROZEN | Shared 2/2 and three separate 1/1 exceptions consumed; no replay, reset or transfer |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Three consumed LOCAL attempts; base reconciliation, required CI/capacity and exact-main remain separate |
| Alpha 2 qualification | W01 / native Linux / CONF-A2-001 | WAITING_PREREQUISITES | Host enforcement, fresh target qualification and integrated read-only evidence |

The latest 022 LOCAL failed readiness command 2/53 after 16.4475 seconds without
timeout. Projected-byte checks did not replace separate raw AST identity checks:
adding four functions changed a protected ten-test inventory to fourteen. The
prior source review missed this exact-equality requirement. Preserve that review
as history, not acceptance; do not weaken the historical checks. Pytest and new
diagnostics never ran. Independent terminal review confirmed cleanup and unchanged
source/history. Retained pins are in
`architecture/packet-schema-performance-inputs/prior-022-terminal.json`.

Author data-only inspection confirms 102 owned changed paths, 190 unchanged
accepted packets, 191 current entries, 13 repository guides, 412 predecessor
edges and matching root unions. All 48 changed accepted test modules retain
their exact ordered identities. The protected module matches accepted bytes
apart from the catalog scalar; all four moved semantic functions preserve their
AST bodies and fourteen static cases. Seven new-module guard/selection cases
and one retained022-history case are additional source coverage, not executed
tests. Reversible bytes, locked inputs and old failure records remain intact.

This packet grants ZERO new executions. Source preparation is not qualification,
and earlier 020 pytest failure identities remain unresolved. Review exact raw
test inventories as well as reversible source bytes, current canonical owner/ID
sets, README ordering and all allowed-root unions. Keep all 53 argv, both full
suites, nested 420 / local 750 / trusted 900 seconds, workflow 15 minutes and
the 32 MiB output ceiling. No cloud, runner registration, privilege, CI, merge,
native or tenant-acceptance promotion. Model-effort transition remains NOT_DUE.

The older source-era checkpoints below retain history, not current grants.

## Historical022 source checkpoint — MET-PERF-022 source preparation, October 2, 2026

Alpha 2 remains open. Accepted main `0314a684` has 190 immutable packet YAML; this
unaccepted source candidate adds only `MET-PERF-022`, for 191. The correction makes the
canonical owner declaration and root tree agree with the packet catalog and
adds semantic consistency regression source. Earlier schema/freshness/diagnostic
work is carried as unaccepted source, not a completed performance improvement.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 preparation | MET-PERF-022 | SOURCE_PREPARED_AWAITING_REVIEW | Owner/index/tree corrections and regression source prepared; data-only relationships checked, independent review and acceptance still required |
| Alpha 2 preparation | MET-PERF-019 / MET-PERF-020 / MET-PERF-021 | FAILED_LOCAL_FROZEN | Shared 2/2 plus 020 exception 1/1 and 021 LOCAL 1/1 consumed; no replay or transfer |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Three consumed LOCAL attempts; base reconciliation, required CI/capacity and exact-main remain separate |
| Alpha 2 qualification | W01 / native Linux / CONF-A2-001 | WAITING_PREREQUISITES | Host enforcement, fresh target qualification and integrated read-only profile evidence remain unresolved |

The latest 021 LOCAL failed at readiness command 2: 2/53 commands, four errors,
29.908 seconds, no timeout. The guide named 020 in its canonical PR-packets section and
omitted `conftest.py` from its exact root tree. The earlier hash/inverse review
missed these semantic inconsistencies. Pytest, diagnostic hooks and the final
scan never ran. The frozen source and independent cleanup/result pins are kept
in `architecture/packet-schema-performance-inputs/prior-021-terminal.json`.

Author data-only inspection now reconciles all 13 guides, 191 physical packet
owners, 191 indexed entries, 412 predecessor edges and every declared root union.
It preserves all 190 accepted packet bytes and reproduces the two defects in
frozen 021 while finding neither in this candidate. This is not test execution,
an independent security verdict or a full readiness result.

Decision: repair the documents and test the parser-scoped relationships;
do not weaken validation, drop tests, increase deadlines or edit failed source.
This packet grants ZERO new executions. Independent exact-source/helper review
and explicit finite successor authority are prerequisites to any later full run.
All 53 command arrays, nested 420 / local 750 / trusted 900 seconds and the
15-minute workflow ceilings remain unchanged.
No signing, activation, CI, root-policy/cloud/runner or tenant-acceptance change.
Alpha 2 is open; model-effort transition NOT_DUE.

The older source-era checkpoints below retain history, not current grants.

## Historical021 source checkpoint — MET-PERF-021 source preparation, October 1, 2026

Alpha 2 remains open. Accepted main `0314a684` contains 190 immutable packets.
This unaccepted candidate adds only `MET-PERF-021` for 191. It carries forward
reviewed-but-unaccepted schema-lifecycle/fresh-authority work and adds bounded,
redacted per-test phase diagnostics. This is source preparation, not acceptance
or a measured performance improvement.

| Phase | ID | Status | Description / gate |
|---|---|---|---|
| Alpha 2 preparation | MET-PERF-021 | ONGOING_SOURCE_PREPARATION | Test identity/phase/outcome diagnostics; independent review and static closure pending |
| Alpha 2 preparation | MET-PERF-019 / MET-PERF-020 | BLOCKED_FROZEN | Original 2/2 plus additional custody exception 1/1 consumed; no replay |
| Alpha 2 runner preparation | MET-LINUX-004 / PR #144 | WAITING | Existing three LOCAL allowances consumed; CI/capacity and accepted-base reconciliation remain separate |
| Alpha 2 qualification | Native Linux prerequisites / CONF-A2-001 | WAITING | Required source, installed-host and exact-target evidence remain unresolved |

The last020 exception reached execution but timed out: nested predecessor pytest
420.016s, outer750.444s,52/53 commands, no final summaries or final scan.
Two additional outer failure markers have no established test identity.
Independent terminal review confirmed cleanup and unchanged source/history.
Sanitized immutable pins are in
`architecture/packet-schema-performance-inputs/prior-020-terminal.json`;
the earlier019 record remains byte-for-byte historical data.

Root pytest diagnostics identify setup/call/teardown and outcomes as observed.
Nested `subprocess.run(capture_output=True)` remains unchanged: its events are
buffered until return or the420s inner timeout, not live streaming. No raw
parameter values, traceback locals, exception text or environment are added.
Byte/count limits and sink failures must be explicit; unmatched START means
unfinished/unknown. Mock-only tests alone cannot prove real capture integration.

This packet grants ZERO executions. No source rename, reviewed code, pipeline
availability or installed activation resets old budgets. A future full run needs
a separately reviewed exact source/helper and explicit finite successor allowance.
Keep all53 argv, tests/skips,420/750/900s limits,15-minute workflow and32MiB
outer output limit. No warm-source access, root-policy change, cloud spending,
runner registration, dispatch, merge or native/tenant promotion is included.

No phase-end effort change is due. Previous source-era checkpoints below are
retained history, not current grants or completion claims.

## Historical020 source checkpoint — MET-PERF-020 source preparation, October 1, 2026

Alpha 2 remains open. Accepted main `0314a684` has 190 unchanged packets. This
candidate adds only MET-PERF-020, not failed MET-PERF-019 or unaccepted PR144. It owns
bounded nested-test diagnostics, fresh authority checks without redundant
runner-bridge JSON parsing, carried-forward schema-lifecycle parity tests and
an exact 191-to-190 source inverse. Performance remains unmeasured.

MET-PERF-019 commit `106ae3ec` is frozen, local and unaccepted. LOCAL1 consumed
the first attempt in the shared schema-performance repair lineage and timed
out at 750 seconds during outer pytest: 52/53 commands, last visible 33%, one F
without a final traceback, no completed nested/outer summary. Independent
cleanup/custody checks closed; no acceptance PASS. The sanitized immutable
failure record is [retained here](../architecture/packet-schema-performance-inputs/prior-local-failure.json).

Source preparation grants zero runs. The cumulative 019+020 LOCAL ceiling is two:
019 consumed one and 020 may receive at most one separately reviewed, exact-source,
finite allowance (packet ordinal 1, lineage ordinal 2), never a reset or automatic
retry. No CI/exact-main allowance is automatic. Keep nested 420 / local 750 /
trusted 900 seconds and workflow 15 minutes, full tests and all isolation/freshness
checks unchanged.
The diagnostics identify START and report an inner timeout immediately when
observed; an outer kill can still leave START only. They are not qualification.

PR144/MET-LINUX-004 remains draft with three consumed LOCAL attempts and no
allowance transfer. Required CI capacity/admission, green merge, exact-main,
native Linux and product/tenant qualification remain separate open gates.
No model/effort change is due.

| Phase / ID | Status | Remaining gate |
|---|---|---|
| Alpha 2 / MET-PERF-019 | FAILED_LOCAL_FROZEN | Retain source and consumed attempt; no replay |
| Alpha 2 / MET-PERF-020 | ONGOING_SOURCE_PREPARATION | Freeze and review exact source; no execution grant |
| Alpha 2 / MET-LINUX-004, PR144 | BLOCKED_ALLOWANCE_EXHAUSTED | Preserve three failed attempts and separate runner work |
| Alpha 2 / required CI and exact-main | WAITING | Independently admitted capacity, complete checks and merge |
| Alpha 2 / native Linux and CONF-A2-001 | WAITING_PREREQUISITES | Fresh native and integrated profile evidence |

The following 019 source-era checkpoint is
retained verbatim as history, not a current execution instruction or PASS.


## Historical 019 source checkpoint — October 1, 2026

Accepted source main is `0314a684ba637fb205856d5fb5e50206071e647a`, the PR #143
source merge under its one-time exception. This is **not** required CI PASS,
installed Linux evidence or a transferable exception. Alpha 2 remains open.
`MET-PERF-019` is a separate **ONGOING_SOURCE_PREPARATION** packet on this base:
one invocation-local task-schema validator, exact error/freshness regressions,
and a reversible 191-to-190 source-history bridge. All 190 accepted packet YAML
and historical authority bytes remain unchanged. Speedup is unmeasured.

Draft [PR #144](https://github.com/caglarsubas/harness-onion/pull/144),
`MET-LINUX-004` at `614a08cfaf34ab0c37788231e03a44972f16727e`, is an unaccepted
diagnostic subject, not this packet's predecessor. Its three LOCAL attempts are
consumed. LOCAL3 completed the nested suite (4,902 passes, ten inherited skips)
but timed out during outer pytest at the installed 900-second boundary; only
52/53 commands ran. Cleanup is retained; acceptance did not pass. No LOCAL4,
allowance transfer, test omission or timeout increase is permitted. On October 1,
its required verify remained queued with zero registered repository runners.

This source preparation grants zero new execution attempts. The proposed finite
maximum LOCAL2 / CI2 / LOCAL_EXACT_MAIN1 remains inactive until independent
exact-source review and a finite owner-delegated execution allowance are bound
before reservation. Installed signed packet activation follows the durable
reservation and precedes launch; the owner allowance JSON is not a signature.
Inherited local/main750s, nested420s, trusted900s and workflow15min ceilings stay
unchanged. The old private930s supervisor is not an inherited allowance.
An independently merged repair would require explicit reconciliation of PR144's
old base/inverse before further work there; it does not certify the excluded
Linux runner-kit changes. Required CI capacity/admission and native Linux
qualification remain separate unpassed gates.

The next paragraph is the retained pre-PR-143 source checkpoint, not current
dispatch, runner availability or completion status.

Current source baseline: `945de93f89c94f42f1d63bff7997e3d0fa704fc4` on accepted main, the merge of MET-UNIFY-005 PR #140. Alpha 2 remains **open**. `MET-RUNNER-001` is a source-only development-CI capacity exception candidate, not an installed runner or permission to provision one. As observed on September 29, 2026, [PR #141](https://github.com/caglarsubas/harness-onion/pull/141) and [draft PR #142](https://github.com/caglarsubas/harness-onion/pull/142) have queued self-hosted `verify` jobs and the repository has zero registered runners. Their source/CI/merge, Linux native and tenant-acceptance evidence remain separate. The [bounded exception](alpha-2/CI_CAPACITY_EXCEPTION.md) requires an independently authorized cost ceiling, a separately reviewed and installed exact-job pre-checkout admission boundary, queue serialization, a qualified Linux guest and verified teardown; this publication supplies none of those operational facts. The next source packet is MET-RUNNER-001, while native AMD64 qualification and the W01/Alpha-2 product gates remain waiting.

The next paragraph is the retained pre-PR-140 source checkpoint, not current dispatch or completion status.

Accepted source baseline: 7a353b253bb257aa0abe2148e7fa62d7570f0b5a (PR #138). The roadmap-publication successor is MET-UNIFY-005; its presence in this branch is source work, not merged acceptance. The unpublished MET-UNIFY-001 local candidate at `2cb0b949ee82` exhausted LOCAL-1 and LOCAL-2. The separate unpublished MET-UNIFY-002 candidate exhausted LOCAL-1/2/3; its last isolated suite exposed a stale inherited 204-file assertion after the current YAML corpus became 205. Unpublished MET-UNIFY-003 [PR #139](https://github.com/caglarsubas/harness-onion/pull/139) passed LOCAL-1, then consumed CI-1 on a GitHub API failure before runner registration and CI-2 on a 15-minute cancellation; its runner was retired with zero registrations remaining. The CI log has a failure marker about 420 seconds after the nested predecessor test began, but cancellation prevented a final traceback; pytest was still active when the job stopped. Unpublished MET-UNIFY-004 local commit `8dbfdac` failed LOCAL-1 on a status-document packet-ID check and LOCAL-2/3 at the unchanged 750-second ceiling during outer pytest; no 004 CI or PR was started. These four candidates and their receipts remain historical evidence, none is a merged predecessor or the live 189th packet, and no allowance transfers to MET-UNIFY-005. Current development phase: **Alpha 2, open**. This page is the single current roadmap and progress entry point. The [indexed source crosswalk](alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md), [accepted source index](../architecture/unified-roadmap-source-index.json), and [exact preceding master](history/master-development-plan-7a353b2.md) retain the implementation detail and history.

## Product goal and first enterprise release

Build an Apache-2.0, modular harness platform that guides an enterprise from business understanding and reliable data to governed agents, evidence and acceptance. The platform must operate on tenant-owned Linux Kubernetes, K3s on existing VMs and OpenShift, including a physically disconnected environment. The same contracts can support operator-hosted SaaS or tenant public cloud on **pre-authorized existing capacity**. macOS is for development; Linux AMD64 and ARM64 need separate native qualification.

The architecture has **four planes, sixteen harnesses and thirteen repositories**. The model is a swappable core dependency, not a fifth harness plane; the administrative control plane is not H17. Every harness has one accountable repository owner. Harnesses in one repository may still have separate processes, images, configuration, permissions, stores, lifecycle and failure scope. The 28 canonical service records are a service inventory, not a count of all images, providers or privileged host components.

Require **at least one qualified baseline for every released harness capability** at the first enterprise release. All sixteen harnesses remain targeted in the Alpha-4 capability floor. A release deferment must identify the source requirement, affected capability, owner, phase and accepted disposition; it cannot silently shrink scope. Qualification binds exact provider/adapter version, capability, integration mode, deployment environment and independent evidence. Multiple alternatives can qualify. Progress toward three or four meaningful options per harness over subsequent waves; these are role-specific compatibility relationships, not 64 mandatory first-release technologies.

No cloud-account creation, billable provisioning, hosted-runner dependency, paid API, API-key requirement, runtime package/model download, external telemetry default, online license check or mutable artifact reference may enter the platform. Existing capacity and locally pinned open-source dependencies are required. The separately governed MET-RUNNER-001 exception concerns one externally operated development-CI guest only; it does not change this product rule or grant a VM, runner or CI PASS. An authorized, already-licensed on-premises external target may be attached only with demonstrated zero incremental charge; the platform cannot redistribute its proprietary code or manage its lifecycle.

The five original warm-start repositories remain untouched and reference-only under the existing source-reuse policy. No product implementation task may open, mount, execute or copy from them. Public endpoint attachment is not source-copy authority. A later import would need separately approved path-level legal and packet authority.

## Guided establishment and deployment

The common industry journey has eight ordered gates:

1. Deployment sovereignty and tenant isolation.
2. Business outcome, owner, workflow and measurable KPI.
3. Risk, regulation, classification and autonomy.
4. Domain vocabulary and canonical entities.
5. Data ownership, quality, completeness, freshness, provenance and access.
6. Integrations, protocols, credentials, tools and side effects.
7. Retrieval, memory, model, ML and orchestration requirements.
8. SLO, recovery, observability, evaluation and tenant acceptance.

The first sector pack is white goods. Sector overlays append to the common journey; tenant-specific answers determine applicable controls, technology and readiness. A mandatory predecessor finding that is OPEN, FAIL or STALE blocks dependent approval. Production control waivers document exceptions but never replace fresh required PASS evidence.

The UI and file workflow share the same schema and deterministic compiler:

**Questionnaire or YAML → TenantDemand → locked profile → reviewed change plan → signed minimal bundle → HarnessInstallation → observed status and evidence.**

The compiler produces exactly six outputs: profile.json, bom.json, install-plan.json, evidence-plan.json, explanation.md and profile.sha256. An active exclusive provider group requires one explicit accepted selector; a recommendation never chooses silently. Bundle composition includes only selected modules and their dependency closure. The current 87-record provider/module catalog is PLANNED: 59 packet-owned implementation dispositions, 23 tenant-supplied external records and five non-installable CONTRACT_ONLY entries. Missing release digests prevent installation or qualification.

| Integration mode | Platform responsibility |
|---|---|
| Built-in, platform managed | Install and manage a qualified provider only inside authorized existing infrastructure. |
| Built-in, externally operated | Manage the approved adapter and binding; preserve tenant ownership of the existing service. |
| Tenant custom adapter | Supply contracts, SDK, isolated artifact admission and independent conformance; tenant engineering owns the integration. |

Custom adapters are separate signed workers/services. They cannot shadow a core provider, run inside the administrative control plane, grant permissions, waive controls or certify tenant acceptance.

## Ownership and dependency policy

| R | Repository | Harnesses or cross-harness responsibility |
|---|---|---|
| R00 | harness-onion / Harness-Engineering | Architecture, planning, taxonomy, packets and release coordination |
| R01 | mas-harness-contracts | Public APIs, events, guidance rules, compiler, compatibility vectors |
| R02 | mas-harness-sdks | Python/TypeScript clients and adapter developer interfaces |
| R03 | mas-harness-industry-packs | Sector journeys, quality/regulatory guidance and fixtures |
| R04 | mas-harness-control-plane | Next.js setup, authenticated tenant overview, plane/harness detail pages |
| R05 | mas-harness-runtime-plane | H3 AI Gateway; H4 Experience & Interaction |
| R06 | mas-harness-model-plane | H2 Model & Inference within the runtime plane |
| R07 | mas-harness-knowledge-plane | H5 Domain; H6 Data Integration; H7 Retrieval; H8 Memory |
| R08 | mas-harness-execution-plane | H9 Protocol; H10 Orchestration; H11 Tools/Sandbox; H12 ML/Decision |
| R09 | mas-harness-trust-plane | H13 Security; H14 Governance; H15 Observability; H16 Assurance |
| R10 | mas-harness-operator | H1 Infrastructure & Runtime, including separately governed host modules |
| R11 | mas-harness-distribution | Minimal OCI assembly, locks, SBOM/license closure and air-gap transfer |
| R12 | mas-harness-conformance-labs | Independent compatibility, native, security, lifecycle and acceptance-candidate evidence |

The [repository graph](../architecture/repositories.yaml), [taxonomy](../architecture/taxonomy.yaml), [service catalog](../architecture/services.yaml), [provider catalog](../architecture/providers.yaml) and [runtime dependency graph](../architecture/dependency-graph.yaml) remain their machine authorities. Arrows mean consumer → provider. Keep contract-source, build-artifact, release-set and runtime-integration edges separate; unconditional graphs stay acyclic. The sole assurance callback exception never permits a source/build cycle.

Release contracts and compatibility vectors first, then SDKs/packs, affected services/operator, exact distribution set and independent conformance. Each cross-repository feature has one parent outcome and separate exact owner packets. A packet is one branch/PR with allowed paths, accepted predecessor versions/digests, direct-argv isolated acceptance, finite attempts and rollback. Repository merge is not harness qualification. R01 owns public contracts; R09 owns authoritative provider registry/promotion; R04 presents their management projection; R10 reconciles the verified installation; R11 packages; R12 qualifies.

The browser reads authenticated control-plane projections and never fans out to all planes. The control plane is outside the synchronous agent request path. The runtime gateway calls the selected model route or task orchestration; it does not retrieve data, assemble context or execute tools. Every service owns its durable state and migrations; no service writes another service’s database schema.

## Provider and research direction

The [provider adoption source](alpha-2/PROVIDER_ADOPTION_ROADMAP.md) retains the `MET-ADOPT-001` policy and its detailed alternatives. It is a historical/detail authority for those decisions, not a second current progress roadmap.

The [sixteen-row research map](alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md) and [adoption ledger](../architecture/research-adoption.json) identify papers, OSS upstreams, owner repositories, proposed packets and qualification gates. They are planning research, not evidence that a provider is installed. At least one qualified provider for each released capability is required; an internal module alone does not satisfy an OSS adoption claim. Preserve later alternatives in the [traceability crosswalk](alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md).

Initial directions include Ollama, llama.cpp and vLLM for H2; LiteLLM’s reviewed open-source compatibility surface for H3; AG-UI/CopilotKit for H4; RDFLib/pySHACL, Trino/Great Expectations/OpenLineage, LlamaIndex/pgvector and a governed memory candidate for H5–H8; MCP/A2A, a separately decided Temporal transition, Wasmtime/gVisor/Kata and local ML/optimization libraries for H9–H12; OPA/Presidio, MLflow integration, OpenTelemetry/Prometheus and Inspect for H13–H16. Milvus external attachment is a later retrieval option before any managed-installation proposal. Ollama attachment to the existing endpoint and managed installation require separate qualification. Framework fake-surface tests do not qualify pinned upstream packages.

Before building another general-purpose router, serving, workflow, retrieval or evaluation engine, publish a measured build-versus-integrate ADR. Failed upstream qualification leaves that option unqualified; it is not permission for unreviewed bespoke replacement. The existing PostgreSQL durable-execution source stays historical while R08 decides the Temporal successor, migration, history replay and single side-effect authority. H12’s competing prose API paths are **INTERFACE_NOT_PUBLISHED** until R01 releases a versioned decision contract and compatibility vectors. Closed-schema consumers require old/new vectors even for additive fields and retain the one-minor migration window.

Jev-style typed semantic judgment is an **optional proposal** across selected existing harnesses, not a fifth plane or H17. The official hosted proprietary Jev model is outside the shipped air-gapped, zero-bill baseline. Laya and SemIF require their own open-weight, license, backend, tokenizer, calibration, domain/language, abstention and independent qualification review; neither is currently selectable. Semantic scores may advise classification, route choice, retrieval relevance, memory proposals, decision features or evaluation. Deterministic policy, budgets, side effects and promotion retain authority. The proposed SEM packet IDs remain unpublished.

After the first enterprise release, consider E1 governed evidence-to-improvement, E2 optional behavior/taste distillation and E3 separately approved reinforcement-learning research. Operational evidence, user memory and eligible training data remain distinct; no trace becomes training input or promoted runtime behavior automatically.

## Phase roadmap and current position

The following is a **source-status checkpoint**, not proof of installed runtime or tenant acceptance. PR #138 placed MET-ENFORCE-003 on accepted source main. Its old “ongoing publication” headers are historical. Alpha 2 is still open.

The [item-level backlog](../architecture/unified-roadmap-backlog.json) records phase, owner, status, predecessors, blocker and planned evidence reference for every published packet and proposal; the [requirement dispositions](../architecture/unified-requirement-dispositions.json) join indexed source sections to ownership and unresolved delivery mappings. All accepted source sections now have reviewed delivery and acceptance-plan dispositions; 38 explicit unresolved markers retain actual future design, packet, native-qualification or provider obligations. They do not count as implementation or acceptance, and the affected work cannot advance until its exact owner packet closes them.

| Phase | ID or workstream | Current status | Deliverable / blocking fact |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundation packets | DONE_RECORDED | Historical source/offline foundation; installed-foundation and production-overview evidence are separate carryovers |
| Alpha 2 preparation | MET-ENFORCE-003 | MERGED_SOURCE_RECORDED | PR #138 on accepted main; reviewed W01 candidate remains a design, not a native enforcement proof |
| Alpha 2 preparation | MET-UNIFY-001 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Unpublished failed local candidate; two LOCAL attempts consumed, no PR/CI/merge or budget transfer |
| Alpha 2 preparation | MET-UNIFY-002 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Unpublished candidate; three LOCAL attempts consumed, stale 204-file assertion retained |
| Alpha 2 preparation | MET-UNIFY-003 | BLOCKED_CI_ALLOWANCE_EXHAUSTED | PR #139 unmerged; LOCAL PASS, CI-1 transport failure and CI-2 15-minute cancellation; no runner remains |
| Alpha 2 preparation | MET-UNIFY-004 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Local commit only; LOCAL-1 status-check failure and LOCAL-2/3 750-second timeouts; no PR, CI or merge |
| Alpha 2 preparation | MET-UNIFY-005 | MERGED_SOURCE_RECORDED | PR #140 on exact accepted main `945de93`; source history only, not Linux or tenant qualification |
| Alpha 2 CI capacity | MET-RUNNER-001 / PR #143 | MERGED_SOURCE_EXCEPTION | Source on `0314a684`; one-time merge exception consumed, not required CI PASS, installed runner or native qualification |
| Alpha 2 validation | MET-PERF-019 | FAILED_LOCAL_FROZEN | Unaccepted source and consumed LOCAL1 retained; no replay or transferred allowance |
| Alpha 2 validation | MET-PERF-020 | FAILED_LOCAL_FROZEN | Shared allowance and additional custody exception consumed; failure records retained without replay |
| Alpha 2 validation | MET-PERF-021 | FAILED_LOCAL_FROZEN | LOCAL1/1 failed readiness before pytest; source, evidence and cleanup retained |
| Alpha 2 validation | MET-PERF-022 | FAILED_LOCAL_FROZEN | LOCAL 1/1 failed historical test identity checks before pytest; source and evidence retained |
| Alpha 2 validation | MET-PERF-023 | FAILED_LOCAL_FROZEN | LOCAL1/1 timed out with invalid diagnostics; exact failure and cleanup records retained |
| Alpha 2 validation | MET-PERF-024 | FAILED_LOCAL_FROZEN | Diagnostic fixes narrowly exercised; whole run timed out at52/53, cleanup confirmed |
| Alpha 2 validation | MET-PERF-025 | FAILED_LOCAL_FROZEN | Nested and outer deadlines exhausted;52/53 commands and independently confirmed cleanup |
| Alpha 2 validation | MET-PERF-026 | SOURCE_PREPARED_AWAITING_REVIEW | Snapshot decode source prepared; final independent review and full execution gates remain |
| Alpha 2 runner repair | MET-LINUX-004 / PR #144 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | All three LOCAL attempts consumed; preserve frozen source/results, separately queued CI and unpassed Linux gates |
| Alpha 2 CI capacity | MET-UNIFY-008 / PR #141 | BLOCKED_SELF_HOSTED_CI | Source PR open; `verify` queued with no registered runner |
| Alpha 2 CI capacity | MET-LINUX-003 / PR #142 | BLOCKED_SELF_HOSTED_CI | Draft source PR open; `verify` queued on the same labels; queue must be serialized before one-job admission |
| Alpha 2A | W01 | ONGOING_DESIGN | Resolve G04–G07/G09; E01–E12 remain OPEN_UNPROVEN |
| Alpha 2A | W02–W07 | WAITING_EXACT_PACKETS | Interface, implementation, packaging and native proof labels, not executable YAML |
| Alpha 2A | CONF-FIX-010 | BLOCKED_SAFE_DESIGN | Zero product attempts; requires separately reviewed safe design and bounded packet authority |
| Alpha 2A | CONF-LIVE-004/005/006 | WAITING_PREREQUISITES | Native probes, package handoff and trusted campaign integration |
| Alpha 2A | CONF-LINUX-001 native AMD64 | NOT_RUN_ENV_UNAVAILABLE | Fresh real-Linux PASS gates runtime coding of CTRL-INTEGRATE-001, MODEL-001, EXEC-001 and RUN-001; ARM64 separate |
| Alpha 2B | Seven EXT proposal IDs | WAITING_PACKET_PUBLICATION | Contract-first provider/adapter/binding qualification, registry, UI, packaging and mode-aware reconciliation |
| Alpha 2B onward | Sixteen OSS adoption proposal IDs | WAITING_PACKET_PUBLICATION | Owner-specific actual pinned upstream integrations and qualification |
| Alpha 2B onward | JEV/Laya/SemIF SEM proposals | WAITING_PACKET_PUBLICATION | Optional local semantic contracts, adapters and independent evidence |
| Alpha 2 acceptance | CONF-A2-001 | WAITING | Integrated cited read-only white-goods profile, installed foundations and real overview |
| Alpha 3 | Governed action / CONF-A3-001 | WAITING | Approval, memory, sandbox, tools, decision service and full interaction |
| Alpha 4 | Enterprise campaigns / CONF-WG-001 | WAITING | Qualified baseline per released capability, disconnected install, lifecycle/security and independent tenant acceptance |
| Post-release | E1–E3 and provider expansion | DEFERRED | Governed improvement research and additional meaningful provider options |

Historical no-go and exhausted work stays closed: PLAN-CANON-001 is a recorded no-go; CONF-PERF-005 is unauthorized; CONF-FIX-007/008 retain prior outcomes; CONF-FIX-009 consumed its local allowance. No old attempt allowance transfers to a successor.

### Counted near-term checklist

These checkboxes count only the named deliverable at the stated evidence level. They are not a platform-completion percentage or permission to dispatch.

- [x] Phase 0 / Alpha 1 · MET-P0-002 · Record the five-source, license and provenance foundation in historical source evidence.
- [x] Alpha 2 · MET-ENFORCE-003 · Merge the reviewed host-interface source candidate as PR #138 on accepted main.
- [x] Alpha 2 · MET-UNIFY-005 · Publish this unified roadmap with exact historical inverse, independent review, declared offline acceptance, required CI and exact-main evidence at `945de93`.
- [ ] Alpha 2 · MET-RUNNER-001 · Publish the source-only bounded development-CI admission contract with exact 189-packet history, isolated acceptance, required CI and exact-main evidence.
- [ ] Alpha 2 · MET-PERF-028 · Complete exact-bytes authority recheck reuse and linear uniqueItems, independent review and separately authorized full LOCAL/CI/exact-main; preserve failed019–027/PR144 and unresolved timing/native Linux gates.
- [ ] Alpha 2 · MET-LINUX-005 · Complete the runner-contract repair on accepted 028 main, independent review and separately authorized full LOCAL/CI/exact-main; preserve PR144 attempts and unresolved native Linux gates.
- [x] Alpha 2 · MET-VERIFY-001 · Publish the owner-operated required verify contract and pass its own required verify through the owner's App; exact-main and native Linux remain separate.
- [ ] Alpha 2 · MET-PERF-029 · Make history-chain authority rechecks linear with unchanged freshness and refusal semantics; pass required verify through the owner's App.
- [ ] Alpha 2A · W01 · Resolve G04–G07/G09 and adopt a versioned host interface only after the required independent review.
- [ ] Alpha 2A · CONF-FIX-010 · Complete safe design and exact authority before any product attempt.
- [ ] Alpha 2A · CONF-LIVE-004 · Produce the exact native-probe source implementation and separately qualify it.
- [ ] Alpha 2A · CONF-LIVE-005 · Produce a reproducible selected package and operator handoff.
- [ ] Alpha 2A · CONF-LIVE-006 · Integrate the external trusted campaign path.
- [ ] Alpha 2A · CONF-LINUX-001 · Obtain fresh native Linux AMD64 PASS for the blocked runtime-coding gate.
- [ ] Alpha 2 · CTRL-INTEGRATE-001 · Complete production tenant overview and durable status projection after its Linux gate.
- [ ] Alpha 2 · CONF-A2-001 · Qualify the exact integrated read-only profile and inherited foundation evidence.
- [ ] Alpha 3 · CONF-A3-001 · Qualify governed action and interaction.
- [ ] Alpha 4 · CONF-WG-001 · Produce an unsigned white-goods tenant-acceptance candidate after required enterprise campaigns.

## Retained MET-PERF-019-era launch order (historical; not current dispatch)

1. Prepare MET-PERF-019 as one source-only packet against accepted main `0314a684`: exact 92 paths, 190 immutable predecessor YAML, reversible current-to-190 projection, inherited 52 commands plus its one declared validator, and source/error-parity review. No executed diagnostic, selected test or new attempt follows from source publication.
2. Bind independently reviewed exact-source finite execution authority before any reservation. Complete the unchanged full isolated acceptance, required self-hosted CI, protected green merge and separate exact-main evidence. A separately authorized operator must prove Linux host image, root-owned signed admission, throughput, egress/cost bounds and automatic plus independent teardown before runner registration. Refresh and serialize the actual queue before exact-job admission. Preserve PR144's failed history and require its own later base/scope reconciliation. Dashboard source registration remains a separately owned orchestrator packet.
3. Continue W01 design and the existing conformance correction chain under their exact approved packet boundaries. W02–W07 and unpublished EXT/OSS/SEM proposals are not dispatch targets.
4. Run native Linux campaigns only with the external trusted signed launcher, pre-existing authorized capacity and the exact server-side zero-cost admission. Missing target/backend is NOT_RUN_ENV_UNAVAILABLE, never PASS or permission to provision.
5. Start an eligible product packet only after its published predecessor contracts, immutable locks, required native gate and repository policy are satisfied. Release qualification and tenant acceptance require their own exact evidence.

All local packet acceptance runs use the preinstalled deny-all-outbound OS-isolated launcher, direct argv and the same process tree for prefetch and acceptance. Warm snapshots remain denied. Live campaign evidence may cover only declared deployment, runtime, security, assurance and unsigned tenant-candidate axes. Source, unit, PR, merge, SBOM/artifact, signature/release, deployment, runtime, assurance and tenant acceptance are independently recorded. A waiver never replaces a fresh required production PASS.

Required cross-harness acceptance includes unknown-outcome retry safety, streaming cancellation acknowledgement, memory deletion surviving restore, staged-versus-committed data, budget reservations, stateful-provider migration and rollback, real tenant RLS, stale overview projections, local assets, WCAG 2.2 AA, offline installation, security/upgrade campaigns and independent tenant acceptance. Thresholds and profile scope must be frozen in the owning packet before tests.

Alpha 2 has not ended, so the requested phase-end model-effort reminder is **NOT_DUE**. Keep the selected model/effort unchanged; at phase closeout report the next phase’s recommended effort without switching it automatically.

## Retained source-navigation keys (historical)

The links and exact tokens below preserve predecessor source-navigation checks. Their recorded labels—including `WAITING_PREDECESSOR_CORRECTION`, `NOT_AUTHORIZED` and `BLOCKED_LOCAL_BUDGET_EXHAUSTED`—describe earlier checkpoints, **not** today's dispatch authority or the current phase status above.

| Detailed source | Retained publication keys |
|---|---|
| [Paper/repository map](alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md) | `MET-ADOPT-002`; `WAITING_PREDECESSOR_CORRECTION` |
| [Proxy diagnostics](alpha-2/PROXY_PERFORMANCE_DIAGNOSTICS.md) | `MET-PERF-006` |
| [Canonical repair](alpha-2/CANONICAL_REPAIR_PLAN.md) | `MET-PERF-007`; `NOT_AUTHORIZED` |
| [Backend timing](alpha-2/BACKEND_TIMING_DIAGNOSTICS.md) | `MET-PERF-008`; `CONF-DIAG-002`; `NOT_AUTHORIZED` |
| [Completion profiling](alpha-2/COMPLETION_PROFILING.md) | `MET-PERF-009`; `CONF-DIAG-003`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Validation performance](alpha-2/VALIDATION_PERFORMANCE_REPAIR.md) | `MET-PERF-010`; `WAITING_PREDECESSOR_CORRECTION` |
| [Document repair plan](alpha-2/DOCUMENT_REPAIR_PLAN.md) | `MET-PERF-011`; `CONF-DIAG-003`; `INCOMPLETE_DIAGNOSTIC_RETAINED`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Document repair authority](alpha-2/DOCUMENT_REPAIR_AUTHORITY.md) | `MET-PERF-012`; `CONF-PERF-006`; `CONF-BENCH-002`; `WAITING_META`; `BLOCKED_LOCAL_BUDGET_EXHAUSTED` |
| [Benchmark transport](alpha-2/BENCHMARK_TRANSPORT.md) | `MET-PERF-013`; `CONF-BENCH-003`; `NON_DISPATCHABLE`; `CANDIDATE_FROZEN` |
| [Factory diagnostics](alpha-2/FACTORY_DIAGNOSTICS.md) | `MET-PERF-014`; `CONF-DIAG-004`; `BLOCKED_LOCAL_FAILURE` |
| [Guard cost repair](alpha-2/GUARD_COST_REPAIR.md) | `MET-PERF-015`; `CONF-FIX-009`; `CLOSED_PARTIAL_DIAGNOSTIC` |
| [Accounting scope](alpha-2/ACCOUNTING_SCOPE_AMENDMENT.md) | `MET-PERF-016`; `CONF-FIX-009` |
| [Guard traversal](alpha-2/GUARD_TRAVERSAL_REPAIR.md) | `MET-PERF-017`; `CONF-FIX-010` |
| [Catalog traversal](alpha-2/CATALOG_TRAVERSAL_REPAIR.md) | `MET-PERF-018`; `BLOCKED_SAFE_DESIGN` |
| [Local acceptance](alpha-2/LOCAL_ACCEPTANCE_REVALIDATION.md) | `MET-ACCEPT-001`; `CONF-LIVE-003` |
| [Conformance publication](alpha-2/CONFORMANCE_PUBLICATION.md) | `MET-PUBLISH-001`; `CONF-LIVE-003` |
| [Conformance completion](alpha-2/CONFORMANCE_COMPLETION.md) | `MET-REPAIR-017`; `WAITING_PREDECESSOR_CORRECTION` |
| [Completion integration](alpha-2/COMPLETION_INTEGRATION.md) | `MET-REPAIR-018`; `CONF-FIX-008`; `DONE_SOURCE_GATES` |
| [Observation/enforcement](alpha-2/OBSERVATION_ENFORCEMENT_PUBLICATION.md) | `MET-REPAIR-019`; `BLOCKED_SAFE_DESIGN` |
| [Enforcement integration](alpha-2/ENFORCEMENT_INTEGRATION.md) | `MET-ENFORCE-001`; `BLOCKED_SAFE_DESIGN` |
| [Host-interface publication](alpha-2/HOST_INTERFACE_PUBLICATION.md) | `MET-ENFORCE-003`; `BLOCKED_SAFE_DESIGN` |
