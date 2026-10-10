# Alpha 2A — independent enforcement test plan (W04-0, MET-ENFORCE-022)

> Current-status page for W04-0. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet status; the
> plan is [`architecture/enforcement-test-plan/`](../../architecture/enforcement-test-plan/README.md).

W04 writes the independent adversarial tests for the host enforcement modules that W03 builds. W04-0 is its plan, as
reviewed data, under the owner's decisions of 2026-10-10 (via the lane monitor):

- **D-R12**: the test source lives in R12 `mas-harness-conformance-labs`. The plan records R12's verification route as
  pending an owner decision; since its review the owner has installed the repository-aware verifier VERIFIER-EXT,
  which R12 adopts through its own bootstrap PR.
- **D-TOOL**: Python 3.12 and pytest for the source and offline groups; static Rust+musl probe binaries for the native
  TG-04 and TG-05 probes.
- **D-MAP**: eight test groups, TG-01 to TG-08, traced against the obligations E01-E12. W04 delivers test source and the
  offline-runnable part; all native execution is W06's.
- **D-OW** and **D-OW-1 = A**: the observation windows are the R12 reader's calls. W04-0 fixes the register's schema;
  W04-7 fills the register of the reader's current calls at a pinned baseline after W05, and W07 adds the removal half.
- **D-ID**: new ids TG-nn and OW-nn.

The plan's packets are W04-0 (this one), W04-1 to W04-6 (test source in R12) and W04-7 (the register). Independence: of
W03's work the plan reads only the merged distribution selection record. Review: four independent rounds, the last
PASS_FOR_SOURCE_PUBLICATION with three notes, all carried in the status record.

The new layer `scripts/validate_enforcement_test_plan.py` binds every reviewed file and every plan input by digest,
checks the review binding, then executes the plan model from this era's reviewed bytes and runs both of its checks,
`check()` and `check_publishable()` (review round 4, R4-1). DATA_CHECK_ONLY: no test is written or run, the register is
empty, and every E01-E12 obligation stays OPEN_UNPROVEN.
