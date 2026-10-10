# Review brief — W03-0, round 2

Subject:
- `architecture/backend-distribution/` (README.md, selection.json) and `scripts/backend_distribution.py`;
- new in this round: `architecture/w03-plan/` (README.md, plan.json) and `scripts/w03_plan.py`, recording the owner's
  toolchain and scope decisions, a W03 obligation register and the packet plan.

Round 1 (`review-round1.json`, bytes in `round1/`) returned CHANGES_REQUIRED. Please check:
1. Each round-1 finding's disposition (README, "Round-1 findings and dispositions"), particularly:
   - SC01 at etcd v3.7.2 (`68c065e562994b89e333e77b039ad066f933c586`): `server/embed/config.go:87, :608-609, :961-965`,
     `server/embed/etcd.go:576, :750-753`, `server/etcdmain/config.go:251`;
   - the license reviews against the owner's decision Q-L (L-a);
   - NRI and every containerd listener (SC11).
2. The etcd 3.7.2 pins: `SHA256SUMS` and the tag-to-commit resolution.
3. The check modules: re-run your round-1 mutation probes against both modules.
4. The plan record:
   - the Rust 1.99.0 start-up re-check against W02d v2's analysed reference, Rust 1.90.0 with musl 1.2.5. Verify at
     `b940084d` against `1159e78c`: `library/std/src/sys/pal/unix/mod.rs` and `stack_overflow.rs`,
     `library/std/src/sys/thread/mod.rs`, and musl v1.2.5 `src/env/__libc_start_main.c` and `src/thread/pthread_create.c`;
   - the musl thread flags against W02d's NATIVE_STATIC thread rule;
   - whether the obligation register misses an obligation the W02 contracts carry to W03, or names a wrong source line;
   - whether the packet plan is consistent with the owner's decisions.

Read-only. Network reads of public sources are fine; avoid large downloads. No sudo, no edits.
