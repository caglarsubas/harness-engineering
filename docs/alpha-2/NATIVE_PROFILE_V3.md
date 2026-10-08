# Alpha 2A — W02a-F native qualification record v3 (MET-ENFORCE-010)

> Current-status page for the W02a-F part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and
> phase status; the adopted v2 record is on the [W02a page](NATIVE_PROFILE_V2.md).

W02a-F: **ADOPTED_DATA_CONTRACT.** The successor record `planeon.internal.native-qualification/v3` passed its independent
source-only review (round 6, PASS_FOR_SOURCE_PUBLICATION). It closes every finding carried to W02a-F: the W02a
review's P1 and P3-P7, W02g's P7 carries and the network-policy agent identity, and W02e's label constants, E1
effective-program census and K1 boot-entry discriminator. The v1 and v2 contracts are byte-identical. It is
DATA_CHECK_ONLY: nothing is observed, installed or qualified, and all E01-E12 remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/native-profile-v3/README.md): what v3 changes and why, the v6.12 cgroup attach types, the
  K1 and E1 scope statements, caller obligations, replayed v2 cases, migration and the review dispositions.
- [Schema](../../architecture/native-profile-v3/qualification.schema.json): `urn:planeon:internal:native-qualification:v3`.
- [Vectors](../../architecture/native-profile-v3/vectors.json): 4 positives, 207 negatives (all 131 v2
  negatives replayed), 9 accepted variants, 14 cross-version and 14 migration cases.
- Reference model `scripts/native_qualification_v3.py`, written as reviewed edits of the unchanged v2 model.

Key rules:
- **Code identity:** no role closure lists another role's executable, and native-only roles list nothing from the
  interpreter tree. Every cgroup member's running image is its role's image, and one inode names one file.
- **Census:** the slice census agrees with the role captures and the slice's `nr_descendants`. The slice holds no process
  of its own.
- **Tasks:** member thread counts equal `pids.current`, within `pids.max`.
- **Backend:** the unit fixture profile is test-only, backend cgroups never nest, and API identities come from the W02g
  closure.
- **Labels:** W02e's label values are schema constants.
- **BPF:** no program is effective on a role cgroup on any of the 22 other cgroup attach types of Linux v6.12.
- **Boot:** every capture is taken on the recorded enrolled boot entry, whose command line carries `lockdown=integrity`
  and never selects `planeon-maintenance.target`.
- **Migration:** v3 needs a maintenance reboot and fresh nonces against the complete v1 and v2 histories.

## Independent review

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | CHANGES_REQUIRED (2 MINOR, 7 NOTE) | `review-round1.json` | `round1/` |
| 2 | CHANGES_REQUIRED (1 MINOR, 6 NOTE) | `review-round2.json` | `round2/` |
| 3 | CHANGES_REQUIRED (1 MINOR, 2 NOTE) | `review-round3.json` | `round3/` |
| 4 | CHANGES_REQUIRED (1 MINOR, 1 NOTE) | `review-round4.json` | `round4/` |
| 5 | CHANGES_REQUIRED (1 MINOR, 3 NOTE) | `review-round5.json` | `round5/` |
| 6 | PASS_FOR_SOURCE_PUBLICATION (3 NOTE) | `review-round6.json` | current files |

The reviewer was a separate agent that did not author the contract. It worked read-only against the exact bytes and the
Linux v6.12 and systemd v256 sources. It replayed every vector independently from the JSON files, probed the closure
with mutated bundles and mutated models, and checked every kernel and loader fact the README states. The
[status record](../../architecture/native-profile-v3/status.json) derives the adoption state from the final verdict.
`scripts/validate_native_profile_v3.py` replays the contract and checks that derivation.

## Carried findings (none blocking)

- **R6-1** (NOTE) → W02a-F2 (restate the K1 guarantee in decision-2 terms: root=, ro and rw drive only systemd fixed root-mount units; the binding fixes the initrd= and root= words; name initrd= and security= in the environment sentence) and W03/T04 (the kernel image or UKI each entry loads with its built-in initramfs, embedded .initrd and .cmdline and addons; systemd-stub sidecars /.extra/global_credentials, sysext and confext; network roots)
- **R6-2** (NOTE) → W02a-F2: restore that on a non-confidential VM systemd-boot and systemd-stub append SMBIOS kernel-cmdline-extra words to /proc/cmdline, which are part of both declared entries and must be inside the grammar
- **R6-3** (NOTE) → W02a-F2: bound-pair grammar and lockdown negatives (or list them as also breaking the binding); maintenance entries differing only by a grammar word or by word order; optional negatives for security=apparmor, rootfstype= and initrd=<addr>,<size>, accepted root=LABEL= and root=/dev/

## Still open

All E01-E12 and T01-T08. Native observation of every v3 field and the measured boot (T04). The production implementation
profile, the backend policy module and the distribution (W03). The seccomp filters (W02d). W03-W07 remain gated. Alpha2
remains open; model-effort transition NOT_DUE.
