# Alpha 2A — license-policy amendment LIC-HOST-A1 (MET-ENFORCE-021)

> Current-status page for LIC-HOST. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet status; the
> record is [`legal/license-policy-amendment/`](../../legal/license-policy-amendment/README.md).

The W03 backend distribution (W03-0) keeps the official upstream binaries, so their statically linked system libraries
and the host's nft need license decisions the base policy does not make. The owner decided Q-L (L-a), Q-L2 (L2-a) and
Q-L3 (L3-a) on 2026-10-10, via the lane monitor. The base policy `legal/third-party-license-policy.yaml` is pinned by
digest in 32 architecture records, and `scripts/validate_reuse.py` pins its version, so it stays byte-identical. The
amendment is a reviewed overlay instead:

- **A host-OS and static system library class.** Each named component is accepted only under its decided license, in its
  decided kinds, in upstream-pinned custody and, when statically linked, only inside its decided official binaries:
  - glibc (LGPL-2.1-or-later, as a host library or static in containerd, pause and runc);
  - libseccomp (LGPL-2.1-only, static in runc only);
  - libgcc and libgcc_eh (GPL-3.0-or-later WITH GCC-exception-3.1, static in the three binaries);
  - libnftnl (GPL-2.0-or-later) and libmnl (LGPL-2.1-or-later), as host libraries of nft.
- **Explicit-review decision records** for nft and libnftables (GPL-2.0-only) and gmp (LGPL-3.0-or-later), scoped to those
  subjects and kinds.
- **Rules.** The OR-choice rule ranks the accepted alternatives, and the owner-named elections are bound to their
  components: libpathrs elects MPL-2.0 in runc, gmp elects LGPL-3.0-or-later. Every AND term must be accepted. A legacy
  "A/B" crate field reads as "A OR B". Precedence never weakens the base's denials.
- **A component-scoped SPDX classifier** (`scripts/license_amendment.py`), with 88 classification vectors.

Review: four independent rounds. The first three returned CHANGES_REQUIRED; round 4 returned PASS_FOR_SOURCE_PUBLICATION
on `c12fa44`. Carried: the musl target's GCC start-up objects (HE-001), the SBOM package-name mapping (HE-008), and SC13
(W02g-F2).

The new layer `scripts/validate_license_amendment.py` first binds every reviewed file, round copy and review record, the
base policy and `safe_yaml` by digest, and checks the adoption record. It then executes the classifier from this era's
reviewed bytes, with this era's `safe_yaml`, and requires its result to carry the owner's decisions. DATA_CHECK_ONLY:
nothing is released, and the base policy keeps every outcome it lists.
