# Alpha 2 — sector catalog overlay (CATALOG-BANK, MET-SECTOR-002)

> Current-status page for the SECTOR-D1 catalog follow-ups. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md)
> gives packet status; [sector direction](SECTOR_DIRECTION.md) gives every SECTOR-D1 disposition.

Owner decision SECTOR-D1 made banking the first and only release sector. MET-SECTOR-001 listed eight exact catalog
follow-ups and kept the catalogs byte-identical. The first design applied them in place and passed content review,
but its build failed: older validators read `architecture/providers.yaml` and `architecture/services.yaml` from disk as
immutable inputs, and 36 earlier architecture records pin them. Owner decision (via the lane monitor): an overlay.

- **The catalogs stay byte-identical.** Older validators keep reading the base bytes.
- **The overlay record.** `architecture/sector-catalog/overlay.json` gives the banking-era view: seven follow-ups applied
  as exact, counted substring replacements, with the base and effective bytes pinned by sha256. The pack manifest
  path stays deferred.
- **The reference module.** `scripts/sector_catalog.py` checks one era through an injected byte reader and packet set.
  Banking-era consumers must read the catalogs only through `effective_bytes` and `effective_catalog`, which run that
  check on the current tree first.
- **The deferral.** It is derived from `implementationOwnership` and `successorProposals`: the pack manifest path is
  bound to the published IND-WG-005 and blocked by the unpublished IND-BANK-005. Until a reviewed revision of the
  module and the overlay schema rebinds that implementation, the consumer gate refuses a published IND-BANK-005
  whatever the overlay contains (review round 4, note R4-N1).
- **The R11 notice.** `docs/repositories/11-mas-harness-distribution.md` carries the sector-direction notice that the
  MET-SECTOR-001 review asked for. Publishing DIST-BANK-001 requires a revised notice, or one re-pointed to a
  still-unpublished successor (review round 4, note R4-N2).
- **Review.** The overlay passed independent review in round 4 (PASS_FOR_SOURCE_PUBLICATION), after three
  CHANGES_REQUIRED rounds. `architecture/sector-catalog/status.json` records all four rounds.

The new layer `scripts/validate_sector_catalog.py` runs the reviewed module from its own era's bytes, so later packets
keep it valid through projection. Its test guards the consumer rule:
- only frozen readers name the catalogs;
- the records that pin or name them are frozen;
- consumers use only the public API, and no module attribute is reassigned;
- readiness's catalog semantics hold on the effective catalogs.

Nothing about the banking pack, its manifest, profile installation or tenant acceptance exists yet; every SECTOR-D1
successor stays an unpublished proposal.
