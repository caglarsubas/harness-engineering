# Sector catalog overlay — CATALOG-BANK v2 (MET-SECTOR-002), round 1

Status: **CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. This changes effective identifiers and text only.
- No catalog byte changes.
- No banking pack, manifest, profile installation or tenant acceptance exists.
- Every SECTOR-D1 successor stays an unpublished proposal.

Owner decision SECTOR-D1 (October 7, 2026) made banking the first and only release sector. MET-SECTOR-001 recorded every
disposition in `architecture/sector-direction.json`. It left the provider and service catalogs byte-identical and listed
eight exact `catalogFollowUps` for a later packet.

## Why an overlay (v2)

The first design (v1) renamed the catalog entries in place, and its content review passed. The packet build then
failed:
- `architecture/providers.yaml` and `architecture/services.yaml` have been unchanged since Phase 0;
- older validators read them from disk as immutable inputs: packet_scalar_repair, proxy_contract, successor_inventory,
  live_backend_readiness and custody_handoff;
- about 33-35 architecture records and scripts pin them;
- the history-chain inverse does not reach those reads.

Owner decision (via the lane monitor): keep the catalogs byte-identical, and give the banking-era view through a
reviewed overlay.

## The overlay

- **`overlay.json`** (`planeon.internal.sector-catalog-overlay/v1`) pins:
  - the SHA-256 of `architecture/sector-direction.json`;
  - each catalog's base bytes (`base`) and effective bytes (`effective`).
  It records the eight follow-ups, in the exact text of `catalogFollowUps` (see the table).
- **`scripts/sector_catalog.py`** applies the overlay.
  - `effective_bytes(path, raw)` checks the base digest, then replaces each applied `current` with its `proposed` text.
    It requires exactly the recorded number of occurrences, and that the proposed text is absent beforehand. It then
    checks the effective digest.
  - `effective_catalog(path)` parses the effective YAML.
  - `check()` verifies that:
    - the overlay covers exactly the SECTOR-D1 follow-ups;
    - no white-goods term (SECTOR-001's detection pattern) remains in any effective catalog, except the deferred entry;
    - the deferred binding is unchanged;
    - the R11 notice is present.
- Banking-era consumers (IND-BANK-001..005, BANK-PACK, CONF-BANK-001, DIST-BANK-001) read catalogs only through this
  module. Older validators keep reading the base bytes.

| File | Current (base) | Effective | Disposition |
|---|---|---|---|
| `architecture/providers.yaml` | `industry.white-goods` (5 occurrences) | `industry.banking` | APPLIED_BY_OVERLAY |
| `architecture/providers.yaml` | `imply.white-goods-guidance` | `imply.banking-guidance` | APPLIED_BY_OVERLAY |
| `architecture/providers.yaml` | `packs/white-goods/manifest.json` | (unchanged) | DEFERRED until IND-BANK-005 is published |
| `architecture/providers.yaml` | `profile.whitegoods-readonly-amd64` | `profile.banking-readonly-amd64` | APPLIED_BY_OVERLAY |
| `architecture/providers.yaml` | `Read-only white-goods assistant` | `Read-only banking assistant` | APPLIED_BY_OVERLAY |
| `architecture/services.yaml` | `white-goods semantic vectors` | `banking semantic vectors` | APPLIED_BY_OVERLAY |
| `docs/PROVIDER_MODULE_CATALOG.md` | `profile.whitegoods-readonly-amd64` | `profile.banking-readonly-amd64` | APPLIED_BY_OVERLAY |
| `docs/PROVIDER_MODULE_CATALOG.md` | `White-goods pack` | `Banking pack` | APPLIED_BY_OVERLAY |

The base catalogs hold 12 white-goods matches in total: 9 in providers.yaml, 1 in services.yaml and 2 in the module
catalog page. The seven applied entries cover 11 of them, and the deferred entry covers the last one.

**Why the pack manifest path is deferred** (unchanged from v1 and its review):
- `artifact.platform.industry-pack` is a `REPOSITORY_PACKET` implementation bound to deliverable 0 of the published
  packet IND-WG-005.
- `validate_readiness` requires a published task packet whose `allowedPaths` cover the implementation path.
- IND-BANK-005, the successor proposal, is not published.
- `CONTRACT_ONLY` is not admissible either, because the profile fixtures use the module.

The entry changes when IND-BANK-005 is published; `check()` refuses if it is published while the overlay still defers.

## Distribution notice

As in v1, which passed review, `docs/repositories/11-mas-harness-distribution.md` gets the sector-direction notice
that the MET-SECTOR-001 round-2 review asked for (finding m1), plus a pointer from the DIST-004 list item to
DIST-BANK-001. In that list item the identifier is written plain, without backticks, so that readiness does not count
it as a declared packet. `sector-direction.json` admits only MET-SECTOR-001's own files as `directionDocs`, so
`overlay.json` records the notice in `distributionNotice`. That doc has been changed through the history chain before
(MET-ENFORCE-003), so the packet's inverse projects it for the older validators.

## Packet (after review)

- A new history-chain layer, `scripts/validate_sector_catalog.py`, runs `check()` and its test.
- Its test adds a guard: no script reads the catalogs directly unless it is one of the allowlisted older readers
  (readiness, reuse, provider_adoption, sector_direction, zero_bill_scan) or goes through `sector_catalog`.
- A current-state page.
- The usual mechanics.
