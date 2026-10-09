# Sector catalog overlay — CATALOG-BANK v2 (MET-SECTOR-002), round 2

Status: **CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. Round 1 (`round1/`) returned CHANGES_REQUIRED; see "Round 1"
below. This changes the effective catalog identifiers and text, plus a notice in the R11 distribution plan.
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
- 36 architecture records pin them (no script pins their digest);
- the history-chain inverse does not reach those reads.

Owner decision (via the lane monitor): keep the catalogs byte-identical, and give the banking-era view through a
reviewed overlay.

## The overlay

- **`overlay.json`** (`planeon.internal.sector-catalog-overlay/v1`) pins:
  - the SHA-256 of `architecture/sector-direction.json`;
  - each catalog's base bytes (`base`) and effective bytes (`effective`).
  It records the eight follow-ups, in the exact text of `catalogFollowUps` (see the table).
- **`scripts/sector_catalog.py`** applies the overlay.
  - `check(read, packets)` validates one era through an injected byte reader and packet set. It checks:
    - that the record is fully closed and typed (JSON with duplicate members and nonfinite numbers refused);
    - the sector-direction pin, and that the overlay covers exactly the eight follow-ups;
    - that `base` equals SECTOR-001's CATALOG pins in `unchangedAuthorities`;
    - each applied entry's exact occurrence count and the absent target, then the effective digests;
    - that no white-goods term remains outside the deferred entry, and the deferred entry's count;
    - that the deferred binding is unchanged, its bound packet is published and its blocking packet is not;
    - that the R11 notice section matches its pinned sha256, and the DIST-004 list item is exactly the pinned line.
  - A history-chain layer passes its own `reviewed_bytes` and `historical_catalog`. Later packets that publish
    IND-BANK-005, rebase the overlay or change a catalog therefore leave that layer valid through projection
    (review round 1, F1).
  - `effective_bytes(path)` and `effective_catalog(path)` serve the current tree. They first run `check()` on the
    current files and the published packets. That is the consumer gate: it refuses, for example, a published
    IND-BANK-005 while the overlay still defers.
  - Reads use the repository's `regular_bytes` pattern (a safe relative path, no linked ancestors, a regular
    single-link file, a size check before reading, an identity check after it). YAML is loaded with duplicate keys
    refused.
- **Consumer rule.** Every SECTOR-D1 successor must read the provider and service catalogs only through
  `effective_bytes` and `effective_catalog`:
  IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001 and CONF-BANK-001. Older validators keep
  reading the base bytes. In this repository, the layer test's guard enforces the rule (see "Packet"). The successors
  live in other repositories, so each successor packet's contract must cite `sector_catalog` and the effective
  digests when it is published here. IND-BANK-005 also rebases the overlay.

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

The entry changes when IND-BANK-005 is published. Until then, the consumer gate (`effective_bytes`) refuses a published
IND-BANK-005 while the overlay still defers.

## Distribution notice

As in v1, which passed review, `docs/repositories/11-mas-harness-distribution.md` gets the sector-direction notice
that the MET-SECTOR-001 round-2 review asked for (finding m1), plus a pointer from the DIST-004 list item to
DIST-BANK-001. In that list item the identifier is written plain, without backticks, so that readiness does not count
it as a declared packet. `sector-direction.json` admits only MET-SECTOR-001's own files as `directionDocs`, so
`overlay.json` records the notice in `distributionNotice`. That doc has been changed through the history chain before
(MET-ENFORCE-003), so the packet's inverse projects it for the older validators.

## Packet (after review)

- **Layer.** A new history-chain layer, `scripts/validate_sector_catalog.py`, runs `check(reviewed_bytes,
  historical_catalog)`. Its test simulates a later successor (one that publishes IND-BANK-005, rewrites the overlay or
  changes a catalog) and shows the layer stays valid through projection. The inverse authority gives R11 an exact
  two-hunk inverse, and the newest accepted layer (`validate_selinux_replay`) is bridged to the new layer.
- **Guard.** The layer test's guard covers every tracked Python file: `scripts/`, `tests/`, `ci/` and `conftest.py`.
  - It scans by AST and by bytes for the three catalog paths and their basenames, including Path joins and globs over
    `architecture/` and `docs/`.
  - Frozen allowlist of literal base readers: readiness, reuse, provider_adoption, sector_direction and zero_bill_scan,
    plus the six tests that name the paths today.
  - Frozen allowlist of indirect authority readers: the set of architecture records that pin a catalog digest stays
    exactly today's 36 plus sector-direction.json and overlay.json; any new record that pins a catalog is refused.
  - Every other reader must import `sector_catalog` and use `effective_bytes` or `effective_catalog`.
- **Readiness semantics.** The layer test also runs readiness's catalog semantics on the effective catalogs (0 errors
  today; applying the deferred path as well gives exactly the expected IND-WG-005 coverage error).
- **Mechanics.** A current-state page and the usual mechanics.

## Carried items

- From v1 review round 1 (N1), for IND-BANK-005: rebind `artifact.platform.industry-pack` to the deliverable that
  builds the manifest. In IND-WG-005 that is deliverable 2 (`build_pack_manifest.py`), while the entry names
  deliverable 0. Rebase the overlay at the same time.
- From v1 N2, for the packet build: the master plan rows.
- From v1 R2-N1: the R11 check is now exact (section sha256 plus the list item).
- From v1 R2-N2/N3: the wording. The deferral and notice texts cite the validator rule (`validate_sector_direction`
  admits only MET-SECTOR-001's own files as `directionDocs`) rather than "immutable".

## Round 1

Review round 1 (subject `0ec8039`, kept in `round1/`) returned CHANGES_REQUIRED: F1 MAJOR, F2-F6 MINOR, N1-N5 NOTE.
- **F1:** the era check with an injected reader, and the consumer gate.
- **F2:** an exact R11 section and list item.
- **F3:** a fully closed, typed record; no `record` parameter; the full check on the consumer path.
- **F4:** `regular_bytes` reads, lstat-based packet listing, validated IDs, unique-key YAML.
- **F5:** the consumer rule above.
- **F6:** the guard plan above.
- **N1, N5:** in the packet plan.
- **N2:** single root.
- **N3:** the carried items.
- **N4:** the wording above.
