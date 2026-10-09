# Sector catalog overlay — CATALOG-BANK v2 (MET-SECTOR-002), round 4

Status: **CANDIDATE_ROUND4_AWAITING_INDEPENDENT_REVIEW**. Rounds 1 to 3 (`round1/` to `round3/`) returned
CHANGES_REQUIRED; see "Rounds 1-3" below. This changes the effective catalog identifiers and text, plus a notice in the R11 distribution plan.
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
- 36 earlier architecture records and `sector-direction.json` pin them (no script pins their digest);
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
    - the deferrals, derived rather than read from the record: a follow-up whose current text is the path of a
      `REPOSITORY_PACKET` implementation stays deferred exactly while the successor that supersedes its packet
      (from `successorProposals`) is unpublished. It is bound to that implementation and blocked by that successor,
      and no other follow-up may be deferred. Today this is the pack manifest path, which is bound to IND-WG-005 and
      blocked by IND-BANK-005;
    - that the R11 notice section matches its pinned sha256;
    - that the notice's proposal is a SECTOR-D1 successor, its predecessor is one of that successor's `predecessorIds`
      (named in the section as a backticked token), and the proposal is unpublished;
    - that inside the plan's `## PR packets` section, the DIST-004 list item is exactly the pinned line, once;
    - that the proposal is backticked only inside the notice, and is not declared in PR packets in any slug form;
    - that every published SECTOR-D1 successor's `contracts` cite `scripts/sector_catalog.py`;
    - before deriving, that each predecessor has at most one superseding successor and each implementation path is
      bound once.
    Each path is read exactly once, so every check sees the same bytes.
  - Planned for the packet: the history-chain layer will pass its own `reviewed_bytes` and
    `frozenset(historical_catalog(...))`. Later packets that publish IND-BANK-005, rebase the overlay or change a
    catalog will then leave that layer valid through projection (review round 1, F1). The layer's authority pins the
    reviewed sha256 of `overlay.json` and `sector_catalog.py` as new files, so a later revision has to supply an
    inverse.
  - **Forward path** (review round 3, R3-F1). The deferral is derived from the base `providers.yaml`, which stays
    byte-identical by design. So once IND-BANK-005 is published, `check()` refuses whatever the overlay contains,
    with "the overlay module and schema must be revised in a reviewed successor packet". Publishing IND-BANK-005
    therefore needs a reviewed revision of `scripts/sector_catalog.py` and of the overlay schema. That revision
    rebinds `artifact.platform.industry-pack` (packetId IND-BANK-005, and the deliverable that builds the manifest;
    see the carried items) and moves the pack path to applied, with the layer's inverse for both pinned files. A
    plain overlay rebase is not enough. Likewise, publishing DIST-BANK-001 requires a revised R11 notice.
  - `effective_bytes(path)` and `effective_catalog(path)` serve this repository's current tree, with no root
    override. They first run `check()` on the current files and the published packets. That is the consumer gate: it
    refuses, for example, a published IND-BANK-005 (see "Forward path"). The task-packet listing refuses
    any non-regular `*.yaml` entry, so a link or directory cannot hide a blocking packet.
  - Reads use the repository's `regular_bytes` pattern (a safe relative path, no linked ancestors, a regular
    single-link file, a size check before reading, an identity check after it). YAML is loaded with duplicate keys
    refused.
- **Consumer rule.** Every SECTOR-D1 successor must read the provider and service catalogs only through
  `effective_bytes` and `effective_catalog`:
  IND-BANK-001 to IND-BANK-005, KN-BANK-001, CTRL-BANK-001, DIST-BANK-001 and CONF-BANK-001. Older validators keep
  reading the base bytes. In this repository, the layer test's guard enforces the rule (see "Packet"). The successors
  live in other repositories, so each successor packet's `contracts` must cite `scripts/sector_catalog.py` when it is
  published here. `check()` verifies this; the effective digests come from the module and are not restated. That check
  is a minimal publication tripwire; the packet's own review checks how the successor uses the module.

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

The entry changes when IND-BANK-005 is published. Until the reviewed module and schema revision described in "Forward
path", the consumer gate (`effective_bytes`) refuses a published IND-BANK-005 whatever the overlay contains.

## Distribution notice

As in v1, which passed review, `docs/repositories/11-mas-harness-distribution.md` gets the sector-direction notice
that the MET-SECTOR-001 round-2 review asked for (finding m1), plus a pointer from the DIST-004 list item to
DIST-BANK-001. In that list item the identifier is written plain, without backticks, so that readiness does not count
it as a declared packet. `sector-direction.json` admits only MET-SECTOR-001's own files as `directionDocs`, so
`overlay.json` records the notice in `distributionNotice`. That doc has been changed through the history chain before
(MET-ENFORCE-003), so the packet's inverse projects it for the older validators.

## Packet (after review)

- **Layer.** A new history-chain layer, `scripts/validate_sector_catalog.py`, runs `check(reviewed_bytes,
  frozenset(historical_catalog(...)))`. Its test simulates a later successor (one that publishes IND-BANK-005, rewrites the overlay or
  changes a catalog) and shows the layer stays valid through projection. The inverse authority gives R11 an exact
  two-hunk inverse, and the newest accepted layer (`validate_selinux_replay`) is bridged to the new layer.
- **Guard.** The layer test's guard covers all tracked Python files. The inert review copies under
  `architecture/sector-catalog/round*/` are frozen exceptions, listed as exact path-to-sha256 pairs.
  - It scans by AST and by bytes for the three catalog paths and their basenames, including Path joins and globs over
    `architecture/` and `docs/`.
  - Frozen allowlist of literal base readers: readiness, reuse, provider_adoption, sector_direction and zero_bill_scan,
    plus the six tests that name the paths today.
  - Frozen set of architecture records that pin a catalog digest, and a frozen set of records that name the three paths.
    Both are derived at build: 41 digest-pinning records with this round's copies, namely the 36 earlier records,
    sector-direction.json, overlay.json and the round1 to round3 overlay copies. Any new record of either kind is
    refused.
  - Consumers must import `sector_catalog` and use only `effective_bytes` or `effective_catalog`. The guard refuses
    direct use of `check`, `_apply`, `disk_reader` or `_yaml` on the catalogs outside the module and its layer. It
    also refuses assignment, `setattr` or monkeypatch of any `sector_catalog` attribute (`ROOT`, `OVERLAY_PATH`,
    `published_packets`, `check`, ...) outside the layer test (review round 3, R3-N3).
  - Publication: `check()` itself refuses any published SECTOR-D1 successor packet whose `contracts` do not cite
    `scripts/sector_catalog.py`.
- **Readiness semantics.** The layer test also runs readiness's catalog semantics on the effective catalogs (0 errors
  today; applying the deferred path as well gives exactly the expected IND-WG-005 coverage error).
- **Mechanics.** A current-state page and the usual mechanics.

## Carried items

- From v1 review round 1 (N1), for IND-BANK-005: rebind `artifact.platform.industry-pack` to the deliverable that
  builds the manifest. In IND-WG-005 that is deliverable 2 (`build_pack_manifest.py`), while the entry names
  deliverable 0. This happens in the reviewed revision of the module and the overlay schema (see "Forward path").
- From v1 N2, for the packet build: the master plan rows.
- From v1 R2-N1: the R11 check is now exact (section sha256 plus the list item).
- From v1 R2-N3: the wording. The notice record cites the validator rule (`validate_sector_direction` admits only
  MET-SECTOR-001's own files as `directionDocs`) rather than "immutable". v1 R2-N2 (the attribution of the m1
  source) is moot: that sentence no longer exists.

## Rounds 1-3

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

Review round 2 (subject `ffca73b`, kept in `round2/`) returned CHANGES_REQUIRED, with no MAJOR findings: R2-F1 to
R2-F3 MINOR, R2-F4 to R2-F7 NOTE.
- **R2-F1:** the deferrals are derived from `implementationOwnership` and `successorProposals`; the consumer API has
  no root override; the layer pins the overlay and the module.
- **R2-F2:** an anchored, whole-line DIST-004 item inside `## PR packets`; backticks only inside the notice; the
  predecessor named in the section.
- **R2-F3:** the packet listing refuses non-regular entries.
- **R2-F4:** each path is read once.
- **R2-F5:** `frozenset(historical_catalog(...))`, and the layer paragraph is worded as a plan.
- **R2-F6:** the guard plan above.
- **R2-F7:** the overlay's `approach` is written as a rule, `nonClaims[1]` mentions the R11 notice, and v1 R2-N2 is
  closed as moot.

Review round 3 (subject `2f28e12`, kept in `round3/`) returned CHANGES_REQUIRED: R3-F1 MINOR, R3-N1 to R3-N5 NOTE. It
confirmed R2-F1 to R2-F4 and R2-F7 fixed, and R2-F5 and R2-F6 addressed.
- **R3-F1:** the forward path is now stated precisely. The refusal message names the required revision of the module
  and schema, and the overlay's deferral reason says the same.
- **R3-N1:** the proposal and its predecessor are checked against `successorProposals`; slug-form declarations in PR
  packets are refused; a published DIST-BANK-001 is refused until the notice is revised.
- **R3-N2:** the successor citation is parsed from `contracts`.
- **R3-N3:** the guard refuses attribute assignment and monkeypatch, lists exact exceptions and derives the counts at
  build.
- **R3-N4:** `frozenset(historical_catalog(...))` everywhere; "the same bytes"; the record count.
- **R3-N5:** duplicate supersedes values and duplicate bound paths are refused before deriving.
