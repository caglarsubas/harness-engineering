# Sector direction: banking replaces white goods (MET-SECTOR-001)

Owner decision SECTOR-D1, October 7, 2026. Machine authority:
[`architecture/sector-direction.json`](../../architecture/sector-direction.json).

## Decision

Banking replaces white goods as the first and only release sector from Alpha 2 through the first
enterprise release. The Domain & Semantic harness (H5, `knowledge.domain-semantic`) carries a banking
glossary and ontology: versioned terms with provenance and business-question readiness, under the
proposed namespace `urn:planeon:banking:*`. The common eight-gate journey is unchanged; banking is its
sector overlay, and tenant answers still decide which controls apply.

## Published packets that name white goods

Published packet YAML is immutable, so this decision records a disposition for each of the 28 packets
whose bytes match `(?i)white[- ]goods|whitegoods|white_goods`. The validator recomputes that set from the exact
accepted bytes and refuses any packet left out.

| Packet | Disposition |
|---|---|
| `CONF-A2-001` | ID kept; now a cited read-only banking agent, with `CONF-BANK-001` and `KN-BANK-001` in place of the white-goods journey and retrieval vectors. |
| `CONF-WG-001` | ID kept, WG prefix historical; now the unsigned banking tenant-acceptance candidate. |
| `IND-WG-001` to `IND-WG-005` | Superseded for release scope by `IND-BANK-001` to `IND-BANK-005`. |
| `CONF-A1-001` | Superseded for release scope by `CONF-BANK-001`. |
| `CTRL-002` | Historical sector inputs; banking replacements `CTRL-BANK-001`, `IND-BANK-005`. Signed pack intake and guided journey kept; the white-goods 0.5.0 acceptance baseline and release intake binding are historical. |
| `CTRL-006` | Historical sector inputs; banking replacements `CTRL-BANK-001`. Alpha 1 control-plane closure kept; the white-goods end-to-end journey spec, make target and evidence are historical. |
| `DIST-004` | Historical sector inputs; banking replacements `DIST-BANK-001`, `IND-BANK-004`. Modular Helm profiles kept; the white-goods provider-profile recommendations and pack digest binding are historical. |
| `KN-DATA-001` | Historical sector inputs; banking replacements `IND-BANK-002`, `KN-BANK-001`. Sector-neutral connector and ingest core kept; its four synthetic white-goods records are historical. |
| `KN-DATA-002` | Historical sector inputs; banking replacements `IND-BANK-002`, `KN-BANK-001`. Sector-neutral readiness processor kept; its white-goods source fixtures are historical. |
| `KN-DOM-001` | Historical sector inputs; banking replacements `IND-BANK-001`, `KN-BANK-001`. Sector-neutral domain service kept; its white-goods ontology parity fixtures are historical. |
| `KN-RET-001` | Historical sector inputs; banking replacements `KN-BANK-001`. Sector-neutral retrieval kept; its white-goods cited retrieval vectors are historical, and the banking revision of CONF-A2-001 needs banking vectors. |
| `IND-001` | Framework kept; its rule that the sector ontology packet admits and locks RDFLib and pySHACL now applies to `IND-BANK-001`. |
| `CONF-002` | Historical warm-source evidence; unchanged. |
| 11 others | Name white goods only in reference-only warm-source test paths; no scope change: `CONF-A3-001`, `CONF-AIR-001`, `CONF-K3S-001`, `DIST-AIR-001`, `EXEC-002`, `EXEC-ORCH-001`, `EXEC-PROT-001`, `EXEC-SBX-001`, `EXEC-TOOL-001`, `KN-002`, `KN-MEM-001`. |

The two retargeted IDs cannot get a second YAML file. Before either is dispatched, a revision amendment,
published by its own packet and independent review in the style of `architecture/*-amendment.json`, must
bind the kept ID to the banking scope; the published YAML stays byte-identical.

## Successor and banking-input proposals

These are unpublished proposals, never dispatch targets. Each needs its own exact packet, predecessor
digests, review and acceptance before any work starts. No proposal may depend on a superseded packet.

| ID | Owner | Supersedes | Replaces sector inputs of | Scope |
|---|---|---|---|---|
| `IND-BANK-001` | R03 | `IND-WG-001` | `KN-DOM-001` | Define the banking business objectives, roles, glossary and ontology (parties, products, accounts, transactions, channels, credit, risk and compliance concepts), KPIs and representative answer sets; admit and lock RDFLib and pySHACL before claiming SHACL validation. |
| `IND-BANK-002` | R03 | `IND-WG-002` | `KN-DATA-001`, `KN-DATA-002` | Add the banking source inventory, synthetic non-personal mock data, and explicit completeness, freshness, provenance and classification thresholds for customer, account and transaction sources. |
| `IND-BANK-003` | R03 | `IND-WG-003` | — | Define banking control mappings, autonomy categories, integrations, credentials, side effects, compensation and waiver requirements; candidate regulatory inputs are evaluated per tenant jurisdiction. |
| `IND-BANK-004` | R03 | `IND-WG-004` | `DIST-004` | Publish deterministic banking provider recommendations and explicit-selector questionnaire choices for minimal ARM64, minimal AMD64, regulated OpenShift, silo and air-gap environments. |
| `IND-BANK-005` | R03 | `IND-WG-005` | `CTRL-002` | Freeze deterministic banking source-contract scenarios, a non-recursive payload lock and an unsigned offline-signing-ready manifest for later conformance campaigns. |
| `KN-BANK-001` | R07 | — | `KN-DATA-001`, `KN-DATA-002`, `KN-DOM-001`, `KN-RET-001` | Add banking ontology parity, synthetic non-personal source records and cited retrieval vectors to the domain, data and retrieval services, replacing their white-goods fixtures. |
| `CTRL-BANK-001` | R04 | — | `CTRL-002`, `CTRL-006` | Bind the signed banking pack release as the control-plane intake acceptance baseline and add the banking guided-session end-to-end journey, make target and evidence. |
| `DIST-BANK-001` | R11 | — | `DIST-004` | Publish the banking provider-profile recommendations in the modular Helm profiles and bind the banking pack digest. |
| `CONF-BANK-001` | R12 | `CONF-A1-001` | — | Certify the banking journey from questionnaire through business, domain, data readiness, signed bundle and installed foundation harnesses; the banking inputs of KN-BANK-001, CTRL-BANK-001 and DIST-BANK-001 complement its white-goods-era intake, data and bundle predecessors. |

## Accepted edges stay

Superseded for release scope does not reopen or invalidate accepted predecessor edges: the historical acceptance of IND-WG-001 to IND-WG-005 and CONF-A1-001 still satisfies every dependent listed here. The record lists every accepted packet with such an edge: `CONF-A2-001` (CONF-A1-001), `CONF-FIX-001` (CONF-A1-001), `CONF-LINUX-001` (CONF-A1-001), `CTRL-002` (IND-WG-005), `DIST-004` (IND-WG-004), `IND-FIX-001` (IND-WG-005), `IND-WG-002` (IND-WG-001), `IND-WG-003` (IND-WG-002), `IND-WG-004` (IND-WG-003), `IND-WG-005` (IND-WG-004), `KN-DATA-001` (IND-WG-002), `KN-DATA-002` (IND-WG-002), `KN-DOM-001` (IND-WG-001), `MET-A2-001` (CONF-A1-001), `TRUST-FIX-001` (CONF-A1-001).

## What stays as it is

Published packet YAML, the unified backlog snapshot (accepted base `7a353b2`) with its source index and
traceability page, every white-goods pack version recorded in the R03 plan (0.1.0 to 0.5.0),
observations, authorities, input snapshots and `docs/history` stay byte-identical. They record what was
specified or built, not current direction.

The provider and service catalogs keep their white-goods entries as historical PLANNED records until a
separate catalog packet replaces them. The record lists every white-goods entry in those catalogs, and the
validator refuses a catalog entry without a follow-up:

- `architecture/providers.yaml`: `industry.white-goods` → `industry.banking`
- `architecture/providers.yaml`: `imply.white-goods-guidance` → `imply.banking-guidance`
- `architecture/providers.yaml`: `packs/white-goods/manifest.json` → `packs/banking/manifest.json`
- `architecture/providers.yaml`: `profile.whitegoods-readonly-amd64` → `profile.banking-readonly-amd64`
- `architecture/providers.yaml`: `Read-only white-goods assistant` → `Read-only banking assistant`
- `architecture/services.yaml`: `white-goods semantic vectors` → `banking semantic vectors`
- `docs/PROVIDER_MODULE_CATALOG.md`: `profile.whitegoods-readonly-amd64` → `profile.banking-readonly-amd64`
- `docs/PROVIDER_MODULE_CATALOG.md`: `White-goods pack` → `Banking pack`

## Candidate regulatory inputs

`IND-BANK-003` evaluates these for each tenant jurisdiction. Applicability is a tenant answer in the
guided journey; this record asserts none.

- BCBS 239 principles for risk data aggregation and risk reporting
- EU DORA, Regulation (EU) 2022/2554, ICT operational resilience
- EU AI Act, Regulation (EU) 2024/1689; creditworthiness evaluation of natural persons is a high-risk use
- GDPR, Regulation (EU) 2016/679
- PSD2, Directive (EU) 2015/2366
- AML/CFT and KYC rules of the tenant's jurisdiction
- Model risk management guidance such as US SR 11-7

## Non-claims

No banking pack, ontology, fixture, catalog entry, provider selection, campaign or tenant acceptance is
built, published or qualified by this packet. Native Linux, exact-main and tenant acceptance stay
separate, and every E01-E12 obligation stays open.
