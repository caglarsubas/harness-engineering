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
whose bytes match `(?i)white[- ]goods|whitegoods|white_goods`. The validator recomputes that set and refuses any packet left out.

| Packet | Disposition |
|---|---|
| `CONF-A2-001` | ID kept; now a cited read-only banking agent. A revised packet restates the banking scope, with `CONF-BANK-001` in place of `CONF-A1-001`, before dispatch. |
| `CONF-WG-001` | ID kept, WG prefix historical; now the unsigned banking tenant-acceptance candidate. Same revision rule. |
| `IND-WG-001` to `IND-WG-005` | Superseded for release scope by `IND-BANK-001` to `IND-BANK-005`. |
| `CONF-A1-001` | Superseded for release scope by `CONF-BANK-001`. |
| `KN-DOM-001`, `KN-DATA-002` | Sector-neutral service scope kept; their white-goods parity fixtures are historical. Banking fixtures come from `IND-BANK-001`, `IND-BANK-002` and `IND-BANK-005`. |
| `CONF-002` | Historical warm-source evidence; unchanged. |
| 17 others | Name white goods only as an example profile or fixture; their successors use banking: `CONF-A3-001`, `CONF-AIR-001`, `CONF-K3S-001`, `CTRL-002`, `CTRL-006`, `DIST-004`, `DIST-AIR-001`, `EXEC-002`, `EXEC-ORCH-001`, `EXEC-PROT-001`, `EXEC-SBX-001`, `EXEC-TOOL-001`, `IND-001`, `KN-002`, `KN-DATA-001`, `KN-MEM-001`, `KN-RET-001`. |

## Successor proposals

These are unpublished proposals, never dispatch targets. Each needs its own exact packet, predecessor
digests, review and acceptance before any work starts.

| ID | Owner | Supersedes | Scope |
|---|---|---|---|
| `IND-BANK-001` | R03 | `IND-WG-001` | Define the banking business objectives, roles, glossary and ontology (parties, products, accounts, transactions, channels, credit, risk and compliance concepts), KPIs and representative answer sets. |
| `IND-BANK-002` | R03 | `IND-WG-002` | Add the banking source inventory, synthetic non-personal mock data, and explicit completeness, freshness, provenance and classification thresholds for customer, account and transaction sources. |
| `IND-BANK-003` | R03 | `IND-WG-003` | Define banking control mappings, autonomy categories, integrations, credentials, side effects, compensation and waiver requirements; candidate regulatory inputs are evaluated per tenant jurisdiction. |
| `IND-BANK-004` | R03 | `IND-WG-004` | Publish deterministic banking provider recommendations and explicit-selector questionnaire choices for the minimal, regulated OpenShift, silo and air-gap environments. |
| `IND-BANK-005` | R03 | `IND-WG-005` | Freeze deterministic banking source-contract scenarios, a non-recursive payload lock and an unsigned offline-signing-ready manifest for later conformance campaigns. |
| `CONF-BANK-001` | R12 | `CONF-A1-001` | Certify the banking journey from questionnaire through business, domain, data readiness, signed bundle and installed foundation harnesses. |

## What stays as it is

Published packet YAML, the unified backlog snapshot (accepted base `7a353b2`), the white-goods pack
versions 0.1.0 to 0.4.0 recorded in the R03 plan, observations, authorities, input snapshots and
`docs/history` stay byte-identical. They record what was specified or built, not current direction.

The provider and service catalogs keep their white-goods entries as historical PLANNED records until a
separate catalog packet adds the banking equivalents with readiness counts:

- `architecture/providers.yaml`: `industry.white-goods` → `industry.banking`
- `architecture/providers.yaml`: `imply.white-goods-guidance` → `imply.banking-guidance`
- `architecture/providers.yaml`: `profile.whitegoods-readonly-amd64` → `profile.banking-readonly-amd64`
- `architecture/providers.yaml`: `packs/white-goods/manifest.json` → `packs/banking/manifest.json`
- `architecture/services.yaml`: `white-goods semantic vectors` → `banking semantic vectors`
- `docs/PROVIDER_MODULE_CATALOG.md`: `profile.whitegoods-readonly-amd64` → `profile.banking-readonly-amd64`

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
