# ADR-0039: Offline Geolocation Default — DB-IP Lite via First-Run Download (Closes the ip-api Egress)

**Date:** June 2026 (accepted 2026-06-12)
**Status:** Accepted

**Decision:** The default geo enricher becomes an **offline MMDB lookup**; the online ip-api.com
enricher is demoted to an explicit opt-in. Concretely:

- **Default = `geo_provider: offline`.** A new MMDB-backed enricher (same `firewatch_sdk.Enricher`
  protocol as today's `GeoEnricher`; drop-in, pipeline wiring unchanged) resolves IPs locally from
  **DB-IP Lite** databases.
- **Databases: DB-IP IP-to-City Lite + DB-IP IP-to-ASN Lite** — both CC-BY 4.0, no account, MMDB
  format. Two files because (verified at db-ip.com, 2026-06-12) **City Lite does not include ASN**;
  ASN/AS-org ships as a separate free Lite database. Together they cover exactly today's `ip_geo`
  field set.
- **Provisioning = a first-run download, then fully offline.** On first run with no DB present,
  FireWatch fetches both public Lite files over **HTTPS** and verifies each against DB-IP's
  published **SHA1SUM** before atomic install; a failed verification discards the file (no partial
  install). After that, every lookup is local — zero network egress.
- **The first-run fetch is not telemetry egress.** It is a one-time pull of a *public* artifact;
  no operator data, no IPs, nothing derived from telemetry leaves the box. The local-first
  invariant stays crisp: *FireWatch never sends operator data anywhere* — it may, once, fetch a
  public file the operator could equally download by hand.
- **Air-gapped operators provide the files offline:** download on a connected box, copy them into
  the documented data-dir location (the workflow lives in the air-gapped mode doc, MI-4/#385).
- **Fields: exactly today's set, no additions** — `country`, `city`, `lat`, `lon`, `asn`,
  `as_name` (the `ip_geo` table incl. the #211 ASN columns, ECS §as naming). Fields a DB cannot
  supply are stored as `None`, never fabricated.
- **Fail-safe:** missing/unreadable/corrupt DB → log a WARNING and pass events through unchanged
  (same never-raise posture as `GeoEnricher`).
- **ip-api.com is kept only as `geo_provider: online`, an explicit opt-in fallback** with an
  egress disclosure in docs/settings: the free tier is **plaintext HTTP** and sends the IPs being
  looked up (attacker-facing telemetry) to a third party.
- **Attribution:** "IP Geolocation by DB-IP" + link wherever bundled-DB geo data is presented
  (docs + one UI/about surface), per CC-BY 4.0.

**What the value is:** this closes the **only non-operator-configured egress** in a default
deployment — and the only plaintext-HTTP call in the product (the enricher's own NB-3 note). With
it gone, the zero-egress air-gapped story (differentiation bet #5) is true by default, not by
configuration, and an OWASP egress-hygiene wart is removed. The value is *closing the last egress /
local-first by default* — not richer geo data.

**Deliberately parked (do NOT build in MI)** — moved to Backlog issue **#391**: richer/paid DBs
(DB-IP ISP, MaxMind), an operator-configurable MMDB path + env-var override, an extensible geo
schema (ISP/extras map), the value-ranked adaptive enriched-field UI, the ASN-pivot feature, and
the VPN/Tor/hosting threat-flag lane. #391 preserves the strategist's analysis and the
honest-rendering rules for when that lane reopens.

**Alternatives considered:**
- **Keep ip-api.com as the default (status quo)** — rejected: plaintext-HTTP egress of
  attacker-facing IPs to a third party in every default install; incompatible with the air-gapped
  positioning and with egress hygiene.
- **Bundle the MMDBs in the package/image instead of first-run download** — rejected: ~100 MB+ of
  data baked into every wheel/repo/image, staleness frozen at build time, and CC-BY redistribution
  bookkeeping in every artifact. First-run fetch keeps artifacts small and data current; air-gapped
  copy-in covers the no-network case.
- **MaxMind GeoLite2 or IP2Location LITE as the source** — rejected on licensing (research,
  `scratch/improvement_ideas_mmdb_licensing_2026-06-12.md`): both require per-user
  accounts/registration/EULA — incompatible with "download once, works everywhere." DB-IP Lite is
  CC-BY 4.0 with no account.
- **IPinfo Lite** — viable alternative (CC-BY-SA 4.0, daily updates) but the share-alike clause adds
  downstream compliance surface, and it lacks city granularity in the free tier; DB-IP's plain
  CC-BY + City+ASN coverage of today's exact fields wins.
- **The richer-enrichment design (configurable path, extensible schema, more fields) now** —
  rejected for MI scope: it expands a one-issue egress fix into a schema + UI program. Parked as
  #391 rather than discarded.

**Reasoning:** The geo enricher's ip-api.com call is the last egress FireWatch makes on its own
initiative — removing it is what makes "a real SOC on one box, offline" honest
(`docs/differentiation-roadmap.md` §A2). MMDB is a file format, not a MaxMind service; the official
`maxminddb` reader handles DB-IP files. Checksum verification of the download (HTTPS for
authenticity in transit, DB-IP's published SHA1SUM for integrity) keeps the one allowed fetch
auditable. Keeping the field set frozen means `get_analytics_geo`/`get_analytics_summary` and every
UI surface work identically regardless of provider — the provider swap is invisible above the
store. Sources: DB-IP City Lite & ASN Lite download pages (licenses + SHA1SUM, verified
2026-06-12) — https://db-ip.com/db/download/ip-to-city-lite ·
https://db-ip.com/db/download/ip-to-asn-lite; licensing matrix
`scratch/improvement_ideas_mmdb_licensing_2026-06-12.md`; field-value research
`scratch/geo_enrichment_research_2026-06-12.md` (note: its claim that City Lite includes ASN is
wrong — corrected above).

**Consequences:**
- MI-1 (#382) implements the offline enricher + first-run downloader; MI-4 (#385) documents the
  air-gapped copy-in and the egress sweep.
- The online enricher code stays (opt-in path), untouched.
- `ip_geo` schema unchanged; no migration.
- Backlog #391 is the single parking lot for the richer-enrichment ambition; reopening it requires
  an architect pass (the extensible schema touches the ADR-0025 store contract).

---

## Amendment — Best-Effort SHA1 Checksum (2026-06, issue #633)

**Observed:** DB-IP stopped publishing `.sha1` checksum sidecars for current monthly editions.
Concretely: `dbip-{city,asn}-lite-2026-06.mmdb.gz` returns HTTP 200; the corresponding
`...mmdb.gz.sha1` returns HTTP 404. The original implementation fetched the sidecar first and
called `raise_for_status()`, causing the 404 to abort the entire fetch before the MMDB was ever
downloaded. `MmdbGeoEnricher`'s fail-safe then swallowed the error silently, leaving `ip_geo`
permanently empty.

**Revised behaviour (checksum is now best-effort):**

- WHEN the `.sha1` sidecar is fetchable (HTTP 200): behaviour is unchanged — the downloaded `.gz`
  is verified against the published hash; a mismatch discards the file with no partial install.
- WHEN the `.sha1` sidecar returns HTTP 404: a WARNING is logged and the download proceeds without
  checksum verification. Transport integrity still comes from HTTPS-only; the size cap and
  atomic-rename install remain in force.
- Any non-404 HTTP error on the sidecar (e.g. 5xx) still aborts the fetch — only a definitive
  "resource does not exist" (404) is treated as "sidecar absent."

**Security posture change:** this weakens the integrity guarantee from SHA1-verified to
HTTPS-only when the sidecar is absent. The residual risk (CDN-level tampering without TLS
termination) is accepted because: (a) TLS provides transport integrity; (b) the size cap still
blocks zip-bomb payloads; (c) the alternative is geo enrichment permanently broken for all users
on current monthly editions; (d) the operator can stage the files manually and bypass the fetch
entirely (air-gapped path, MI-4/#385). This is a pragmatic, time-limited degradation — if DB-IP
re-publishes sidecars the verified path activates automatically, with no code change required.
