# Data dictionary — operational schema

Tables created by Django migrations in the `public` schema. The warehouse (`dw` schema) is documented in [data_warehouse_dictionary.md](data_warehouse_dictionary.md).

## CTI reference data (`cti` app)

### `cti_vulnerability` — one row per published CVE

| Column | Type | Source | Description |
|---|---|---|---|
| `id` | bigint, PK | — | Technical key |
| `cve_id` | varchar(32), unique | CVE List V5 `cveMetadata.cveId` | CVE identifier, format `CVE-YYYY-NNNN…` |
| `description` | text | CVE List V5 CNA `descriptions` (English) | Vulnerability description |
| `published_at` | timestamptz, null | CVE List V5 `datePublished` | Publication date (records before 2023 may be inconsistent, risk R3) |
| `source_updated_at` | timestamptz, null, indexed | CVE List V5 `dateUpdated` | Last update of the record; watermark of the incremental load |
| `nvd_status` | varchar(32) | NVD API (Sprint 2) | NVD analysis status |
| `epss_score` | float, null | FIRST EPSS (`epss` connector) | Probability of exploitation within 30 days (0–1) |
| `epss_percentile` | float, null | FIRST EPSS (`epss` connector) | Percentile of the EPSS score (0–1) |
| `effective_severity` | varchar, indexed | Computed after each run | Severity of the effective CVSS score (FR-06: NVD > CNA > CISA ADP, newest version first); empty = no score yet. Used by the search filters (US03) |
| `effective_score` | float, null | Computed after each run | Base score of that effective CVSS score |

EPSS columns: only the latest score is kept; the `epss` connector updates them in place at each run. The model version and the score date of each run are in `pipeline_ingestiontask.quality_report` (history belongs to the warehouse).

### `cti_cvssmetric` — CVSS scores, one row per vulnerability × provider × version

| Column | Type | Description |
|---|---|---|
| `vulnerability_id` | FK → `cti_vulnerability` | Scored vulnerability |
| `provider` | `NVD` / `CNA` / `CISA_ADP` | Who published the score (CVE List V5 loads CNA and CISA ADP) |
| `version` | varchar(8) | CVSS version: `2.0`, `3.0`, `3.1`, `4.0` |
| `vector` | varchar(200) | CVSS vector string |
| `base_score` | float, check 0–10 | Base score |
| `severity` | `NONE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` | Qualitative rating (computed from the score when the record has none, e.g. CVSS 2.0) |

Unique: (`vulnerability`, `provider`, `version`). CISA ADP SSVC exploitation fields are never loaded (M2 label leakage, FR-24).

### `cti_product` — normalized products

| Column | Type | Description |
|---|---|---|
| `vendor`, `name` | varchar(200) | Lowercase, single-spaced names as published by the CNA; unique together. Placeholders (`n/a`, `unknown`…) are not loaded. |
| `cpe_prefix` | varchar(200) | CPE prefix (NVD, Sprint 2) |

### `cti_affectedproduct` — vulnerability × affected product

| Column | Type | Description |
|---|---|---|
| `vulnerability_id`, `product_id` | FK | Unique together |
| `versions` | text | Affected versions listed by the CNA (comma-separated) |

### `cti_keventry` — CISA KEV catalog, 0..1 per vulnerability

| Column | Type | Source field | Description |
|---|---|---|---|
| `vulnerability_id` | FK, unique | `cveID` | Exploited vulnerability (must already exist: referential integrity) |
| `date_added` | date | `dateAdded` | Date added to the KEV catalog |
| `due_date` | date, null | `dueDate` | Remediation deadline set by CISA |
| `required_action` | text | `requiredAction` | Action required by CISA |
| `ransomware_use` | boolean | `knownRansomwareCampaignUse` | `true` when the value is `Known` |

### `cti_weakness` — MITRE CWE catalog (weaknesses and categories)

| Column | Type | Source field | Description |
|---|---|---|---|
| `cwe_id` | varchar(16), unique | `ID` | `CWE-` + number, e.g. `CWE-79` |
| `name` | varchar(300) | `Name` | Empty while a CWE named by a CVE is not yet in the loaded catalog |
| `kind` | varchar(10) | element | `WEAKNESS` or `CATEGORY` (views are not loaded) |
| `abstraction` | varchar(20) | `Abstraction` | `Pillar`, `Class`, `Base`, `Variant`, `Compound` (weaknesses only) |
| `status` | varchar(20) | `Status` | `Stable`, `Draft`, `Incomplete`, `Deprecated`, `Obsolete`… (deprecated entries are kept: old CVEs still name them) |

### `cti_vulnerabilityweakness` — vulnerability × CWE

| Column | Type | Source field | Description |
|---|---|---|---|
| `vulnerability_id`, `weakness_id` | FK | `problemTypes[].descriptions[].cweId` | CWE named by the CVE record |
| `provider` | varchar(10) | container | `CNA` or `CISA_ADP` (`NVD` from the NVD connector); unique with the two FKs |

## Watchlist (`watchlist` app)

### `watchlist_watchlistitem` — a product watched by an organization (US07, FR-07)

| Column | Type | Description |
|---|---|---|
| `organization_id` | FK → `accounts_organization` | Organization that runs the product |
| `product_id` | FK → `cti_product` | Normalized product (created if no CVE names it yet) |
| `criticality` | smallint, check 1–4 | Business criticality: 1 low, 2 medium, 3 high, 4 critical |
| `added_at` | timestamptz | Date the product was added |

Unique together: (`organization_id`, `product_id`).

### `watchlist_productalias` — other spellings of a product published by the CNAs (FR-08, risk R10)

| Column | Type | Description |
|---|---|---|
| `product_id` | FK → `cti_product` | Product the raw name designates |
| `raw_vendor`, `raw_product` | varchar(200) | Raw names as found in CVE records, stored with the same rule as `cti_product` (lowercase, single spaces) |

Unique together: (`raw_vendor`, `raw_product`): a raw name designates one product only.
**Matching:** a watched product matches the CVE-record products whose (vendor, name) is its own name or one of its aliases (`watchlist/matching.py`). The *Unmatched names* page lists the names of CVE records that look like a watched product but match none, so the analyst can turn them into aliases.

## Alerts (`alerts` app)

### `alerts_alert` — a CVE that affects a watched product (US08, FR-08, FR-09)

| Column | Type | Description |
|---|---|---|
| `vulnerability_id` | FK → `cti_vulnerability` | The CVE |
| `watchlist_item_id` | FK → `watchlist_watchlistitem` | The watched product (and so the organization) |
| `created_at` | timestamptz | Creation by the alert step of the pipeline |
| `status` | varchar | NEW, IN_PROGRESS, FIXED, RISK_ACCEPTED, FALSE_POSITIVE (open = NEW or IN_PROGRESS) |
| `priority_score` | float | 0 until the prioritization is computed (US11, FR-10) |
| `due_date` | date | Creation date + `ALERT_DUE_DAYS[effective severity]` (CRITICAL 7, HIGH 30, MEDIUM 90, LOW 180, no score 30 days); CISA's KEV due date when it is earlier |
| `assignee_id` | FK → `accounts_user`, null | Analyst in charge (US11) |

Unique together: (`vulnerability_id`, `watchlist_item_id`): never two alerts for the same CVE and watched product.
**Effective severity** (FR-06): the CVSS score of the first provider in the order NVD > CNA > CISA ADP, newest CVSS version first (`Vulnerability.effective_metric()`).

### `alerts_alertstatuschange` — status history of an alert

| Column | Type | Description |
|---|---|---|
| `alert_id` | FK → `alerts_alert` | |
| `old_status`, `new_status` | varchar | Empty old status = creation |
| `comment` | text | e.g. "Created by pipeline run 12." |
| `changed_at` | timestamptz | |
| `changed_by_id` | FK → `accounts_user`, null | Empty = the system (pipeline) |

### `alerts_alertgeneration` — result of the alert step of a run

| Column | Type | Description |
|---|---|---|
| `run_id` | FK → `pipeline_pipelinerun`, null | Empty = `generate_alerts` command |
| `cves_checked`, `alerts_created` | int | New or updated CVEs checked, alerts created |
| `unmatched_names` | JSON | Names of these CVEs that look like a watched product but match no name or alias ("vendor / product") |
| `error_message` | text | Set when the step failed (the run is then PARTIAL) |

## ETL monitoring (`pipeline` app)

### `pipeline_source`

| Column | Description |
|---|---|
| `name` | Connector key (`cwe`, `cve`, `kev`, `epss`), unique |
| `label`, `url` | Display name and reference URL |
| `frequency` | Update frequency (default `daily`) |
| `is_active` | Disabled sources are skipped by `run_pipeline` (FR-15) |

### `pipeline_pipelinerun` — one row per run

| Column | Description |
|---|---|
| `started_at`, `ended_at` | Run duration |
| `status` | `RUNNING`, `SUCCESS` (every source succeeded), `PARTIAL` (at least one failed), `FAILED` (all failed) |
| `triggered_by_id` | Administrator who started it; empty = scheduler |

### `pipeline_ingestiontask` — one row per source in a run

| Column | Description |
|---|---|
| `run_id`, `source_id` | Run and source |
| `status` | `SUCCESS` or `FAILED` (an exception; the other sources still run) |
| `extracted` | Records read from the snapshot (after skipping non-published and unchanged records) |
| `loaded` | Records loaded (upsert) |
| `rejected` | Records refused by the quality checks |
| `quality_report` | JSON: snapshot file, skipped counts, loaded sub-counts, `rejected_by_reason`, up to 200 `rejected_examples` |
| `error_message` | Exception and short traceback when the task failed |

## Quality rules applied at load time

| Source | Rule | Effect |
|---|---|---|
| CVE List V5 | identifier matches `CVE-YYYY-NNNN…` | otherwise rejected |
| CVE List V5 | English description present | otherwise rejected |
| CVE List V5 | every CVSS base score in 0–10 | otherwise rejected |
| CVE List V5 | state = `PUBLISHED` | otherwise skipped (counted) |
| CVE List V5 | same CVE twice in a file | last one kept (counted) |
| CVE List V5 | `cweId` matches `CWE-NNN` | otherwise not linked (free-text problem types ignored) |
| CWE | identifier is a number | otherwise rejected |
| CWE | name present | otherwise rejected |
| CWE | CWE once in the catalog | duplicates rejected |
| KEV | CVE already in `cti_vulnerability` | otherwise rejected |
| KEV | `dateAdded` is a valid date | otherwise rejected |
| KEV | CVE once in the catalog | duplicates rejected |
| EPSS | identifier matches `CVE-YYYY-NNNN…` | otherwise rejected |
| EPSS | `epss` and `percentile` are numbers | otherwise rejected |
| EPSS | `epss` and `percentile` between 0 and 1 (limits included) | otherwise rejected |
| EPSS | CVE already in `cti_vulnerability` | otherwise rejected |
| EPSS | CVE once in the file | duplicates rejected |
| all | re-running the same period | no duplicate row (upsert, FR-18) |
