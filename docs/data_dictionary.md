# Data dictionary — operational schema

Tables created by Django migrations in the `public` schema. The warehouse (`dw` schema) is documented separately (Sprint 2).

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
| `epss_score` | float, null | FIRST EPSS (Sprint 2) | Probability of exploitation within 30 days (0–1) |
| `epss_percentile` | float, null | FIRST EPSS (Sprint 2) | Percentile of the EPSS score (0–1) |

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

## ETL monitoring (`pipeline` app)

### `pipeline_source`

| Column | Description |
|---|---|
| `name` | Connector key (`cve`, `kev`), unique |
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
| KEV | CVE already in `cti_vulnerability` | otherwise rejected |
| KEV | `dateAdded` is a valid date | otherwise rejected |
| KEV | CVE once in the catalog | duplicates rejected |
| all | re-running the same period | no duplicate row (upsert, FR-18) |
