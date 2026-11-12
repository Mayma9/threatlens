# Data dictionary — warehouse (`dw` schema)

Constellation schema of section 11.2 of the specification (FR-19): three fact tables that share conformed dimensions. The `dw` schema is rebuilt by SQL (ELT) from the operational schema (`public`, see [data_dictionary.md](data_dictionary.md)).

## How it is loaded

| Topic | Rule |
|---|---|
| When | Last step of every pipeline run (UC21, FR-16), after the data load, the effective severity and the alerts. By hand: `docker compose exec -T web python manage.py refresh_warehouse` |
| Scripts | `warehouse/sql/01_constellation_ddl.sql` creates the tables if they do not exist; `warehouse/sql/02_refresh.sql` rebuilds them. Queries of FR-20 are in `warehouse/sql/olap/` (they are never run by the refresh). |
| Method | Full rebuild in **one transaction**: all or nothing. Running the refresh twice gives the same rows (tested). |
| Failure | The run becomes `PARTIAL`, the `dw` schema keeps its previous content. The error is printed in the console output; it is not stored in the database yet. |
| Keys | The key of a loaded dimension is the id of the operational row (`vuln_key` = `cti_vulnerability.id`, `product_key` = `cti_product.id`, `source_key` = `pipeline_source.id`), so keys do not change between refreshes. Key `0` is the "unknown" member of a dimension. |
| Counting CVEs | `fact_vulnerability` has one row per CVE × affected product: always count CVEs with `DISTINCTCOUNT(vuln_key)`. |
| Power BI | Read-only login `powerbi_reader` (`SELECT` on the `dw` schema, `search_path = dw`). |

## What is loaded today

| Table | State | Why |
|---|---|---|
| `dim_date`, `dim_source`, `dim_vulnerability`, `dim_product`, `dim_severity`, `dim_alert_status`, `fact_vulnerability` | Loaded | Sources exist in `public` |
| `fact_alert` | Loaded, empty while no product is watched | Alerts come from the watchlist |
| `dim_weakness` | Only the member `unknown` (key 0) | The CWE connector does not exist yet |
| `dim_technique`, `bridge_cve_technique` | Empty | ATT&CK mapping is not loaded yet |
| `dim_indicator`, `dim_malware`, `dim_threat_type`, `fact_ioc` | Empty | The ThreatFox connector does not exist yet |

## Fact tables

### `fact_vulnerability` — grain: one row per CVE × affected product

A CVE that names no affected product gets one row with `product_key = 0` (unknown product), so that no CVE is lost. Primary key: (`vuln_key`, `product_key`).

| Column | Type | Description |
|---|---|---|
| `vuln_key` | FK → `dim_vulnerability` | The CVE |
| `product_key` | FK → `dim_product` | Affected product; `0` when the CVE names none |
| `published_date_key` | FK → `dim_date` (role: published) | UTC date of `published_at` |
| `kev_date_key` | FK → `dim_date` (role: kev_added), null | Date added to CISA KEV; empty when the CVE is not in KEV |
| `weakness_key` | FK → `dim_weakness` | Primary CWE; always `0` (unknown) until the CWE connector exists |
| `severity_key` | FK → `dim_severity` | Effective severity (FR-06); `NO_SCORE` when the CVE has no CVSS score |
| `source_key` | FK → `dim_source` | Source of the record (`cve`) |
| `cvss_score` | float 0–10, null | Effective CVSS base score; empty when there is no score |
| `epss_score` | float 0–1, null | Latest EPSS score; empty when the CVE is not in the EPSS file |
| `epss_percentile` | float 0–1, null | Latest EPSS percentile |
| `is_kev` | boolean | The CVE is in the CISA KEV catalog |
| `days_to_kev` | integer, null | KEV date minus publication date. Large for the older CVEs that CISA added when the catalog started: use the median, not the average |
| `exploit_probability` | float 0–1, null | Prediction of model M2 (Sprint 3); empty today |
| `is_severity_predicted` | boolean | `true` when the severity comes from model M1 (Sprint 3); always `false` today |

### `fact_alert` — grain: one row per alert, rebuilt at each run

An alert belongs to one watched product of one organization, so a CVE that touches the watched products of two organizations gives two rows. Primary key: `alert_id`.

| Column | Type | Description |
|---|---|---|
| `alert_id` | bigint, PK | Id of `alerts_alert` (added to give the grain a key) |
| `vuln_key` | FK → `dim_vulnerability` | The CVE |
| `product_key` | FK → `dim_product` | The watched product |
| `severity_key` | FK → `dim_severity` | Effective severity of the CVE |
| `status_key` | FK → `dim_alert_status` | Current status |
| `created_date_key` | FK → `dim_date` (role: alert_created) | UTC date of creation |
| `closed_date_key` | FK → `dim_date` (role: alert_closed), null | Date of the last change to `FIXED`, `RISK_ACCEPTED` or `FALSE_POSITIVE`; empty while the alert is open. This path is not covered by a test yet: no alert can be closed before Sprint 3. |
| `priority_score` | float | `alerts_alert.priority_score` (0 until the prioritization exists) |
| `criticality` | smallint 1–4 | Criticality of the watched product |
| `days_open` | integer | Days from creation to closing, or to today while the alert is open |
| `is_kev` | boolean | The CVE is in KEV |
| `is_overdue` | boolean | The alert is open and its due date is before today |

### `fact_ioc` — grain: one row per indicator × first-seen day × source

Empty until the ThreatFox connector exists. Primary key: (`indicator_key`, `first_seen_date_key`, `source_key`).

| Column | Type | Description |
|---|---|---|
| `indicator_key` | FK → `dim_indicator` | The indicator |
| `first_seen_date_key` | FK → `dim_date` (role: first_seen) | First day the indicator was seen |
| `malware_key` | FK → `dim_malware`, null | Malware family, when known |
| `threat_type_key` | FK → `dim_threat_type` | Type of threat |
| `source_key` | FK → `dim_source` | Source |
| `ioc_count` | integer | Number of indicators |
| `confidence` | integer 0–100, null | Confidence given by the source |

## Dimensions

| Table | Key | Columns | Loading rule |
|---|---|---|---|
| `dim_date` | `date_key` (yyyymmdd) | `full_date`, `day`, `week` (ISO), `month`, `quarter`, `year` | One row per day, from the earliest to the latest date used by the data (and today). One table, four roles: published, kev_added, alert_created, alert_closed (and first_seen for IOCs). |
| `dim_source` | `source_key` | `name`, `source_type`, `url` | From `pipeline_source`. `source_type` is a label chosen for the warehouse: `cve` = vulnerability catalog, `kev` = exploitation catalog, `epss` = scoring. |
| `dim_vulnerability` | `vuln_key` | `cve_id`, `description`, `nvd_status`, `published_at` (date) | From `cti_vulnerability` |
| `dim_product` | `product_key` (0 = unknown) | `vendor`, `product`, `cpe_prefix`, `is_watched`, `criticality` | From `cti_product`. `is_watched` is true when an organization watches the product; `criticality` is the **highest** criticality among the organizations that watch it. Names are as published by the CNAs (risk R10): the same vendor may appear under several spellings. |
| `dim_weakness` | `weakness_key` (0 = unknown) | `cwe_id`, `name` | Only the `unknown` member today |
| `dim_severity` | `severity_key` | `label`, `score_min`, `score_max` | Static: 0 `NO_SCORE` (no CVSS score), 1 `NONE` (0.0), 2 `LOW` (0.1–3.9), 3 `MEDIUM` (4.0–6.9), 4 `HIGH` (7.0–8.9), 5 `CRITICAL` (9.0–10.0) |
| `dim_alert_status` | `status_key` | `label`, `is_open` | Static: 1 `NEW` and 2 `IN_PROGRESS` (open), 3 `FIXED`, 4 `RISK_ACCEPTED`, 5 `FALSE_POSITIVE` (closed) |
| `dim_technique` | `technique_key` | `technique_id`, `name`, `tactic` | Empty (ATT&CK) |
| `dim_indicator` | `indicator_key` | `value`, `ioc_type` | Empty (ThreatFox) |
| `dim_malware` | `malware_key` | `family`, `category` | Empty (ThreatFox) |
| `dim_threat_type` | `threat_type_key` | `label`, `description` | Empty (ThreatFox) |

### `bridge_cve_technique` — CVE × ATT&CK technique

| Column | Type | Description |
|---|---|---|
| `vuln_key` | FK → `dim_vulnerability` | The CVE |
| `technique_key` | FK → `dim_technique` | The technique |
| `mapping_source` | varchar | Where the mapping comes from |

Empty until the ATT&CK mapping is loaded. Primary key: (`vuln_key`, `technique_key`).

## Checks

| Check | Where |
|---|---|
| Range checks in the tables: CVSS 0–10, EPSS 0–1, criticality 1–4, confidence 0–100 | `01_constellation_ddl.sql` (`CHECK`) |
| Foreign keys are enforced, so no fact row can point to a missing dimension row | `01_constellation_ddl.sql` and test `test_every_fact_row_joins_to_its_dimensions` |
| Refresh twice gives the same row counts | test `test_running_the_refresh_twice_gives_the_same_row_counts` |
| A CVE without product is kept, with its `NO_SCORE` severity | test `test_one_row_per_cve_and_product_and_a_cve_without_product_is_kept` |
| An open alert becomes one row of `fact_alert`; a watched product is flagged | tests in `WarehouseAlertTests` |
| The pipeline runs the refresh as its last step; a failing refresh makes the run `PARTIAL` | tests in `WarehouseInPipelineTests` |

All tests are in `backend/pipeline/tests/test_warehouse.py`.
