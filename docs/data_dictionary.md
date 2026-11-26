# Data dictionary — operational schema

Tables created by Django migrations in the `public` schema. The warehouse (`dw` schema) is documented in [data_warehouse_dictionary.md](data_warehouse_dictionary.md).

## CTI reference data (`cti` app)

### `cti_vulnerability` — one row per published CVE

| Column | Type | Source | Description |
|---|---|---|---|
| `id` | bigint, PK | — | Technical key |
| `cve_id` | varchar(32), unique | CVE List V5 `cveMetadata.cveId` | CVE identifier, format `CVE-YYYY-NNNN…` |
| `assigner` | varchar(64) | CVE List V5 `cveMetadata.assignerShortName` | CNA that published the record, in lowercase (e.g. `wordfence`); a feature of model M1 |
| `title` | varchar(300) | CVE List V5 CNA `title` | Title of the record when the CNA gives one (about 4 CVEs in 10); a feature of model M1 |
| `description` | text | CVE List V5 CNA `descriptions` (English) | Vulnerability description |
| `published_at` | timestamptz, null | CVE List V5 `datePublished` | Publication date (records before 2023 may be inconsistent, risk R3) |
| `source_updated_at` | timestamptz, null, indexed | CVE List V5 `dateUpdated` | Last update of the record; watermark of the incremental load |
| `nvd_status` | varchar(32) | NVD API `vulnStatus` | NVD analysis status (`Analyzed`, `Awaiting Analysis`, `Deferred`, `Modified`…); empty = not read from the NVD yet |
| `epss_score` | float, null | FIRST EPSS (`epss` connector) | Probability of exploitation within 30 days (0–1) |
| `epss_percentile` | float, null | FIRST EPSS (`epss` connector) | Percentile of the EPSS score (0–1) |
| `effective_severity` | varchar, indexed | Computed after each run | Effective severity (FR-06): the severity of the first CVSS score in the order NVD > CNA > CISA ADP, newest version first; without any score, the severity predicted by the active M1 version; empty = no score and no prediction. Used by the search filters (US03) |
| `effective_score` | float, null | Computed after each run | Base score of that effective CVSS score; empty when there is no CVSS score (also when the severity is predicted) |
| `is_severity_predicted` | boolean | Computed after each run | `true` when `effective_severity` comes from M1: shown as *predicted* in the console |

EPSS columns: only the latest score is kept; the `epss` connector updates them in place at each run. The model version and the score date of each run are in `pipeline_ingestiontask.quality_report` (history belongs to the warehouse).

### `cti_cvssmetric` — CVSS scores, one row per vulnerability × provider × version

| Column | Type | Description |
|---|---|---|
| `vulnerability_id` | FK → `cti_vulnerability` | Scored vulnerability |
| `provider` | `NVD` / `CNA` / `CISA_ADP` | Who published the score (CVE List V5 loads CNA and CISA ADP; the NVD connector loads the NVD scores of type *Primary*) |
| `version` | varchar(8) | CVSS version: `2.0`, `3.0`, `3.1`, `4.0` |
| `vector` | varchar(200) | CVSS vector string |
| `base_score` | float, check 0–10 | Base score |
| `severity` | `NONE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` | Qualitative rating (computed from the score when the record has none, e.g. CVSS 2.0) |

Unique: (`vulnerability`, `provider`, `version`). CISA ADP SSVC exploitation fields are never loaded (M2 label leakage, FR-24).

### `cti_product` — normalized products

| Column | Type | Description |
|---|---|---|
| `vendor`, `name` | varchar(200) | Lowercase, single-spaced names as published by the CNA; unique together. Placeholders (`n/a`, `unknown`…) are not loaded. |
| `cpe_prefix` | varchar(200) | NVD CPE prefix `cpe:2.3:part:vendor:product`, set when a vulnerable CPE of one of the product's CVEs names exactly this vendor and product (`_` read as a space); empty when the CNA and the NVD spell the names differently. The first prefix found is kept |

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
| `provider` | varchar(10) | container | `CNA` or `CISA_ADP` (cve connector), `NVD` (NVD weaknesses of type *Primary*); unique with the two FKs |

### `cti_malware` — malware families named by ThreatFox

| Column | Type | Source field | Description |
|---|---|---|---|
| `malpedia_id` | varchar(100), unique | `malware` | Malpedia name, e.g. `win.cobalt_strike`; `unknown` is not stored |
| `name` | varchar(200) | `malware_printable` | Display name, e.g. `Cobalt Strike` |
| `category` | varchar(50) | prefix of `malware` | Target platform: `win` → Windows, `elf` → Linux, `apk` → Android, `osx` → macOS…; `Other` otherwise |

### `cti_indicator` — indicators of compromise (abuse.ch ThreatFox)

IOC values are data only: never visited, resolved or shown as links (risk R9). Read-only in the admin.

| Column | Type | Source field | Description |
|---|---|---|---|
| `threatfox_id` | bigint, unique | `id` | ThreatFox identifier (key of the upsert) |
| `value` | text | `ioc` | The indicator: `ip:port`, domain, URL or file hash |
| `ioc_type` | varchar(50) | `ioc_type` | `ip:port`, `domain`, `url`, `md5_hash`, `sha256_hash`… |
| `threat_type` | varchar(50) | `threat_type` | `botnet_cc`, `payload_delivery`, `payload`… |
| `malware_id` | FK, null | `malware` | Malware family; empty when ThreatFox gives `unknown` |
| `confidence` | smallint 0–100 | `confidence_level` | Confidence given by the reporter |
| `first_seen`, `last_seen` | timestamptz | `first_seen`, `last_seen` | UTC; `last_seen` is often empty |

### `cti_technique` — MITRE ATT&CK Enterprise techniques and sub-techniques (attack connector, #61)

| Column | Type | Source field | Description |
|---|---|---|---|
| `technique_id` | varchar(16), unique | `external_references` (`mitre-attack`) | ATT&CK id, e.g. `T1059`, or the sub-technique `T1059.001` |
| `stix_id` | varchar(100), unique | `id` | STIX id (`attack-pattern--…`), used to read the relationships |
| `name` | varchar(300) | `name` | e.g. `Command and Scripting Interpreter` |
| `tactics` | varchar(300) | `kill_chain_phases` (`mitre-attack`) | Comma-separated tactics, e.g. `execution` |
| `is_subtechnique` | boolean | `x_mitre_is_subtechnique` | |

### `cti_threatgroup` — MITRE ATT&CK threat groups (attack connector, US17)

| Column | Type | Source field | Description |
|---|---|---|---|
| `group_id` | varchar(16), unique | `external_references` (`mitre-attack`) | e.g. `G0007` |
| `stix_id` | varchar(100), unique | `id` | `intrusion-set--…` |
| `name` | varchar(200) | `name` | e.g. `APT28` |
| `aliases` | JSON list | `aliases`, without the name | e.g. `["Fancy Bear", "Sofacy"]` |
| `cluster_id` | integer, nullable | — | Cluster of groups with similar techniques, set by the clustering model M3; empty until M3 runs |

The links of a group come from the ATT&CK *uses* relationships and are rebuilt at each run: `cti_threatgroup_techniques` (`threatgroup_id`, `technique_id`: the binary group × technique matrix of M3) and `cti_threatgroup_software` (`threatgroup_id`, `software_id`). Revoked and deprecated objects are skipped. Rejected: invalid ATT&CK id, missing name, missing STIX id, duplicate object.

### `cti_software` — MITRE ATT&CK software: malware and tools (attack connector)

Kept apart from `cti_malware` (ThreatFox families named by Malpedia): the two catalogs use different identifiers.

| Column | Type | Source field | Description |
|---|---|---|---|
| `software_id` | varchar(16), unique | `external_references` (`mitre-attack`) | e.g. `S0154` |
| `stix_id` | varchar(100), unique | `id` | `malware--…` or `tool--…` |
| `name` | varchar(200) | `name` | e.g. `Cobalt Strike` |
| `kind` | varchar(10) | STIX type | `MALWARE` or `TOOL` |
| `aliases` | JSON list | `x_mitre_aliases`, without the name | |

### `cti_vulnerabilitytechnique` — vulnerability × ATT&CK technique (ctid connector, #61)

From the CTID mappings of the KEV catalog (Mappings Explorer), rebuilt at each run. Partial coverage: on 26 Nov 2026, 419 CVEs, 23.4 % of the KEV catalog. Rejected: invalid CVE id, CVE not in the CVE list, technique not in the loaded ATT&CK version, unknown mapping type, duplicate mapping.

| Column | Type | Source field | Description |
|---|---|---|---|
| `vulnerability_id` | FK → `cti_vulnerability` | `capability_id` | The CVE |
| `technique_id` | FK → `cti_technique` | `attack_object_id` | The technique |
| `mapping_type` | varchar(30) | `mapping_type` | `exploitation_technique`, `primary_impact`, `secondary_impact` or `uncategorized` |
| `source` | varchar(20) | — | `ctid_kev` |

Unique: (`vulnerability_id`, `technique_id`, `mapping_type`).

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
| `priority_score` | float 0–100 | Weighted mean of severity, EPSS, KEV and product criticality (FR-10, weights in `settings.PRIORITY_WEIGHTS`, see the README); recomputed for open alerts at each run, frozen when the alert is closed |
| `due_date` | date | Creation date + `ALERT_DUE_DAYS[effective severity]` (CRITICAL 7, HIGH 30, MEDIUM 90, LOW 180, no score 30 days); CISA's KEV due date when it is earlier |
| `assignee_id` | FK → `accounts_user`, null | Analyst in charge (US11) |
| `plan_id` | FK → `alerts_remediationplan`, null | Weekly plan that schedules the fix (US14); an open alert of an earlier week's plan can be moved to a later plan |

Unique together: (`vulnerability_id`, `watchlist_item_id`): never two alerts for the same CVE and watched product.
**Effective severity** (FR-06): the CVSS score of the first provider in the order NVD > CNA > CISA ADP, newest CVSS version first (`Vulnerability.effective_metric()`).

### `alerts_remediationplan` — weekly remediation plan (US14, FR-12)

One plan per organization and week. Workflow: `DRAFT` → `SUBMITTED` → `APPROVED`, or `SUBMITTED` → `CHANGES_REQUESTED` → `SUBMITTED`. The plan can be changed only while `DRAFT` or `CHANGES_REQUESTED`.

| Column | Type | Description |
|---|---|---|
| `organization_id` | FK → `accounts_organization` | Unique with `period_start` |
| `period_start`, `period_end` | date | Monday and Sunday of the week |
| `status` | varchar(20) | `DRAFT`, `SUBMITTED`, `CHANGES_REQUESTED`, `APPROVED` |
| `prepared_by_id` | FK → `accounts_user` | Analyst who created the plan |
| `created_at`, `submitted_at` | timestamptz | Creation and last submission |
| `validated_at`, `validated_by_id` | timestamptz, FK → `accounts_user`, null | Approval date and approver (a CISO who did not prepare the plan) |
| `ciso_comment` | text | Approval note, or the changes requested (required to request changes) |

### `alerts_alertstatuschange` — status history of an alert

| Column | Type | Description |
|---|---|---|
| `alert_id` | FK → `alerts_alert` | |
| `old_status`, `new_status` | varchar | Empty old status = creation |
| `comment` | text | e.g. "Created by pipeline run 12."; written by the analyst with a status change (US11) |
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
| `name` | Connector key (`cwe`, `cve`, `nvd`, `kev`, `epss`, `threatfox`), unique |
| `label`, `url` | Display name and reference URL |
| `frequency` | `hourly`, `daily` (default) or `weekly`: a scheduled run (`run_pipeline --scheduled`) skips the source until 90 % of this delay has passed since its last successful task; an unknown value counts as `daily` (FR-15) |
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

## Machine learning (`ml` app)

### `ml_mlmodel` — trained model versions (FR-26)

| Column | Type | Description |
|---|---|---|
| `name` | varchar(50) | `m1-severity` (M2 and M3 later) |
| `task` | `SEVERITY` / `EXPLOITATION` / `CLUSTERING` | M1, M2, M3 |
| `version` | varchar(20) | `1`, `2`… in training order; unique with `name` |
| `algorithm` | varchar(200) | e.g. "TF-IDF + logistic regression: severity class and CVSS base metrics (official CVSS formula), combined" |
| `metrics` | JSON | Test period, strict split: `macro_f1`, `accuracy`, `right_or_one_class_away`, `f1_by_class`, `confusion_matrix`, `by_scorer`, `by_confidence`, `reference_text_only`; `retrained_each_quarter` (same scores with a model retrained before each quarter, and the detail by quarter); settings (`features`, `C`, `metric_weight` and its validation scores), `label`, periods and sizes |
| `artifact` | varchar(200) | File in `ml/models/` (git-ignored), e.g. `m1_severity_v1.joblib` |
| `trained_at` | timestamptz | |
| `is_active` | boolean | Version used for scoring; at most one active version per task |

### `ml_severityprediction` — severity predicted by M1 (FR-23, UC19)

One row per model version × CVE. The pipeline predicts the CVEs without any CVSS score: not yet predicted by the active version, or updated since their prediction. The prediction is the score an independent analyst (CISA ADP, NVD) would give, since the CNA gave none.

| Column | Type | Description |
|---|---|---|
| `model_id` | FK → `ml_mlmodel` | Model version that made the prediction |
| `vulnerability_id` | FK → `cti_vulnerability` | Unique with `model_id` |
| `created_at` | timestamptz | Date of the (latest) prediction |
| `predicted_severity` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` | Predicted class |
| `confidence` | float, check 0–1 | Probability of the predicted class given by the model (in `ml_mlmodel.metrics`, `by_confidence` gives the scores of the most confident predictions) |

The predictions stay when the CVE later gets a CVSS score (the score then wins, FR-06). The secondary target of FR-23 (CWE) is not predicted: risk R4 plan, see [decisions](decisions.md).

## Quality rules applied at load time

| Source | Rule | Effect |
|---|---|---|
| CVE List V5 | identifier matches `CVE-YYYY-NNNN…` | otherwise rejected |
| CVE List V5 | English description present | otherwise rejected |
| CVE List V5 | every CVSS base score in 0–10 | otherwise rejected |
| CVE List V5 | state = `PUBLISHED` | otherwise skipped (counted) |
| CVE List V5 | same CVE twice in a file | last one kept (counted) |
| CVE List V5 | `cweId` matches `CWE-NNN` | otherwise not linked (free-text problem types ignored) |
| NVD | identifier matches `CVE-YYYY-NNNN…` | otherwise rejected |
| NVD | every CVSS base score in 0–10 | otherwise rejected |
| NVD | CVE already in `cti_vulnerability` | otherwise skipped (counted: `skipped_not_in_cve_list`) |
| NVD | only data of type *Primary* (NIST); `NVD-CWE-Other` / `NVD-CWE-noinfo` ignored | CNA data comes from CVE List V5 |
| NVD | same CVE in two overlapping windows | last one kept (counted) |
| NVD | CPE prefix only for an affected product of the same CVE with exactly the same vendor and product | otherwise not used (counted: `cpes_not_matched`) |
| ThreatFox | `id` is a number | otherwise rejected |
| ThreatFox | IOC value, IOC type and threat type present | otherwise rejected |
| ThreatFox | `confidence_level` between 0 and 100 | otherwise rejected |
| ThreatFox | `first_seen` is a valid date | otherwise rejected |
| ThreatFox | IOC once in the file | duplicates rejected |
| ThreatFox | malware `unknown` | IOC kept without family (counted: `without_malware_family`) |
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
