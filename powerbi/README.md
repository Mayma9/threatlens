# Power BI

Power BI Desktop reports (`.pbix`) connected to the `dw` schema of the PostgreSQL warehouse. Reports are opened in Power BI Desktop, outside the Django console (specification FR-21).

## Connection

| Parameter | Value |
|---|---|
| Connector | PostgreSQL database (*Get data → Database → PostgreSQL database*) |
| Server | `localhost:5432` |
| Database | `threatlens` (value of `POSTGRES_DB` in `.env`) |
| Data connectivity mode | Import |
| User | `powerbi_reader` |
| Password | value of `POWERBI_READER_PASSWORD` in your `.env` |

The `powerbi_reader` account is read-only and can only see the `dw` schema (created by `warehouse/init/01_dw_schema_and_powerbi_user.sh`). The containers must be running (`docker compose up -d`).

If Power BI asks about encryption, accept connecting without encryption: the database only listens on your own computer.

To refresh the report with the latest data: run the pipeline (or `docker compose exec -T web python manage.py refresh_warehouse`), then click **Refresh** in Power BI Desktop.

## Files

| File | Content |
|---|---|
| `threatlens_exposure.pbix` | First report (US09): vulnerability volume, severity and exposure |
| `check_kpis.sql` | Expected values of the report cards, computed in SQL (data-quality check of the report) |
| `threatlens_decision.pbix` | Decision report (US12): threat activity, remediation, drill-down (the ML page is not built yet) |
| `check_threat_activity.sql` | Expected values of the *Threat activity* page of the decision report, computed in SQL |
| `check_remediation.sql` | Expected values of the *Remediation* page (KEV delay, alerts), computed in SQL |
| `check_drilldown.sql` | Expected values of the *Drill-down* page (top vendors, CWEs of the first vendor), computed in SQL |

## Report `threatlens_exposure.pbix` (US09)

### Model

| Table | Rows | Note |
|---|---|---|
| `fact_vulnerability` | one per CVE × affected product | Count CVEs with `DISTINCTCOUNT(vuln_key)` |
| `fact_alert` | one per alert | Exposure of the watchlist (CVE × watched product, product aliases included) |
| `dim_date`, `dim_vulnerability`, `dim_product`, `dim_weakness`, `dim_severity` | dimensions | `dim_vulnerability` is loaded without `description` (size) |

The IOC and alert-status tables are used by the decision report below; the ATT&CK tables (`dim_technique`, `bridge_cve_technique`) are still empty.

Relationships (many-to-one, single direction, from the fact table to the dimension):

| From | To | Active |
|---|---|---|
| `fact_vulnerability[vuln_key]` | `dim_vulnerability[vuln_key]` | yes |
| `fact_vulnerability[product_key]` | `dim_product[product_key]` | yes |
| `fact_vulnerability[weakness_key]` | `dim_weakness[weakness_key]` | yes |
| `fact_vulnerability[severity_key]` | `dim_severity[severity_key]` | yes |
| `fact_vulnerability[published_date_key]` | `dim_date[date_key]` | yes (role: published) |
| `fact_vulnerability[kev_date_key]` | `dim_date[date_key]` | **no** (role: KEV added, used with `USERELATIONSHIP`) |
| `fact_alert[vuln_key]` | `dim_vulnerability[vuln_key]` | yes |
| `fact_alert[product_key]` | `dim_product[product_key]` | yes |
| `fact_alert[severity_key]` | `dim_severity[severity_key]` | yes |
| `fact_alert[created_date_key]` | `dim_date[date_key]` | yes (role: alert created) |

Model settings:
- *File → Options and settings → Options → Current file → Data load*: **Auto date/time** off.
- `dim_severity[label]`: *Sort by column* → `severity_key`.
- Calculated column `dim_date[Year Month] = FORMAT(dim_date[full_date], "yyyy-MM")` (DAX names are case-insensitive: `Month` would clash with the `month` column).
- Hierarchy **Calendar** in `dim_date`: `year` → `quarter` → `month` → `full_date`.

### Measures

```dax
-- in fact_vulnerability
CVEs = DISTINCTCOUNT ( fact_vulnerability[vuln_key] )
New CVEs (30 days) = CALCULATE ( [CVEs], dim_date[full_date] > TODAY () - 30 )
CVEs without CVSS = CALCULATE ( [CVEs], FILTER ( ALL ( fact_vulnerability[cvss_score] ), ISBLANK ( fact_vulnerability[cvss_score] ) ) )
% without CVSS = DIVIDE ( [CVEs without CVSS], [CVEs] )
KEV CVEs = CALCULATE ( [CVEs], fact_vulnerability[is_kev] = TRUE () )
% KEV = DIVIDE ( [KEV CVEs], [CVEs] )
Median days to KEV =
    CALCULATE (
        MEDIANX (
            SUMMARIZE ( fact_vulnerability, fact_vulnerability[vuln_key], fact_vulnerability[days_to_kev] ),
            fact_vulnerability[days_to_kev]
        ),
        fact_vulnerability[is_kev] = TRUE ()
    )
KEV CVEs by date added = CALCULATE ( [KEV CVEs], USERELATIONSHIP ( fact_vulnerability[kev_date_key], dim_date[date_key] ) )
Median days to KEV by date added = CALCULATE ( [Median days to KEV], USERELATIONSHIP ( fact_vulnerability[kev_date_key], dim_date[date_key] ) )

-- in fact_alert
Watchlist CVEs = DISTINCTCOUNT ( fact_alert[vuln_key] )
Watchlist KEV CVEs = CALCULATE ( [Watchlist CVEs], fact_alert[is_kev] = TRUE () )

-- in dim_product
Watched products = CALCULATE ( COUNTROWS ( dim_product ), dim_product[is_watched] = TRUE () )
```

Format: `% without CVSS` and `% KEV` as percentage with 1 decimal; the others as whole numbers.

### Pages

| Page | Visuals |
|---|---|
| **Volume** | Cards: `CVEs`, `New CVEs (30 days)`, `% KEV`. Clustered column chart: X = hierarchy **Calendar**, Y = `CVEs` (drill-down year → quarter → month → day). Line chart: X = `dim_date[Year Month]`, Y = `CVEs`, filter `full_date` in the last 24 months. Slicers: `dim_date[year]` (between), `dim_severity[label]`. |
| **Severity** | Cards: `CVEs without CVSS`, `% without CVSS`. Stacked column chart: X = `dim_date[year]`, Y = `CVEs`, legend = `dim_severity[label]`. Line chart: X = `dim_date[Year Month]`, Y = `% without CVSS`, last 24 months (shows the CVEs left without a score). Bar chart: Y = `dim_severity[label]`, X = `CVEs`. Slicer: `dim_date[year]`. |
| **Exposure** | Cards: `Watched products`, `Watchlist CVEs`, `Watchlist KEV CVEs`, `Median days to KEV`. Table of watched products: `vendor`, `product`, `criticality`, `Watchlist CVEs`, `Watchlist KEV CVEs` (filter `is_watched` = True). Bar charts: top 10 `dim_product[vendor]` by `CVEs` (visual filters: `dim_product[product_key]` is not 0, Top N 10 on `vendor`) and top 10 `dim_weakness[cwe_id]` by `CVEs` with `name` in the tooltip (visual filters: `dim_weakness[weakness_key]` is not 0, Top N 10 on `cwe_id`). Line and clustered column chart: X = `dim_date[year]`, columns = `KEV CVEs by date added`, line = `Median days to KEV by date added`, visual filter `year` ≥ 2021 (start of the KEV catalog). No date slicer on this page. |

**Check.** With no slicer selected, the cards must show the values of `docker compose exec -T db psql -U threatlens -d threatlens < powerbi/check_kpis.sql` (in Windows PowerShell: `Get-Content powerbi\check_kpis.sql -Raw | docker compose exec -T db psql -U threatlens -d threatlens`).

Severity colors (same as the console): CRITICAL `#FF6B6B`, HIGH `#F5B544`, MEDIUM `#2DD4EF`, LOW `#7BD88F`, NONE `#9FB3CA`, NO_SCORE `#5B6B7F`.

## Report `threatlens_decision.pbix` (US12)

Decision report for the CISO. It is a separate file from `threatlens_exposure.pbix` because a `.pbix` is binary and cannot be merged by Git. Same connection as above (Import mode, `powerbi_reader`). Pages: **Threat activity**, **Remediation**, **Drill-down**; the ML page is not built yet (see `docs/decisions.md`). In Import mode the file stores a copy of the loaded columns (public CVE, product and IOC metadata, no secret), about 23 MB.

After each pipeline run, click **Refresh** for the whole report: tables loaded at different times do not match (for example a CVE published after the last load of `dim_date` disappears from the Remediation page).

### Model

| Table | Rows | Note |
|---|---|---|
| `fact_ioc` | one per indicator × first-seen day × source | `malware_key` is empty for the IOCs that ThreatFox gives with no family or as `unknown` (see below) |
| `fact_kev` | one per KEV CVE × affected product | Query on `dw.fact_vulnerability` filtered on `is_kev` = TRUE, columns `vuln_key`, `published_date_key`, `is_kev`, `days_to_kev` |
| `fact_vulnerability` | one per CVE × affected product | Columns `vuln_key`, `product_key`, `weakness_key` (drill-down); count CVEs with `DISTINCTCOUNT(vuln_key)` |
| `fact_alert` | one per alert | `is_overdue` is true only for open alerts |
| `dim_product`, `dim_vulnerability`, `dim_weakness` | dimensions | Only `product_key`, `vendor`, `product`; `vuln_key`, `cve_id`; `weakness_key`, `cwe_id`, `name` |
| `dim_date`, `dim_malware`, `dim_threat_type`, `dim_alert_status` | dimensions | |

`dim_indicator` is **not loaded**: it holds the IOC values, which are never shown or opened (risk R9). The tables are renamed without the `dw` prefix that Power BI adds (`fact_ioc`, not `dw fact_ioc`), so the measures below can be copied as they are.

Relationships (many-to-one, single direction, from the fact table to the dimension):

| From | To | Active |
|---|---|---|
| `fact_ioc[first_seen_date_key]` | `dim_date[date_key]` | yes (role: first seen) |
| `fact_ioc[malware_key]` | `dim_malware[malware_key]` | yes |
| `fact_ioc[threat_type_key]` | `dim_threat_type[threat_type_key]` | yes |
| `fact_kev[published_date_key]` | `dim_date[date_key]` | yes (role: published) |
| `fact_alert[status_key]` | `dim_alert_status[status_key]` | yes |
| `fact_alert[vuln_key]` | `dim_vulnerability[vuln_key]` | yes |
| `fact_alert[product_key]` | `dim_product[product_key]` | yes |
| `fact_vulnerability[vuln_key]` | `dim_vulnerability[vuln_key]` | yes |
| `fact_vulnerability[product_key]` | `dim_product[product_key]` | yes |
| `fact_vulnerability[weakness_key]` | `dim_weakness[weakness_key]` | yes |

`fact_alert` has no relationship with `dim_date`, so the page filter of the Remediation page (CVEs published since 2023) acts on the KEV visuals only. Check that `fact_alert[vuln_key]` is many-to-one: Power BI may propose one-to-one (both directions) when no CVE has two alerts, which makes `fact_vulnerability[product_key]` inactive.

Model settings: **Auto date/time** off (as above); page size *Custom* 1280 × 720 on each page; `dim_date[year]`: *Summarization* → Don't summarize; *Sort by column*: `fact_kev[KEV delay]` → `KEV delay order`, `fact_alert[Priority band]` → `Priority band order`, `dim_alert_status[label]` → `status_key`.

### Measures

```dax
-- in fact_ioc
IOCs = SUM ( fact_ioc[ioc_count] )
Families = DISTINCTCOUNTNOBLANK ( fact_ioc[malware_key] )
Average confidence = AVERAGE ( fact_ioc[confidence] )
IOCs without family = CALCULATE ( [IOCs], ISBLANK ( fact_ioc[malware_key] ) )
% IOCs without family = DIVIDE ( [IOCs without family], [IOCs] )

-- in fact_kev
KEV CVEs = DISTINCTCOUNT ( fact_kev[vuln_key] )
Median days to KEV = MEDIANX ( SUMMARIZE ( fact_kev, fact_kev[vuln_key], fact_kev[days_to_kev] ), fact_kev[days_to_kev] )
% KEV before publication = DIVIDE ( CALCULATE ( [KEV CVEs], fact_kev[days_to_kev] < 0 ), [KEV CVEs] )
% KEV within 30 days = DIVIDE ( CALCULATE ( [KEV CVEs], fact_kev[days_to_kev] <= 30 ), [KEV CVEs] )
% KEV within 90 days = DIVIDE ( CALCULATE ( [KEV CVEs], fact_kev[days_to_kev] <= 90 ), [KEV CVEs] )
% KEV within 180 days = DIVIDE ( CALCULATE ( [KEV CVEs], fact_kev[days_to_kev] <= 180 ), [KEV CVEs] )

-- calculated columns in fact_kev
KEV delay = SWITCH ( TRUE (), fact_kev[days_to_kev] < 0, "Before publication", fact_kev[days_to_kev] <= 30, "0-30 days", fact_kev[days_to_kev] <= 90, "31-90 days", fact_kev[days_to_kev] <= 180, "91-180 days", "Over 180 days" )
KEV delay order = SWITCH ( TRUE (), fact_kev[days_to_kev] < 0, 1, fact_kev[days_to_kev] <= 30, 2, fact_kev[days_to_kev] <= 90, 3, fact_kev[days_to_kev] <= 180, 4, 5 )

-- in fact_alert
Alerts = COUNTROWS ( fact_alert )
Open alerts = CALCULATE ( COUNTROWS ( fact_alert ), dim_alert_status[is_open] = TRUE () )
Overdue alerts = CALCULATE ( COUNTROWS ( fact_alert ), fact_alert[is_overdue] = TRUE () )
Fixed alerts = CALCULATE ( COUNTROWS ( fact_alert ), dim_alert_status[label] = "FIXED" )
MTTR (days) = CALCULATE ( AVERAGE ( fact_alert[days_open] ), dim_alert_status[label] = "FIXED" )
Priority score = MAX ( fact_alert[priority_score] )

-- calculated columns in fact_alert
Priority band = SWITCH ( TRUE (), fact_alert[priority_score] >= 75, "Very high", fact_alert[priority_score] >= 50, "High", fact_alert[priority_score] >= 25, "Medium", "Low" )
Priority band order = SWITCH ( TRUE (), fact_alert[priority_score] >= 75, 1, fact_alert[priority_score] >= 50, 2, fact_alert[priority_score] >= 25, 3, 4 )

-- in fact_vulnerability
CVEs = DISTINCTCOUNT ( fact_vulnerability[vuln_key] )
```

`Families` uses `DISTINCTCOUNTNOBLANK`: `DISTINCTCOUNT` would count the empty family as one more family, unlike SQL `count(DISTINCT ...)`. `KEV CVEs` and `Median days to KEV` count each CVE once (one row per CVE × product). `MTTR (days)` counts FIXED alerts only (FR-22). Format: the `%` measures as percentage with 1 decimal; `Average confidence`, `Median days to KEV`, `MTTR (days)` and `Priority score` with 1 decimal; the others as whole numbers.

### Pages

| Page | Visuals |
|---|---|
| **Threat activity** | Cards: `IOCs`, `Families`, `Average confidence`, `% IOCs without family`. Clustered bar chart *Top 10 malware families (IOCs)*: Y = `dim_malware[family]`, X = `IOCs` (visual filters: Top N 10 on `family` by `IOCs`, `fact_ioc[malware_key]` is not blank). Clustered bar chart *IOCs by threat type*: Y = `dim_threat_type[label]`, X = `IOCs`. Clustered column chart *IOCs by first-seen day*: X = `dim_date[full_date]`, Y = `IOCs`, no date filter (each ThreatFox load returns the IOCs first seen in the last 7 days). A text box explains the source, "Unknown Loader", the IOCs without family and risk R9. |
| **Remediation** | Page filter: `dim_date[year]` ≥ 2023 (acts on `fact_kev` only). Top, alerts: cards `Open alerts`, `Overdue alerts`, `Fixed alerts`, `MTTR (days)`; stacked bar chart *Open alerts by priority and status*: Y = `fact_alert[Priority band]`, X = `Open alerts`, legend = `dim_alert_status[label]`; table *Overdue alerts*: `dim_vulnerability[cve_id]`, `dim_product[vendor]`, `dim_product[product]`, `dim_alert_status[label]`, `Priority score` (visual filter `fact_alert[is_overdue]` = True, sorted by `Priority score`, totals off); a text box on the demo data. Bottom, KEV delay: cards `KEV CVEs`, `Median days to KEV`, `% KEV within 30 days`, `% KEV before publication`; clustered column chart *KEV CVEs by delay after publication*: X = `fact_kev[KEV delay]`, Y = `KEV CVEs`; line and clustered column chart *KEV CVEs and median delay by publication year*: X = `dim_date[year]` (categorical), columns = `KEV CVEs`, line = `Median days to KEV` (secondary axis); a text box (source, "before publication", recent years, all-time median on the exposure report). |
| **Drill-down** | Clustered bar chart *CVEs by vendor, then CWE, then CVE*: Y = `dim_product[vendor]`, then `dim_weakness[cwe_id]`, then `dim_vulnerability[cve_id]`; X = `CVEs` (visual filters: `dim_product[product_key]` is not 0, Top N 10 on `vendor` by `CVEs`). Drill with the arrows of the visual. A text box explains how to drill, risk R10 and the missing technique level. |

**IOCs without family.** The ThreatFox connector stores no family when ThreatFox gives an empty value or `unknown` (`UNKNOWN_MALWARE` in `backend/pipeline/connectors/threatfox.py`), and counts these IOCs in the quality report of the run (`without_malware_family`). They are counted in `IOCs` and in their own card, and left out of the top 10. "Unknown Loader" is a ThreatFox catch-all label for loaders not attributed to a known family; it is kept as a family.

**Alerts on a development database.** Alerts exist only for watched products. Add products in the console (`/watchlist/`), run `docker compose exec -T web python manage.py generate_alerts --since <YYYY-MM-DD>` then `refresh_warehouse`, and change a few statuses in `/alerts/` (start the comment with "Demo:"). Alerts created and fixed the same day give an MTTR of 0 days: a demo value, not a real remediation time.

**Unknown CWE.** On the Drill-down page, `unknown` (weakness key 0) groups the CVEs whose record names no CWE, for example more than half of the Linux CVEs on the local warehouse in November 2026.

**Checks.** With no filter selected and no drill, each page must show the values of its SQL file: `check_threat_activity.sql`, `check_remediation.sql` (part 1: KEV delay, part 2: alerts), `check_drilldown.sql`. Run one with `docker compose exec -T db psql -U threatlens -d threatlens < powerbi/<file>.sql` (in Windows PowerShell: `Get-Content powerbi\<file>.sql -Raw | docker compose exec -T db psql -U threatlens -d threatlens`). If two families tie for the 10th place, Power BI shows both while SQL shows one.

## Troubleshooting

| Problem | Fix |
|---|---|
| *We couldn't authenticate with the credentials provided* although the password is the one of `.env` | Another PostgreSQL installed on Windows also listens on port 5432 (`netstat -ano \| grep ":5432 "` shows two PIDs). Stop it (PowerShell as administrator: `Get-Service *postgres* \| Stop-Service`) or use the server `127.0.0.1:5432`. |
| The `powerbi_reader` password in the database differs from `.env` (the role is created once, with the database volume) | Reset it from `.env`: see the command below. |
| The first **Refresh** after opening a `.pbix` fails with *A cyclic reference was encountered during evaluation* on some tables, although the same file refreshes on another computer | Known Power BI Desktop issue with the first refresh after opening a file: click **Close**, then **Refresh** again. If it comes back, update Power BI Desktop or clear its cache (*File → Options and settings → Options → Global → Data load → Clear cache*). |
| A page shows fewer CVEs or IOCs than its SQL check after a pipeline run | Some tables of the report are older than others: click **Refresh** for the whole report, not one table. |

```bash
PW=$(grep '^POWERBI_READER_PASSWORD=' .env | cut -d= -f2-)
docker compose exec -T db psql -U threatlens -d threatlens -v ON_ERROR_STOP=1 -v pw="$PW" <<'SQL'
SELECT 'CREATE ROLE powerbi_reader LOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'powerbi_reader')\gexec
ALTER ROLE powerbi_reader WITH LOGIN PASSWORD :'pw';
GRANT CONNECT ON DATABASE threatlens TO powerbi_reader;
GRANT USAGE ON SCHEMA dw TO powerbi_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA dw TO powerbi_reader;
ALTER ROLE powerbi_reader SET search_path = dw;
SQL
```

## KPIs

| KPI (FR-22) | Definition | Measure | Source |
|---|---|---|---|
| New CVEs per period | Distinct CVEs by publication date (day, month, quarter, year) | `CVEs` with the **Calendar** hierarchy; `New CVEs (30 days)` | `fact_vulnerability`, `dim_date` (published) |
| Share of CVEs without any CVSS score | CVEs with an empty `cvss_score` / all CVEs (with or without a severity predicted by M1) | `% without CVSS` | `fact_vulnerability` |
| KEV vulnerabilities affecting the watchlist | Distinct KEV CVEs with an alert on a watched product (product names and aliases) | `Watchlist KEV CVEs` | `fact_alert` |
| Delay between publication and KEV addition | Median of `days_to_kev` over distinct KEV CVEs (the median, because CVEs added when the catalog started in 2021 are years old); on the decision report, for the CVEs published since 2023, with the share added within 30, 90 and 180 days | `Median days to KEV`, `Median days to KEV by date added`; `% KEV within 30 days` (report `threatlens_decision.pbix`) | `fact_vulnerability`, `dim_date` (KEV added); `fact_kev`, `dim_date` (published) |
| Open alerts by priority and status, mean time to remediate, overdue alerts | Open alerts (NEW, IN_PROGRESS) by priority band and status; mean days from creation to FIXED; open alerts past their due date | `Open alerts`, `MTTR (days)`, `Overdue alerts` (report `threatlens_decision.pbix`) | `fact_alert`, `dim_alert_status` |
| IOC volume by malware family | IOCs by first-seen day, malware family and threat type (ThreatFox); IOCs without family counted apart | `IOCs`, `Families`, `% IOCs without family` (report `threatlens_decision.pbix`) | `fact_ioc`, `dim_malware`, `dim_threat_type`, `dim_date` (first seen) |
| Performance of M1 and M2 | Sprint 3–4: table `dw.ml_model_metric` to build first (see `docs/decisions.md`) | | ML metrics |

`Watchlist CVEs` counts only the CVEs that have an alert. For CVEs loaded before a product was added to the watchlist, run `generate_alerts --since` first (see the main README).
