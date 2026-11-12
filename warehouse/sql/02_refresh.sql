-- warehouse/sql/02_refresh.sql
-- ELT refresh of the dw schema from the operational (public) schema. It is a full rebuild: it empties
-- the tables it fills, then loads the dimensions, then the fact tables. Run it inside ONE transaction
-- (psql -1, or the refresh_warehouse command): if anything fails, nothing changes.
-- Running it twice gives the same rows (idempotent).
--
-- Not filled yet (no source in the operational schema): dim_technique, bridge_cve_technique,
-- dim_indicator, dim_malware, dim_threat_type and fact_ioc stay empty.

TRUNCATE
    dw.fact_vulnerability, dw.fact_alert, dw.fact_ioc, dw.bridge_cve_technique,
    dw.dim_date, dw.dim_source, dw.dim_vulnerability, dw.dim_product,
    dw.dim_weakness, dw.dim_severity, dw.dim_alert_status;

-- ============================================================ dimensions

-- Calendar from the earliest to the latest date used by the data (and today).
WITH bounds AS (
    SELECT
        least(
            (SELECT min((published_at AT TIME ZONE 'UTC')::date) FROM public.cti_vulnerability),
            (SELECT min(date_added) FROM public.cti_keventry),
            (SELECT min((created_at AT TIME ZONE 'UTC')::date) FROM public.alerts_alert),
            (now() AT TIME ZONE 'UTC')::date
        ) AS first_day,
        greatest(
            (SELECT max((published_at AT TIME ZONE 'UTC')::date) FROM public.cti_vulnerability),
            (SELECT max(date_added) FROM public.cti_keventry),
            (SELECT max((created_at AT TIME ZONE 'UTC')::date) FROM public.alerts_alert),
            (now() AT TIME ZONE 'UTC')::date
        ) AS last_day
)
INSERT INTO dw.dim_date (date_key, full_date, day, week, month, quarter, year)
SELECT
    to_char(g.d::date, 'YYYYMMDD')::integer,
    g.d::date,
    EXTRACT(day FROM g.d)::smallint,
    EXTRACT(week FROM g.d)::smallint,
    EXTRACT(month FROM g.d)::smallint,
    EXTRACT(quarter FROM g.d)::smallint,
    EXTRACT(year FROM g.d)::smallint
FROM bounds
CROSS JOIN LATERAL generate_series(bounds.first_day::timestamp, bounds.last_day::timestamp, interval '1 day') AS g(d);

INSERT INTO dw.dim_source (source_key, name, source_type, url)
SELECT
    id,
    name,
    CASE name
        WHEN 'cve'  THEN 'vulnerability catalog'
        WHEN 'cwe'  THEN 'weakness catalog'
        WHEN 'kev'  THEN 'exploitation catalog'
        WHEN 'epss' THEN 'scoring'
        ELSE 'other'
    END,
    COALESCE(url, '')
FROM public.pipeline_source;

-- Severity labels as stored in cti_vulnerability.effective_severity; an empty value = no CVSS score.
INSERT INTO dw.dim_severity (severity_key, label, score_min, score_max) VALUES
    (0, 'NO_SCORE', NULL, NULL),
    (1, 'NONE',     0.0,  0.0),
    (2, 'LOW',      0.1,  3.9),
    (3, 'MEDIUM',   4.0,  6.9),
    (4, 'HIGH',     7.0,  8.9),
    (5, 'CRITICAL', 9.0, 10.0);

INSERT INTO dw.dim_alert_status (status_key, label, is_open) VALUES
    (1, 'NEW',            true),
    (2, 'IN_PROGRESS',    true),
    (3, 'FIXED',          false),
    (4, 'RISK_ACCEPTED',  false),
    (5, 'FALSE_POSITIVE', false);

-- CWE catalog (cwe connector) and the CWEs named by the CVE records. Key 0: the record names no CWE.
INSERT INTO dw.dim_weakness (weakness_key, cwe_id, name) VALUES
    (0, 'unknown', 'No CWE named by the CVE record');

INSERT INTO dw.dim_weakness (weakness_key, cwe_id, name)
SELECT id, cwe_id, name
FROM public.cti_weakness;

INSERT INTO dw.dim_vulnerability (vuln_key, cve_id, description, nvd_status, published_at)
SELECT id, cve_id, description, nvd_status, (published_at AT TIME ZONE 'UTC')::date
FROM public.cti_vulnerability;

-- Unknown product (key 0): CVEs that name no affected product stay in fact_vulnerability.
INSERT INTO dw.dim_product (product_key, vendor, product, cpe_prefix, is_watched, criticality)
VALUES (0, 'unknown', 'unknown', '', false, NULL);

-- A product watched by several organizations takes the highest criticality.
INSERT INTO dw.dim_product (product_key, vendor, product, cpe_prefix, is_watched, criticality)
SELECT
    p.id,
    p.vendor,
    p.name,
    COALESCE(p.cpe_prefix, ''),
    (w.product_id IS NOT NULL),
    w.criticality
FROM public.cti_product p
LEFT JOIN (
    SELECT product_id, max(criticality) AS criticality
    FROM public.watchlist_watchlistitem
    GROUP BY product_id
) w ON w.product_id = p.id;

-- ============================================================ fact tables

-- Grain: one row per CVE x affected product (a CVE with no affected product gets product 0).
INSERT INTO dw.fact_vulnerability (
    vuln_key, product_key, published_date_key, kev_date_key, weakness_key, severity_key, source_key,
    cvss_score, epss_score, epss_percentile, is_kev, days_to_kev, exploit_probability, is_severity_predicted
)
SELECT
    v.id,
    COALESCE(a.product_id, 0),
    to_char((v.published_at AT TIME ZONE 'UTC')::date, 'YYYYMMDD')::integer,
    to_char(k.date_added, 'YYYYMMDD')::integer,
    COALESCE(pw.weakness_id, 0),
    s.severity_key,
    (SELECT source_key FROM dw.dim_source WHERE name = 'cve'),
    v.effective_score,
    v.epss_score,
    v.epss_percentile,
    (k.vulnerability_id IS NOT NULL),
    CASE WHEN k.vulnerability_id IS NOT NULL
         THEN k.date_added - (v.published_at AT TIME ZONE 'UTC')::date END,
    NULL,
    false
FROM public.cti_vulnerability v
LEFT JOIN public.cti_affectedproduct a ON a.vulnerability_id = v.id
LEFT JOIN public.cti_keventry k ON k.vulnerability_id = v.id
-- Primary CWE of each CVE, same rule as the CVE record (Vulnerability.ordered_weaknesses):
-- NVD > CNA > CISA ADP, weaknesses before categories, then the first CWE cited in the record.
LEFT JOIN (
    SELECT DISTINCT ON (vw.vulnerability_id) vw.vulnerability_id, vw.weakness_id
    FROM public.cti_vulnerabilityweakness vw
    JOIN public.cti_weakness w ON w.id = vw.weakness_id
    ORDER BY vw.vulnerability_id,
             CASE vw.provider WHEN 'NVD' THEN 0 WHEN 'CNA' THEN 1 WHEN 'CISA_ADP' THEN 2 ELSE 9 END,
             (w.kind = 'CATEGORY'),
             vw.id
) pw ON pw.vulnerability_id = v.id
JOIN dw.dim_severity s ON s.label = COALESCE(NULLIF(v.effective_severity, ''), 'NO_SCORE');

-- Grain: one row per alert (rebuilt at each run). The closing date is the last change to a closed status.
INSERT INTO dw.fact_alert (
    alert_id, vuln_key, product_key, severity_key, status_key, created_date_key, closed_date_key,
    priority_score, criticality, days_open, is_kev, is_overdue
)
SELECT
    al.id,
    al.vulnerability_id,
    wi.product_id,
    s.severity_key,
    st.status_key,
    to_char((al.created_at AT TIME ZONE 'UTC')::date, 'YYYYMMDD')::integer,
    CASE WHEN NOT st.is_open
         THEN to_char((closed.closed_at AT TIME ZONE 'UTC')::date, 'YYYYMMDD')::integer END,
    al.priority_score,
    wi.criticality,
    (COALESCE(CASE WHEN NOT st.is_open THEN closed.closed_at END, now()) AT TIME ZONE 'UTC')::date
        - (al.created_at AT TIME ZONE 'UTC')::date,
    (k.vulnerability_id IS NOT NULL),
    (st.is_open AND al.due_date < (now() AT TIME ZONE 'UTC')::date)
FROM public.alerts_alert al
JOIN public.watchlist_watchlistitem wi ON wi.id = al.watchlist_item_id
JOIN public.cti_vulnerability v ON v.id = al.vulnerability_id
JOIN dw.dim_severity s ON s.label = COALESCE(NULLIF(v.effective_severity, ''), 'NO_SCORE')
JOIN dw.dim_alert_status st ON st.label = al.status
LEFT JOIN public.cti_keventry k ON k.vulnerability_id = al.vulnerability_id
LEFT JOIN LATERAL (
    SELECT max(c.changed_at) AS closed_at
    FROM public.alerts_alertstatuschange c
    WHERE c.alert_id = al.id AND c.new_status IN ('FIXED', 'RISK_ACCEPTED', 'FALSE_POSITIVE')
) closed ON true;

ANALYZE dw.fact_vulnerability;
ANALYZE dw.fact_alert;
