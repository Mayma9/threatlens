-- powerbi/check_remediation.sql
-- Expected values of the page "Remediation" of threatlens_decision.pbix, computed in SQL.
-- Part 1: delay between publication and KEV addition, for the CVEs published since 2023
-- (one row per CVE: fact_vulnerability has one row per CVE x affected product).
-- days_to_kev < 0 means the CVE was added to KEV before its publication date (already exploited).
-- Run: docker compose exec -T db psql -U threatlens -d threatlens < powerbi/check_remediation.sql

-- 1. Cards
WITH k AS (
    SELECT DISTINCT f.vuln_key, f.days_to_kev
    FROM dw.fact_vulnerability f
    JOIN dw.dim_date d ON d.date_key = f.published_date_key
    WHERE f.is_kev AND d.year >= 2023
)
SELECT count(*) AS kev_cves,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY days_to_kev) AS median_days_to_kev,
       round(100.0 * count(*) FILTER (WHERE days_to_kev < 0) / nullif(count(*), 0), 1) AS pct_before_publication,
       round(100.0 * count(*) FILTER (WHERE days_to_kev <= 30) / nullif(count(*), 0), 1) AS pct_within_30_days,
       round(100.0 * count(*) FILTER (WHERE days_to_kev <= 90) / nullif(count(*), 0), 1) AS pct_within_90_days,
       round(100.0 * count(*) FILTER (WHERE days_to_kev <= 180) / nullif(count(*), 0), 1) AS pct_within_180_days
FROM k;

-- 2. KEV CVEs by delay bucket
WITH k AS (
    SELECT DISTINCT f.vuln_key, f.days_to_kev
    FROM dw.fact_vulnerability f
    JOIN dw.dim_date d ON d.date_key = f.published_date_key
    WHERE f.is_kev AND d.year >= 2023
)
SELECT CASE
           WHEN days_to_kev < 0 THEN '1 Before publication'
           WHEN days_to_kev <= 30 THEN '2 0-30 days'
           WHEN days_to_kev <= 90 THEN '3 31-90 days'
           WHEN days_to_kev <= 180 THEN '4 91-180 days'
           ELSE '5 Over 180 days'
       END AS delay_bucket,
       count(*) AS kev_cves
FROM k
GROUP BY 1
ORDER BY 1;

-- 3. By publication year
WITH k AS (
    SELECT DISTINCT f.vuln_key, f.days_to_kev, d.year
    FROM dw.fact_vulnerability f
    JOIN dw.dim_date d ON d.date_key = f.published_date_key
    WHERE f.is_kev AND d.year >= 2023
)
SELECT year AS published_year,
       count(*) AS kev_cves,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY days_to_kev) AS median_days_to_kev,
       round(100.0 * count(*) FILTER (WHERE days_to_kev <= 30) / nullif(count(*), 0), 1) AS pct_within_30_days
FROM k
GROUP BY year
ORDER BY year;

-- Part 2: alerts on the watchlist (FR-22). On a development database these are demo alerts:
-- an alert created and closed the same week gives a remediation time of 0 days.
-- is_overdue is only true for open alerts (a closed alert is never overdue).
-- Priority bands: Very high 75-100, High 50-74, Medium 25-49, Low under 25.

-- 4. Alert cards (MTTR: FIXED alerts only)
SELECT count(*) AS alerts,
       count(*) FILTER (WHERE s.is_open) AS open_alerts,
       count(*) FILTER (WHERE a.is_overdue) AS overdue_alerts,
       count(*) FILTER (WHERE s.label = 'FIXED') AS fixed_alerts,
       round(avg(a.days_open) FILTER (WHERE s.label = 'FIXED'), 1) AS mttr_days
FROM dw.fact_alert a
JOIN dw.dim_alert_status s ON s.status_key = a.status_key;

-- 5. Alerts by status and priority band
SELECT s.label AS status,
       CASE
           WHEN a.priority_score >= 75 THEN '1 Very high'
           WHEN a.priority_score >= 50 THEN '2 High'
           WHEN a.priority_score >= 25 THEN '3 Medium'
           ELSE '4 Low'
       END AS priority_band,
       count(*) AS alerts
FROM dw.fact_alert a
JOIN dw.dim_alert_status s ON s.status_key = a.status_key
GROUP BY 1, 2
ORDER BY 1, 2;

-- 6. Overdue alerts, highest priority first
SELECT v.cve_id, p.vendor, p.product, s.label AS status,
       round(a.priority_score::numeric, 1) AS priority, a.is_kev, a.days_open
FROM dw.fact_alert a
JOIN dw.dim_alert_status s ON s.status_key = a.status_key
JOIN dw.dim_vulnerability v ON v.vuln_key = a.vuln_key
JOIN dw.dim_product p ON p.product_key = a.product_key
WHERE a.is_overdue
ORDER BY a.priority_score DESC, v.cve_id;
