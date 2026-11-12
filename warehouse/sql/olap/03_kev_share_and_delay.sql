-- warehouse/sql/olap/03_kev_share_and_delay.sql
-- FR-20 (3): share of KEV vulnerabilities and delay between publication and addition to KEV.

-- Share of CVEs that are in the CISA KEV catalog.
SELECT count(DISTINCT vuln_key) FILTER (WHERE is_kev) AS kev_cves,
       count(DISTINCT vuln_key) AS cves,
       round(100.0 * count(DISTINCT vuln_key) FILTER (WHERE is_kev) / count(DISTINCT vuln_key), 2) AS pct_kev
FROM dw.fact_vulnerability;

-- Delay in days between publication and addition to KEV, by year of the KEV addition.
-- One row per CVE first (a CVE has one row per affected product), so the average is not weighted by products.
WITH kev AS (
    SELECT DISTINCT vuln_key, kev_date_key, days_to_kev
    FROM dw.fact_vulnerability
    WHERE is_kev
)
SELECT d.year AS kev_year,
       count(*) AS kev_cves,
       round(avg(k.days_to_kev)::numeric, 1) AS avg_days,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY k.days_to_kev) AS median_days
FROM kev k
JOIN dw.dim_date d ON d.date_key = k.kev_date_key
GROUP BY d.year
ORDER BY d.year;
