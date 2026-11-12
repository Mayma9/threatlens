-- warehouse/sql/olap/01_volume_by_period.sql
-- FR-20 (1): vulnerability volume by year, quarter, month and day (roll-up and drill-down).
-- fact_vulnerability has one row per CVE x affected product, so CVEs are counted with count(DISTINCT vuln_key).

-- Roll-up over the last 3 years: month rows, then quarter and year sub-totals, then the grand total.
-- A NULL in a column means "all values of that level".
SELECT d.year, d.quarter, d.month, count(DISTINCT f.vuln_key) AS new_cves
FROM dw.fact_vulnerability f
JOIN dw.dim_date d ON d.date_key = f.published_date_key
WHERE d.year >= (SELECT max(year) FROM dw.dim_date) - 2
GROUP BY ROLLUP (d.year, d.quarter, d.month)
ORDER BY d.year, d.quarter, d.month;

-- Drill-down: the days of the latest month that has CVEs.
SELECT d.full_date, count(DISTINCT f.vuln_key) AS new_cves
FROM dw.fact_vulnerability f
JOIN dw.dim_date d ON d.date_key = f.published_date_key
WHERE (d.year, d.month) = (
    SELECT d2.year, d2.month
    FROM dw.dim_date d2
    WHERE d2.date_key = (SELECT max(published_date_key) FROM dw.fact_vulnerability)
)
GROUP BY d.full_date
ORDER BY d.full_date;
