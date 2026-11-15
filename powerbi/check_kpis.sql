-- powerbi/check_kpis.sql
-- Expected values of the cards of threatlens_exposure.pbix (no slicer selected), computed in SQL.
-- After a refresh, the Power BI cards must show the same numbers.
-- Run: docker compose exec -T db psql -U threatlens -d threatlens < powerbi/check_kpis.sql

SELECT kpi, expected FROM (
SELECT 1 AS n, 'CVEs' AS kpi, count(DISTINCT vuln_key)::text AS expected FROM dw.fact_vulnerability
UNION ALL
SELECT 2, 'New CVEs (30 days)', count(DISTINCT f.vuln_key)::text
FROM dw.fact_vulnerability f JOIN dw.dim_date d ON d.date_key = f.published_date_key
WHERE d.full_date > current_date - 30
UNION ALL
SELECT 3, '% KEV', round(100.0 * count(DISTINCT vuln_key) FILTER (WHERE is_kev) / nullif(count(DISTINCT vuln_key), 0), 1)::text || ' %'
FROM dw.fact_vulnerability
UNION ALL
SELECT 4, 'CVEs without CVSS', count(DISTINCT f.vuln_key)::text
FROM dw.fact_vulnerability f JOIN dw.dim_severity s USING (severity_key) WHERE s.label = 'NO_SCORE'
UNION ALL
SELECT 5, '% without CVSS', round(100.0 * count(DISTINCT f.vuln_key) FILTER (WHERE s.label = 'NO_SCORE')
                               / nullif(count(DISTINCT f.vuln_key), 0), 1)::text || ' %'
FROM dw.fact_vulnerability f JOIN dw.dim_severity s USING (severity_key)
UNION ALL
SELECT 6, 'Watched products', count(*)::text FROM dw.dim_product WHERE is_watched
UNION ALL
SELECT 7, 'Watchlist CVEs', count(DISTINCT vuln_key)::text FROM dw.fact_alert
UNION ALL
SELECT 8, 'Watchlist KEV CVEs', count(DISTINCT vuln_key)::text FROM dw.fact_alert WHERE is_kev
UNION ALL
SELECT 9, 'Median days to KEV', (percentile_cont(0.5) WITHIN GROUP (ORDER BY days_to_kev))::text
FROM (SELECT DISTINCT vuln_key, days_to_kev FROM dw.fact_vulnerability WHERE is_kev) k
) AS kpis
ORDER BY n;
