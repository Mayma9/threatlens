-- powerbi/check_threat_activity.sql
-- Expected values of the page "Threat activity" of threatlens_decision.pbix (no filter selected), computed in SQL.
-- After a refresh, the Power BI cards and charts must show the same numbers.
-- Run: docker compose exec -T db psql -U threatlens -d threatlens < powerbi/check_threat_activity.sql
-- Only counts, families, threat types and dates are read: never dw.dim_indicator (IOC values, risk R9).

-- 1. Cards
SELECT kpi, expected FROM (
SELECT 1 AS n, 'IOCs' AS kpi, coalesce(sum(ioc_count), 0)::text AS expected FROM dw.fact_ioc
UNION ALL
SELECT 2, 'Families', count(DISTINCT malware_key)::text FROM dw.fact_ioc
UNION ALL
SELECT 3, 'Average confidence', round(avg(confidence), 1)::text FROM dw.fact_ioc
UNION ALL
SELECT 4, 'IOCs without family', coalesce(sum(ioc_count) FILTER (WHERE malware_key IS NULL), 0)::text FROM dw.fact_ioc
UNION ALL
SELECT 5, '% IOCs without family', round(100.0 * coalesce(sum(ioc_count) FILTER (WHERE malware_key IS NULL), 0)
                                   / nullif(sum(ioc_count), 0), 1)::text || ' %'
FROM dw.fact_ioc
) AS cards
ORDER BY n;

-- 2. Top 10 malware families by IOCs (IOCs without family left out, as in the report)
SELECT m.family, sum(f.ioc_count) AS iocs
FROM dw.fact_ioc f JOIN dw.dim_malware m ON m.malware_key = f.malware_key
GROUP BY m.family
ORDER BY iocs DESC, m.family
LIMIT 10;

-- 3. IOCs by threat type
SELECT t.label AS threat_type, sum(f.ioc_count) AS iocs
FROM dw.fact_ioc f JOIN dw.dim_threat_type t ON t.threat_type_key = f.threat_type_key
GROUP BY t.label
ORDER BY iocs DESC;

-- 4. IOCs by first-seen day
SELECT d.full_date AS first_seen, sum(f.ioc_count) AS iocs
FROM dw.fact_ioc f JOIN dw.dim_date d ON d.date_key = f.first_seen_date_key
GROUP BY d.full_date
ORDER BY d.full_date;
