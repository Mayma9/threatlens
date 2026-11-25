-- powerbi/check_drilldown.sql
-- Expected values of the page "Drill-down" of threatlens_decision.pbix (vendor -> CWE -> CVE), computed in SQL.
-- CVEs are counted once (distinct vuln_key); CVEs with no affected product (product_key 0) are left out.
-- Run: docker compose exec -T db psql -U threatlens -d threatlens < powerbi/check_drilldown.sql

-- 1. The "unknown" member of dim_weakness (CVEs without a CWE)
SELECT weakness_key, cwe_id FROM dw.dim_weakness WHERE weakness_key = 0;

-- 2. Top 10 vendors by CVEs (first level of the chart)
SELECT p.vendor, count(DISTINCT f.vuln_key) AS cves
FROM dw.fact_vulnerability f
JOIN dw.dim_product p ON p.product_key = f.product_key
WHERE f.product_key <> 0
GROUP BY p.vendor
ORDER BY cves DESC, p.vendor
LIMIT 10;

-- 3. Top 10 CWEs of the first vendor (second level, after a click on the first bar)
WITH top_vendor AS (
    SELECT p.vendor
    FROM dw.fact_vulnerability f
    JOIN dw.dim_product p ON p.product_key = f.product_key
    WHERE f.product_key <> 0
    GROUP BY p.vendor
    ORDER BY count(DISTINCT f.vuln_key) DESC, p.vendor
    LIMIT 1
)
SELECT p.vendor, w.cwe_id, count(DISTINCT f.vuln_key) AS cves
FROM dw.fact_vulnerability f
JOIN dw.dim_product p ON p.product_key = f.product_key
JOIN dw.dim_weakness w ON w.weakness_key = f.weakness_key
WHERE f.product_key <> 0 AND p.vendor = (SELECT vendor FROM top_vendor)
GROUP BY p.vendor, w.cwe_id
ORDER BY cves DESC, w.cwe_id
LIMIT 10;
