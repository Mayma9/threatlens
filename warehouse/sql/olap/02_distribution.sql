-- warehouse/sql/olap/02_distribution.sql
-- FR-20 (2): distribution of CVEs by severity, vendor, product and CWE (CVEs counted with DISTINCT).

-- By effective severity. "predicted" = severity predicted by M1 (no CVSS score); NO_SCORE = no score and no prediction.
-- The CVEs without any CVSS score (KPI of FR-22) are the NO_SCORE line + the predicted lines.
SELECT s.label AS severity,
       f.is_severity_predicted AS predicted,
       count(DISTINCT f.vuln_key) AS cves,
       round(100.0 * count(DISTINCT f.vuln_key) / (SELECT count(DISTINCT vuln_key) FROM dw.fact_vulnerability), 1) AS pct
FROM dw.fact_vulnerability f
JOIN dw.dim_severity s USING (severity_key)
GROUP BY s.severity_key, s.label, f.is_severity_predicted
ORDER BY s.severity_key, f.is_severity_predicted;

-- Top 10 vendors (CVEs with no affected product are left out).
SELECT p.vendor, count(DISTINCT f.vuln_key) AS cves
FROM dw.fact_vulnerability f
JOIN dw.dim_product p USING (product_key)
WHERE p.product_key <> 0
GROUP BY p.vendor
ORDER BY cves DESC, p.vendor
LIMIT 10;

-- Top 10 products.
SELECT p.vendor, p.product, count(DISTINCT f.vuln_key) AS cves
FROM dw.fact_vulnerability f
JOIN dw.dim_product p USING (product_key)
WHERE p.product_key <> 0
GROUP BY p.vendor, p.product
ORDER BY cves DESC, p.vendor, p.product
LIMIT 10;

-- Top 10 CWEs (primary CWE of each CVE). CVEs whose record names no CWE (key 0) are left out.
SELECT w.cwe_id, w.name, count(DISTINCT f.vuln_key) AS cves
FROM dw.fact_vulnerability f
JOIN dw.dim_weakness w USING (weakness_key)
WHERE w.weakness_key <> 0
GROUP BY w.cwe_id, w.name
ORDER BY cves DESC, w.cwe_id
LIMIT 10;
