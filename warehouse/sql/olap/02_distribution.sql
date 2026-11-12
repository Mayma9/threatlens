-- warehouse/sql/olap/02_distribution.sql
-- FR-20 (2): distribution of CVEs by severity, vendor, product and CWE (CVEs counted with DISTINCT).

-- By severity. The NO_SCORE line is the share of CVEs without any CVSS score (KPI of FR-22).
SELECT s.label AS severity,
       count(DISTINCT f.vuln_key) AS cves,
       round(100.0 * count(DISTINCT f.vuln_key) / (SELECT count(DISTINCT vuln_key) FROM dw.fact_vulnerability), 1) AS pct
FROM dw.fact_vulnerability f
JOIN dw.dim_severity s USING (severity_key)
GROUP BY s.severity_key, s.label
ORDER BY s.severity_key;

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

-- By CWE. Until the CWE connector exists, every CVE is in the "unknown" weakness.
SELECT w.cwe_id, w.name, count(DISTINCT f.vuln_key) AS cves
FROM dw.fact_vulnerability f
JOIN dw.dim_weakness w USING (weakness_key)
GROUP BY w.cwe_id, w.name
ORDER BY cves DESC, w.cwe_id
LIMIT 10;
