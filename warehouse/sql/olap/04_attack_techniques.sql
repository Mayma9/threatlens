-- warehouse/sql/olap/04_attack_techniques.sql
-- FR-20 (4): most frequent ATT&CK techniques among exploited (KEV) CVEs.
-- Returns no row until the ATT&CK mapping is loaded: dim_technique and bridge_cve_technique have no source yet.

SELECT t.technique_id, t.name, t.tactic, count(DISTINCT b.vuln_key) AS exploited_cves
FROM dw.bridge_cve_technique b
JOIN dw.dim_technique t USING (technique_key)
JOIN dw.fact_vulnerability f ON f.vuln_key = b.vuln_key AND f.is_kev
GROUP BY t.technique_id, t.name, t.tactic
ORDER BY exploited_cves DESC, t.technique_id
LIMIT 10;
