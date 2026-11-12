-- warehouse/sql/olap/06_ioc_volume.sql
-- FR-20 (6): indicator-of-compromise volume by malware family and threat type.
-- Returns no row until the ThreatFox connector exists: fact_ioc and its dimensions have no source yet.

SELECT m.family, t.label AS threat_type, sum(f.ioc_count) AS iocs
FROM dw.fact_ioc f
LEFT JOIN dw.dim_malware m USING (malware_key)
JOIN dw.dim_threat_type t USING (threat_type_key)
GROUP BY m.family, t.label
ORDER BY iocs DESC, m.family, t.label;
