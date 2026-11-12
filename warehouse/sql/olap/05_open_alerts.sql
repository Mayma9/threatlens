-- warehouse/sql/olap/05_open_alerts.sql
-- FR-20 (5): open alerts and remediation delay by product, severity and status.
-- Returns no row while there is no watched product (so no alert).

-- Open alerts by product, severity and status, with the number of overdue ones.
SELECT p.vendor, p.product, s.label AS severity, st.label AS status,
       count(*) AS alerts,
       sum(f.is_overdue::int) AS overdue
FROM dw.fact_alert f
JOIN dw.dim_product p USING (product_key)
JOIN dw.dim_severity s USING (severity_key)
JOIN dw.dim_alert_status st USING (status_key)
WHERE st.is_open
GROUP BY p.vendor, p.product, s.severity_key, s.label, st.label
ORDER BY s.severity_key DESC, alerts DESC, p.vendor, p.product;

-- Remediation delay: days from creation to closing, for the alerts marked FIXED, by severity.
SELECT s.label AS severity,
       count(*) AS fixed_alerts,
       round(avg(f.days_open)::numeric, 1) AS avg_days_to_fix
FROM dw.fact_alert f
JOIN dw.dim_severity s USING (severity_key)
JOIN dw.dim_alert_status st USING (status_key)
WHERE st.label = 'FIXED'
GROUP BY s.severity_key, s.label
ORDER BY s.severity_key DESC;
