"""Derived CTI values recomputed after each pipeline run."""

from django.db import connection

# FR-06: NVD > CNA > CISA ADP, newest CVSS version first ("4.0" > "3.1" > "3.0" > "2.0"), then the severity
# predicted by the active M1 model (labeled as predicted, no score). Same rule as Vulnerability.effective_metric(),
# written in SQL to update every CVE in one statement.
REFRESH_EFFECTIVE_SEVERITY = """
UPDATE cti_vulnerability AS v
SET effective_severity = COALESCE(best.severity, predicted.predicted_severity, ''),
    effective_score = best.base_score,
    is_severity_predicted = (best.severity IS NULL AND predicted.predicted_severity IS NOT NULL)
FROM cti_vulnerability AS target
LEFT JOIN (
    SELECT DISTINCT ON (vulnerability_id) vulnerability_id, severity, base_score
    FROM cti_cvssmetric
    ORDER BY vulnerability_id,
             CASE provider WHEN 'NVD' THEN 0 WHEN 'CNA' THEN 1 ELSE 2 END,
             version DESC
) AS best ON best.vulnerability_id = target.id
LEFT JOIN (
    SELECT p.vulnerability_id, p.predicted_severity
    FROM ml_severityprediction p
    JOIN ml_mlmodel m ON m.id = p.model_id
    WHERE m.is_active AND m.task = 'SEVERITY'
) AS predicted ON predicted.vulnerability_id = target.id
WHERE v.id = target.id
  AND (v.effective_severity IS DISTINCT FROM COALESCE(best.severity, predicted.predicted_severity, '')
       OR v.effective_score IS DISTINCT FROM best.base_score
       OR v.is_severity_predicted IS DISTINCT FROM (best.severity IS NULL AND predicted.predicted_severity IS NOT NULL))
"""


def refresh_effective_severity() -> int:
    """Copies the effective severity (CVSS score, else M1 prediction) onto every vulnerability; returns the rows changed."""
    with connection.cursor() as cursor:
        cursor.execute(REFRESH_EFFECTIVE_SEVERITY)
        return cursor.rowcount
