"""Derived CTI values recomputed after each pipeline run."""

from django.db import connection

# FR-06: NVD > CNA > CISA ADP, newest CVSS version first ("4.0" > "3.1" > "3.0" > "2.0").
# Same rule as Vulnerability.effective_metric(), written in SQL to update every CVE in one statement.
REFRESH_EFFECTIVE_SEVERITY = """
UPDATE cti_vulnerability AS v
SET effective_severity = COALESCE(best.severity, ''), effective_score = best.base_score
FROM cti_vulnerability AS target
LEFT JOIN (
    SELECT DISTINCT ON (vulnerability_id) vulnerability_id, severity, base_score
    FROM cti_cvssmetric
    ORDER BY vulnerability_id,
             CASE provider WHEN 'NVD' THEN 0 WHEN 'CNA' THEN 1 ELSE 2 END,
             version DESC
) AS best ON best.vulnerability_id = target.id
WHERE v.id = target.id
  AND (v.effective_severity IS DISTINCT FROM COALESCE(best.severity, '')
       OR v.effective_score IS DISTINCT FROM best.base_score)
"""


def refresh_effective_severity() -> int:
    """Copies the effective CVSS severity and score onto every vulnerability; returns the number of rows changed."""
    with connection.cursor() as cursor:
        cursor.execute(REFRESH_EFFECTIVE_SEVERITY)
        return cursor.rowcount
