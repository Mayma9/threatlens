"""Refresh of the dw schema (UC21, FR-16): run the SQL scripts of warehouse/sql/ in one transaction (ELT).

01_*.sql creates the constellation tables if they do not exist; 02_*.sql rebuilds them from the
operational schema. Scripts in sub-folders (warehouse/sql/olap/) are queries, they are not run here.
"""

from __future__ import annotations

from pathlib import Path

from django.db import connection, transaction

SQL_DIR = Path(__file__).resolve().parents[2] / "warehouse" / "sql"
FACT_TABLES = ("fact_vulnerability", "fact_alert", "fact_ioc")


def refresh_warehouse(sql_dir: Path = SQL_DIR) -> dict[str, int]:
    """Create the dw tables if needed, then rebuild them. All or nothing. Returns the rows of each fact table."""
    scripts = sorted(sql_dir.glob("*.sql"))
    if not scripts:
        raise FileNotFoundError(f"no SQL script in {sql_dir}")
    counts: dict[str, int] = {}
    with transaction.atomic():
        with connection.cursor() as cursor:
            for script in scripts:
                cursor.execute(script.read_text(encoding="utf-8"))
            for table in FACT_TABLES:
                cursor.execute(f"SELECT count(*) FROM dw.{table}")
                counts[table] = cursor.fetchone()[0]
    return counts
