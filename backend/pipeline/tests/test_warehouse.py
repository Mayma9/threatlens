"""Tests of the warehouse refresh (T08, UC21): the constellation schema is rebuilt by SQL from the operational schema."""

import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import patch

from django.db import connection
from django.test import TestCase, override_settings

from cti.models import AffectedProduct, KEVEntry, Product, Vulnerability
from pipeline.models import RunStatus
from pipeline.services import ensure_sources, run_pipeline
from pipeline.warehouse import refresh_warehouse

from .factories import write_kev_json


def query(sql):
    with connection.cursor() as cursor:
        cursor.execute(sql)
        return cursor.fetchall()


class WarehouseRefreshTests(TestCase):
    def setUp(self):
        ensure_sources()
        self.product = Product.objects.create(vendor="acme", name="widget")
        self.known = Vulnerability.objects.create(
            cve_id="CVE-2024-0001",
            description="scored, exploited, with a product",
            published_at=datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc),
            effective_severity="HIGH",
            effective_score=7.5,
            epss_score=0.3,
            epss_percentile=0.9,
        )
        AffectedProduct.objects.create(vulnerability=self.known, product=self.product, versions="1.0")
        KEVEntry.objects.create(
            vulnerability=self.known, date_added=date(2024, 5, 10), required_action="patch", ransomware_use=False
        )
        self.bare = Vulnerability.objects.create(
            cve_id="CVE-2024-0002",
            description="no score, no product",
            published_at=datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc),
        )

    def test_one_row_per_cve_and_product_and_a_cve_without_product_is_kept(self):
        counts = refresh_warehouse()
        self.assertEqual(counts["fact_vulnerability"], 2)  # CVE 1 x acme/widget, CVE 2 x unknown product
        rows = query("""
            SELECT v.cve_id, p.product, s.label, f.is_kev, f.days_to_kev, f.cvss_score, f.epss_score
            FROM dw.fact_vulnerability f
            JOIN dw.dim_vulnerability v USING (vuln_key)
            JOIN dw.dim_product p USING (product_key)
            JOIN dw.dim_severity s USING (severity_key)
            ORDER BY v.cve_id
        """)
        self.assertEqual(rows, [
            ("CVE-2024-0001", "widget", "HIGH", True, 9, 7.5, 0.3),
            ("CVE-2024-0002", "unknown", "NO_SCORE", False, None, None, None),
        ])

    def test_running_the_refresh_twice_gives_the_same_row_counts(self):
        first = refresh_warehouse()
        tables = [name for (name,) in query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'dw' ORDER BY 1")]
        before = {name: query(f"SELECT count(*) FROM dw.{name}")[0][0] for name in tables}
        second = refresh_warehouse()
        after = {name: query(f"SELECT count(*) FROM dw.{name}")[0][0] for name in tables}
        self.assertEqual(len(tables), 15)
        self.assertEqual(first, second)
        self.assertEqual(before, after)

    def test_every_fact_row_joins_to_its_dimensions(self):
        refresh_warehouse()
        joined = query("""
            SELECT count(*)
            FROM dw.fact_vulnerability f
            JOIN dw.dim_vulnerability USING (vuln_key)
            JOIN dw.dim_product USING (product_key)
            JOIN dw.dim_severity USING (severity_key)
            JOIN dw.dim_weakness USING (weakness_key)
            JOIN dw.dim_source USING (source_key)
            JOIN dw.dim_date d ON d.date_key = f.published_date_key
        """)[0][0]
        self.assertEqual(joined, query("SELECT count(*) FROM dw.fact_vulnerability")[0][0])


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class WarehouseInPipelineTests(TestCase):
    def setUp(self):
        Vulnerability.objects.create(
            cve_id="CVE-2024-0001",
            description="known",
            published_at=datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc),
        )
        self.catalog = write_kev_json(Path(tempfile.mkdtemp()) / "kev.json", [("CVE-2024-0001", "2024-05-02", "Known")])

    def test_the_pipeline_refreshes_the_warehouse_as_its_last_step(self):
        run = run_pipeline(sources=["kev"], local_file=str(self.catalog))
        self.assertEqual(run.status, RunStatus.SUCCESS)
        rows = query("SELECT v.cve_id, f.is_kev FROM dw.fact_vulnerability f JOIN dw.dim_vulnerability v USING (vuln_key)")
        self.assertEqual(rows, [("CVE-2024-0001", True)])

    def test_a_failing_refresh_makes_the_run_partial(self):
        with patch("pipeline.services.refresh_warehouse", side_effect=RuntimeError("boom")):
            run = run_pipeline(sources=["kev"], local_file=str(self.catalog))
        self.assertEqual(run.status, RunStatus.PARTIAL)
        self.assertEqual(run.tasks.get().status, RunStatus.SUCCESS)  # the data load itself succeeded
