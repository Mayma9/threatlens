"""Tests of the warehouse refresh (T08, UC21): the constellation schema is rebuilt by SQL from the operational schema."""

import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import patch

from django.core.management import call_command
from django.db import connection
from django.test import TestCase, override_settings

from accounts.models import Organization
from alerts.services import generate_alerts
from cti.models import AffectedProduct, KEVEntry, Product, ScoreProvider, Vulnerability, VulnerabilityWeakness, Weakness
from pipeline.models import RunStatus
from pipeline.services import ensure_sources, run_pipeline
from pipeline.warehouse import refresh_warehouse
from watchlist.models import WatchlistItem

from .factories import write_kev_json

DUE_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "UNKNOWN": 30}


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


class WarehouseWeaknessTests(TestCase):
    """dim_weakness is the CWE catalog; fact_vulnerability keeps the primary CWE of each CVE (spec 11.2)."""

    def setUp(self):
        ensure_sources()
        self.cves = {}
        for number in range(1, 5):
            self.cves[number] = Vulnerability.objects.create(
                cve_id=f"CVE-2026-000{number}", description="x",
                published_at=datetime(2026, 1, number, tzinfo=timezone.utc))
        weakness = Weakness.Kind.WEAKNESS
        self.link(1, "CWE-20", ScoreProvider.CISA_ADP, weakness)  # cited first, but CISA ADP comes after the CNA
        self.link(1, "CWE-79", ScoreProvider.CNA, weakness)
        self.link(2, "CWE-16", ScoreProvider.CNA, Weakness.Kind.CATEGORY)  # a category comes after a weakness
        self.link(2, "CWE-787", ScoreProvider.CNA, weakness)
        self.link(2, "CWE-125", ScoreProvider.CNA, weakness)  # same provider and kind: the first cited wins
        self.link(3, "CWE-89", ScoreProvider.CNA, weakness)
        self.link(3, "CWE-22", ScoreProvider.NVD, weakness)  # NVD comes first
        Weakness.objects.create(cwe_id="CWE-1000", name="Not named by any CVE", kind=weakness)
        # CVE 4 names no CWE

    def link(self, number, cwe_id, provider, kind):
        item, _ = Weakness.objects.get_or_create(cwe_id=cwe_id, defaults={"name": f"{cwe_id} name", "kind": kind})
        VulnerabilityWeakness.objects.create(vulnerability=self.cves[number], weakness=item, provider=provider)

    def primary_cwes(self):
        return dict(query("""
            SELECT v.cve_id, w.cwe_id
            FROM dw.fact_vulnerability f
            JOIN dw.dim_vulnerability v USING (vuln_key)
            JOIN dw.dim_weakness w USING (weakness_key)
        """))

    def test_fact_vulnerability_keeps_the_primary_cwe(self):
        refresh_warehouse()
        self.assertEqual(self.primary_cwes(), {
            "CVE-2026-0001": "CWE-79", "CVE-2026-0002": "CWE-787", "CVE-2026-0003": "CWE-22",
            "CVE-2026-0004": "unknown"})

    def test_same_primary_cwe_as_the_cve_record(self):
        refresh_warehouse()
        record = {v.cve_id: v.ordered_weaknesses()[0][0].cwe_id
                  for v in Vulnerability.objects.prefetch_related("weakness_links__weakness") if v.weakness_links.all()}
        warehouse = {cve: cwe for cve, cwe in self.primary_cwes().items() if cwe != "unknown"}
        self.assertEqual(warehouse, record)

    def test_dim_weakness_is_the_whole_catalog_plus_unknown(self):
        refresh_warehouse()
        self.assertEqual(query("SELECT count(*) FROM dw.dim_weakness")[0][0], Weakness.objects.count() + 1)
        self.assertEqual(query("SELECT cwe_id, name FROM dw.dim_weakness WHERE weakness_key = 0"),
                         [("unknown", "No CWE named by the CVE record")])


@override_settings(ALERT_DUE_DAYS=DUE_DAYS)
class WarehouseAlertTests(TestCase):
    def setUp(self):
        ensure_sources()
        self.org = Organization.objects.create(name="Demo Bank")
        self.product = Product.objects.create(vendor="fortinet", name="fortios")
        WatchlistItem.objects.create(organization=self.org, product=self.product, criticality=4)
        vulnerability = Vulnerability.objects.create(
            cve_id="CVE-2026-0001",
            description="exploited fortios flaw",
            published_at=datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc),
            source_updated_at=datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc),
            effective_severity="CRITICAL",
            effective_score=9.8,
        )
        AffectedProduct.objects.create(vulnerability=vulnerability, product=self.product)
        KEVEntry.objects.create(
            vulnerability=vulnerability, date_added=date(2026, 11, 5), required_action="patch", ransomware_use=False
        )
        generate_alerts(Vulnerability.objects.all())

    def test_an_open_alert_becomes_one_row_of_fact_alert(self):
        counts = refresh_warehouse()
        self.assertEqual(counts["fact_alert"], 1)
        rows = query("""
            SELECT v.cve_id, p.product, s.label, st.label, st.is_open,
                   f.criticality, f.is_kev, f.is_overdue, f.days_open, f.closed_date_key
            FROM dw.fact_alert f
            JOIN dw.dim_vulnerability v USING (vuln_key)
            JOIN dw.dim_product p USING (product_key)
            JOIN dw.dim_severity s USING (severity_key)
            JOIN dw.dim_alert_status st USING (status_key)
        """)
        self.assertEqual(rows, [("CVE-2026-0001", "fortios", "CRITICAL", "NEW", True, 4, True, False, 0, None)])

    def test_a_watched_product_is_flagged_with_its_criticality(self):
        refresh_warehouse()
        rows = query("SELECT is_watched, criticality FROM dw.dim_product WHERE product = 'fortios'")
        self.assertEqual(rows, [(True, 4)])


class RefreshCommandTests(TestCase):
    def test_the_command_works_before_the_first_pipeline_run(self):
        Vulnerability.objects.create(cve_id="CVE-2024-0001", description="x",
                                     published_at=datetime(2024, 5, 1, tzinfo=timezone.utc))
        call_command("refresh_warehouse", stdout=open("/dev/null", "w"))  # no pipeline_source row yet
        self.assertEqual(query("SELECT s.name FROM dw.fact_vulnerability JOIN dw.dim_source s USING (source_key)"),
                         [("cve",)])


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
