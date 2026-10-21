"""Tests of the CVE List V5 connector and of the pipeline run logging (US02, FR-16 to FR-18)."""

import tempfile
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase, override_settings

from cti.models import AffectedProduct, CVSSMetric, Product, Vulnerability
from pipeline.connectors.cve_list_v5 import parse_record, severity_from_score
from pipeline.models import IngestionTask, PipelineRun, RunStatus, Source
from pipeline.services import run_pipeline

from .factories import cve_doc, write_bulk_zip


class ParseRecordTests(TestCase):
    def test_keeps_cna_and_cisa_adp_scores_but_not_ssvc(self):
        record = parse_record(cve_doc("CVE-2024-0001", cna_score=9.8, adp_score=8.8))
        providers = sorted((m["provider"], m["base_score"]) for m in record["metrics"])
        self.assertEqual(providers, [("CISA_ADP", 8.8), ("CNA", 9.8)])

    def test_rejected_record_is_skipped(self):
        self.assertIsNone(parse_record(cve_doc("CVE-2024-0002", state="REJECTED")))

    def test_products_are_normalized_and_placeholders_ignored(self):
        record = parse_record(cve_doc("CVE-2024-0003", affected=(("  Fortinet ", "FortiOS", "7.2"), ("n/a", "n/a", "1"))))
        self.assertEqual(list(record["products"]), [("fortinet", "fortios")])

    def test_cvss_v2_severity_is_computed(self):
        self.assertEqual(severity_from_score(7.5, "2.0"), "HIGH")
        self.assertEqual(severity_from_score(9.1, "3.1"), "CRITICAL")


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class CveConnectorRunTests(TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.bulk = write_bulk_zip(self.tmp / "all_CVEs_at_midnight.zip", [
            cve_doc("CVE-2024-0001", adp_score=8.8),
            cve_doc("CVE-2024-0002", cna_score=None, affected=(("Microsoft", "Windows", "10"),)),
            cve_doc("CVE-2024-0003", state="REJECTED"),
            cve_doc("CVE-2024-0004", description=""),              # rejected: no description
            cve_doc("CVE-2024-0005", cna_score=11.0),             # rejected: score out of range
            cve_doc("CVE-24-1"),                                  # rejected: invalid identifier
        ])

    def run_cve(self, full=False):
        return run_pipeline(sources=["cve"], local_file=str(self.bulk), full=full)

    def test_load_counts_and_rejects_are_logged(self):
        run = self.run_cve()
        task = run.tasks.get()
        self.assertEqual(run.status, RunStatus.SUCCESS)
        self.assertEqual((task.extracted, task.loaded, task.rejected), (5, 2, 3))
        self.assertEqual(task.quality_report["skipped_not_published"], 1)
        self.assertEqual(task.quality_report["rejected_by_reason"]["missing English description"], 1)
        self.assertEqual(set(Vulnerability.objects.values_list("cve_id", flat=True)), {"CVE-2024-0001", "CVE-2024-0002"})
        self.assertEqual(CVSSMetric.objects.filter(vulnerability__cve_id="CVE-2024-0001").count(), 2)
        self.assertTrue(Product.objects.filter(vendor="microsoft", name="windows").exists())

    def test_running_twice_creates_no_duplicates(self):
        self.run_cve(full=True)
        counts = (Vulnerability.objects.count(), CVSSMetric.objects.count(), AffectedProduct.objects.count(), Product.objects.count())
        self.run_cve(full=True)
        self.assertEqual(counts, (Vulnerability.objects.count(), CVSSMetric.objects.count(), AffectedProduct.objects.count(), Product.objects.count()))

    def test_second_run_is_incremental(self):
        self.run_cve()
        task = self.run_cve().tasks.get()
        self.assertEqual(task.loaded, 0)
        # the 2 loaded records + the 3 records rejected the first time (unchanged since): nothing to do
        self.assertEqual(task.quality_report["skipped_unchanged"], 5)

    def test_raw_snapshot_is_kept_in_staging(self):
        from django.conf import settings
        self.run_cve()
        self.assertTrue(any((Path(settings.STAGING_DIR) / "cve").iterdir()))


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class PipelineRunTests(TestCase):
    def test_failing_source_does_not_stop_the_others(self):
        tmp = Path(tempfile.mkdtemp())
        broken = tmp / "broken.zip"
        broken.write_text("not a zip")
        run = run_pipeline(local_file=str(broken))  # cve fails (bad file); kev also gets the bad file
        self.assertIn(run.status, {RunStatus.FAILED, RunStatus.PARTIAL})
        self.assertEqual(run.tasks.filter(status=RunStatus.FAILED, source__name="cve").count(), 1)
        self.assertTrue(run.tasks.get(source__name="cve").error_message)

    def test_disabled_source_is_skipped(self):
        call_command("run_pipeline", "--source", "cve", "--file", str(write_bulk_zip(Path(tempfile.mkdtemp()) / "a.zip", [cve_doc("CVE-2024-0001")])), stdout=open("/dev/null", "w"))
        Source.objects.filter(name="cve").update(is_active=False)
        run = run_pipeline(sources=["cve"])
        self.assertEqual(run.tasks.count(), 0)
        self.assertEqual(PipelineRun.objects.count(), 2)

    def test_command_logs_one_task_per_source(self):
        bulk = write_bulk_zip(Path(tempfile.mkdtemp()) / "b.zip", [cve_doc("CVE-2024-0001")])
        call_command("run_pipeline", "--source", "cve", "--file", str(bulk), stdout=open("/dev/null", "w"))
        self.assertEqual(IngestionTask.objects.get().status, RunStatus.SUCCESS)
