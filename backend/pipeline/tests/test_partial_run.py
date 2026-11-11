"""A failing source must not stop the others: the run ends PARTIAL (US06, FR-17)."""

import gzip
import tempfile
from unittest.mock import patch

from django.test import TestCase, override_settings

from cti.models import Vulnerability
from pipeline.connectors.epss import EpssConnector
from pipeline.connectors.kev import KevConnector
from pipeline.models import RunStatus
from pipeline.services import run_pipeline


def failing_download(self, destination):
    raise RuntimeError("source unavailable")


def small_epss_download(self, destination):
    with gzip.open(destination, "wt", encoding="utf-8") as handle:
        handle.write("#model_version:v1,score_date:2026-11-10T00:00:00Z\ncve,epss,percentile\nCVE-2024-0001,0.5,0.5\n")


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class PartialRunTests(TestCase):
    def test_one_failing_source_gives_a_partial_run(self):
        Vulnerability.objects.create(cve_id="CVE-2024-0001", description="known")
        with patch.object(KevConnector, "download", failing_download), \
             patch.object(EpssConnector, "download", small_epss_download):
            run = run_pipeline(sources=["kev", "epss"])
        self.assertEqual(run.status, RunStatus.PARTIAL)
        kev = run.tasks.get(source__name="kev")
        epss = run.tasks.get(source__name="epss")
        self.assertEqual(kev.status, RunStatus.FAILED)
        self.assertIn("source unavailable", kev.error_message)
        self.assertEqual(epss.status, RunStatus.SUCCESS)
        self.assertEqual(epss.loaded, 1)