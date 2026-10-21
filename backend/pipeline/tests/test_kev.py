"""Tests of the CISA KEV connector (US02)."""

import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from cti.models import KEVEntry, Vulnerability
from pipeline.models import RunStatus
from pipeline.services import run_pipeline

from .factories import write_kev_json


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class KevConnectorTests(TestCase):
    def setUp(self):
        Vulnerability.objects.create(cve_id="CVE-2024-0001", description="known")
        self.catalog = write_kev_json(Path(tempfile.mkdtemp()) / "kev.json", [
            ("CVE-2024-0001", "2024-05-01", "Known"),
            ("CVE-2099-9999", "2024-05-02", "Unknown"),   # not in the database -> rejected
            ("CVE-2024-0001", "2024-05-01", "Known"),     # duplicate -> rejected
        ])

    def run_kev(self):
        return run_pipeline(sources=["kev"], local_file=str(self.catalog))

    def test_known_cve_is_loaded_unknown_is_rejected(self):
        task = self.run_kev().tasks.get()
        self.assertEqual(task.status, RunStatus.SUCCESS)
        self.assertEqual((task.extracted, task.loaded, task.rejected), (3, 1, 2))
        entry = KEVEntry.objects.get()
        self.assertTrue(entry.ransomware_use)
        self.assertEqual(str(entry.date_added), "2024-05-01")

    def test_running_twice_creates_no_duplicates(self):
        self.run_kev()
        self.run_kev()
        self.assertEqual(KEVEntry.objects.count(), 1)
