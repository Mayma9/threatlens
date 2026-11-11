"""Tests of the EPSS connector (US05) and of its quality rule: scores between 0 and 1 (US06).

The scores are written into the two EPSS columns of cti_vulnerability; the model version and
the score date of the file are kept in the quality report of the ingestion task.
"""

import gzip
import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from cti.models import Vulnerability
from pipeline.models import RunStatus
from pipeline.services import run_pipeline


def write_epss_csv_gz(path, rows, version="v2025.03.14", day="2026-11-09"):
    """Write a small EPSS file: a comment line, the header, then one line per (cve, epss, percentile)."""
    lines = [f"#model_version:{version},score_date:{day}T00:00:00Z", "cve,epss,percentile"]
    lines += [f"{cve},{epss},{percentile}" for cve, epss, percentile in rows]
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return path


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class EpssConnectorTests(TestCase):
    def setUp(self):
        for number in range(1, 6):
            Vulnerability.objects.create(cve_id=f"CVE-2024-000{number}", description="known")
        self.folder = Path(tempfile.mkdtemp())

    def run_epss(self, rows, name="epss.csv.gz"):
        path = write_epss_csv_gz(self.folder / name, rows)
        return run_pipeline(sources=["epss"], local_file=str(path))

    def scores(self):
        """{cve_id: (epss_score, epss_percentile)} for the vulnerabilities that have a score."""
        rows = Vulnerability.objects.filter(epss_score__isnull=False).values_list(
            "cve_id", "epss_score", "epss_percentile"
        )
        return {cve_id: (score, percentile) for cve_id, score, percentile in rows}

    def test_valid_row_is_loaded_others_are_rejected(self):
        task = self.run_epss([
            ("CVE-2024-0001", "0.12345", "0.67890"),  # valid -> loaded
            ("CVE-2099-9999", "0.5", "0.5"),          # not in the database -> rejected
            ("CVE-2024-0001", "0.12345", "0.67890"),  # duplicate -> rejected
            ("CVE-2024-0002", "1.5", "0.5"),          # score above 1 -> rejected
        ]).tasks.get()
        self.assertEqual(task.status, RunStatus.SUCCESS)
        self.assertEqual((task.extracted, task.loaded, task.rejected), (4, 1, 3))
        scores = self.scores()
        self.assertEqual(list(scores), ["CVE-2024-0001"])
        score, percentile = scores["CVE-2024-0001"]
        self.assertAlmostEqual(score, 0.12345)
        self.assertAlmostEqual(percentile, 0.67890)
        # The other columns of the vulnerability are untouched.
        self.assertEqual(Vulnerability.objects.get(cve_id="CVE-2024-0001").description, "known")
        # The date comes from the file's comment line (2026-11-09), not from today's date.
        self.assertEqual(task.quality_report["score_date"], "2026-11-09")
        self.assertEqual(task.quality_report["model_version"], "v2025.03.14")

    def test_scores_outside_0_1_are_rejected_and_the_limits_are_accepted(self):
        task = self.run_epss([
            ("CVE-2024-0001", "1.5", "0.5"),   # score above 1 -> rejected
            ("CVE-2024-0002", "-0.1", "0.5"),  # score below 0 -> rejected
            ("CVE-2024-0003", "0.5", "1.2"),   # percentile above 1 -> rejected
            ("CVE-2024-0004", "0", "0"),       # lower limit -> accepted
            ("CVE-2024-0005", "1", "1"),       # upper limit -> accepted
        ]).tasks.get()
        self.assertEqual((task.extracted, task.loaded, task.rejected), (5, 2, 3))
        self.assertEqual(set(self.scores()), {"CVE-2024-0004", "CVE-2024-0005"})

    def test_running_twice_creates_no_duplicates(self):
        rows = [("CVE-2024-0001", "0.1", "0.2"), ("CVE-2024-0002", "0.3", "0.4")]
        self.run_epss(rows)
        self.run_epss(rows)
        self.assertEqual(Vulnerability.objects.count(), 5)  # no vulnerability row added
        self.assertEqual(len(self.scores()), 2)

    def test_second_run_updates_the_score_in_place(self):
        self.run_epss([("CVE-2024-0001", "0.1", "0.2")])
        self.run_epss([("CVE-2024-0001", "0.9", "0.95")])
        score, percentile = self.scores()["CVE-2024-0001"]  # still one row for this CVE
        self.assertAlmostEqual(score, 0.9)
        self.assertAlmostEqual(percentile, 0.95)
