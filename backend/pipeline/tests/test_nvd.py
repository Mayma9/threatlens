"""Tests of the NVD connector (US05): NVD scores, CWEs and status, paging, rate limit, incremental windows."""

import gzip
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import requests
from django.test import TestCase, override_settings

from cti.models import CVSSMetric, ScoreProvider, Vulnerability, VulnerabilityWeakness, Weakness
from pipeline.connectors.cve_list_v5 import severity_from_score
from pipeline.connectors.nvd import MAX_ATTEMPTS, MAX_WINDOW, OVERLAP, NvdConnector, parse_cve
from pipeline.models import IngestionTask, PipelineRun, RunStatus, Source
from pipeline.services import ensure_sources, run_pipeline


def nvd_cve(cve_id, *, status="Analyzed", v31=9.8, v2=None, cna_v31=7.5, cwes=("CWE-79",), cna_cwes=("CWE-20",)):
    """One `cve` object as returned by the NVD API 2.0 (Primary = NVD, Secondary = CNA)."""
    metrics = {}
    if v31 is not None:
        metrics["cvssMetricV31"] = [{
            "source": "nvd@nist.gov", "type": "Primary",
            "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                         "baseScore": v31, "baseSeverity": severity_from_score(v31, "3.1")},
        }]
    if cna_v31 is not None:
        metrics.setdefault("cvssMetricV31", []).append({
            "source": "psirt@vendor.example", "type": "Secondary",
            "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/cna", "baseScore": cna_v31, "baseSeverity": "HIGH"},
        })
    if v2 is not None:  # CVSS v2: severity outside cvssData
        metrics["cvssMetricV2"] = [{
            "source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
            "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "baseScore": v2},
        }]
    weaknesses = [
        {"source": "nvd@nist.gov", "type": "Primary",
         "description": [{"lang": "en", "value": c} for c in cwes] + [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
        {"source": "psirt@vendor.example", "type": "Secondary",
         "description": [{"lang": "en", "value": c} for c in cna_cwes]},
    ]
    return {"id": cve_id, "vulnStatus": status, "lastModified": "2026-11-10T10:00:00.000",
            "metrics": metrics, "weaknesses": weaknesses}


def page(cves, start=0, total=None):
    return {"resultsPerPage": len(cves), "startIndex": start, "totalResults": len(cves) if total is None else total,
            "format": "NVD_CVE", "version": "2.0", "vulnerabilities": [{"cve": c} for c in cves]}


def write_snapshot(path: Path, pages) -> Path:
    """Same layout as the snapshot of the connector: gzipped JSON Lines, one API page per line."""
    with gzip.open(path, "wt", encoding="utf-8") as out:
        for item in pages:
            out.write(json.dumps(item) + "\n")
    return path


class ParseTests(TestCase):
    def test_only_nvd_primary_data_is_kept(self):
        record = parse_cve(nvd_cve("CVE-2026-0001", v2=7.5))
        self.assertEqual(sorted((m["version"], m["base_score"], m["severity"]) for m in record["metrics"]),
                         [("2.0", 7.5, "HIGH"), ("3.1", 9.8, "CRITICAL")])
        self.assertTrue(all(m["provider"] == ScoreProvider.NVD for m in record["metrics"]))
        self.assertEqual(record["weaknesses"], ["CWE-79"])  # not the CNA CWE-20, not NVD-CWE-noinfo
        self.assertEqual(record["nvd_status"], "Analyzed")

    def test_cve_without_nvd_enrichment(self):
        record = parse_cve(nvd_cve("CVE-2026-0002", status="Awaiting Analysis", v31=None, cwes=()))
        self.assertEqual((record["metrics"], record["weaknesses"]), ([], []))


class NvdLoadTests(TestCase):
    def setUp(self):
        # one staging folder per test: snapshots of the same second must not clean each other
        staging = override_settings(STAGING_DIR=tempfile.mkdtemp())
        staging.enable()
        self.addCleanup(staging.disable)
        self.folder = Path(tempfile.mkdtemp())
        self.cve = Vulnerability.objects.create(cve_id="CVE-2026-0001", description="x")
        Vulnerability.objects.create(cve_id="CVE-2026-0002", description="y")
        CVSSMetric.objects.create(vulnerability=self.cve, provider=ScoreProvider.CNA, version="3.1",
                                  base_score=7.5, severity="HIGH")  # from the cve connector

    def run_nvd(self, cves, name="nvd.jsonl.gz"):
        snapshot = write_snapshot(self.folder / name, [page(cves)])
        run = run_pipeline(sources=["nvd"], local_file=str(snapshot))
        return run, run.tasks.get()

    def test_scores_cwes_and_status_are_loaded(self):
        run, task = self.run_nvd([nvd_cve("CVE-2026-0001"),
                                  nvd_cve("CVE-2026-0002", status="Awaiting Analysis", v31=None, cwes=())])
        self.assertEqual(run.status, RunStatus.SUCCESS)
        self.assertEqual((task.extracted, task.loaded, task.rejected), (2, 2, 0))
        self.assertEqual(task.quality_report["without_nvd_score"], 1)
        nvd = CVSSMetric.objects.get(vulnerability=self.cve, provider=ScoreProvider.NVD)
        self.assertEqual((nvd.version, nvd.base_score, nvd.severity), ("3.1", 9.8, "CRITICAL"))
        self.assertTrue(CVSSMetric.objects.filter(vulnerability=self.cve, provider=ScoreProvider.CNA).exists())
        self.assertEqual(list(VulnerabilityWeakness.objects.filter(provider=ScoreProvider.NVD)
                              .values_list("vulnerability__cve_id", "weakness__cwe_id")), [("CVE-2026-0001", "CWE-79")])
        self.assertEqual(Weakness.objects.get(cwe_id="CWE-79").name, "")  # named by the cwe connector
        self.assertEqual(dict(Vulnerability.objects.values_list("cve_id", "nvd_status")),
                         {"CVE-2026-0001": "Analyzed", "CVE-2026-0002": "Awaiting Analysis"})

    def test_effective_severity_prefers_the_nvd_score(self):
        self.run_nvd([nvd_cve("CVE-2026-0001", v31=5.3)])  # NVD 5.3 MEDIUM beats the CNA 7.5 HIGH (FR-06)
        self.cve.refresh_from_db()
        self.assertEqual((self.cve.effective_severity, self.cve.effective_score), ("MEDIUM", 5.3))

    def test_cves_not_in_the_cve_list_are_skipped(self):
        _, task = self.run_nvd([nvd_cve("CVE-2026-0001"), nvd_cve("CVE-2026-9999")])
        self.assertEqual(task.loaded, 1)
        self.assertEqual(task.quality_report["skipped_not_in_cve_list"], 1)
        self.assertFalse(Vulnerability.objects.filter(cve_id="CVE-2026-9999").exists())

    def test_invalid_records_are_rejected_with_a_reason(self):
        _, task = self.run_nvd([nvd_cve("CVE-26-1"), nvd_cve("CVE-2026-0002", v31=11.0)])
        self.assertEqual(task.rejected, 2)
        self.assertEqual(task.quality_report["rejected_by_reason"],
                         {"invalid CVE identifier": 1, "CVSS base score outside 0-10": 1})

    def test_running_again_replaces_nvd_data_only(self):
        self.run_nvd([nvd_cve("CVE-2026-0001", v31=9.8, cwes=("CWE-79",))])
        self.run_nvd([nvd_cve("CVE-2026-0001", v31=8.1, cwes=("CWE-89",))], name="nvd2.jsonl.gz")
        self.assertEqual(list(CVSSMetric.objects.filter(vulnerability=self.cve).order_by("provider")
                              .values_list("provider", "base_score")), [("CNA", 7.5), ("NVD", 8.1)])
        self.assertEqual(list(VulnerabilityWeakness.objects.values_list("weakness__cwe_id", flat=True)), ["CWE-89"])

    def test_same_cve_in_two_overlapping_windows_is_loaded_once(self):
        snapshot = write_snapshot(self.folder / "two.jsonl.gz",
                                  [page([nvd_cve("CVE-2026-0001", v31=9.8)]), page([nvd_cve("CVE-2026-0001", v31=8.8)])])
        run_pipeline(sources=["nvd"], local_file=str(snapshot))
        self.assertEqual(CVSSMetric.objects.get(vulnerability=self.cve, provider="NVD").base_score, 8.8)

    def test_a_plain_json_page_saved_by_hand_is_accepted(self):
        path = self.folder / "page.json"
        path.write_text(json.dumps(page([nvd_cve("CVE-2026-0001")]), indent=2), encoding="utf-8")
        task = run_pipeline(sources=["nvd"], local_file=str(path)).tasks.get()
        self.assertEqual((task.status, task.loaded), (RunStatus.SUCCESS, 1))


class FakeResponse:
    def __init__(self, status, payload=None, broken_body=False):
        self.status_code, self.payload, self.broken_body = status, payload or {}, broken_body
        self.text = "Bad request"

    def json(self):
        if self.broken_body:  # body cut in the middle
            raise requests.exceptions.JSONDecodeError("Unterminated string", '{"vulnerabilities": [{"cve', 30)
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@override_settings(STAGING_DIR=tempfile.mkdtemp(), NVD_API_KEY="test-key")
class NvdApiTests(TestCase):
    """Download through the API, with a fake HTTP session (no network in the tests)."""

    def connector(self, responses, **kwargs):
        connector = NvdConnector(**kwargs)
        connector.sleep = mock.Mock()
        connector.session = mock.Mock()
        connector.session.get.side_effect = responses
        return connector

    def test_pages_are_read_until_the_total_with_the_api_key(self):
        cves = [nvd_cve(f"CVE-2026-000{i}") for i in range(1, 4)]
        connector = self.connector([FakeResponse(200, page(cves[:2], 0, 3)), FakeResponse(200, page(cves[2:], 2, 3))])
        records = list(connector.transform(connector.extract()))
        self.assertEqual([r["cve_id"] for r in records], ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"])
        calls = connector.session.get.call_args_list
        self.assertEqual([c.kwargs["params"]["startIndex"] for c in calls], [0, 2])
        self.assertEqual(calls[0].kwargs["headers"], {"apiKey": "test-key"})
        self.assertNotIn("lastModStartDate", calls[0].kwargs["params"])  # first run: everything
        self.assertEqual(connector.counters["window_start"], "full")

    def test_rate_limit_answer_is_retried_with_backoff(self):
        connector = self.connector([FakeResponse(403), FakeResponse(503), FakeResponse(200, page([nvd_cve("CVE-2026-0001")]))])
        list(connector.transform(connector.extract()))
        self.assertEqual(connector.counters["api_retries"], 2)
        self.assertEqual([c.args[0] for c in connector.sleep.call_args_list], [6, 12])

    def test_cut_or_invalid_responses_are_retried(self):
        connector = self.connector([
            requests.exceptions.ChunkedEncodingError("Connection broken: IncompleteRead"),
            FakeResponse(200, broken_body=True),
            FakeResponse(200, page([nvd_cve("CVE-2026-0001")])),
        ])
        self.assertEqual(len(list(connector.transform(connector.extract()))), 1)
        self.assertEqual(connector.counters["api_retries"], 2)

    def test_waits_are_capped_at_two_minutes(self):
        connector = self.connector([FakeResponse(503)] * (MAX_ATTEMPTS - 1) + [FakeResponse(200, page([]))])
        connector.extract()
        self.assertEqual([c.args[0] for c in connector.sleep.call_args_list], [6, 12, 24, 48, 96, 120, 120])

    def test_api_still_failing_fails_the_task(self):
        connector = self.connector([FakeResponse(503)] * MAX_ATTEMPTS)
        with self.assertRaisesMessage(RuntimeError, f"NVD API unavailable after {MAX_ATTEMPTS} attempts at startIndex 0 (HTTP 503)"):
            connector.extract()

    def test_wrong_request_is_not_retried(self):
        connector = self.connector([FakeResponse(400)])
        with self.assertRaisesMessage(RuntimeError, "NVD API refused the request: HTTP 400"):
            connector.extract()
        connector.sleep.assert_not_called()

    def previous_success(self, window_end):
        ensure_sources()
        IngestionTask.objects.create(run=PipelineRun.objects.create(), source=Source.objects.get(name="nvd"),
                                     status=RunStatus.SUCCESS, quality_report={"window_end": window_end.isoformat()})

    def test_next_run_reads_only_the_cves_modified_since_the_last_one(self):
        now = datetime(2026, 11, 15, 10, 0, tzinfo=timezone.utc)
        self.previous_success(now - timedelta(days=1))
        connector = self.connector([])
        self.assertEqual(connector.windows(now), [(now - timedelta(days=1) - OVERLAP, now)])

    def test_long_period_is_split_into_windows_of_120_days(self):
        now = datetime(2026, 11, 15, tzinfo=timezone.utc)
        self.previous_success(now - timedelta(days=300))
        windows = self.connector([]).windows(now)
        self.assertEqual(len(windows), 3)
        self.assertTrue(all(end - start <= MAX_WINDOW for start, end in windows))
        self.assertEqual((windows[0][0], windows[-1][1]), (now - timedelta(days=300) - OVERLAP, now))

    def test_full_option_ignores_the_previous_run(self):
        now = datetime(2026, 11, 15, tzinfo=timezone.utc)
        self.previous_success(now - timedelta(days=1))
        self.assertEqual(self.connector([], full=True).windows(now), [(None, now)])

    def test_incremental_request_sends_the_dates(self):
        self.previous_success(datetime.now(timezone.utc) - timedelta(days=2))
        connector = self.connector([FakeResponse(200, page([]))])
        connector.extract()
        params = connector.session.get.call_args.kwargs["params"]
        self.assertTrue(params["lastModStartDate"].endswith("+00:00"))
        self.assertIn("lastModEndDate", params)
