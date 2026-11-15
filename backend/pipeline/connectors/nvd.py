"""NVD connector (NIST National Vulnerability Database, API 2.0).

Source: https://services.nvd.nist.gov/rest/json/cves/2.0, paged (2,000 CVEs per request).
A free API key (NVD_API_KEY in .env) raises the limit from 5 to 50 requests per 30 seconds.

Per CVE we keep only what NIST itself published (type "Primary"): the NVD CVSS scores
(every version), the NVD CWE identifiers and the NVD analysis status (vulnStatus).
The scores and CWEs of the CNA ("Secondary") already come from the cve connector.
Since 15 April 2026 NIST only enriches priority CVEs: many records have no NVD score.

CVEs that are not in cti_vulnerability (not yet in CVE List V5, or rejected there) are skipped:
CVE List V5 is the reference list of vulnerabilities.

Incremental: the first run (or --full) reads every CVE; the next runs read only the CVEs
modified since the end of the last successful run (lastModStartDate / lastModEndDate,
windows of at most 120 days, as the API requires). The raw pages are kept as a gzipped
JSON Lines snapshot in data/staging/nvd/.
"""

from __future__ import annotations

import gzip
import json
import re
import time
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from typing import Iterator

import requests
from django.conf import settings
from django.db import transaction

from cti.models import CVSSMetric, ScoreProvider, Vulnerability, VulnerabilityWeakness, Weakness
from pipeline.models import IngestionTask, RunStatus

from .base import BaseConnector, Reject
from .cve_list_v5 import severity_from_score

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # maximum allowed by the API
MAX_WINDOW = timedelta(days=120)  # maximum lastModStartDate..lastModEndDate range
OVERLAP = timedelta(hours=1)  # re-read a little before the previous end: nothing is missed
DELAY_WITH_KEY = 1.0  # seconds between requests (limit: 50 requests / 30 s)
DELAY_WITHOUT_KEY = 6.0  # limit: 5 requests / 30 s
RETRY_STATUS = {403, 429, 500, 502, 503, 504}  # the NVD answers 403 when the rate limit is hit
MAX_ATTEMPTS = 8  # waits 6, 12, 24, 48, 96, 120, 120 s: about 7 minutes of tolerance
MAX_WAIT = 120
REQUEST_TIMEOUT = 120
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_ID = re.compile(r"^CWE-\d+$")
NVD_METRIC_KEYS = {"cvssMetricV2": "2.0", "cvssMetricV30": "3.0", "cvssMetricV31": "3.1", "cvssMetricV40": "4.0"}


def nvd_time(value: datetime) -> str:
    """Date format of the API: 2026-11-15T10:00:00.000+00:00."""
    return value.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def parse_cve(cve: dict) -> dict:
    """One `cve` object of the API -> clean record (NVD "Primary" data only)."""
    metrics = []
    for key, version in NVD_METRIC_KEYS.items():
        for metric in cve.get("metrics", {}).get(key, []) or []:
            data = metric.get("cvssData") or {}
            if metric.get("type") != "Primary" or data.get("baseScore") is None:
                continue
            score = float(data["baseScore"])
            # CVSS v2 puts the severity next to cvssData, v3 and v4 inside it
            severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "").upper()
            metrics.append({
                "provider": ScoreProvider.NVD,
                "version": str(data.get("version") or version),
                "vector": str(data.get("vectorString") or "")[:200],
                "base_score": score,
                "severity": severity or severity_from_score(score, version),
            })
    weaknesses = []
    for weakness in cve.get("weaknesses", []) or []:
        if weakness.get("type") != "Primary":
            continue
        for description in weakness.get("description", []) or []:
            cwe_id = str(description.get("value") or "").strip().upper()
            if CWE_ID.match(cwe_id) and cwe_id not in weaknesses:  # NVD-CWE-Other / NVD-CWE-noinfo are ignored
                weaknesses.append(cwe_id)
    return {
        "cve_id": str(cve.get("id") or "").strip(),
        "nvd_status": str(cve.get("vulnStatus") or "")[:32],
        "metrics": metrics,
        "weaknesses": weaknesses,
    }


class NvdConnector(BaseConnector):
    name = "nvd"
    label = "NVD API 2.0"
    url = "https://nvd.nist.gov/developers/vulnerabilities"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = settings.NVD_API_KEY
        self.sleep = time.sleep  # replaced in the tests
        self.session = requests.Session()

    def snapshot_suffix(self) -> str:
        return ".jsonl.gz"

    # ---- extract -----------------------------------------------------------------
    def windows(self, now: datetime) -> list[tuple[datetime | None, datetime]]:
        """Periods to read: [(None, now)] for a full read, else windows of at most 120 days."""
        previous = (
            IngestionTask.objects.filter(
                source__name=self.name, status=RunStatus.SUCCESS, quality_report__has_key="window_end"
            )
            .order_by("-started_at")
            .first()
        )
        if self.full or previous is None:
            return [(None, now)]
        start = datetime.fromisoformat(previous.quality_report["window_end"]) - OVERLAP
        windows = []
        while start < now:
            end = min(start + MAX_WINDOW, now)
            windows.append((start, end))
            start = end
        return windows

    def download(self, destination: Path) -> None:
        now = datetime.now(dt_timezone.utc)
        windows = self.windows(now)
        self.counters["window_start"] = "full" if windows[0][0] is None else windows[0][0].isoformat()
        self.counters["window_end"] = now.isoformat()
        self.counters["api_key_used"] = bool(self.api_key)
        with gzip.open(destination, "wt", encoding="utf-8") as out:
            for start, end in windows:
                for page in self.fetch_pages(start, end):
                    out.write(json.dumps(page) + "\n")

    def fetch_pages(self, start: datetime | None, end: datetime) -> Iterator[dict]:
        params = {"resultsPerPage": PAGE_SIZE, "startIndex": 0}
        if start is not None:
            params.update(lastModStartDate=nvd_time(start), lastModEndDate=nvd_time(end))
        while True:
            page = self.get_page(params)
            items = page.get("vulnerabilities") or []
            total = int(page.get("totalResults") or 0)
            self.counters["api_requests"] += 1
            yield page
            params["startIndex"] += len(items)
            self.log(f"  nvd: {min(params['startIndex'], total)} / {total} CVEs read")
            if not items or params["startIndex"] >= total:
                return
            self.sleep(DELAY_WITH_KEY if self.api_key else DELAY_WITHOUT_KEY)

    def get_page(self, params: dict) -> dict:
        """One API request, retried with an exponential backoff: rate limit, server errors, and
        responses cut in the middle (connection reset, incomplete or invalid JSON body)."""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self.session.get(NVD_API, params=dict(params), headers=headers, timeout=REQUEST_TIMEOUT)
                if response.status_code in RETRY_STATUS:
                    error = f"HTTP {response.status_code}"
                elif response.status_code >= 400:  # a wrong request: retrying would not help
                    raise RuntimeError(f"NVD API refused the request: HTTP {response.status_code} {response.text[:200]}")
                else:
                    return response.json()
            except requests.RequestException as exc:  # includes ChunkedEncodingError and JSONDecodeError
                error = f"{type(exc).__name__}: {str(exc)[:200]}"
            if attempt == MAX_ATTEMPTS:
                raise RuntimeError(f"NVD API unavailable after {MAX_ATTEMPTS} attempts at startIndex "
                                   f"{params.get('startIndex')} ({error})")
            wait = min(6 * 2 ** (attempt - 1), MAX_WAIT)
            self.counters["api_retries"] += 1
            self.log(f"  nvd: {error}, new attempt in {wait} s")
            self.sleep(wait)
        raise AssertionError("unreachable")

    # ---- transform -----------------------------------------------------------------
    def transform(self, snapshot: Path) -> Iterator[dict]:
        for page in self._iter_pages(snapshot):
            for item in page.get("vulnerabilities") or []:
                yield parse_cve(item.get("cve") or {})

    @staticmethod
    def _iter_pages(snapshot: Path) -> Iterator[dict]:
        """gzipped or plain JSON Lines (one API page per line, read line by line: a full snapshot
        is several GB once unzipped), or one indented JSON page saved by hand (--file)."""
        with open(snapshot, "rb") as handle:
            is_gzip = handle.read(2) == b"\x1f\x8b"
        opener = gzip.open if is_gzip else open
        with opener(snapshot, "rt", encoding="utf-8") as text:
            first = next((line for line in text if line.strip()), None)
            if first is None:
                return
            try:
                page = json.loads(first)
            except json.JSONDecodeError:  # not JSON Lines: one indented JSON document
                text.seek(0)
                yield json.load(text)
                return
            yield page
            for line in text:
                if line.strip():
                    yield json.loads(line)

    # ---- validate ------------------------------------------------------------------
    def validate(self, records: list[dict]) -> tuple[list[dict], list[Reject]]:
        rejects, kept = [], {}
        for record in records:
            cve_id = record["cve_id"]
            if not CVE_ID.match(cve_id):
                rejects.append(Reject(cve_id or "?", "invalid CVE identifier"))
            elif any(not 0 <= m["base_score"] <= 10 for m in record["metrics"]):
                rejects.append(Reject(cve_id, "CVSS base score outside 0-10"))
            else:
                kept[cve_id] = record  # the same CVE in two overlapping windows: the last one wins
        self.counters["duplicates_in_snapshot"] += len(records) - len(rejects) - len(kept)
        return list(kept.values()), rejects

    # ---- load (idempotent) -------------------------------------------------------
    @transaction.atomic
    def load(self, records: list[dict]) -> int:
        ids = dict(Vulnerability.objects.filter(cve_id__in=[r["cve_id"] for r in records]).values_list("cve_id", "id"))
        known = [r for r in records if r["cve_id"] in ids]
        self.counters["skipped_not_in_cve_list"] += len(records) - len(known)
        if not known:
            return 0

        Vulnerability.objects.bulk_update(
            [Vulnerability(id=ids[r["cve_id"]], nvd_status=r["nvd_status"]) for r in known], ["nvd_status"]
        )

        # NVD scores and CWE links are replaced; CNA and CISA ADP data stay untouched
        vulnerability_ids = [ids[r["cve_id"]] for r in known]
        CVSSMetric.objects.filter(vulnerability_id__in=vulnerability_ids, provider=ScoreProvider.NVD).delete()
        metrics = {(ids[r["cve_id"]], m["version"]): m for r in known for m in r["metrics"]}
        CVSSMetric.objects.bulk_create([CVSSMetric(vulnerability_id=v, **m) for (v, _), m in metrics.items()])

        cwe_ids = {cwe_id for r in known for cwe_id in r["weaknesses"]}
        Weakness.objects.bulk_create([Weakness(cwe_id=c) for c in cwe_ids], ignore_conflicts=True)  # named by the cwe connector
        weakness_ids = dict(Weakness.objects.filter(cwe_id__in=cwe_ids).values_list("cwe_id", "id"))
        VulnerabilityWeakness.objects.filter(
            vulnerability_id__in=vulnerability_ids, provider=ScoreProvider.NVD
        ).delete()
        links = [
            VulnerabilityWeakness(vulnerability_id=ids[r["cve_id"]], weakness_id=weakness_ids[c], provider=ScoreProvider.NVD)
            for r in known
            for c in r["weaknesses"]
        ]
        VulnerabilityWeakness.objects.bulk_create(links)

        self.counters["cvss_metrics_loaded"] += len(metrics)
        self.counters["cwe_links_loaded"] += len(links)
        self.counters["without_nvd_score"] += sum(1 for r in known if not r["metrics"])
        return len(known)
