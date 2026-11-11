"""FIRST EPSS connector (Exploit Prediction Scoring System).

Source: the daily EPSS file, a gzipped CSV, free and without authentication. One row per CVE:
cve, epss (probability 0 to 1), percentile (0 to 1). The first line is a comment with the
model version and the score date. Values outside 0..1 are rejected (quality rule of US06).

The scores are written into the two EPSS columns of cti_vulnerability (latest score only).
The model version and the score date of the file are kept in the quality report of the run.
"""

from __future__ import annotations

import csv
import gzip
import itertools
import re
from datetime import date
from pathlib import Path
from typing import Iterator

from django.db import transaction

from cti.models import Vulnerability

from .base import BaseConnector, Reject

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"  # redirects to the dated file
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def open_text(path: Path):
    """The snapshot is normally gzip; also accept plain text, in case a server decompressed it."""
    with open(path, "rb") as handle:
        is_gzip = handle.read(2) == b"\x1f\x8b"
    if is_gzip:
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return open(path, encoding="utf-8", newline="")


def to_float(value) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number else None  # NaN -> None


class EpssConnector(BaseConnector):
    name = "epss"
    label = "FIRST EPSS scores"
    url = EPSS_URL
    score_date: date | None = None
    model_version: str = ""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.seen: set[str] = set()  # CVEs already accepted in this run, across every batch

    def snapshot_suffix(self) -> str:
        return ".csv.gz"

    def download(self, destination: Path) -> None:
        self.http_download(EPSS_URL, destination)

    def transform(self, snapshot: Path) -> Iterator[dict]:
        with open_text(snapshot) as handle:
            first = handle.readline()
            header = handle.readline() if first.startswith("#") else first
            version = re.search(r"model_version:([^,\s]+)", first)
            day = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", first)
            self.model_version = version.group(1) if version else ""
            self.score_date = date.fromisoformat(day.group(1)) if day else date.today()
            self.counters["model_version"] = self.model_version
            self.counters["score_date"] = self.score_date.isoformat()
            for row in csv.DictReader(itertools.chain([header], handle)):
                yield {
                    "cve_id": (row.get("cve") or "").strip(),
                    "epss": to_float(row.get("epss")),
                    "percentile": to_float(row.get("percentile")),
                }

    def validate(self, records: list[dict]) -> tuple[list[dict], list[Reject]]:
        known = set(
            Vulnerability.objects.filter(cve_id__in=[r["cve_id"] for r in records]).values_list("cve_id", flat=True)
        )
        valid, rejects = [], []
        for record in records:
            cve_id = record["cve_id"]
            if not CVE_ID.match(cve_id):
                rejects.append(Reject(cve_id or "?", "invalid CVE identifier"))
            elif record["epss"] is None or record["percentile"] is None:
                rejects.append(Reject(cve_id, "epss or percentile is not a number"))
            elif not (0.0 <= record["epss"] <= 1.0 and 0.0 <= record["percentile"] <= 1.0):
                rejects.append(Reject(cve_id, "epss or percentile outside 0..1"))
            elif cve_id not in known:
                rejects.append(Reject(cve_id, "CVE not in the database (run the cve source first)"))
            elif cve_id in self.seen:
                rejects.append(Reject(cve_id, "duplicate row in the file"))
            else:
                self.seen.add(cve_id)
                valid.append(record)
        return valid, rejects

    @transaction.atomic
    def load(self, records: list[dict]) -> int:
        """Update the two EPSS columns of the vulnerabilities (validate already rejected unknown CVEs)."""
        ids = dict(Vulnerability.objects.filter(cve_id__in=[r["cve_id"] for r in records]).values_list("cve_id", "id"))
        rows = [
            Vulnerability(id=ids[r["cve_id"]], epss_score=r["epss"], epss_percentile=r["percentile"])
            for r in records
            if r["cve_id"] in ids
        ]
        Vulnerability.objects.bulk_update(rows, ["epss_score", "epss_percentile"], batch_size=1000)
        return len(rows)
