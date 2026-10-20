"""Common interface of every CTI connector.

A connector is run in 5 steps:

    extract()    download the source (or take a local file) -> raw snapshot in data/staging/<source>/
    transform()  read the snapshot and yield one clean record (dict) per item
    validate()   quality checks on a batch -> (valid records, rejected records with a reason)
    load()       idempotent load of a batch into the operational schema
    report       counts + quality report stored in the IngestionTask (FR-17)

Adding a source = a new subclass + an entry in connectors.REGISTRY.
"""

from __future__ import annotations

import itertools
import shutil
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from typing import Iterable, Iterator

import requests
from django.conf import settings
from django.utils import timezone

BATCH_SIZE = 2000
SNAPSHOTS_KEPT = 3  # raw snapshots kept per source in data/staging
MAX_REJECT_EXAMPLES = 200
HTTP_TIMEOUT = 60


@dataclass
class Reject:
    key: str
    reason: str


@dataclass
class ConnectorResult:
    extracted: int = 0
    loaded: int = 0
    rejected: int = 0
    report: dict = field(default_factory=dict)


class BaseConnector:
    name: str = ""  # registry key, also the Source.name
    label: str = ""
    url: str = ""

    def __init__(self, *, local_file: str | None = None, full: bool = False, stdout=None):
        self.local_file = Path(local_file) if local_file else None
        self.full = full  # ignore the incremental watermark
        self.stdout = stdout
        self.counters: Counter = Counter()  # extra numbers for the quality report
        self.reject_reasons: Counter = Counter()
        self.reject_examples: list[dict] = []

    # ---- steps implemented by each connector -------------------------------------
    def download(self, destination: Path) -> None:
        raise NotImplementedError

    def transform(self, snapshot: Path) -> Iterator[dict]:
        raise NotImplementedError

    def validate(self, records: list[dict]) -> tuple[list[dict], list[Reject]]:
        return records, []

    def load(self, records: list[dict]) -> int:
        raise NotImplementedError

    def snapshot_suffix(self) -> str:
        return ".json"

    # ---- orchestration ---------------------------------------------------------------
    def run(self) -> ConnectorResult:
        snapshot = self.extract()
        result = ConnectorResult()
        records = self.transform(snapshot)
        while batch := list(itertools.islice(records, BATCH_SIZE)):
            result.extracted += len(batch)
            valid, rejects = self.validate(batch)
            self._record_rejects(rejects)
            result.rejected += len(rejects)
            if valid:
                result.loaded += self.load(valid)
            self.log(f"  {self.name}: {result.extracted} read, {result.loaded} loaded, {result.rejected} rejected")
        result.report = {
            "snapshot": snapshot.name,
            **dict(self.counters),
            "rejected_by_reason": dict(self.reject_reasons),
            "rejected_examples": self.reject_examples,
        }
        return result

    def extract(self) -> Path:
        """Raw snapshot in data/staging/<source>/ (copy of --file, or a fresh download)."""
        folder = Path(settings.STAGING_DIR) / self.name
        folder.mkdir(parents=True, exist_ok=True)
        stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
        if self.local_file:
            snapshot = folder / f"{stamp}_{self.local_file.name}"
            shutil.copyfile(self.local_file, snapshot)
        else:
            snapshot = folder / f"{stamp}_{self.name}{self.snapshot_suffix()}"
            self.download(snapshot)
        self._clean_old_snapshots(folder)
        return snapshot

    # ---- helpers -----------------------------------------------------------------
    def http_download(self, url: str, destination: Path) -> None:
        self.log(f"  downloading {url}")
        with requests.get(url, stream=True, timeout=HTTP_TIMEOUT) as response:
            response.raise_for_status()
            written = 0
            with open(destination, "wb") as out:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    out.write(chunk)
                    written += len(chunk)
                    if written % (50 * 1024 * 1024) < len(chunk):
                        self.log(f"  {written // (1024 * 1024)} MB")

    def log(self, message: str) -> None:
        if self.stdout:
            self.stdout.write(message)

    def _record_rejects(self, rejects: Iterable[Reject]) -> None:
        for reject in rejects:
            self.reject_reasons[reject.reason] += 1
            if len(self.reject_examples) < MAX_REJECT_EXAMPLES:
                self.reject_examples.append({"key": reject.key, "reason": reject.reason})

    @staticmethod
    def _clean_old_snapshots(folder: Path) -> None:
        snapshots = sorted(p for p in folder.iterdir() if p.is_file())
        for old in snapshots[:-SNAPSHOTS_KEPT]:
            old.unlink(missing_ok=True)


def parse_datetime(value: str | None) -> datetime | None:
    """ISO 8601 from the sources ('2024-01-31T10:00:00.000Z', with or without zone) -> aware datetime."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timezone.is_naive(parsed):
        parsed = parsed.replace(tzinfo=dt_timezone.utc)
    return parsed
