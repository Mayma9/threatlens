"""CISA Known Exploited Vulnerabilities (KEV) connector.

Source: the official KEV catalog in JSON (free, no authentication).
Per entry we keep: date added, due date, required action, known ransomware use.
An entry whose CVE is not in the database yet is rejected (referential integrity),
so the CVE List V5 source must run first.
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Iterator

from django.db import transaction

from cti.models import KEVEntry, Vulnerability

from .base import BaseConnector, Reject

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def parse_date(value) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


class KevConnector(BaseConnector):
    name = "kev"
    label = "CISA KEV catalog"
    url = KEV_URL

    def download(self, destination: Path) -> None:
        self.http_download(KEV_URL, destination)

    def transform(self, snapshot: Path) -> Iterator[dict]:
        catalog = json.loads(snapshot.read_text(encoding="utf-8"))
        self.counters["catalog_version"] = catalog.get("catalogVersion", "")
        self.counters["catalog_count"] = catalog.get("count", 0)
        for item in catalog.get("vulnerabilities", []):
            yield {
                "cve_id": str(item.get("cveID", "")).strip(),
                "date_added": parse_date(item.get("dateAdded")),
                "due_date": parse_date(item.get("dueDate")),
                "required_action": str(item.get("requiredAction", "")).strip(),
                "ransomware_use": str(item.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
            }

    def validate(self, records: list[dict]) -> tuple[list[dict], list[Reject]]:
        known = set(
            Vulnerability.objects.filter(cve_id__in=[r["cve_id"] for r in records]).values_list("cve_id", flat=True)
        )
        valid, rejects, seen = [], [], set()
        for record in records:
            cve_id = record["cve_id"]
            if not CVE_ID.match(cve_id):
                rejects.append(Reject(cve_id or "?", "invalid CVE identifier"))
            elif record["date_added"] is None:
                rejects.append(Reject(cve_id, "missing or invalid dateAdded"))
            elif cve_id not in known:
                rejects.append(Reject(cve_id, "CVE not in the database (run the cve source first)"))
            elif cve_id in seen:
                rejects.append(Reject(cve_id, "duplicate entry in the catalog"))
            else:
                seen.add(cve_id)
                valid.append(record)
        return valid, rejects

    @transaction.atomic
    def load(self, records: list[dict]) -> int:
        ids = dict(Vulnerability.objects.filter(cve_id__in=[r["cve_id"] for r in records]).values_list("cve_id", "id"))
        KEVEntry.objects.bulk_create(
            [
                KEVEntry(
                    vulnerability_id=ids[r["cve_id"]],
                    date_added=r["date_added"],
                    due_date=r["due_date"],
                    required_action=r["required_action"],
                    ransomware_use=r["ransomware_use"],
                )
                for r in records
            ],
            update_conflicts=True,
            unique_fields=["vulnerability"],
            update_fields=["date_added", "due_date", "required_action", "ransomware_use"],
        )
        return len(records)
