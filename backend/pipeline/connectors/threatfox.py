"""abuse.ch ThreatFox connector (indicators of compromise).

Source: the ThreatFox API (POST https://threatfox-api.abuse.ch/api/v1/, query get_iocs).
An Auth-Key is required (ABUSECH_AUTH_KEY in .env). The API returns the IOCs first seen in
the last 1 to 7 days; each run asks for 7 days, so a run every day (or every few days) misses
nothing, and the same IOC read twice is updated in place (key: the ThreatFox id).

Per IOC we keep: ThreatFox id, value, IOC type, threat type, malware family, confidence (0-100),
first seen and last seen. Malware families are stored once, with their Malpedia name and a
category = the target platform given by the Malpedia prefix (win -> Windows, elf -> Linux...).

IOC values are data only: they are never visited, resolved or rendered as links (risk R9),
and no malware sample is downloaded. Only the metadata of the API is used.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from typing import Iterator

import requests
from django.conf import settings
from django.db import transaction

from cti.models import Indicator, Malware

from .base import BaseConnector, Reject

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
DAYS = 7  # maximum allowed by get_iocs
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 4
REQUEST_TIMEOUT = 120
PLATFORMS = {
    "win": "Windows", "elf": "Linux", "apk": "Android", "osx": "macOS", "ios": "iOS", "js": "JavaScript",
    "jar": "Java", "ps1": "PowerShell", "vbs": "VBScript", "py": "Python", "php": "PHP", "asp": "ASP",
}
UNKNOWN_MALWARE = {"", "unknown"}


def platform(malpedia_id: str) -> str:
    """'win.cobalt_strike' -> 'Windows'; a prefix outside the list -> 'Other'."""
    prefix = malpedia_id.split(".", 1)[0] if "." in malpedia_id else ""
    return PLATFORMS.get(prefix, "Other")


def parse_time(value) -> datetime | None:
    """ThreatFox dates look like '2026-11-15 08:29:40 UTC'."""
    if not value:
        return None
    try:
        return datetime.strptime(str(value).replace(" UTC", "").strip(), "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=dt_timezone.utc
        )
    except ValueError:
        return None


def parse_ioc(item: dict) -> dict:
    """One element of `data` -> record (types are checked in validate)."""
    malpedia_id = str(item.get("malware") or "").strip().lower()
    return {
        "threatfox_id": item.get("id"),
        "value": str(item.get("ioc") or "").strip(),
        "ioc_type": str(item.get("ioc_type") or "").strip()[:50],
        "threat_type": str(item.get("threat_type") or "").strip()[:50],
        "malpedia_id": "" if malpedia_id in UNKNOWN_MALWARE else malpedia_id[:100],
        "malware_name": " ".join(str(item.get("malware_printable") or "").split())[:200],
        "confidence": item.get("confidence_level"),
        "first_seen": parse_time(item.get("first_seen")),
        "last_seen": parse_time(item.get("last_seen")),
    }


class ThreatFoxConnector(BaseConnector):
    name = "threatfox"
    label = "abuse.ch ThreatFox"
    url = "https://threatfox.abuse.ch/"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.auth_key = settings.ABUSECH_AUTH_KEY
        self.sleep = time.sleep  # replaced in the tests
        self.session = requests.Session()
        self.seen: set[int] = set()  # ThreatFox ids already accepted in this run, across every batch

    def snapshot_suffix(self) -> str:
        return ".json"

    # ---- extract -----------------------------------------------------------------
    def download(self, destination: Path) -> None:
        if not self.auth_key:
            raise RuntimeError("ABUSECH_AUTH_KEY is empty in .env: the ThreatFox API requires an Auth-Key")
        answer = self.post({"query": "get_iocs", "days": DAYS})
        status = answer.get("query_status")
        if status == "no_result":
            answer["data"] = []
        elif status != "ok":
            raise RuntimeError(f"ThreatFox API answered query_status={status!r}")
        self.counters["days_requested"] = DAYS
        destination.write_text(json.dumps(answer), encoding="utf-8")

    def post(self, body: dict) -> dict:
        """One API request, retried with a backoff on rate limit and server errors."""
        headers = {"Auth-Key": self.auth_key}
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self.session.post(THREATFOX_API, json=body, headers=headers, timeout=REQUEST_TIMEOUT)
                if response.status_code in (401, 403):
                    raise RuntimeError(f"ThreatFox refused the Auth-Key (HTTP {response.status_code}): check ABUSECH_AUTH_KEY")
                if response.status_code in RETRY_STATUS:
                    error = f"HTTP {response.status_code}"
                elif response.status_code >= 400:
                    raise RuntimeError(f"ThreatFox API refused the request: HTTP {response.status_code}")
                else:
                    return response.json()
            except requests.RequestException as exc:  # connection cut, invalid JSON body, timeout
                error = f"{type(exc).__name__}: {str(exc)[:200]}"
            if attempt == MAX_ATTEMPTS:
                raise RuntimeError(f"ThreatFox API unavailable after {MAX_ATTEMPTS} attempts ({error})")
            wait = 10 * 2 ** (attempt - 1)
            self.counters["api_retries"] += 1
            self.log(f"  threatfox: {error}, new attempt in {wait} s")
            self.sleep(wait)
        raise AssertionError("unreachable")

    # ---- transform -----------------------------------------------------------------
    def transform(self, snapshot: Path) -> Iterator[dict]:
        with open(snapshot, encoding="utf-8") as handle:
            data = json.load(handle).get("data")
        for item in data if isinstance(data, list) else []:
            yield parse_ioc(item if isinstance(item, dict) else {})

    # ---- validate ------------------------------------------------------------------
    def validate(self, records: list[dict]) -> tuple[list[dict], list[Reject]]:
        valid, rejects = [], []
        for record in records:
            key = str(record["threatfox_id"] or "?")
            try:
                record["threatfox_id"] = int(record["threatfox_id"])
            except (TypeError, ValueError):
                rejects.append(Reject(key, "invalid ThreatFox id"))
                continue
            try:
                confidence = int(record["confidence"])
            except (TypeError, ValueError):
                confidence = -1
            if not record["value"]:
                rejects.append(Reject(key, "missing IOC value"))
            elif not record["ioc_type"] or not record["threat_type"]:
                rejects.append(Reject(key, "missing IOC type or threat type"))
            elif not 0 <= confidence <= 100:
                rejects.append(Reject(key, "confidence outside 0-100"))
            elif record["first_seen"] is None:
                rejects.append(Reject(key, "invalid first_seen date"))
            elif record["threatfox_id"] in self.seen:
                rejects.append(Reject(key, "duplicate IOC in the file"))
            else:
                record["confidence"] = confidence
                self.seen.add(record["threatfox_id"])
                valid.append(record)
        return valid, rejects

    # ---- load (idempotent) -------------------------------------------------------
    @transaction.atomic
    def load(self, records: list[dict]) -> int:
        families = {r["malpedia_id"]: r["malware_name"] or r["malpedia_id"] for r in records if r["malpedia_id"]}
        Malware.objects.bulk_create(
            [Malware(malpedia_id=key, name=name, category=platform(key)) for key, name in families.items()],
            update_conflicts=True,
            unique_fields=["malpedia_id"],
            update_fields=["name", "category"],
        )
        malware_ids = dict(Malware.objects.filter(malpedia_id__in=families).values_list("malpedia_id", "id"))
        Indicator.objects.bulk_create(
            [
                Indicator(
                    threatfox_id=r["threatfox_id"],
                    value=r["value"],
                    ioc_type=r["ioc_type"],
                    threat_type=r["threat_type"],
                    malware_id=malware_ids.get(r["malpedia_id"]),
                    confidence=r["confidence"],
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                )
                for r in records
            ],
            update_conflicts=True,
            unique_fields=["threatfox_id"],
            update_fields=["value", "ioc_type", "threat_type", "malware", "confidence", "first_seen", "last_seen"],
        )
        self.counters["without_malware_family"] += sum(1 for r in records if not r["malpedia_id"])
        return len(records)
