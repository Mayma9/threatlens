"""CVE List V5 connector (CVE Program, github.com/CVEProject/cvelistV5).

Source: the daily "all CVEs at midnight" bulk file of the latest GitHub release
(a zip that contains cves.zip, which contains one JSON file per CVE record).

Per record we keep: CVE id, English description, publication and update dates,
CVSS scores published by the CNA and by CISA ADP (every version), affected products.
REJECTED records are skipped. CISA ADP SSVC fields are NOT loaded (M2 label leakage).

Incremental: records whose dateUpdated is not newer than the latest one already
loaded are skipped (use --full to reload everything).
"""

from __future__ import annotations

import json
import re
import shutil
import zipfile
from pathlib import Path
from typing import Iterator

import requests
from django.db import transaction
from django.db.models import Max

from cti.models import AffectedProduct, CVSSMetric, Product, ScoreProvider, Severity, Vulnerability

from .base import HTTP_TIMEOUT, BaseConnector, Reject, parse_datetime

RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
CVSS_KEYS = {"cvssV2_0": "2.0", "cvssV3_0": "3.0", "cvssV3_1": "3.1", "cvssV4_0": "4.0"}
IGNORED_NAMES = {"", "n/a", "na", "unknown", "unspecified", "-"}


def severity_from_score(score: float, version: str) -> str:
    """Qualitative rating when the record gives none (always the case for CVSS v2)."""
    if version == "2.0":
        return Severity.LOW if score < 4 else Severity.MEDIUM if score < 7 else Severity.HIGH
    if score == 0:
        return Severity.NONE
    if score < 4:
        return Severity.LOW
    if score < 7:
        return Severity.MEDIUM
    if score < 9:
        return Severity.HIGH
    return Severity.CRITICAL


def extract_metrics(metrics: list, provider: str) -> list[dict]:
    found = []
    for entry in metrics or []:
        for key, version in CVSS_KEYS.items():
            data = entry.get(key)
            if not isinstance(data, dict) or data.get("baseScore") is None:
                continue
            score = float(data["baseScore"])
            severity = str(data.get("baseSeverity") or "").upper() or severity_from_score(score, version)
            found.append(
                {
                    "provider": provider,
                    "version": version,
                    "vector": data.get("vectorString", "")[:200],
                    "base_score": score,
                    "severity": severity,
                }
            )
    return found


def clean_name(value) -> str:
    return " ".join(str(value or "").split()).lower()[:200]


def parse_record(doc: dict) -> dict | None:
    """One CVE JSON 5.x document -> clean record, or None when the CVE is not PUBLISHED."""
    meta = doc.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return None
    cna = doc.get("containers", {}).get("cna", {})
    description = next(
        (d.get("value", "") for d in cna.get("descriptions", []) if str(d.get("lang", "")).lower().startswith("en")),
        "",
    )
    metrics = extract_metrics(cna.get("metrics"), ScoreProvider.CNA)
    for adp in doc.get("containers", {}).get("adp", []) or []:
        if adp.get("providerMetadata", {}).get("shortName") == "CISA-ADP":
            metrics += extract_metrics(adp.get("metrics"), ScoreProvider.CISA_ADP)

    products: dict[tuple[str, str], list[str]] = {}
    for item in cna.get("affected", []) or []:
        vendor, product = clean_name(item.get("vendor")), clean_name(item.get("product"))
        if vendor in IGNORED_NAMES or product in IGNORED_NAMES:
            continue
        versions = [
            str(v.get("version"))
            for v in item.get("versions", []) or []
            if v.get("status") == "affected" and v.get("version")
        ]
        products.setdefault((vendor, product), []).extend(versions)

    return {
        "cve_id": str(meta.get("cveId", "")).strip(),
        "description": description.strip(),
        "published_at": parse_datetime(meta.get("datePublished")),
        "source_updated_at": parse_datetime(meta.get("dateUpdated")),
        "metrics": metrics,
        "products": products,
    }


class CveListV5Connector(BaseConnector):
    name = "cve"
    label = "CVE List V5"
    url = "https://github.com/CVEProject/cvelistV5"

    def snapshot_suffix(self) -> str:
        return ".zip"

    # ---- extract -----------------------------------------------------------------
    def download(self, destination: Path) -> None:
        release = requests.get(RELEASES_API, timeout=HTTP_TIMEOUT)
        release.raise_for_status()
        assets = release.json().get("assets", [])
        bulk = next((a for a in assets if "all_CVEs_at_midnight" in a.get("name", "")), None)
        if bulk is None:
            raise RuntimeError("No 'all_CVEs_at_midnight' file in the latest cvelistV5 release")
        self.counters["release_file"] = bulk["name"]
        self.http_download(bulk["browser_download_url"], destination)

    # ---- transform -----------------------------------------------------------------
    def transform(self, snapshot: Path) -> Iterator[dict]:
        watermark = None
        if not self.full:
            watermark = Vulnerability.objects.aggregate(m=Max("source_updated_at"))["m"]
        for doc in self._iter_documents(snapshot):
            record = parse_record(doc)
            if record is None:
                self.counters["skipped_not_published"] += 1
                continue
            updated = record["source_updated_at"]
            if watermark and updated and updated <= watermark:
                self.counters["skipped_unchanged"] += 1
                continue
            yield record

    def _iter_documents(self, snapshot: Path) -> Iterator[dict]:
        with zipfile.ZipFile(snapshot) as outer:
            names = outer.namelist()
            inner_zips = [n for n in names if n.endswith(".zip")]
            if inner_zips and not any(n.endswith(".json") for n in names):
                # Bulk release file: a zip that contains cves.zip -> unpacked next to the snapshot
                inner_path = snapshot.with_name(snapshot.stem + "_inner.zip")
                with outer.open(inner_zips[0]) as raw, open(inner_path, "wb") as out:
                    shutil.copyfileobj(raw, out, length=16 * 1024 * 1024)
                try:
                    with zipfile.ZipFile(inner_path) as inner:
                        yield from self._iter_json(inner)
                finally:
                    inner_path.unlink(missing_ok=True)
            else:
                yield from self._iter_json(outer)

    def _iter_json(self, archive: zipfile.ZipFile) -> Iterator[dict]:
        for name in archive.namelist():
            if not name.endswith(".json") or not Path(name).name.startswith("CVE-"):
                continue  # skips delta.json, deltaLog.json, folders
            try:
                yield json.loads(archive.read(name))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.counters["unreadable_files"] += 1

    # ---- validate ------------------------------------------------------------------
    def validate(self, records: list[dict]) -> tuple[list[dict], list[Reject]]:
        rejects, seen = [], {}
        for record in records:
            cve_id = record["cve_id"]
            if not CVE_ID.match(cve_id):
                rejects.append(Reject(cve_id or "?", "invalid CVE identifier"))
            elif not record["description"]:
                rejects.append(Reject(cve_id, "missing English description"))
            elif any(not 0 <= m["base_score"] <= 10 for m in record["metrics"]):
                rejects.append(Reject(cve_id, "CVSS base score outside 0-10"))
            else:
                seen[cve_id] = record  # duplicate id in the file: the last one wins
        self.counters["duplicates_in_file"] += len(records) - len(rejects) - len(seen)
        return list(seen.values()), rejects

    # ---- load (idempotent) -------------------------------------------------------
    @transaction.atomic
    def load(self, records: list[dict]) -> int:
        Vulnerability.objects.bulk_create(
            [
                Vulnerability(
                    cve_id=r["cve_id"],
                    description=r["description"],
                    published_at=r["published_at"],
                    source_updated_at=r["source_updated_at"],
                )
                for r in records
            ],
            update_conflicts=True,
            unique_fields=["cve_id"],
            update_fields=["description", "published_at", "source_updated_at"],
        )
        ids = dict(Vulnerability.objects.filter(cve_id__in=[r["cve_id"] for r in records]).values_list("cve_id", "id"))

        # Scores from this source are replaced, NVD scores are left untouched
        CVSSMetric.objects.filter(
            vulnerability_id__in=ids.values(), provider__in=[ScoreProvider.CNA, ScoreProvider.CISA_ADP]
        ).delete()
        metrics = {}
        for r in records:
            for m in r["metrics"]:
                metrics[(ids[r["cve_id"]], m["provider"], m["version"])] = m  # one per provider + version
        CVSSMetric.objects.bulk_create(
            [CVSSMetric(vulnerability_id=v, **m) for (v, _, _), m in metrics.items()]
        )

        pairs = {key for r in records for key in r["products"]}
        Product.objects.bulk_create([Product(vendor=v, name=n) for v, n in pairs], ignore_conflicts=True)
        product_ids = {}
        for vendor, name, pk in Product.objects.filter(vendor__in={v for v, _ in pairs}).values_list(
            "vendor", "name", "id"
        ):
            product_ids[(vendor, name)] = pk
        AffectedProduct.objects.filter(vulnerability_id__in=ids.values()).delete()
        AffectedProduct.objects.bulk_create(
            [
                AffectedProduct(
                    vulnerability_id=ids[r["cve_id"]],
                    product_id=product_ids[key],
                    versions=", ".join(dict.fromkeys(versions))[:2000],
                )
                for r in records
                for key, versions in r["products"].items()
            ]
        )
        self.counters["cvss_metrics_loaded"] += len(metrics)
        self.counters["affected_products_loaded"] += sum(len(r["products"]) for r in records)
        return len(records)
