"""CTID connector: the ATT&CK techniques of the exploited CVEs (CISA KEV), mapped by the Center for
Threat-Informed Defense (#61, US17, FR-13).

Source: the KEV mappings of Mappings Explorer (JSON), free and without authentication. Each mapping links a CVE
(capability_id) to an ATT&CK technique (attack_object_id) with a type: exploitation_technique, primary_impact,
secondary_impact or uncategorized. The coverage is partial: only part of the KEV catalog is mapped, and the
quality report gives the share of KEV CVEs with at least one technique.

The mappings are made for one ATT&CK version (16.1 for the KEV version of 07/28/2025): a technique renamed or
removed since then is rejected. Runs after the cve, kev and attack connectors. The links are rebuilt at each run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator

from django.db import transaction

from cti.models import KEVEntry, Technique, Vulnerability, VulnerabilityTechnique

from .base import BaseConnector, Reject

CTID_URL = (
    "https://ctid.mitre.org/mappings/data/kev/attack-16.1/kev-07.28.2025/enterprise/"
    "kev-07.28.2025_attack-16.1-enterprise_json.json"
)
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAPPING_TYPES = set(VulnerabilityTechnique.MappingType.values)
SOURCE = "ctid_kev"


class CtidConnector(BaseConnector):
    name = "ctid"
    label = "CTID mappings of the KEV CVEs to ATT&CK"
    url = CTID_URL

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.seen: set[tuple[str, str, str]] = set()  # (CVE, technique, type) accepted in this run
        self.techniques: dict[str, int] | None = None  # technique_id -> primary key, read once
        self.links_cleared = False
        self.mapped_cves: set[int] = set()
        self.mapped_kev: set[int] = set()

    def download(self, destination: Path) -> None:
        self.http_download(CTID_URL, destination)

    def transform(self, snapshot: Path) -> Iterator[dict]:
        with open(snapshot, encoding="utf-8") as handle:
            data = json.load(handle)
        metadata = data.get("metadata") or {}
        self.counters["attack_version"] = str(metadata.get("attack_version") or "")
        self.counters["kev_version"] = str(metadata.get("mapping_framework_version") or "")
        self.counters["last_update"] = str(metadata.get("last_update") or "")
        for item in data.get("mapping_objects") or []:
            yield {
                "cve_id": str(item.get("capability_id") or "").strip().upper(),
                "technique_id": str(item.get("attack_object_id") or "").strip(),
                "mapping_type": str(item.get("mapping_type") or "").strip(),
            }

    def validate(self, records: list[dict]) -> tuple[list[dict], list[Reject]]:
        if self.techniques is None:
            self.techniques = dict(Technique.objects.values_list("technique_id", "pk"))
            if not self.techniques:
                raise RuntimeError("No ATT&CK technique in the database: run the attack source first")
        if not self.links_cleared:  # the file is the full mapping: the links are rebuilt at each run
            VulnerabilityTechnique.objects.filter(source=SOURCE).delete()
            self.links_cleared = True
        cves = dict(Vulnerability.objects.filter(cve_id__in={r["cve_id"] for r in records})
                    .values_list("cve_id", "pk"))
        valid, rejects = [], []
        for record in records:
            key = f"{record['cve_id'] or '?'} {record['technique_id'] or '?'}"
            mapping = (record["cve_id"], record["technique_id"], record["mapping_type"])
            if not CVE_ID.match(record["cve_id"]):
                rejects.append(Reject(key, "invalid CVE id"))
            elif record["cve_id"] not in cves:
                rejects.append(Reject(key, "CVE not in the CVE list"))
            elif record["technique_id"] not in self.techniques:
                rejects.append(Reject(key, "technique not in the loaded ATT&CK version"))
            elif record["mapping_type"] not in MAPPING_TYPES:
                rejects.append(Reject(key, "unknown mapping type"))
            elif mapping in self.seen:
                rejects.append(Reject(key, "duplicate mapping in the file"))
            else:
                self.seen.add(mapping)
                record["vulnerability_pk"] = cves[record["cve_id"]]
                record["technique_pk"] = self.techniques[record["technique_id"]]
                valid.append(record)
        return valid, rejects

    @transaction.atomic
    def load(self, records: list[dict]) -> int:
        VulnerabilityTechnique.objects.bulk_create(
            [VulnerabilityTechnique(vulnerability_id=r["vulnerability_pk"], technique_id=r["technique_pk"],
                                    mapping_type=r["mapping_type"], source=SOURCE) for r in records],
            ignore_conflicts=True,
        )
        cves = {r["vulnerability_pk"] for r in records}
        self.mapped_cves |= cves
        kev = KEVEntry.objects.filter(vulnerability_id__in=cves).values_list("vulnerability_id", flat=True)
        self.mapped_kev |= set(kev)
        kev_total = KEVEntry.objects.count()
        # Coverage (#61, criterion 2): CVEs with at least one technique
        self.counters["cves_with_technique"] = len(self.mapped_cves)
        self.counters["kev_cves_with_technique"] = len(self.mapped_kev)
        self.counters["kev_coverage_percent"] = round(100 * len(self.mapped_kev) / kev_total, 1) if kev_total else 0.0
        return len(records)
