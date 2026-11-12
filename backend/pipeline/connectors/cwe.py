"""MITRE CWE connector (Common Weakness Enumeration catalog).

Source: the official CWE list in XML, a zip file, free and without authentication.
Per entry we keep: CWE identifier, name, kind (weakness or category), abstraction and status.
Views are not loaded. Deprecated entries are kept: old CVE records still name them.

The links between CVEs and CWEs come from the CVE records themselves (cve connector):
a CWE named by a CVE before this catalog is loaded is created with an empty name and
completed here at the next run.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Iterator
from xml.etree import ElementTree

from django.db import transaction

from cti.models import Weakness

from .base import BaseConnector, Reject

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_ID = re.compile(r"^CWE-\d+$")
KINDS = {"Weakness": Weakness.Kind.WEAKNESS, "Category": Weakness.Kind.CATEGORY}


def local_name(tag: str) -> str:
    """'{http://cwe.mitre.org/cwe-7}Weakness' -> 'Weakness' (works for every schema version)."""
    return tag.rsplit("}", 1)[-1]


class CweConnector(BaseConnector):
    name = "cwe"
    label = "MITRE CWE catalog"
    url = CWE_URL

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.seen: set[str] = set()  # CWE ids already accepted in this run, across every batch

    def snapshot_suffix(self) -> str:
        return ".xml.zip"

    def download(self, destination: Path) -> None:
        self.http_download(CWE_URL, destination)

    def transform(self, snapshot: Path) -> Iterator[dict]:
        with zipfile.ZipFile(snapshot) as archive:
            xml_name = next((n for n in archive.namelist() if n.endswith(".xml")), None)
            if xml_name is None:
                raise RuntimeError("No XML file in the CWE archive")
            with archive.open(xml_name) as xml:
                # iterparse: the catalog is read element by element, never fully in memory
                for event, element in ElementTree.iterparse(xml, events=("start", "end")):
                    tag = local_name(element.tag)
                    if event == "start" and tag == "Weakness_Catalog":
                        self.counters["catalog_version"] = element.get("Version", "")
                        self.counters["catalog_date"] = element.get("Date", "")
                    elif event == "end" and tag in KINDS:
                        identifier = (element.get("ID") or "").strip()
                        yield {
                            "cwe_id": f"CWE-{identifier}",
                            "name": " ".join((element.get("Name") or "").split())[:300],
                            "kind": KINDS[tag],
                            "abstraction": (element.get("Abstraction") or "")[:20],
                            "status": (element.get("Status") or "")[:20],
                        }
                        element.clear()
                    elif event == "end" and tag == "View":
                        element.clear()

    def validate(self, records: list[dict]) -> tuple[list[dict], list[Reject]]:
        valid, rejects = [], []
        for record in records:
            cwe_id = record["cwe_id"]
            if not CWE_ID.match(cwe_id):
                rejects.append(Reject(cwe_id, "invalid CWE identifier"))
            elif not record["name"]:
                rejects.append(Reject(cwe_id, "missing name"))
            elif cwe_id in self.seen:
                rejects.append(Reject(cwe_id, "duplicate entry in the catalog"))
            else:
                self.seen.add(cwe_id)
                valid.append(record)
        return valid, rejects

    @transaction.atomic
    def load(self, records: list[dict]) -> int:
        """Insert new entries, update the others (also the ones created empty by the cve connector)."""
        Weakness.objects.bulk_create(
            [Weakness(**record) for record in records],
            update_conflicts=True,
            unique_fields=["cwe_id"],
            update_fields=["name", "kind", "abstraction", "status"],
        )
        return len(records)
