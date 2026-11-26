"""MITRE ATT&CK Enterprise connector: techniques, threat groups and software (#61, US17, FR-13).

Source: the official STIX 2.1 bundle of ATT&CK Enterprise (mitre-attack/attack-stix-data on GitHub), free and
without authentication; enterprise-attack.json is always the latest release.
Per object we keep the ATT&CK id (T1059, G0007, S0154), the name, the tactics of a technique and the aliases
of a group or a software. Revoked and deprecated objects are skipped.

The "uses" relationships of the groups give the binary group x technique matrix of the clustering model M3 and
the software (malware and tools) of each group. They are rebuilt at each run from the bundle.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator

from django.db import transaction

from cti.models import Software, Technique, ThreatGroup

from .base import BaseConnector, Reject

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)
ID_PATTERNS = {
    "technique": re.compile(r"^T\d{4}(\.\d{3})?$"),
    "group": re.compile(r"^G\d{4}$"),
    "software": re.compile(r"^S\d{4}$"),
}
OBJECT_KINDS = {"attack-pattern": "technique", "intrusion-set": "group", "malware": "software", "tool": "software"}
LINK_TARGETS = ("attack-pattern--", "malware--", "tool--")


def attack_id(obj: dict) -> str:
    """The ATT&CK id of a STIX object (T1059, G0007, S0154), from its mitre-attack external reference."""
    for reference in obj.get("external_references") or []:
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return str(reference["external_id"]).strip()
    return ""


def is_withdrawn(obj: dict) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


class AttackConnector(BaseConnector):
    name = "attack"
    label = "MITRE ATT&CK Enterprise"
    url = ATTACK_URL

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.seen: set[str] = set()  # ATT&CK ids accepted in this run, across every batch
        self.accepted: set[str] = set()  # STIX ids of the objects accepted in this run
        self.links_cleared = False
        self.keys: dict[str, tuple[str, int]] | None = None  # STIX id -> (kind, primary key), read once

    def download(self, destination: Path) -> None:
        self.http_download(ATTACK_URL, destination)

    def transform(self, snapshot: Path) -> Iterator[dict]:
        """Every technique, group and software first, then the "uses" relationships of the groups."""
        with open(snapshot, encoding="utf-8") as handle:
            bundle = json.load(handle)
        relationships = []
        for obj in bundle.get("objects") or []:
            stix_type = obj.get("type")
            if stix_type == "x-mitre-collection":
                self.counters["attack_version"] = str(obj.get("x_mitre_version") or "")
            elif stix_type == "relationship":
                if (obj.get("relationship_type") == "uses" and not is_withdrawn(obj)
                        and str(obj.get("source_ref", "")).startswith("intrusion-set--")
                        and str(obj.get("target_ref", "")).startswith(LINK_TARGETS)):
                    relationships.append(obj)
            elif stix_type in OBJECT_KINDS:
                if is_withdrawn(obj):
                    self.counters["skipped_revoked_or_deprecated"] += 1
                    continue
                yield self.record(obj, OBJECT_KINDS[stix_type])
        for relationship in relationships:
            yield {"kind": "uses", "source": relationship["source_ref"], "target": relationship["target_ref"]}

    @staticmethod
    def record(obj: dict, kind: str) -> dict:
        name = " ".join((obj.get("name") or "").split())
        record = {"kind": kind, "stix_id": str(obj.get("id") or ""), "attack_id": attack_id(obj), "name": name[:300]}
        if kind == "technique":
            phases = [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases") or []
                      if phase.get("kill_chain_name") == "mitre-attack"]
            record["tactics"] = ", ".join(phases)[:300]
            record["is_subtechnique"] = bool(obj.get("x_mitre_is_subtechnique"))
        elif kind == "group":
            record["aliases"] = [alias for alias in obj.get("aliases") or [] if alias != obj.get("name")]
        else:
            record["software_kind"] = Software.Kind.MALWARE if obj.get("type") == "malware" else Software.Kind.TOOL
            record["aliases"] = [alias for alias in obj.get("x_mitre_aliases") or [] if alias != obj.get("name")]
        return record

    def validate(self, records: list[dict]) -> tuple[list[dict], list[Reject]]:
        if not self.links_cleared:  # the group links are rebuilt from the bundle at each run, even if none is valid
            ThreatGroup.techniques.through.objects.all().delete()
            ThreatGroup.software.through.objects.all().delete()
            self.links_cleared = True
        valid, rejects = [], []
        for record in records:
            if record["kind"] == "uses":
                # A link to a skipped (revoked, deprecated or rejected) object is not a quality problem of the link
                if record["source"] in self.accepted and record["target"] in self.accepted:
                    valid.append(record)
                else:
                    self.counters["relationships_to_skipped_objects"] += 1
                continue
            key = record["attack_id"] or record["stix_id"] or "?"
            if not ID_PATTERNS[record["kind"]].match(record["attack_id"]):
                rejects.append(Reject(key, f"invalid ATT&CK {record['kind']} id"))
            elif not record["name"]:
                rejects.append(Reject(key, "missing name"))
            elif not record["stix_id"]:
                rejects.append(Reject(key, "missing STIX id"))
            elif record["attack_id"] in self.seen:
                rejects.append(Reject(key, "duplicate object in the bundle"))
            else:
                self.seen.add(record["attack_id"])
                self.accepted.add(record["stix_id"])
                valid.append(record)
        return valid, rejects

    @transaction.atomic
    def load(self, records: list[dict]) -> int:
        """Insert or update the objects (cluster_id of the groups is kept), then rebuild the group links."""
        by_kind = {"technique": [], "group": [], "software": [], "uses": []}
        for record in records:
            by_kind[record["kind"]].append(record)
        if by_kind["technique"]:
            Technique.objects.bulk_create(
                [Technique(technique_id=r["attack_id"], stix_id=r["stix_id"], name=r["name"], tactics=r["tactics"],
                           is_subtechnique=r["is_subtechnique"]) for r in by_kind["technique"]],
                update_conflicts=True, unique_fields=["technique_id"],
                update_fields=["stix_id", "name", "tactics", "is_subtechnique"],
            )
        if by_kind["software"]:
            Software.objects.bulk_create(
                [Software(software_id=r["attack_id"], stix_id=r["stix_id"], name=r["name"], kind=r["software_kind"],
                          aliases=r["aliases"]) for r in by_kind["software"]],
                update_conflicts=True, unique_fields=["software_id"],
                update_fields=["stix_id", "name", "kind", "aliases"],
            )
        if by_kind["group"]:
            ThreatGroup.objects.bulk_create(
                [ThreatGroup(group_id=r["attack_id"], stix_id=r["stix_id"], name=r["name"], aliases=r["aliases"])
                 for r in by_kind["group"]],
                update_conflicts=True, unique_fields=["group_id"], update_fields=["stix_id", "name", "aliases"],
            )
        self.counters["techniques_loaded"] += len(by_kind["technique"])
        self.counters["groups_loaded"] += len(by_kind["group"])
        self.counters["software_loaded"] += len(by_kind["software"])
        if by_kind["uses"]:
            self.load_links(by_kind["uses"])
        return len(records)

    def load_links(self, links: list[dict]) -> None:
        group_techniques = ThreatGroup.techniques.through
        group_software = ThreatGroup.software.through
        if self.keys is None:
            self.keys = {}
            for model, kind in ((Technique, "technique"), (Software, "software"), (ThreatGroup, "group")):
                for pk, stix_id in model.objects.filter(stix_id__in=self.accepted).values_list("pk", "stix_id"):
                    self.keys[stix_id] = (kind, pk)
        techniques, software = set(), set()
        for link in links:
            source, target = self.keys.get(link["source"]), self.keys.get(link["target"])
            if not source or not target or source[0] != "group":
                continue
            if target[0] == "technique":
                techniques.add((source[1], target[1]))
            elif target[0] == "software":
                software.add((source[1], target[1]))
        group_techniques.objects.bulk_create(
            [group_techniques(threatgroup_id=g, technique_id=t) for g, t in techniques], ignore_conflicts=True)
        group_software.objects.bulk_create(
            [group_software(threatgroup_id=g, software_id=s) for g, s in software], ignore_conflicts=True)
        self.counters["group_techniques"] += len(techniques)
        self.counters["group_software"] += len(software)
