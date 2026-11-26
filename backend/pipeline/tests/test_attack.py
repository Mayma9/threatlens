"""Tests of the MITRE ATT&CK connector (#61, US17): techniques, groups, software and the links of the groups."""

import json
import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from cti.models import Software, Technique, ThreatGroup
from pipeline.models import RunStatus
from pipeline.services import run_pipeline


def mitre_ref(external_id):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


def technique(key, external_id, name, tactics=("execution",), sub=False, **extra):
    return {"type": "attack-pattern", "id": f"attack-pattern--{key}", "name": name,
            "external_references": mitre_ref(external_id), "x_mitre_is_subtechnique": sub,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic} for tactic in tactics],
            **extra}


def group(key, external_id, name, aliases=(), **extra):
    return {"type": "intrusion-set", "id": f"intrusion-set--{key}", "name": name, "aliases": [name, *aliases],
            "external_references": mitre_ref(external_id), **extra}


def software(key, external_id, name, stix_type="malware"):
    return {"type": stix_type, "id": f"{stix_type}--{key}", "name": name, "x_mitre_aliases": [name],
            "external_references": mitre_ref(external_id)}


def uses(source, target, **extra):
    return {"type": "relationship", "id": f"relationship--{source['id']}-{target['id']}", "relationship_type": "uses",
            "source_ref": source["id"], "target_ref": target["id"], **extra}


def write_bundle(path, objects, version="19.2"):
    collection = {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": version}
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--1", "objects": [collection, *objects]}),
                    encoding="utf-8")
    return path


CMD = technique("1", "T1059", "Command and Scripting Interpreter")
POWERSHELL = technique("2", "T1059.001", "PowerShell", sub=True)
PHISHING = technique("3", "T1566", "Phishing", tactics=("initial-access",))
APT28 = group("1", "G0007", "APT28", aliases=("Fancy Bear", "Sofacy"))
APT29 = group("2", "G0016", "APT29")
COBALT = software("1", "S0154", "Cobalt Strike")
MIMIKATZ = software("2", "S0002", "Mimikatz", stix_type="tool")


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class AttackConnectorTests(TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())

    def run_attack(self, objects, name="attack.json"):
        path = write_bundle(self.folder / name, objects)
        return run_pipeline(sources=["attack"], local_file=str(path)).tasks.get()

    def test_techniques_groups_software_and_group_links_are_loaded(self):
        task = self.run_attack([
            CMD, POWERSHELL, PHISHING, APT28, APT29, COBALT, MIMIKATZ,
            uses(APT28, CMD), uses(APT28, PHISHING), uses(APT28, COBALT), uses(APT29, POWERSHELL),
            uses(COBALT, CMD),  # software -> technique: not a link of a group, not kept
        ])
        self.assertEqual(task.status, RunStatus.SUCCESS)
        self.assertEqual((task.extracted, task.loaded, task.rejected), (11, 11, 0))
        self.assertTrue(Technique.objects.get(technique_id="T1059.001").is_subtechnique)
        self.assertEqual(Technique.objects.get(technique_id="T1566").tactics, "initial-access")
        apt28 = ThreatGroup.objects.get(group_id="G0007")
        self.assertEqual(apt28.aliases, ["Fancy Bear", "Sofacy"])
        self.assertIsNone(apt28.cluster_id)  # filled by M3
        self.assertEqual(list(apt28.techniques.values_list("technique_id", flat=True)), ["T1059", "T1566"])
        self.assertEqual(list(apt28.software.values_list("software_id", flat=True)), ["S0154"])
        self.assertEqual(Software.objects.get(software_id="S0002").kind, Software.Kind.TOOL)
        report = task.quality_report
        self.assertEqual((report["attack_version"], report["group_techniques"], report["group_software"]),
                         ("19.2", 3, 1))

    def test_revoked_and_deprecated_objects_are_skipped(self):
        old = technique("9", "T1086", "PowerShell (old)", revoked=True)
        gone = group("9", "G0099", "Old group", x_mitre_deprecated=True)
        self.run_attack([CMD, APT28, uses(APT28, CMD)])  # a first run with one link
        task = self.run_attack([CMD, old, gone, APT28, uses(APT28, old), uses(gone, CMD)], name="attack2.json")
        self.assertFalse(Technique.objects.filter(technique_id="T1086").exists())
        self.assertFalse(ThreatGroup.objects.filter(group_id="G0099").exists())
        self.assertEqual(ThreatGroup.objects.get(group_id="G0007").techniques.count(), 0)  # the old link is gone
        self.assertEqual(task.quality_report["skipped_revoked_or_deprecated"], 2)
        self.assertEqual(task.quality_report["relationships_to_skipped_objects"], 2)

    def test_invalid_objects_are_rejected_with_a_reason(self):
        task = self.run_attack([CMD, technique("4", "X123", "Bad id"), group("3", "G0010", ""),
                                technique("5", "T1059", "Duplicate")])
        self.assertEqual((task.loaded, task.rejected), (1, 3))
        self.assertEqual(task.quality_report["rejected_by_reason"], {
            "invalid ATT&CK technique id": 1, "missing name": 1, "duplicate object in the bundle": 1})

    def test_running_again_updates_the_objects_rebuilds_the_links_and_keeps_the_cluster(self):
        self.run_attack([CMD, PHISHING, APT28, uses(APT28, CMD)])
        ThreatGroup.objects.filter(group_id="G0007").update(cluster_id=3)  # as M3 would
        renamed = {**CMD, "name": "Command-Line Interpreter"}
        self.run_attack([renamed, PHISHING, APT28, uses(APT28, PHISHING)], name="attack2.json")
        self.assertEqual(Technique.objects.get(technique_id="T1059").name, "Command-Line Interpreter")
        apt28 = ThreatGroup.objects.get(group_id="G0007")
        self.assertEqual(list(apt28.techniques.values_list("technique_id", flat=True)), ["T1566"])
        self.assertEqual(apt28.cluster_id, 3)
        self.assertEqual(ThreatGroup.objects.count(), 1)
