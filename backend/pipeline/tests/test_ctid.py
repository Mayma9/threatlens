"""Tests of the CTID connector (#61): ATT&CK techniques of the KEV CVEs, and the warehouse bridge."""

import json
import tempfile
from pathlib import Path

from django.db import connection
from django.test import TestCase, override_settings

from cti.models import Technique, Vulnerability, VulnerabilityTechnique
from pipeline.models import RunStatus
from pipeline.services import run_pipeline


def mapping(cve_id, technique_id, mapping_type="exploitation_technique"):
    return {"capability_id": cve_id, "capability_description": "Example vulnerability", "mapping_type": mapping_type,
            "attack_object_id": technique_id, "attack_object_name": "Example technique",
            "capability_group": "command_injection", "comments": "", "references": []}


def write_mappings(path, mappings):
    metadata = {"technology_domain": "enterprise", "attack_version": "16.1", "mapping_framework": "kev",
                "mapping_framework_version": "07/28/2025", "creation_date": "07/28/2025", "last_update": "08/28/2025"}
    path.write_text(json.dumps({"metadata": metadata, "mapping_objects": mappings}), encoding="utf-8")
    return path


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class CtidConnectorTests(TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        for cve_id in ("CVE-2024-0001", "CVE-2024-0002"):
            Vulnerability.objects.create(cve_id=cve_id, description="known")
        Technique.objects.create(technique_id="T1190", stix_id="attack-pattern--1",
                                 name="Exploit Public-Facing Application", tactics="initial-access")
        Technique.objects.create(technique_id="T1059", stix_id="attack-pattern--2",
                                 name="Command and Scripting Interpreter", tactics="execution")

    def run_ctid(self, mappings, name="kev.json"):
        path = write_mappings(self.folder / name, mappings)
        return run_pipeline(sources=["ctid"], local_file=str(path)).tasks.get()

    def links(self):
        return sorted(VulnerabilityTechnique.objects.values_list(
            "vulnerability__cve_id", "technique__technique_id", "mapping_type"))

    def test_mappings_link_cves_to_techniques(self):
        task = self.run_ctid([mapping("CVE-2024-0001", "T1190"), mapping("CVE-2024-0001", "T1059", "primary_impact")])
        self.assertEqual(task.status, RunStatus.SUCCESS)
        self.assertEqual(self.links(), [("CVE-2024-0001", "T1059", "primary_impact"),
                                        ("CVE-2024-0001", "T1190", "exploitation_technique")])
        report = task.quality_report
        self.assertEqual((report["attack_version"], report["kev_version"], report["last_update"]),
                         ("16.1", "07/28/2025", "08/28/2025"))
        self.assertEqual(report["cves_with_technique"], 1)

    def test_invalid_mappings_are_rejected_with_a_reason(self):
        task = self.run_ctid([
            mapping("CVE-2024-0001", "T1190"),
            mapping("not-a-cve", "T1190"),
            mapping("CVE-2024-9999", "T1190"),
            mapping("CVE-2024-0002", "T1086"),
            mapping("CVE-2024-0002", "T1059", "other"),
            mapping("CVE-2024-0001", "T1190"),
        ])
        self.assertEqual((task.loaded, task.rejected), (1, 5))
        self.assertEqual(task.quality_report["rejected_by_reason"], {
            "invalid CVE id": 1, "CVE not in the CVE list": 1, "technique not in the loaded ATT&CK version": 1,
            "unknown mapping type": 1, "duplicate mapping in the file": 1})

    def test_running_again_replaces_the_links(self):
        self.run_ctid([mapping("CVE-2024-0001", "T1190")])
        self.run_ctid([mapping("CVE-2024-0002", "T1059")], name="kev2.json")
        self.assertEqual(self.links(), [("CVE-2024-0002", "T1059", "exploitation_technique")])

    def test_without_attack_techniques_the_source_fails_with_a_clear_message(self):
        Technique.objects.all().delete()
        task = self.run_ctid([mapping("CVE-2024-0001", "T1190")])
        self.assertEqual(task.status, RunStatus.FAILED)
        self.assertIn("run the attack source first", task.error_message)

    def test_the_warehouse_bridge_counts_each_cve_and_technique_once(self):
        self.run_ctid([mapping("CVE-2024-0001", "T1190"), mapping("CVE-2024-0001", "T1190", "primary_impact"),
                       mapping("CVE-2024-0002", "T1059")])
        with connection.cursor() as cursor:
            cursor.execute("SELECT technique_id FROM dw.dim_technique ORDER BY technique_id")
            self.assertEqual([row[0] for row in cursor.fetchall()], ["T1059", "T1190"])
            cursor.execute("SELECT count(*) FROM dw.bridge_cve_technique")
            self.assertEqual(cursor.fetchone()[0], 2)
