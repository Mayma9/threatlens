"""Tests of the CWE connector (US05) and of the CVE-to-CWE links read from the CVE records."""

import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from cti.models import ScoreProvider, Vulnerability, VulnerabilityWeakness, Weakness
from pipeline.models import RunStatus
from pipeline.services import run_pipeline

from .factories import cve_doc, write_bulk_zip, write_cwe_zip

XSS = ("79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Base", "Stable")
SQLI = ("89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Base", "Stable")
OLD = ("16", "Configuration", "Obsolete")


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class CweCatalogTests(TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())

    def run_cwe(self, weaknesses=(), categories=(), name="cwe.xml.zip"):
        path = write_cwe_zip(self.folder / name, weaknesses, categories)
        return run_pipeline(sources=["cwe"], local_file=str(path)).tasks.get()

    def test_weaknesses_and_categories_are_loaded_views_are_not(self):
        task = self.run_cwe([XSS, SQLI], [OLD])
        self.assertEqual(task.status, RunStatus.SUCCESS)
        self.assertEqual((task.extracted, task.loaded, task.rejected), (3, 3, 0))
        xss = Weakness.objects.get(cwe_id="CWE-79")
        self.assertEqual((xss.kind, xss.abstraction, xss.status), ("WEAKNESS", "Base", "Stable"))
        self.assertTrue(xss.name.startswith("Improper Neutralization of Input"))
        self.assertEqual(Weakness.objects.get(cwe_id="CWE-16").kind, "CATEGORY")
        self.assertFalse(Weakness.objects.filter(cwe_id="CWE-1000").exists())  # the view
        self.assertFalse(Weakness.objects.filter(cwe_id="CWE-20").exists())  # only a relation inside a weakness
        self.assertEqual((task.quality_report["catalog_version"], task.quality_report["catalog_date"]),
                         ("4.16", "2024-11-19"))

    def test_invalid_entries_are_rejected_with_a_reason(self):
        task = self.run_cwe([XSS, ("ABC", "Bad id", "Base", "Draft"), ("90", "", "Base", "Draft"), XSS])
        self.assertEqual((task.loaded, task.rejected), (1, 3))
        self.assertEqual(task.quality_report["rejected_by_reason"], {
            "invalid CWE identifier": 1, "missing name": 1, "duplicate entry in the catalog": 1})

    def test_running_again_updates_in_place(self):
        self.run_cwe([XSS])
        self.run_cwe([("79", "Cross-site Scripting (renamed)", "Base", "Stable")], name="cwe2.xml.zip")
        self.assertEqual(Weakness.objects.count(), 1)
        self.assertEqual(Weakness.objects.get().name, "Cross-site Scripting (renamed)")


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class CveWeaknessLinkTests(TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())

    def load_cves(self, docs, name="bulk.zip", full=True):
        path = write_bulk_zip(self.folder / name, docs)
        return run_pipeline(sources=["cve"], local_file=str(path), full=full)

    def links(self, cve_id):
        return sorted(VulnerabilityWeakness.objects.filter(vulnerability__cve_id=cve_id)
                      .values_list("weakness__cwe_id", "provider"))

    def test_cna_and_cisa_adp_weaknesses_are_linked(self):
        self.load_cves([cve_doc("CVE-2024-0001", cna_cwes=["CWE-79"], adp_cwes=["CWE-79", "CWE-89"])])
        self.assertEqual(self.links("CVE-2024-0001"), [
            ("CWE-79", ScoreProvider.CISA_ADP), ("CWE-79", ScoreProvider.CNA), ("CWE-89", ScoreProvider.CISA_ADP)])

    def test_free_text_and_invalid_identifiers_are_ignored(self):
        self.load_cves([cve_doc("CVE-2024-0001", cna_cwes=["CWE-ABC", "NVD-CWE-Other"])])
        self.assertEqual(self.links("CVE-2024-0001"), [])

    def test_cwe_named_before_the_catalog_is_completed_by_the_cwe_connector(self):
        self.load_cves([cve_doc("CVE-2024-0001", cna_cwes=["CWE-79"])])
        self.assertEqual(Weakness.objects.get(cwe_id="CWE-79").name, "")  # created empty
        run_pipeline(sources=["cwe"], local_file=str(write_cwe_zip(self.folder / "cwe.xml.zip", [XSS])))
        weakness = Weakness.objects.get(cwe_id="CWE-79")
        self.assertTrue(weakness.name.startswith("Improper Neutralization"))
        self.assertEqual(self.links("CVE-2024-0001"), [("CWE-79", ScoreProvider.CNA)])  # link kept

    def test_updated_record_replaces_its_links_but_keeps_nvd_links(self):
        self.load_cves([cve_doc("CVE-2024-0001", cna_cwes=["CWE-79"])])
        vulnerability = Vulnerability.objects.get(cve_id="CVE-2024-0001")
        nvd_weakness = Weakness.objects.create(cwe_id="CWE-20", name="Improper Input Validation")
        VulnerabilityWeakness.objects.create(vulnerability=vulnerability, weakness=nvd_weakness,
                                             provider=ScoreProvider.NVD)
        self.load_cves([cve_doc("CVE-2024-0001", cna_cwes=["CWE-89"], updated="2024-05-01T00:00:00.000Z")],
                       name="bulk2.zip", full=False)
        self.assertEqual(self.links("CVE-2024-0001"), [("CWE-20", ScoreProvider.NVD), ("CWE-89", ScoreProvider.CNA)])
