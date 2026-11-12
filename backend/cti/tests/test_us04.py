"""Acceptance tests of US04: the analyst opens the enriched CVE record (FR-05, FR-06)."""

from datetime import date

from django.test import TestCase
from django.urls import reverse

from accounts.models import Role
from accounts.tests.test_us01 import make_user
from cti.models import (
    CVSSMetric,
    KEVEntry,
    ScoreProvider,
    Vulnerability,
    VulnerabilityWeakness,
    Weakness,
)
from cti.services import refresh_effective_severity

from .test_us03 import cve


def link(vulnerability, cwe_id, provider, name="", kind=Weakness.Kind.WEAKNESS):
    weakness, _ = Weakness.objects.get_or_create(cwe_id=cwe_id, defaults={"name": name, "kind": kind})
    return VulnerabilityWeakness.objects.create(vulnerability=vulnerability, weakness=weakness, provider=provider)


class RecordTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.pan = cve("CVE-2024-3400", "palo alto networks", "pan-os", "2024-04-12", score=10.0)
        CVSSMetric.objects.create(vulnerability=cls.pan, provider=ScoreProvider.CISA_ADP, version="3.1",
                                  base_score=9.8, severity="CRITICAL", vector="CVSS:3.1/AV:N/adp")
        CVSSMetric.objects.create(vulnerability=cls.pan, provider=ScoreProvider.CNA, version="4.0",
                                  base_score=8.7, severity="HIGH", vector="CVSS:4.0/AV:N/cna")
        cls.pan.epss_score, cls.pan.epss_percentile = 0.94352, 0.99912
        cls.pan.save()
        KEVEntry.objects.create(vulnerability=cls.pan, date_added=date(2024, 4, 12), due_date=date(2024, 4, 19),
                                required_action="Apply mitigations.", ransomware_use=True)
        link(cls.pan, "CWE-77", ScoreProvider.CNA, "Command Injection")
        link(cls.pan, "CWE-20", ScoreProvider.CISA_ADP, "Improper Input Validation")
        link(cls.pan, "CWE-77", ScoreProvider.CISA_ADP)
        cls.bare = cve("CVE-2026-1003", "fortinet", "fortios", "2026-07-01")  # no score, EPSS, KEV or CWE
        refresh_effective_severity()

    def setUp(self):
        self.client.force_login(make_user("analyst", Role.ANALYST))

    def record(self, cve_id):
        response = self.client.get(reverse("cti:detail", args=[cve_id]))
        self.assertEqual(response.status_code, 200)
        return response

    def test_record_shows_scores_epss_kev_and_cwe(self):
        response = self.record("CVE-2024-3400")
        page = response.content.decode()
        self.assertIn("Issue in pan-os", page)
        # every CVSS score with its provider, the effective one first (CNA v4.0 before CNA v3.1, then CISA ADP)
        rows = [(m.provider, m.version) for m in response.context["metrics"]]
        self.assertEqual(rows, [("CNA", "4.0"), ("CNA", "3.1"), ("CISA_ADP", "3.1")])
        self.assertEqual(response.context["effective"].base_score, 8.7)
        self.assertIn("from the CNA CVSS 4.0 score", page)
        self.assertIn("CVSS:3.1/AV:N/adp", page)
        # EPSS as percentages, KEV entry
        self.assertIn("94.35 %", page)
        self.assertIn("Higher than 99.9 % of scored CVEs", page)
        self.assertIn("12 Apr 2024", page)
        self.assertIn("19 Apr 2024", page)
        self.assertIn("Known", page)
        self.assertIn("Exploited", page)
        # CWE: one entry per CWE with every provider, the primary one first
        weaknesses = [(w.cwe_id, providers) for w, providers in response.context["weaknesses"]]
        self.assertEqual(weaknesses, [("CWE-77", ["CNA", "CISA ADP"]), ("CWE-20", ["CISA ADP"])])
        self.assertIn("Command Injection", page)
        self.assertIn("Primary", page)
        self.assertIn("palo alto networks", page)

    def test_record_without_enrichment_says_so(self):
        page = self.record("CVE-2026-1003").content.decode()
        self.assertIn("No score yet", page)
        self.assertIn("No CVSS score published yet", page)
        self.assertIn("not in the latest EPSS file", page)
        self.assertIn("Not in the catalog of actively exploited vulnerabilities", page)
        self.assertIn("No CWE named by the CNA or CISA ADP", page)
        self.assertNotIn("Exploited</span>", page)

    def test_identifier_is_case_insensitive(self):
        self.assertEqual(self.record("cve-2024-3400").context["vulnerability"], self.pan)

    def test_unknown_cve_goes_back_to_the_search_with_an_explanation(self):
        response = self.client.get(reverse("cti:detail", args=["CVE-2099-0001"]), follow=True)
        self.assertRedirects(response, reverse("cti:search") + "?cve=CVE-2099-0001")
        self.assertContains(response, "CVE-2099-0001 is not in ThreatLens")

    def test_search_results_link_to_the_record(self):
        response = self.client.get(reverse("cti:search"), {"vendor": "fortinet"})
        self.assertContains(response, reverse("cti:detail", args=["CVE-2026-1003"]) + "?vendor=fortinet")

    def test_record_runs_a_fixed_number_of_queries(self):
        # session + user, then vulnerability with KEV, CVSS scores, affected products, CWE links
        with self.assertNumQueries(6):
            self.record("CVE-2024-3400")


class PrimaryWeaknessTests(TestCase):
    """Primary CWE rule (shared with the warehouse): NVD > CNA > CISA ADP, weaknesses before categories, first cited."""

    def primary(self, vulnerability):
        vulnerability = Vulnerability.objects.prefetch_related("weakness_links__weakness").get(pk=vulnerability.pk)
        return vulnerability.ordered_weaknesses()[0][0].cwe_id

    def test_provider_order_wins(self):
        vulnerability = cve("CVE-2026-2001")
        link(vulnerability, "CWE-20", ScoreProvider.CISA_ADP)
        link(vulnerability, "CWE-79", ScoreProvider.CNA)
        self.assertEqual(self.primary(vulnerability), "CWE-79")
        link(vulnerability, "CWE-89", ScoreProvider.NVD)
        self.assertEqual(self.primary(vulnerability), "CWE-89")

    def test_weakness_before_category_then_first_cited(self):
        vulnerability = cve("CVE-2026-2002")
        link(vulnerability, "CWE-16", ScoreProvider.CNA, kind=Weakness.Kind.CATEGORY)
        link(vulnerability, "CWE-787", ScoreProvider.CNA)
        link(vulnerability, "CWE-125", ScoreProvider.CNA)
        self.assertEqual(self.primary(vulnerability), "CWE-787")


class RecordAccessTests(TestCase):
    """FR-03: analysts and CISOs open the record; the administrator role does not."""

    @classmethod
    def setUpTestData(cls):
        cve("CVE-2024-3400")
        cls.url = reverse("cti:detail", args=["CVE-2024-3400"])

    def test_ciso_can_open_the_record(self):
        self.client.force_login(make_user("ciso", Role.CISO))
        self.assertEqual(self.client.get(self.url).status_code, 200)

    def test_administrator_gets_403(self):
        self.client.force_login(make_user("admin", Role.ADMIN))
        self.assertEqual(self.client.get(self.url).status_code, 403)

    def test_anonymous_user_goes_to_login(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])
