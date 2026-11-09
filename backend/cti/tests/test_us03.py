"""Acceptance tests of US03: the analyst searches vulnerabilities (FR-04)."""

from datetime import date, datetime, timezone

from django.test import TestCase
from django.urls import reverse

from accounts.models import Role
from accounts.tests.test_us01 import make_user
from cti.models import AffectedProduct, CVSSMetric, KEVEntry, Product, ScoreProvider, Vulnerability
from cti.services import refresh_effective_severity

URL = reverse("cti:search")


def cve(cve_id, vendor="acme", product="router", published="2026-05-01", score=None, provider=ScoreProvider.CNA):
    vulnerability = Vulnerability.objects.create(
        cve_id=cve_id, description=f"Issue in {product}",
        published_at=datetime.fromisoformat(published).replace(tzinfo=timezone.utc))
    item, _ = Product.objects.get_or_create(vendor=vendor, name=product)
    AffectedProduct.objects.create(vulnerability=vulnerability, product=item)
    if score is not None:
        severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
        CVSSMetric.objects.create(vulnerability=vulnerability, provider=provider, version="3.1",
                                  base_score=score, severity=severity, vector="CVSS:3.1/test")
    return vulnerability


class SearchTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.pan = cve("CVE-2024-3400", "palo alto networks", "pan-os", "2024-04-12", score=10.0)
        cls.fortios = cve("CVE-2026-1001", "fortinet", "fortios", "2026-03-01", score=7.5)
        cls.fortiweb = cve("CVE-2026-1002", "fortinet", "fortiweb", "2026-06-01", score=5.0)
        cls.unscored = cve("CVE-2026-1003", "fortinet", "fortios", "2026-07-01")
        KEVEntry.objects.create(vulnerability=cls.fortios, date_added=date(2026, 3, 5), due_date=date(2026, 3, 26),
                                required_action="Apply updates.")
        refresh_effective_severity()

    def setUp(self):
        self.client.force_login(make_user("analyst", Role.ANALYST))

    def ids(self, **filters):
        response = self.client.get(URL, filters)
        self.assertEqual(response.status_code, 200)
        return [v.cve_id for v in response.context["page"].object_list]

    def test_cve_identifier_finds_that_vulnerability(self):
        self.assertEqual(self.ids(cve="cve-2024-3400"), ["CVE-2024-3400"])
        self.assertEqual(self.ids(cve="CVE-2026-100"), ["CVE-2026-1003", "CVE-2026-1002", "CVE-2026-1001"])

    def test_filters_combine(self):
        self.assertEqual(self.ids(vendor="Fortinet"), ["CVE-2026-1003", "CVE-2026-1002", "CVE-2026-1001"])
        self.assertEqual(self.ids(vendor="fortinet", product="fortios"), ["CVE-2026-1003", "CVE-2026-1001"])
        self.assertEqual(self.ids(vendor="fortinet", severity="HIGH"), ["CVE-2026-1001"])
        self.assertEqual(self.ids(vendor="fortinet", severity="UNSCORED"), ["CVE-2026-1003"])
        self.assertEqual(self.ids(kev="yes"), ["CVE-2026-1001"])
        self.assertEqual(self.ids(vendor="fortinet", kev="no", published_from="2026-05-01"),
                         ["CVE-2026-1003", "CVE-2026-1002"])
        self.assertEqual(self.ids(published_to="2025-12-31"), ["CVE-2024-3400"])

    def test_results_are_paginated(self):
        for number in range(30):
            cve(f"CVE-2025-{2000 + number}", published="2025-01-01")
        first = self.client.get(URL)
        self.assertEqual(first.context["page"].paginator.count, 34)
        self.assertEqual(len(first.context["page"].object_list), 25)
        second = self.client.get(URL, {"page": 2})
        self.assertEqual(len(second.context["page"].object_list), 9)

    def test_no_result_message(self):
        response = self.client.get(URL, {"cve": "CVE-2099-0001"})
        self.assertContains(response, "No result")
        self.assertContains(response, "CVE-2099-0001 is not in ThreatLens")
        response = self.client.get(URL, {"vendor": "nobody"})
        self.assertContains(response, "No vulnerability matches these filters")

    def test_invalid_period_is_refused(self):
        response = self.client.get(URL, {"published_from": "2026-12-01", "published_to": "2026-01-01"})
        self.assertContains(response, "ends before it starts", status_code=400)

    def test_page_shows_severity_and_kev(self):
        response = self.client.get(URL, {"vendor": "fortinet", "product": "fortios"})
        self.assertContains(response, "High 7.5")
        self.assertContains(response, "Exploited")
        self.assertContains(response, "No score yet")

    def test_roles(self):
        self.client.force_login(make_user("admin", Role.ADMIN))
        self.assertEqual(self.client.get(URL).status_code, 403)
        self.client.force_login(make_user("ciso", Role.CISO))
        self.assertEqual(self.client.get(URL).status_code, 200)


class EffectiveSeverityTests(TestCase):
    def test_nvd_wins_then_cna_then_adp(self):
        vulnerability = cve("CVE-2026-2000", score=5.0, provider=ScoreProvider.CISA_ADP)
        refresh_effective_severity()
        vulnerability.refresh_from_db()
        self.assertEqual((vulnerability.effective_severity, vulnerability.effective_score), ("MEDIUM", 5.0))
        CVSSMetric.objects.create(vulnerability=vulnerability, provider=ScoreProvider.CNA, version="3.1",
                                  base_score=8.1, severity="HIGH", vector="x")
        CVSSMetric.objects.create(vulnerability=vulnerability, provider=ScoreProvider.NVD, version="3.1",
                                  base_score=9.8, severity="CRITICAL", vector="x")
        self.assertEqual(refresh_effective_severity(), 1)
        vulnerability.refresh_from_db()
        self.assertEqual(vulnerability.effective_severity, "CRITICAL")
        self.assertEqual(vulnerability.effective_metric().provider, ScoreProvider.NVD)  # same rule in Python
        self.assertEqual(refresh_effective_severity(), 0)  # nothing changed
