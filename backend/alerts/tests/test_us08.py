"""Acceptance tests of US08: alerts created automatically when a watched product is affected (FR-08, FR-09)."""

from datetime import date, datetime, timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.models import Organization
from alerts.models import Alert, AlertGeneration, AlertStatus
from alerts.services import due_date_for, generate_alerts
from cti.models import AffectedProduct, CVSSMetric, KEVEntry, Product, ScoreProvider, Vulnerability
from pipeline.services import run_pipeline
from pipeline.tests.factories import cve_doc, write_bulk_zip
from watchlist.models import ProductAlias, WatchlistItem

DUE_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "UNKNOWN": 30}


def cve(cve_id, vendor, product, updated="2026-11-01T00:00:00Z", score=None):
    """A loaded CVE that names (vendor, product), optionally with a CNA CVSS 3.1 score."""
    vulnerability = Vulnerability.objects.create(
        cve_id=cve_id, description="test", source_updated_at=datetime.fromisoformat(updated.replace("Z", "+00:00")))
    item, _ = Product.objects.get_or_create(vendor=vendor, name=product)
    AffectedProduct.objects.create(vulnerability=vulnerability, product=item)
    if score is not None:
        severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
        CVSSMetric.objects.create(vulnerability=vulnerability, provider=ScoreProvider.CNA, version="3.1",
                                  base_score=score, severity=severity, vector="CVSS:3.1/test")
    return vulnerability


@override_settings(ALERT_DUE_DAYS=DUE_DAYS)
class GenerationTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Demo Bank")
        self.product = Product.objects.create(vendor="fortinet", name="fortios")
        self.item = WatchlistItem.objects.create(organization=self.org, product=self.product, criticality=4)

    def test_matching_cve_creates_one_new_alert(self):
        hit = cve("CVE-2026-0001", "fortinet", "fortios", score=9.8)
        cve("CVE-2026-0002", "cisco", "ios xe", score=9.8)
        result = generate_alerts(Vulnerability.objects.all())
        alert = Alert.objects.get()
        self.assertEqual((alert.vulnerability, alert.watchlist_item, alert.status), (hit, self.item, AlertStatus.NEW))
        self.assertEqual((result.cves_checked, result.alerts_created), (2, 1))

    def test_alias_spelling_also_creates_an_alert(self):
        ProductAlias.objects.create(product=self.product, raw_vendor="fortinet, inc.", raw_product="fortios")
        cve("CVE-2026-0003", "fortinet, inc.", "fortios")
        generate_alerts(Vulnerability.objects.all())
        self.assertEqual(Alert.objects.get().vulnerability.cve_id, "CVE-2026-0003")

    def test_running_again_creates_no_second_alert(self):
        cve("CVE-2026-0001", "fortinet", "fortios")
        generate_alerts(Vulnerability.objects.all())
        second = generate_alerts(Vulnerability.objects.all())
        self.assertEqual(Alert.objects.count(), 1)
        self.assertEqual(second.alerts_created, 0)

    def test_one_alert_per_cve_and_watchlist_item(self):
        other = WatchlistItem.objects.create(organization=Organization.objects.create(name="Other Bank"),
                                             product=self.product, criticality=2)
        cve("CVE-2026-0001", "fortinet", "fortios")
        generate_alerts(Vulnerability.objects.all())
        self.assertEqual(set(Alert.objects.values_list("watchlist_item", flat=True)), {self.item.pk, other.pk})

    def test_new_alert_has_a_due_date_and_a_creation_in_its_history(self):
        cve("CVE-2026-0001", "fortinet", "fortios", score=9.8)
        now = timezone.make_aware(datetime(2026, 11, 10, 9, 0))
        generate_alerts(Vulnerability.objects.all(), now=now)
        alert = Alert.objects.get()
        self.assertEqual(alert.due_date, date(2026, 11, 17))  # CRITICAL: 7 days
        change = alert.history.get()
        self.assertEqual((change.old_status, change.new_status, change.changed_by), ("", AlertStatus.NEW, None))
        self.assertIn("Created by", change.comment)

    def test_due_date_rules(self):
        now = timezone.make_aware(datetime(2026, 11, 10, 9, 0))
        no_score = cve("CVE-2026-0001", "x", "y")
        self.assertEqual(due_date_for(no_score, now), date(2026, 12, 10))  # unknown severity: 30 days
        medium = cve("CVE-2026-0002", "x", "y", score=5.0)
        self.assertEqual(due_date_for(medium, now), now.date() + timedelta(days=90))
        KEVEntry.objects.create(vulnerability=medium, date_added=date(2026, 11, 1), due_date=date(2026, 11, 22),
                                required_action="Apply updates.")
        medium = Vulnerability.objects.select_related("kev_entry").get(pk=medium.pk)
        self.assertEqual(due_date_for(medium, now), date(2026, 11, 22))  # CISA's earlier due date wins

    def test_nvd_score_comes_before_cna_score(self):
        vulnerability = cve("CVE-2026-0001", "x", "y", score=5.0)
        CVSSMetric.objects.create(vulnerability=vulnerability, provider=ScoreProvider.NVD, version="3.1",
                                  base_score=9.1, severity="CRITICAL", vector="CVSS:3.1/test")
        self.assertEqual(vulnerability.effective_metric().provider, ScoreProvider.NVD)

    def test_unmatched_names_are_listed_for_review(self):
        cve("CVE-2026-0001", "fortinet, inc.", "fortios")
        cve("CVE-2026-0002", "cisco", "ios xe")
        result = generate_alerts(Vulnerability.objects.all())
        self.assertEqual(result.unmatched_names, ["fortinet, inc. / fortios"])
        self.assertFalse(Alert.objects.exists())

    def test_command_creates_alerts_since_a_date(self):
        cve("CVE-2025-0001", "fortinet", "fortios", updated="2025-01-01T00:00:00Z")
        cve("CVE-2026-0001", "fortinet", "fortios", updated="2026-11-01T00:00:00Z")
        out = StringIO()
        call_command("generate_alerts", "--since", "2026-10-01", stdout=out)
        self.assertEqual(list(Alert.objects.values_list("vulnerability__cve_id", flat=True)), ["CVE-2026-0001"])
        self.assertIn("1 alerts created for 1 CVEs", out.getvalue())


@override_settings(ALERT_DUE_DAYS=DUE_DAYS)
class PipelineStepTests(TestCase):
    """The pipeline creates the alerts of its new or updated CVEs only."""

    def setUp(self):
        org = Organization.objects.create(name="Demo Bank")
        product = Product.objects.create(vendor="fortinet", name="fortios")
        WatchlistItem.objects.create(organization=org, product=product, criticality=4)
        # Already loaded before the run: no alert expected for it
        cve("CVE-2026-0100", "fortinet", "fortios", updated="2026-10-01T00:00:00Z")

    def test_run_alerts_new_or_updated_cves(self):
        with TemporaryDirectory() as folder, self.settings(STAGING_DIR=Path(folder) / "staging"):
            bulk = write_bulk_zip(Path(folder) / "bulk.zip", [
                cve_doc("CVE-2026-0200", affected=(("Fortinet", "FortiOS", "7.2.0"),), updated="2026-11-05T00:00:00.000Z"),
                cve_doc("CVE-2026-0201", affected=(("Cisco", "IOS XE", "17.9"),), updated="2026-11-05T00:00:00.000Z"),
            ])
            run = run_pipeline(sources=["cve"], local_file=str(bulk))
        self.assertEqual(run.status, "SUCCESS")
        self.assertEqual(list(Alert.objects.values_list("vulnerability__cve_id", flat=True)), ["CVE-2026-0200"])
        generation = AlertGeneration.objects.get(run=run)
        self.assertEqual((generation.cves_checked, generation.alerts_created), (2, 1))
