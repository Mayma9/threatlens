"""Acceptance tests of US11: priority score (FR-10), prioritized list (FR-11) and status updates with history (FR-09)."""

from datetime import date, timedelta

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from accounts.models import Organization, Role, User
from alerts.models import Alert, AlertStatus, AlertStatusChange
from alerts.priority import factors, priority_score, refresh_priority_scores
from alerts.services import change_status
from cti.models import KEVEntry, Product, Vulnerability
from watchlist.models import WatchlistItem

WEIGHTS = {"severity": 0.35, "exploitation": 0.25, "kev": 0.25, "criticality": 0.15}


def user(username, role, organization):
    return User.objects.create_user(username=username, password="pw-Test-2026", role=role, organization=organization)


class Scenario(TestCase):
    """Demo Bank watches fortios (criticality 4) and windows 10 (criticality 1); Other Bank watches fortios."""

    @classmethod
    def setUpTestData(cls):
        cls.bank = Organization.objects.create(name="Demo Bank")
        cls.other_bank = Organization.objects.create(name="Other Bank")
        cls.analyst = user("analyst", Role.ANALYST, cls.bank)
        cls.ciso = user("ciso", Role.CISO, cls.bank)
        cls.outsider = user("outsider", Role.ANALYST, cls.other_bank)
        fortios = Product.objects.create(vendor="fortinet", name="fortios")
        windows = Product.objects.create(vendor="microsoft", name="windows 10")
        cls.fortios = WatchlistItem.objects.create(organization=cls.bank, product=fortios, criticality=4)
        cls.windows = WatchlistItem.objects.create(organization=cls.bank, product=windows, criticality=1)
        cls.other_item = WatchlistItem.objects.create(organization=cls.other_bank, product=fortios, criticality=2)

        def cve(cve_id, score, severity, epss=None, kev=False):
            vulnerability = Vulnerability.objects.create(cve_id=cve_id, description="x", effective_score=score,
                                                         effective_severity=severity, epss_score=epss)
            if kev:
                KEVEntry.objects.create(vulnerability=vulnerability, date_added=date(2026, 11, 1),
                                        due_date=date(2026, 11, 22), required_action="Patch.")
            return vulnerability

        cls.critical_kev = cve("CVE-2026-0001", 9.8, "CRITICAL", epss=0.9, kev=True)
        cls.medium = cve("CVE-2026-0002", 5.0, "MEDIUM", epss=0.02)
        cls.unscored = cve("CVE-2026-0003", None, "")
        today = timezone.localdate()
        cls.alert_top = Alert.objects.create(vulnerability=cls.critical_kev, watchlist_item=cls.fortios,
                                             due_date=today + timedelta(days=7))
        cls.alert_medium = Alert.objects.create(vulnerability=cls.medium, watchlist_item=cls.windows,
                                                due_date=today - timedelta(days=1))  # overdue
        cls.alert_unscored = Alert.objects.create(vulnerability=cls.unscored, watchlist_item=cls.fortios,
                                                  due_date=today + timedelta(days=30))
        cls.alert_fixed = Alert.objects.create(vulnerability=cls.medium, watchlist_item=cls.fortios,
                                               status=AlertStatus.FIXED, priority_score=12.0)
        cls.alert_other_bank = Alert.objects.create(vulnerability=cls.critical_kev, watchlist_item=cls.other_item)
        for alert in Alert.objects.all():
            AlertStatusChange.objects.create(alert=alert, old_status="", new_status=AlertStatus.NEW,
                                             comment="Created by pipeline run 1.")


@override_settings(PRIORITY_WEIGHTS=WEIGHTS, PRIORITY_UNSCORED_SEVERITY=0.5)
class PriorityScoreTests(Scenario):
    """FR-10: score = 100 x (0.35 severity + 0.25 EPSS + 0.25 KEV + 0.15 criticality)."""

    def test_formula(self):
        # 100 x (0.35 x 0.98 + 0.25 x 0.9 + 0.25 x 1 + 0.15 x 1) = 96.8
        self.assertEqual(priority_score(self.critical_kev, 4), 96.8)
        # 100 x (0.35 x 0.5 + 0.25 x 0.02 + 0 + 0) = 18.0
        self.assertEqual(priority_score(self.medium, 1), 18.0)

    def test_cve_without_cvss_gets_the_neutral_severity(self):
        severity = factors(self.unscored, 4)[0]
        self.assertEqual((severity.value, severity.shown), (0.5, "No CVSS score yet (neutral value)"))
        self.assertEqual(priority_score(self.unscored, 4), 32.5)  # 100 x (0.35 x 0.5 + 0.15 x 1)

    @override_settings(PRIORITY_WEIGHTS={"severity": 2, "exploitation": 0, "kev": 0, "criticality": 2})
    def test_weights_are_normalized(self):
        self.assertEqual(priority_score(self.critical_kev, 4), 99.0)  # (0.98 + 1) / 2

    def test_refresh_scores_open_alerts_and_keeps_closed_ones(self):
        self.assertEqual(refresh_priority_scores(), 4)  # every open alert, both organizations
        self.alert_top.refresh_from_db()
        self.alert_fixed.refresh_from_db()
        self.assertEqual(self.alert_top.priority_score, 96.8)
        self.assertEqual(self.alert_fixed.priority_score, 12.0)

    def test_new_criticality_rescores_the_product_alerts(self):
        refresh_priority_scores()
        self.client.force_login(self.analyst)
        self.client.post(reverse("watchlist:item", args=[self.windows.pk]), {"action": "criticality", "criticality": 4})
        self.alert_medium.refresh_from_db()
        self.assertEqual(self.alert_medium.priority_score, 33.0)  # + 15 points

    def test_command(self):
        call_command("refresh_priorities", stdout=open("/dev/null", "w"))
        self.assertEqual(Alert.objects.get(pk=self.alert_unscored.pk).priority_score, 32.5)


@override_settings(PRIORITY_WEIGHTS=WEIGHTS, PRIORITY_UNSCORED_SEVERITY=0.5)
class PrioritizedListTests(Scenario):
    """FR-11: open alerts of the organization, sorted by priority, with filters."""

    def setUp(self):
        refresh_priority_scores()
        self.client.force_login(self.analyst)

    def listed(self, **filters):
        response = self.client.get(reverse("alerts:list"), filters)
        self.assertEqual(response.status_code, 200)
        return [alert.pk for alert in response.context["page"].object_list]

    def test_open_alerts_sorted_by_priority(self):
        self.assertEqual(self.listed(), [self.alert_top.pk, self.alert_unscored.pk, self.alert_medium.pk])

    def test_other_organizations_are_not_shown(self):
        self.assertNotIn(self.alert_other_bank.pk, self.listed(status="all"))

    def test_filters(self):
        self.assertEqual(self.listed(status="all"),
                         [self.alert_top.pk, self.alert_unscored.pk, self.alert_medium.pk, self.alert_fixed.pk])
        self.assertEqual(self.listed(status="FIXED"), [self.alert_fixed.pk])
        self.assertEqual(self.listed(item=self.windows.pk), [self.alert_medium.pk])
        self.assertEqual(self.listed(severity="CRITICAL"), [self.alert_top.pk])
        self.assertEqual(self.listed(severity="UNSCORED"), [self.alert_unscored.pk])
        self.assertEqual(self.listed(kev="yes"), [self.alert_top.pk])
        self.assertEqual(self.listed(kev="no"), [self.alert_unscored.pk, self.alert_medium.pk])

    def test_page_shows_score_and_overdue(self):
        response = self.client.get(reverse("alerts:list"))
        self.assertContains(response, "97")  # 96.8 rounded
        self.assertContains(response, "tl-overdue", count=1)
        self.assertContains(response, reverse("alerts:detail", args=[self.alert_top.pk]))

    def test_access(self):
        self.client.force_login(user("admin1", Role.ADMIN, self.bank))
        self.assertEqual(self.client.get(reverse("alerts:list")).status_code, 403)
        self.client.force_login(self.ciso)
        self.assertEqual(self.client.get(reverse("alerts:list")).status_code, 200)
        self.client.logout()
        self.assertEqual(self.client.get(reverse("alerts:list")).status_code, 302)


@override_settings(PRIORITY_WEIGHTS=WEIGHTS, PRIORITY_UNSCORED_SEVERITY=0.5)
class AlertUpdateTests(Scenario):
    """FR-09: every status change is recorded with its author, its date and an optional comment."""

    def setUp(self):
        self.client.force_login(self.analyst)
        self.url = reverse("alerts:detail", args=[self.alert_top.pk])

    def post(self, **data):
        return self.client.post(self.url, {"status": self.alert_top.status, "assignee": "", "comment": "", **data})

    def test_page_explains_the_score(self):
        response = self.client.get(self.url)
        self.assertContains(response, "Why this priority")
        self.assertContains(response, "In the CISA KEV catalog")
        self.assertContains(response, "Created by pipeline run 1.")

    def test_status_change_is_recorded_with_author_and_comment(self):
        response = self.post(status=AlertStatus.IN_PROGRESS, assignee=self.analyst.pk, comment="Patch planned on 20 Nov.")
        self.assertRedirects(response, self.url)
        self.alert_top.refresh_from_db()
        self.assertEqual((self.alert_top.status, self.alert_top.assignee), (AlertStatus.IN_PROGRESS, self.analyst))
        change = self.alert_top.history.latest("changed_at")
        self.assertEqual((change.old_status, change.new_status, change.changed_by, change.comment),
                         (AlertStatus.NEW, AlertStatus.IN_PROGRESS, self.analyst, "Patch planned on 20 Nov."))

    def test_closed_alert_leaves_the_open_list(self):
        self.post(status=AlertStatus.FIXED)
        response = self.client.get(reverse("alerts:list"))
        self.assertNotIn(self.alert_top.pk, [a.pk for a in response.context["page"].object_list])

    def test_assignee_alone_changes_without_history_line(self):
        self.post(assignee=self.ciso.pk)
        self.alert_top.refresh_from_db()
        self.assertEqual(self.alert_top.assignee, self.ciso)
        self.assertEqual(self.alert_top.history.count(), 1)

    def test_comment_without_status_change_is_refused(self):
        response = self.post(comment="Just a note")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.alert_top.history.count(), 1)

    def test_nothing_changed_is_refused(self):
        self.assertEqual(self.post().status_code, 400)

    def test_assignee_must_be_an_analyst_or_ciso_of_the_organization(self):
        response = self.post(status=AlertStatus.IN_PROGRESS, assignee=self.outsider.pk)
        self.assertEqual(response.status_code, 400)
        self.alert_top.refresh_from_db()
        self.assertEqual(self.alert_top.status, AlertStatus.NEW)

    def test_alert_of_another_organization_gives_404(self):
        response = self.client.get(reverse("alerts:detail", args=[self.alert_other_bank.pk]))
        self.assertEqual(response.status_code, 404)

    def test_service_can_reopen_a_closed_alert(self):
        changes = change_status(self.alert_fixed, new_status=AlertStatus.IN_PROGRESS, user=self.ciso,
                                comment="Patch failed on one site.")
        self.assertEqual(changes, ["status Fixed → In progress"])
        self.assertEqual(Alert.objects.get(pk=self.alert_fixed.pk).status, AlertStatus.IN_PROGRESS)
