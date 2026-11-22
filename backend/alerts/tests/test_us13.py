"""Acceptance tests of US13: weekly remediation plan prepared by an analyst and approved by a CISO (FR-12)."""

from datetime import date

from django.test import TestCase
from django.urls import reverse

from accounts.models import Organization, Role, User
from alerts import plans
from alerts.models import Alert, AlertStatus, PlanStatus, RemediationPlan
from cti.models import Product, Vulnerability
from watchlist.models import WatchlistItem


def user(username, role, organization):
    return User.objects.create_user(username=username, password="pw-Test-2026", role=role, organization=organization)


class PlanScenario(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.bank = Organization.objects.create(name="Demo Bank")
        cls.other_bank = Organization.objects.create(name="Other Bank")
        cls.analyst = user("analyst", Role.ANALYST, cls.bank)
        cls.ciso = user("ciso", Role.CISO, cls.bank)
        cls.outsider = user("outsider", Role.ANALYST, cls.other_bank)
        product = Product.objects.create(vendor="fortinet", name="fortios")
        item = WatchlistItem.objects.create(organization=cls.bank, product=product, criticality=4)
        other_item = WatchlistItem.objects.create(organization=cls.other_bank, product=product, criticality=2)

        def alert(number, score, status=AlertStatus.NEW, watched=item):
            vulnerability = Vulnerability.objects.create(cve_id=f"CVE-2026-000{number}", description="x")
            return Alert.objects.create(vulnerability=vulnerability, watchlist_item=watched, status=status,
                                        priority_score=score)

        cls.high = alert(1, 90)
        cls.low = alert(2, 20)
        cls.fixed = alert(3, 80, status=AlertStatus.FIXED)
        cls.foreign = alert(4, 99, watched=other_item)

    def new_plan(self, day=date(2026, 11, 18), by=None):
        return plans.create_plan(self.bank, by or self.analyst, day)


class WorkflowTests(PlanScenario):
    def test_plan_covers_monday_to_sunday_once_per_week(self):
        plan = self.new_plan(date(2026, 11, 18))  # a Wednesday
        self.assertEqual((plan.period_start, plan.period_end), (date(2026, 11, 16), date(2026, 11, 22)))
        with self.assertRaisesMessage(plans.PlanError, "already exists for the week of 16 Nov 2026"):
            self.new_plan(date(2026, 11, 22))

    def test_only_open_alerts_of_the_organization_can_be_added(self):
        plan = self.new_plan()
        self.assertEqual(list(plans.selectable_alerts(plan)), [self.high, self.low])
        added = plans.add_alerts(plan, [self.high.pk, self.fixed.pk, self.foreign.pk])
        self.assertEqual(added, 1)
        self.assertEqual(list(plan.alerts.all()), [self.high])

    def test_open_alert_of_an_earlier_week_can_be_planned_again(self):
        last_week = self.new_plan(date(2026, 11, 11))
        plans.add_alerts(last_week, [self.high.pk])
        this_week = self.new_plan(date(2026, 11, 18))
        self.assertIn(self.high, plans.selectable_alerts(this_week))
        plans.add_alerts(this_week, [self.high.pk])
        self.assertEqual(Alert.objects.get(pk=self.high.pk).plan, this_week)
        next_week = self.new_plan(date(2026, 11, 25))
        self.assertIn(self.high, plans.selectable_alerts(next_week))  # still open next week
        self.assertNotIn(self.high, plans.selectable_alerts(last_week))  # not taken back by an older plan

    def test_submit_needs_alerts_and_locks_the_plan(self):
        plan = self.new_plan()
        with self.assertRaisesMessage(plans.PlanError, "Add at least one alert"):
            plans.submit(plan)
        plans.add_alerts(plan, [self.high.pk])
        plans.submit(plan)
        self.assertEqual(plan.status, PlanStatus.SUBMITTED)
        self.assertIsNotNone(plan.submitted_at)
        with self.assertRaisesMessage(plans.PlanError, "can no longer be changed"):
            plans.add_alerts(plan, [self.low.pk])

    def submitted_plan(self, by=None):
        plan = self.new_plan(by=by)
        plans.add_alerts(plan, [self.high.pk])
        plans.submit(plan)
        return plan

    def test_ciso_approval_is_recorded(self):
        plan = self.submitted_plan()
        plans.approve(plan, self.ciso, "OK, patch the firewall first.")
        plan.refresh_from_db()
        self.assertEqual((plan.status, plan.validated_by, plan.ciso_comment),
                         (PlanStatus.APPROVED, self.ciso, "OK, patch the firewall first."))
        self.assertIsNotNone(plan.validated_at)
        self.assertEqual(plan.prepared_by, self.analyst)

    def test_requested_changes_need_a_comment_and_reopen_the_plan(self):
        plan = self.submitted_plan()
        with self.assertRaisesMessage(plans.PlanError, "Explain the changes"):
            plans.request_changes(plan, self.ciso, "  ")
        plans.request_changes(plan, self.ciso, "Add the KEV alerts.")
        self.assertEqual(plan.status, PlanStatus.CHANGES_REQUESTED)
        self.assertIsNone(plan.validated_at)
        plans.add_alerts(plan, [self.low.pk])  # editable again
        plans.submit(plan)
        self.assertEqual(plan.status, PlanStatus.SUBMITTED)

    def test_analyst_cannot_review(self):
        plan = self.submitted_plan()
        with self.assertRaisesMessage(plans.PlanError, "Only a CISO"):
            plans.approve(plan, self.analyst)

    def test_ciso_cannot_approve_own_plan(self):
        plan = plans.create_plan(self.bank, self.ciso, date(2026, 11, 25))
        plans.add_alerts(plan, [self.low.pk])
        plans.submit(plan)
        with self.assertRaisesMessage(plans.PlanError, "another CISO must review it"):
            plans.approve(plan, self.ciso)

    def test_approved_plan_cannot_be_approved_again(self):
        plan = self.submitted_plan()
        plans.approve(plan, self.ciso)
        with self.assertRaisesMessage(plans.PlanError, "Only a submitted plan"):
            plans.request_changes(plan, self.ciso, "Too late")


class PlanPageTests(PlanScenario):
    def setUp(self):
        self.client.force_login(self.analyst)

    def test_analyst_creates_fills_and_submits_a_plan(self):
        response = self.client.post(reverse("plans:list"), {"week": "2026-11-18"})
        plan = RemediationPlan.objects.get()
        url = reverse("plans:detail", args=[plan.pk])
        self.assertRedirects(response, url)
        page = self.client.get(url)
        self.assertContains(page, "CVE-2026-0001")  # selectable
        self.assertNotContains(page, "CVE-2026-0004")  # other organization
        self.client.post(url, {"action": "add", "alerts": [self.high.pk, self.low.pk]})
        self.client.post(url, {"action": "remove", "alerts": [self.low.pk]})
        self.assertEqual(list(plan.alerts.all()), [self.high])
        self.client.post(url, {"action": "submit"})
        plan.refresh_from_db()
        self.assertEqual(plan.status, PlanStatus.SUBMITTED)
        self.assertNotContains(self.client.get(url), "Approve")  # an analyst does not review

    def test_ciso_approves_from_the_page(self):
        plan = plans.create_plan(self.bank, self.analyst, date(2026, 11, 18))
        plans.add_alerts(plan, [self.high.pk])
        plans.submit(plan)
        self.client.force_login(self.ciso)
        url = reverse("plans:detail", args=[plan.pk])
        self.assertContains(self.client.get(url), "CISO review")
        self.client.post(url, {"action": "approve", "comment": "Go."})
        plan.refresh_from_db()
        self.assertEqual((plan.status, plan.validated_by), (PlanStatus.APPROVED, self.ciso))
        self.assertContains(self.client.get(reverse("plans:list")), "Approved")

    def test_refused_action_shows_why(self):
        plan = plans.create_plan(self.bank, self.analyst, date(2026, 11, 18))
        response = self.client.post(reverse("plans:detail", args=[plan.pk]), {"action": "submit"})
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Add at least one alert", status_code=400)

    def test_duplicate_week_is_refused(self):
        plans.create_plan(self.bank, self.analyst, date(2026, 11, 18))
        response = self.client.post(reverse("plans:list"), {"week": "2026-11-20"})
        self.assertEqual(response.status_code, 400)

    def test_plan_of_another_organization_gives_404(self):
        plan = plans.create_plan(self.other_bank, self.outsider, date(2026, 11, 18))
        self.assertEqual(self.client.get(reverse("plans:detail", args=[plan.pk])).status_code, 404)

    def test_alert_page_shows_its_plan(self):
        plan = plans.create_plan(self.bank, self.analyst, date(2026, 11, 18))
        plans.add_alerts(plan, [self.high.pk])
        response = self.client.get(reverse("alerts:detail", args=[self.high.pk]))
        self.assertContains(response, "Week of 16 Nov 2026")

    def test_administrator_gets_403(self):
        self.client.force_login(user("admin1", Role.ADMIN, self.bank))
        self.assertEqual(self.client.get(reverse("plans:list")).status_code, 403)
