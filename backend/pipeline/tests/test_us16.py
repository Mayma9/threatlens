"""Acceptance tests of US16: the administrator monitors the pipeline runs (UC14, FR-17)."""

import tempfile
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from accounts.models import Role
from accounts.tests.test_us01 import make_user
from alerts.models import AlertGeneration
from pipeline.connectors.kev import KevConnector
from pipeline.models import IngestionTask, PipelineRun, RunStatus, Source
from pipeline.services import run_pipeline
from pipeline.views import execute_run, format_duration


def failing_download(self, destination):
    raise RuntimeError("source unavailable")


def make_run(status, minutes=3, hours_ago=1, triggered_by=None):
    run = PipelineRun.objects.create(status=status, triggered_by=triggered_by)
    started = timezone.now() - timedelta(hours=hours_ago)
    ended = None if status == RunStatus.RUNNING else started + timedelta(minutes=minutes)
    PipelineRun.objects.filter(pk=run.pk).update(started_at=started, ended_at=ended)  # auto_now_add ignores a value
    run.refresh_from_db()
    return run


def source(name):
    return Source.objects.get_or_create(name=name, defaults={"label": name.upper(), "url": "https://example.org/"})[0]


class AccessTests(TestCase):
    def test_only_the_administrator_reaches_the_pages(self):
        run = make_run(RunStatus.SUCCESS)
        urls = [reverse("runs:list"), reverse("runs:detail", args=[run.pk])]
        for username, role in (("analyst", Role.ANALYST), ("ciso", Role.CISO)):
            self.client.force_login(make_user(username, role))
            for url in urls:
                self.assertEqual(self.client.get(url).status_code, 403)
            self.assertEqual(self.client.post(reverse("runs:start")).status_code, 403)
        self.assertEqual(PipelineRun.objects.count(), 1)

    def test_an_anonymous_user_goes_to_the_login_page(self):
        response = self.client.get(reverse("runs:list"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])

    def test_the_administrator_menu_links_to_the_monitoring_page(self):
        self.client.force_login(make_user("admin", Role.ADMIN))
        response = self.client.get(reverse("home"))
        self.assertContains(response, f'href="{reverse("runs:list")}"')


class RunListTests(TestCase):
    """Criterion 1: each run with its status, duration and per-source counts."""

    def setUp(self):
        self.client.force_login(make_user("admin", Role.ADMIN))

    def test_each_run_shows_status_duration_and_per_source_counts(self):
        night_admin = make_user("night_admin", Role.ADMIN)
        run = make_run(RunStatus.PARTIAL, minutes=4, triggered_by=night_admin)
        IngestionTask.objects.create(
            run=run, source=source("epss"), status=RunStatus.SUCCESS, extracted=1200, loaded=1195, rejected=5
        )
        IngestionTask.objects.create(run=run, source=source("kev"), status=RunStatus.FAILED)
        scheduled = make_run(RunStatus.SUCCESS, minutes=1, hours_ago=30)

        response = self.client.get(reverse("runs:list"))

        self.assertContains(response, "Partial")
        self.assertContains(response, "4 min 00 s")
        self.assertContains(response, "<strong>epss</strong> 1200 extracted &middot; 1195 loaded &middot; 5 rejected")
        self.assertContains(response, "<strong>kev</strong>")
        self.assertContains(response, "night_admin")
        self.assertContains(response, "Scheduler")
        self.assertContains(response, reverse("runs:detail", args=[scheduled.pk]))

    def test_a_running_run_shows_how_long_it_has_been_running(self):
        make_run(RunStatus.RUNNING, hours_ago=1)
        response = self.client.get(reverse("runs:list"))
        self.assertContains(response, "running for 1 h 00 min")

    def test_durations_are_readable(self):
        self.assertEqual(format_duration(timedelta(seconds=45)), "45 s")
        self.assertEqual(format_duration(timedelta(minutes=3, seconds=7)), "3 min 07 s")
        self.assertEqual(format_duration(timedelta(hours=2, minutes=5)), "2 h 05 min")


class RunDetailTests(TestCase):
    """Criterion 2: a FAILED or PARTIAL run shows the error message and the quality report."""

    def setUp(self):
        self.client.force_login(make_user("admin", Role.ADMIN))

    def test_a_partial_run_shows_the_error_and_the_quality_reports(self):
        run = make_run(RunStatus.PARTIAL)
        IngestionTask.objects.create(
            run=run, source=source("kev"), status=RunStatus.FAILED,
            error_message="RuntimeError: source unavailable\n\nTraceback (most recent call last):",
            quality_report={"rejected_by_reason": {"missing cveID": 2}},
        )
        IngestionTask.objects.create(
            run=run, source=source("epss"), status=RunStatus.SUCCESS, extracted=10, loaded=9, rejected=1,
            quality_report={"score_date": "2026-11-09", "rejected_by_reason": {"duplicate row in the file": 1}},
        )

        response = self.client.get(reverse("runs:detail", args=[run.pk]))

        self.assertContains(response, "RuntimeError: source unavailable")
        self.assertContains(response, "Rejected by reason")
        self.assertContains(response, "missing cveID: 2")
        self.assertContains(response, "Score date")
        self.assertContains(response, "2026-11-09")
        self.assertContains(response, "duplicate row in the file: 1")

    def test_threatfox_examples_never_show_their_keys(self):
        """R9: an IOC value must never appear on the page, even as a rejected example."""
        run = make_run(RunStatus.SUCCESS)
        IngestionTask.objects.create(
            run=run, source=source("threatfox"), status=RunStatus.SUCCESS, extracted=2, loaded=1, rejected=1,
            quality_report={
                "rejected_by_reason": {"duplicate IOC in the file": 1},
                "rejected_examples": [{"key": "ioc-value.invalid", "reason": "duplicate IOC in the file"}],
            },
        )
        response = self.client.get(reverse("runs:detail", args=[run.pk]))
        self.assertNotContains(response, "ioc-value.invalid")
        self.assertContains(response, "1 kept, not shown on this page (IOC data, R9)")
        self.assertContains(response, "duplicate IOC in the file: 1")

    def test_examples_of_other_sources_are_shown_up_to_ten(self):
        run = make_run(RunStatus.SUCCESS)
        reason = "missing English description"
        examples = [{"key": f"CVE-2026-{number:04d}", "reason": reason} for number in range(1, 13)]
        IngestionTask.objects.create(
            run=run, source=source("cve"), status=RunStatus.SUCCESS, rejected=12,
            quality_report={"rejected_examples": examples},
        )
        IngestionTask.objects.create(
            run=run, source=source("kev"), status=RunStatus.SUCCESS, quality_report={"rejected_examples": []},
        )
        response = self.client.get(reverse("runs:detail", args=[run.pk]))
        self.assertContains(response, "CVE-2026-0001: missing English description")
        self.assertContains(response, "CVE-2026-0010: missing English description")
        self.assertNotContains(response, "CVE-2026-0011")
        self.assertContains(response, "and 2 more")
        self.assertContains(response, "<dd class=\"col-sm-8\">none</dd>", html=False)

    def test_an_alert_step_error_is_shown(self):
        run = make_run(RunStatus.PARTIAL)
        IngestionTask.objects.create(run=run, source=source("kev"), status=RunStatus.SUCCESS)
        AlertGeneration.objects.create(run=run, error_message="ValueError: watchlist item without product")
        response = self.client.get(reverse("runs:detail", args=[run.pk]))
        self.assertContains(response, "ValueError: watchlist item without product")

    def test_an_unknown_run_gives_404(self):
        self.assertEqual(self.client.get(reverse("runs:detail", args=[999999])).status_code, 404)


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class StartRunTests(TestCase):
    """Criterion 3: a manual run is created with the administrator as trigger."""

    def setUp(self):
        self.admin = make_user("admin", Role.ADMIN)
        self.client.force_login(self.admin)

    def test_a_manual_run_is_created_with_the_administrator_as_trigger(self):
        with self.captureOnCommitCallbacks() as callbacks:  # the thread is not started inside a test
            response = self.client.post(reverse("runs:start"))
        self.assertRedirects(response, reverse("runs:list"))
        run = PipelineRun.objects.get()
        self.assertEqual(run.triggered_by, self.admin)
        self.assertEqual(run.status, RunStatus.RUNNING)
        self.assertEqual(len(callbacks), 1)

    def test_the_background_run_completes_the_run_created_by_the_page(self):
        run = PipelineRun.objects.create(triggered_by=self.admin)
        with patch.object(KevConnector, "download", failing_download):
            result = run_pipeline(sources=["kev"], run=run)
        self.assertEqual(result.pk, run.pk)
        self.assertEqual(PipelineRun.objects.count(), 1)
        result.refresh_from_db()
        self.assertEqual(result.triggered_by, self.admin)
        self.assertEqual(result.status, RunStatus.FAILED)
        self.assertIn("source unavailable", result.tasks.get(source__name="kev").error_message)

    def test_a_crash_outside_the_sources_marks_the_run_failed(self):
        run = PipelineRun.objects.create(triggered_by=self.admin)
        with patch("pipeline.views.run_pipeline", side_effect=RuntimeError("boom")), \
             patch("pipeline.views.connection"), \
             self.assertLogs("pipeline.views", level="ERROR"):
            execute_run(run.pk)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatus.FAILED)
        self.assertIsNotNone(run.ended_at)

    def test_a_second_run_is_refused_while_one_is_running(self):
        running = make_run(RunStatus.RUNNING, hours_ago=1)
        response = self.client.post(reverse("runs:start"), follow=True)
        self.assertEqual(PipelineRun.objects.count(), 1)
        self.assertContains(response, f"Run #{running.pk} is still running")

    def test_a_stuck_run_does_not_block_a_new_one(self):
        make_run(RunStatus.RUNNING, hours_ago=13)
        with self.captureOnCommitCallbacks():
            self.client.post(reverse("runs:start"))
        self.assertEqual(PipelineRun.objects.count(), 2)

    def test_a_get_request_never_starts_a_run(self):
        self.assertEqual(self.client.get(reverse("runs:start")).status_code, 405)
        self.assertEqual(PipelineRun.objects.count(), 0)
