"""Tests of the frequency of a source (FR-15, criterion 5 of #12): a scheduled run skips the sources that are not due."""

import tempfile
from datetime import timedelta
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from cti.models import Vulnerability
from pipeline.models import IngestionTask, PipelineRun, RunStatus, Source
from pipeline.services import ensure_sources, run_pipeline, source_is_due

from .factories import write_kev_json


def finished_task(source, ago, status=RunStatus.SUCCESS):
    """A task of the source that ended `ago` before now."""
    run = PipelineRun.objects.create()
    task = IngestionTask.objects.create(run=run, source=source, status=status)
    IngestionTask.objects.filter(pk=task.pk).update(ended_at=timezone.now() - ago)
    return task


class SourceIsDueTests(TestCase):
    def setUp(self):
        ensure_sources()
        self.source = Source.objects.get(name="kev")  # frequency daily by default

    def set_frequency(self, value):
        Source.objects.filter(pk=self.source.pk).update(frequency=value)
        self.source.refresh_from_db()

    def test_a_source_that_never_ran_is_due(self):
        self.assertTrue(source_is_due(self.source))

    def test_a_daily_source_that_ran_one_hour_ago_is_not_due(self):
        finished_task(self.source, timedelta(hours=1))
        self.assertFalse(source_is_due(self.source))

    def test_a_daily_source_that_ran_twenty_hours_ago_is_not_due(self):
        finished_task(self.source, timedelta(hours=20))
        self.assertFalse(source_is_due(self.source))

    def test_a_daily_source_is_due_the_next_day_even_if_the_scheduler_fires_a_little_early(self):
        finished_task(self.source, timedelta(hours=23, minutes=55))
        self.assertTrue(source_is_due(self.source))

    def test_an_hourly_source_that_ran_two_hours_ago_is_due(self):
        self.set_frequency("hourly")
        finished_task(self.source, timedelta(hours=2))
        self.assertTrue(source_is_due(self.source))

    def test_a_weekly_source_that_ran_three_days_ago_is_not_due(self):
        self.set_frequency("weekly")
        finished_task(self.source, timedelta(days=3))
        self.assertFalse(source_is_due(self.source))

    def test_an_unknown_frequency_counts_as_daily(self):
        self.set_frequency("monthly")
        finished_task(self.source, timedelta(hours=1))
        self.assertFalse(source_is_due(self.source))

    def test_an_unknown_frequency_is_due_after_two_days(self):
        self.set_frequency("monthly")
        finished_task(self.source, timedelta(days=2))
        self.assertTrue(source_is_due(self.source))

    def test_the_frequency_ignores_case_and_spaces(self):
        self.set_frequency(" Weekly ")
        finished_task(self.source, timedelta(days=3))
        self.assertFalse(source_is_due(self.source))

    def test_a_failed_task_does_not_postpone_the_next_run(self):
        finished_task(self.source, timedelta(minutes=5), status=RunStatus.FAILED)
        self.assertTrue(source_is_due(self.source))


@override_settings(STAGING_DIR=tempfile.mkdtemp())
class ScheduledRunTests(TestCase):
    def setUp(self):
        Vulnerability.objects.create(cve_id="CVE-2024-0001", description="known")
        self.catalog = write_kev_json(Path(tempfile.mkdtemp()) / "kev.json", [("CVE-2024-0001", "2024-05-01", "Known")])

    def test_a_second_scheduled_run_skips_a_source_that_just_succeeded(self):
        first = run_pipeline(sources=["kev"], local_file=str(self.catalog), scheduled=True)
        second = run_pipeline(sources=["kev"], local_file=str(self.catalog), scheduled=True)
        self.assertEqual(first.tasks.count(), 1)
        self.assertEqual(second.tasks.count(), 0)

    def test_a_manual_run_is_never_skipped(self):
        run_pipeline(sources=["kev"], local_file=str(self.catalog), scheduled=True)
        manual = run_pipeline(sources=["kev"], local_file=str(self.catalog))
        self.assertEqual(manual.tasks.count(), 1)

    def test_the_command_option_scheduled_skips_the_source_that_is_not_due(self):
        args = ["run_pipeline", "--scheduled", "--source", "kev", "--file", str(self.catalog)]
        call_command(*args, stdout=StringIO())
        out = StringIO()
        call_command(*args, stdout=out)
        self.assertIn("kev: not due (daily), skipped", out.getvalue())
