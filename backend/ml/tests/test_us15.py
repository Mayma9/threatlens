"""Acceptance tests of US15: the administrator reviews the metrics of a model version and activates it (FR-26)."""

import tempfile
from pathlib import Path

from django.contrib.admin.models import CHANGE, LogEntry
from django.test import TestCase, override_settings

from accounts.models import Role
from accounts.tests.test_us01 import make_user
from ml.models import MLModel, SeverityPrediction
from ml.scoring import score_severity

from .test_us10 import register_model, unscored_cve

LIST_URL = "/admin/ml/mlmodel/"


class ModelVersionAdminTests(TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.settings_override = override_settings(ML_MODELS_DIR=self.folder)
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        self.v1 = register_model(self.folder, "1", activate=True)
        self.v2 = register_model(self.folder, "2", activate=False)
        self.admin = make_user("admin", Role.ADMIN, is_superuser=True)

    def activate(self, *models):
        return self.client.post(
            LIST_URL, {"action": "activate_version", "_selected_action": [m.pk for m in models]}, follow=True
        )

    def active_versions(self):
        return list(MLModel.objects.filter(is_active=True).values_list("version", flat=True))

    # Criterion 1: the list shows each version with its task, algorithm, metrics and training date
    def test_admin_sees_each_version_with_task_algorithm_metric_and_date(self):
        self.client.force_login(self.admin)
        response = self.client.get(LIST_URL)
        self.assertEqual(response.status_code, 200)
        page = response.content.decode()
        for text in ("m1-severity v1", "m1-severity v2", "Severity (M1)", "test",
                     f"macro-F1 {self.v1.metrics['macro_f1']:.3f}", "Trained at"):
            self.assertIn(text, page)

    def test_page_of_a_version_shows_its_metrics(self):
        self.client.force_login(self.admin)
        response = self.client.get(f"{LIST_URL}{self.v2.pk}/change/")
        self.assertEqual(response.status_code, 200)
        page = response.content.decode()
        for text in ("Test macro-F1", "Right or one class away", "F1 by class", "Test period", "All metrics (JSON)",
                     "To activate it"):
            self.assertIn(text, page)
        self.assertNotIn('name="_save"', page)  # read-only page: activation is an action of the list

    # Criterion 2: the activated version becomes the only active one and the next scoring uses it
    def test_activation_makes_it_the_only_active_version_and_the_next_scoring_uses_it(self):
        self.client.force_login(self.admin)
        response = self.activate(self.v2)
        self.assertContains(response, "Version m1-severity v2 is now active for Severity (M1) (previous: m1-severity v1)")
        self.assertEqual(self.active_versions(), ["2"])
        unscored_cve("CVE-2026-0001", "HIGH")
        result = score_severity()
        self.assertEqual(result.model, self.v2)
        self.assertEqual(SeverityPrediction.objects.get().model, self.v2)

    def test_activation_is_logged_with_the_administrator(self):
        self.client.force_login(self.admin)
        self.activate(self.v2)
        entry = LogEntry.objects.get(object_id=str(self.v2.pk), action_flag=CHANGE)
        self.assertEqual(entry.user, self.admin)
        self.assertIn("previous active version: m1-severity v1", entry.get_change_message())

    def test_exactly_one_version_must_be_selected(self):
        self.client.force_login(self.admin)
        response = self.activate(self.v1, self.v2)
        self.assertContains(response, "Select exactly one version to activate.")
        self.assertEqual(self.active_versions(), ["1"])

    def test_a_version_whose_file_is_missing_is_not_activated(self):
        (self.folder / self.v2.artifact).unlink()
        self.client.force_login(self.admin)
        response = self.activate(self.v2)
        self.assertContains(response, "is missing on this machine")
        self.assertEqual(self.active_versions(), ["1"])

    def test_versions_cannot_be_added_or_deleted_in_the_admin(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(f"{LIST_URL}add/").status_code, 403)
        self.assertEqual(self.client.get(f"{LIST_URL}{self.v1.pk}/delete/").status_code, 403)

    # Criterion 3: a non-admin user cannot activate a model
    def test_non_admin_users_are_refused(self):
        for username, role in [("analyst", Role.ANALYST), ("ciso", Role.CISO)]:
            self.client.force_login(make_user(username, role))
            self.assertRedirects(self.client.get(LIST_URL), f"/admin/login/?next={LIST_URL}")
            self.client.post(LIST_URL, {"action": "activate_version", "_selected_action": [self.v2.pk]})
            self.assertEqual(self.active_versions(), ["1"])
