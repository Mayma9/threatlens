"""Alerts: Django messages and the login error are marked for SweetAlert2 (accounts/js/alerts.js)."""

from django.test import TestCase
from django.urls import reverse

from accounts.models import Role
from accounts.tests.test_us01 import PASSWORD, make_user


class AlertTests(TestCase):
    def test_login_error_becomes_a_popup(self):
        response = self.client.post(reverse("login"), {"username": "nobody", "password": "wrong"})
        self.assertContains(response, 'data-tl-alert data-level="error"')
        self.assertContains(response, 'data-title="Login failed"')
        self.assertContains(response, "sweetalert2@11.26.24")
        self.assertContains(response, "accounts/js/alerts.js")

    def test_welcome_toast_after_login(self):
        make_user("analyst", Role.ANALYST)
        response = self.client.post(reverse("login"), {"username": "analyst", "password": PASSWORD}, follow=True)
        self.assertContains(response, 'data-level="success"')
        self.assertContains(response, "Welcome back")

    def test_logout_toast_on_the_login_page(self):
        self.client.force_login(make_user("analyst", Role.ANALYST))
        response = self.client.post(reverse("logout"), follow=True)
        self.assertTemplateUsed(response, "registration/login.html")
        self.assertContains(response, "You are logged out.")
