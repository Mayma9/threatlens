from django.contrib.auth import get_user_model
from django.test import TestCase


class SmokeTests(TestCase):
    def test_custom_user_model_is_used(self):
        self.assertEqual(get_user_model()._meta.label, "accounts.User")

    def test_admin_login_page_is_reachable(self):
        response = self.client.get("/admin/login/")
        self.assertEqual(response.status_code, 200)
