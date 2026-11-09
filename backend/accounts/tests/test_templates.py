"""Templates live inside their app (<app>/templates/...), not in a project-level folder."""

from django.conf import settings
from django.test import TestCase, override_settings
from django.urls import include, path, reverse

from accounts.models import Role
from accounts.permissions import role_required
from accounts.tests.test_us01 import make_user


@role_required(Role.CISO)
def ciso_only(request):  # pragma: no cover - an analyst never reaches it
    raise AssertionError


urlpatterns = [
    path("ciso-only/", ciso_only),
    path("", include("config.urls")),
]


class TemplateLocationTests(TestCase):
    def test_no_project_level_template_folder(self):
        self.assertEqual(settings.TEMPLATES[0]["DIRS"], [])
        self.assertTrue(settings.TEMPLATES[0]["APP_DIRS"])

    def test_home_page_uses_the_accounts_templates(self):
        self.client.force_login(make_user("analyst", Role.ANALYST))
        response = self.client.get(reverse("home"))
        self.assertTemplateUsed(response, "accounts/home.html")
        self.assertTemplateUsed(response, "accounts/base.html")
        self.assertContains(response, "accounts/css/threatlens.css")

    def test_login_page_shows_the_animated_lens(self):
        response = self.client.get(reverse("login"))
        self.assertTemplateUsed(response, "registration/login.html")
        self.assertContains(response, "tl-lens--live")

    @override_settings(ROOT_URLCONF=__name__)
    def test_access_denied_page_comes_from_the_app(self):
        self.client.force_login(make_user("analyst", Role.ANALYST))
        response = self.client.get("/ciso-only/")
        self.assertEqual(response.status_code, 403)
        self.assertTemplateUsed(response, "403.html")
        self.assertContains(response, "Your role can", status_code=403)

    def test_admin_uses_the_threatlens_theme(self):
        self.client.force_login(make_user("admin", Role.ADMIN))
        response = self.client.get("/admin/")
        self.assertTemplateUsed(response, "admin/base_site.html")
        self.assertContains(response, "ThreatLens administration")
        self.assertContains(response, "accounts/css/admin.css")
        self.assertNotContains(response, "admin/css/dark_mode.css")  # always dark, no light/dark switch

    def test_admin_errors_use_sweetalert(self):
        self.client.force_login(make_user("analyst", Role.ANALYST))
        response = self.client.get("/admin/login/?next=/admin/")
        self.assertContains(response, "errornote")  # Django's message, turned into a pop-up by the scripts below
        self.assertContains(response, "accounts/js/admin_alerts.js")
        self.assertContains(response, "sweetalert2@11.26.24")
        self.assertContains(response, "accounts/css/alerts.css")
