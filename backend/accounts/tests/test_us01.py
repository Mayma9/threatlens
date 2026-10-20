"""Acceptance tests of US01 — accounts and roles (FR-01, FR-02, FR-03)."""

from django.core.exceptions import PermissionDenied
from django.core.management import call_command
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.views import APIView

from accounts.models import Organization, Role, User
from accounts.permissions import HasRole, role_required

PASSWORD = "Str0ng-test-passw0rd!"


def make_user(username, role, **extra):
    org, _ = Organization.objects.get_or_create(name="Test Bank")
    return User.objects.create_user(username=username, password=PASSWORD, role=role, organization=org, **extra)


class LoginTests(TestCase):
    def setUp(self):
        self.analyst = make_user("analyst", Role.ANALYST)

    def test_password_is_hashed(self):
        self.assertNotEqual(self.analyst.password, PASSWORD)
        self.assertTrue(self.analyst.check_password(PASSWORD))

    def test_valid_login_reaches_home(self):
        response = self.client.post(reverse("login"), {"username": "analyst", "password": PASSWORD}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["user"].is_authenticated)
        self.assertContains(response, "Security analyst")

    def test_wrong_password_shows_error_and_creates_no_session(self):
        response = self.client.post(reverse("login"), {"username": "analyst", "password": "wrong"})
        self.assertContains(response, "Invalid username or password")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_anonymous_user_is_redirected_to_login(self):
        response = self.client.get(reverse("home"))
        self.assertRedirects(response, f"{reverse('login')}?next=/")

    def test_logout_then_protected_page_redirects_to_login(self):
        self.client.force_login(self.analyst)
        self.client.post(reverse("logout"))
        response = self.client.get(reverse("home"))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse("login")))


class RoleModelTests(TestCase):
    def test_each_role_and_ciso_inherits_analyst(self):
        analyst = make_user("a", Role.ANALYST)
        ciso = make_user("c", Role.CISO)
        admin = make_user("d", Role.ADMIN)
        self.assertTrue(analyst.has_role(Role.ANALYST))
        self.assertFalse(analyst.has_role(Role.CISO))
        self.assertTrue(ciso.has_role(Role.CISO))
        self.assertTrue(ciso.has_role(Role.ANALYST))
        self.assertTrue(admin.has_role(Role.ADMIN))
        self.assertFalse(admin.has_role(Role.ANALYST))

    def test_only_admin_role_is_staff(self):
        self.assertFalse(make_user("a", Role.ANALYST).is_staff)
        self.assertFalse(make_user("c", Role.CISO).is_staff)
        self.assertTrue(make_user("d", Role.ADMIN).is_staff)

    def test_superuser_always_gets_admin_role(self):
        root = User.objects.create_superuser("root", "root@example.com", PASSWORD)
        self.assertEqual(root.role, Role.ADMIN)

    def test_inactive_user_has_no_role(self):
        self.assertFalse(make_user("x", Role.CISO, is_active=False).has_role(Role.CISO))


def ok_view(request):
    return HttpResponse("ok")


class AccessControlTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.analyst = make_user("analyst", Role.ANALYST)
        self.ciso = make_user("ciso", Role.CISO)
        self.admin = make_user("admin", Role.ADMIN, is_superuser=True)

    def call(self, view, user):
        request = self.factory.get("/protected/")
        request.user = user
        return view(request)

    def test_analyst_page_allows_analyst_and_ciso(self):
        view = role_required(Role.ANALYST)(ok_view)
        self.assertEqual(self.call(view, self.analyst).status_code, 200)
        self.assertEqual(self.call(view, self.ciso).status_code, 200)
        with self.assertRaises(PermissionDenied):
            self.call(view, self.admin)

    def test_ciso_page_refuses_analyst(self):
        view = role_required(Role.CISO)(ok_view)
        self.assertEqual(self.call(view, self.ciso).status_code, 200)
        with self.assertRaises(PermissionDenied):
            self.call(view, self.analyst)

    def test_api_permission_checks_role(self):
        class CisoOnly(APIView):
            permission_classes = [HasRole.of(Role.CISO)]

            def get(self, request):
                return HttpResponse("ok")

        factory = APIRequestFactory()
        for user, expected in [(self.ciso, 200), (self.analyst, 403), (self.admin, 403)]:
            request = factory.get("/api/ciso-only/")
            force_authenticate(request, user=user)
            self.assertEqual(CisoOnly.as_view()(request).status_code, expected, user.username)

    def test_api_me_requires_authentication(self):
        self.assertEqual(self.client.get(reverse("api-me")).status_code, 403)
        self.client.force_login(self.ciso)
        response = self.client.get(reverse("api-me"))
        self.assertEqual(response.json()["role"], "CISO")

    def test_only_admin_reaches_django_admin(self):
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get("/admin/").status_code, 302)  # sent to the admin login
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get("/admin/").status_code, 200)
        self.assertEqual(self.client.get("/admin/accounts/user/add/").status_code, 200)

    def test_home_menu_depends_on_role(self):
        self.client.force_login(self.analyst)
        self.assertNotContains(self.client.get(reverse("home")), "Open administration")
        self.client.force_login(self.admin)
        self.assertContains(self.client.get(reverse("home")), "Open administration")


class DemoUsersCommandTests(TestCase):
    @override_settings(DEMO_USER_PASSWORD=PASSWORD)
    def test_creates_three_demo_accounts_idempotently(self):
        call_command("create_demo_users", stdout=open("/dev/null", "w"))
        call_command("create_demo_users", stdout=open("/dev/null", "w"))
        roles = dict(User.objects.values_list("username", "role"))
        self.assertEqual(roles, {"analyst1": Role.ANALYST, "ciso1": Role.CISO, "admin1": Role.ADMIN})
        self.assertTrue(User.objects.get(username="ciso1").check_password(PASSWORD))
        self.assertEqual(Organization.objects.count(), 1)

    @override_settings(DEMO_USER_PASSWORD="")
    def test_refuses_to_run_without_password(self):
        from django.core.management.base import CommandError

        with self.assertRaises(CommandError):
            call_command("create_demo_users")
