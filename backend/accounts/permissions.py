"""Role-based access control for views and API endpoints (FR-03).

Every page requires authentication (LoginRequiredMiddleware in settings).
On top of that, views restricted to some roles use one of these helpers:

    @role_required(Role.CISO)                     # function-based view
    class PlanApprovalView(RoleRequiredMixin, View):
        allowed_roles = [Role.CISO]               # class-based view
    permission_classes = [HasRole.of(Role.ADMIN)] # Django REST Framework

A CISO automatically passes checks for Role.ANALYST.
"""

from functools import wraps

from django.contrib.auth.mixins import AccessMixin
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission


def role_required(*roles):
    """Decorator: anonymous users go to the login page, other roles get HTTP 403."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated:
                return redirect_to_login(request.get_full_path())
            if not user.has_any_role(*roles):
                raise PermissionDenied
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


class RoleRequiredMixin(AccessMixin):
    """Class-based view mixin. Set `allowed_roles` on the view."""

    allowed_roles: list[str] = []

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        if not request.user.has_any_role(*self.allowed_roles):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)


class HasRole(BasePermission):
    """DRF permission. Use `HasRole.of(Role.CISO)` in `permission_classes`."""

    allowed_roles: tuple[str, ...] = ()

    @classmethod
    def of(cls, *roles):
        return type(f"HasRole_{'_'.join(roles)}", (cls,), {"allowed_roles": roles})

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.has_any_role(*self.allowed_roles))
