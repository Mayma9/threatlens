from django.contrib.auth.decorators import login_not_required
from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response


def home(request):
    """Console home page. Every authenticated user can open it."""
    return render(request, "accounts/home.html")


@login_not_required  # DRF answers 403 itself instead of redirecting to the login page
@api_view(["GET"])
def me(request):
    """Current user's identity and role (used by the console and in tests)."""
    user = request.user
    return Response(
        {
            "username": user.username,
            "role": user.role,
            "organization": user.organization.name if user.organization else None,
        }
    )
