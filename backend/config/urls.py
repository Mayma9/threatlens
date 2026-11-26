from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),  # login, logout, password change
    path("vulnerabilities/", include("cti.urls")),
    path("watchlist/", include("watchlist.urls")),
    path("alerts/", include("alerts.urls")),
    path("plans/", include("alerts.plan_urls")),
    path("runs/", include("pipeline.urls")),
    path("", include("accounts.urls")),
]
