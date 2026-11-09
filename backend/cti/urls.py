from django.urls import path

from . import views

app_name = "cti"

urlpatterns = [
    path("", views.VulnerabilitySearchView.as_view(), name="search"),
]
