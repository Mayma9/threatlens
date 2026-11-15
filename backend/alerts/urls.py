from django.urls import path

from . import views

app_name = "alerts"

urlpatterns = [
    path("", views.AlertListView.as_view(), name="list"),
    path("<int:pk>/", views.AlertDetailView.as_view(), name="detail"),
]
