from django.urls import path

from . import views

app_name = "runs"

urlpatterns = [
    path("", views.RunListView.as_view(), name="list"),
    path("<int:pk>/", views.RunDetailView.as_view(), name="detail"),
    path("start/", views.RunStartView.as_view(), name="start"),
]
