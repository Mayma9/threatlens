from django.urls import path

from . import plan_views

app_name = "plans"

urlpatterns = [
    path("", plan_views.PlanListView.as_view(), name="list"),
    path("<int:pk>/", plan_views.PlanDetailView.as_view(), name="detail"),
]
