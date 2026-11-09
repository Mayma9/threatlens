from django.urls import path

from . import views

app_name = "watchlist"

urlpatterns = [
    path("", views.WatchlistView.as_view(), name="list"),
    path("unmatched/", views.UnmatchedNamesView.as_view(), name="unmatched"),
    path("<int:pk>/", views.WatchlistItemView.as_view(), name="item"),
    path("<int:pk>/remove/", views.WatchlistItemDeleteView.as_view(), name="remove"),
    path("aliases/<int:pk>/remove/", views.AliasDeleteView.as_view(), name="remove-alias"),
]
