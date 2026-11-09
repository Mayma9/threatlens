"""Alerts on watched products (US08, FR-08, FR-09) and their status history (class diagram 9.3)."""

from django.conf import settings
from django.db import models
from django.utils import timezone


class AlertStatus(models.TextChoices):
    NEW = "NEW", "New"
    IN_PROGRESS = "IN_PROGRESS", "In progress"
    FIXED = "FIXED", "Fixed"
    RISK_ACCEPTED = "RISK_ACCEPTED", "Risk accepted"
    FALSE_POSITIVE = "FALSE_POSITIVE", "False positive"


OPEN_STATUSES = [AlertStatus.NEW, AlertStatus.IN_PROGRESS]


class Alert(models.Model):
    """A vulnerability that affects a watched product: one alert per CVE and watchlist item."""

    vulnerability = models.ForeignKey("cti.Vulnerability", on_delete=models.CASCADE, related_name="alerts")
    watchlist_item = models.ForeignKey("watchlist.WatchlistItem", on_delete=models.CASCADE, related_name="alerts")
    created_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, choices=AlertStatus.choices, default=AlertStatus.NEW, db_index=True)
    priority_score = models.FloatField(default=0)  # computed by the prioritization (US11, FR-10)
    due_date = models.DateField(null=True, blank=True)
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_alerts"
    )

    class Meta:
        ordering = ["-priority_score", "due_date"]
        constraints = [
            models.UniqueConstraint(fields=["vulnerability", "watchlist_item"], name="uniq_alert_cve_watchlist_item"),
        ]

    def __str__(self) -> str:
        return f"{self.vulnerability} on {self.watchlist_item.product}"

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATUSES


class AlertStatusChange(models.Model):
    """One line of an alert's history. The creation is recorded with an empty old status."""

    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name="history")
    old_status = models.CharField(max_length=20, choices=AlertStatus.choices, blank=True)
    new_status = models.CharField(max_length=20, choices=AlertStatus.choices)
    comment = models.TextField(blank=True)
    changed_at = models.DateTimeField(default=timezone.now)
    # Empty = done by the system (alert generation in the pipeline)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ["alert", "changed_at"]

    def __str__(self) -> str:
        return f"{self.alert}: {self.old_status or 'created'} -> {self.new_status}"


class AlertGeneration(models.Model):
    """Result of the alert step of a pipeline run: CVEs checked, alerts created, unmatched names to review."""

    run = models.OneToOneField("pipeline.PipelineRun", on_delete=models.CASCADE, null=True, blank=True,
                               related_name="alert_generation")  # empty = launched with the generate_alerts command
    created_at = models.DateTimeField(default=timezone.now)
    cves_checked = models.PositiveIntegerField(default=0)
    alerts_created = models.PositiveIntegerField(default=0)
    unmatched_names = models.JSONField(default=list, blank=True)  # "vendor / product" strings
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        source = f"run {self.run_id}" if self.run_id else "command"
        return f"Alert generation ({source}): {self.alerts_created} alerts"
