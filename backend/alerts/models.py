"""Alerts on watched products (US08, FR-08, FR-09), their status history and the weekly
remediation plan validated by the CISO (US14, FR-12) (class diagram 9.3)."""

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


class PlanStatus(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    SUBMITTED = "SUBMITTED", "Waiting for approval"
    CHANGES_REQUESTED = "CHANGES_REQUESTED", "Changes requested"
    APPROVED = "APPROVED", "Approved"


EDITABLE_PLAN_STATUSES = [PlanStatus.DRAFT, PlanStatus.CHANGES_REQUESTED]


class RemediationPlan(models.Model):
    """Weekly remediation plan (FR-12): open alerts selected by an analyst, approved by the CISO.

    Workflow: DRAFT -> SUBMITTED -> APPROVED, or SUBMITTED -> CHANGES_REQUESTED -> SUBMITTED again.
    """

    organization = models.ForeignKey("accounts.Organization", on_delete=models.CASCADE, related_name="plans")
    period_start = models.DateField()  # Monday of the week
    period_end = models.DateField()  # Sunday of the week
    status = models.CharField(max_length=20, choices=PlanStatus.choices, default=PlanStatus.DRAFT)
    prepared_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="prepared_plans")
    created_at = models.DateTimeField(default=timezone.now)
    submitted_at = models.DateTimeField(null=True, blank=True)
    validated_at = models.DateTimeField(null=True, blank=True)  # approval date
    validated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True,
                                     related_name="validated_plans")  # approver (CISO)
    ciso_comment = models.TextField(blank=True)  # approval note or requested changes

    class Meta:
        ordering = ["-period_start"]
        constraints = [
            models.UniqueConstraint(fields=["organization", "period_start"], name="uniq_plan_organization_week"),
        ]

    def __str__(self) -> str:
        return f"Remediation plan {self.period_start:%d %b} - {self.period_end:%d %b %Y} ({self.organization})"

    @property
    def is_editable(self) -> bool:
        return self.status in EDITABLE_PLAN_STATUSES


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
    plan = models.ForeignKey(RemediationPlan, on_delete=models.SET_NULL, null=True, blank=True,
                             related_name="alerts")  # the weekly plan that schedules its remediation (FR-12)

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
