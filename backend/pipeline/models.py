"""ETL pipeline logging: sources, runs and one ingestion task per source (class diagram 9.4, FR-15, FR-17)."""

from django.conf import settings
from django.db import models


class RunStatus(models.TextChoices):
    RUNNING = "RUNNING", "Running"
    SUCCESS = "SUCCESS", "Success"
    PARTIAL = "PARTIAL", "Partial"
    FAILED = "FAILED", "Failed"


class Source(models.Model):
    """A CTI source. The administrator enables/disables it and sets its frequency (FR-15)."""

    name = models.SlugField(max_length=50, unique=True)  # connector key, e.g. "cve", "kev"
    label = models.CharField(max_length=100)
    url = models.URLField(max_length=300)
    frequency = models.CharField(max_length=20, default="daily")
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.label


class PipelineRun(models.Model):
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=RunStatus.choices, default=RunStatus.RUNNING)
    # Empty = started by the scheduler
    triggered_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"Run {self.pk} ({self.status})"


class IngestionTask(models.Model):
    run = models.ForeignKey(PipelineRun, on_delete=models.CASCADE, related_name="tasks")
    source = models.ForeignKey(Source, on_delete=models.PROTECT, related_name="tasks")
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=RunStatus.choices, default=RunStatus.RUNNING)
    extracted = models.PositiveIntegerField(default=0)
    loaded = models.PositiveIntegerField(default=0)
    rejected = models.PositiveIntegerField(default=0)
    quality_report = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["run", "started_at"]

    def __str__(self) -> str:
        return f"{self.source.name} in run {self.run_id} ({self.status})"
