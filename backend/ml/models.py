"""Machine learning models and their predictions (class diagram 9.4, FR-26).

A model is trained by a command or a notebook (ml.m1), saved as a file in ml/models/ and registered here
with its metrics. Only the active version of a task is used for scoring; each prediction keeps the model
version and a confidence value.
"""

from django.db import models, transaction

from cti.models import Severity, Vulnerability


class MLTask(models.TextChoices):
    SEVERITY = "SEVERITY", "Severity (M1)"
    EXPLOITATION = "EXPLOITATION", "Exploitation (M2)"
    CLUSTERING = "CLUSTERING", "Clustering (M3)"


class MLModel(models.Model):
    name = models.CharField(max_length=50)  # e.g. "m1-severity"
    task = models.CharField(max_length=20, choices=MLTask.choices)
    version = models.CharField(max_length=20)  # "1", "2"... in training order
    algorithm = models.CharField(max_length=200)
    metrics = models.JSONField(default=dict)  # evaluation on the test period, settings, data periods
    artifact = models.CharField(max_length=200)  # file name in settings.ML_MODELS_DIR (git-ignored)
    trained_at = models.DateTimeField()
    is_active = models.BooleanField(default=False)

    class Meta:
        ordering = ["task", "-trained_at"]
        verbose_name = "ML model"
        constraints = [
            models.UniqueConstraint(fields=["name", "version"], name="uniq_ml_model_version"),
            models.UniqueConstraint(
                fields=["task"], condition=models.Q(is_active=True), name="one_active_model_per_task"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.name} v{self.version}"

    @transaction.atomic
    def activate(self) -> None:
        """Makes this version the one used for scoring; the other versions of the same task are deactivated."""
        MLModel.objects.filter(task=self.task, is_active=True).exclude(pk=self.pk).update(is_active=False)
        self.is_active = True
        self.save(update_fields=["is_active"])


class Prediction(models.Model):
    """Output of a model for one vulnerability (abstract, specialized by task)."""

    model = models.ForeignKey(MLModel, on_delete=models.CASCADE, related_name="%(class)ss")
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="%(class)ss")
    created_at = models.DateTimeField()
    confidence = models.FloatField()  # probability of the predicted class, 0-1

    class Meta:
        abstract = True


class SeverityPrediction(Prediction):
    """Severity predicted by M1 for a CVE without any CVSS score (FR-23). The CWE target was dropped (risk R4)."""

    predicted_severity = models.CharField(max_length=10, choices=Severity.choices)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["model", "vulnerability"], name="uniq_severity_prediction"),
            models.CheckConstraint(
                condition=models.Q(confidence__gte=0) & models.Q(confidence__lte=1), name="severity_confidence_0_1"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.vulnerability} {self.predicted_severity} ({self.model})"
