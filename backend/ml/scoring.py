"""Scoring (UC19): the active M1 version predicts the severity of the CVEs that have no CVSS score."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
from django.conf import settings
from django.db import connection
from django.utils import timezone

from . import m1
from .models import MLModel, MLTask, SeverityPrediction

BATCH_SIZE = 5000

# CVEs without any CVSS score (every provider and version) whose prediction by this model is missing
# or older than the last update of the record (the features come from the record).
TO_SCORE_SQL = """
SELECT v.id
FROM cti_vulnerability v
WHERE NOT EXISTS (SELECT 1 FROM cti_cvssmetric m WHERE m.vulnerability_id = v.id)
  AND (%(rescore)s OR NOT EXISTS (
        SELECT 1 FROM ml_severityprediction p
        WHERE p.vulnerability_id = v.id AND p.model_id = %(model)s
          AND p.created_at >= COALESCE(v.source_updated_at, '-infinity'::timestamptz)))
ORDER BY v.id
"""


@dataclass
class ScoringResult:
    model: MLModel
    scored: int


def artifact_path(model: MLModel) -> Path:
    return Path(settings.ML_MODELS_DIR) / model.artifact


def active_severity_model() -> MLModel | None:
    return MLModel.objects.filter(task=MLTask.SEVERITY, is_active=True).first()


def score_severity(*, rescore: bool = False) -> ScoringResult | None:
    """Predicts the severity of the unscored CVEs with the active M1 version.

    Returns None when no M1 version is active. rescore=True predicts again every unscored CVE.
    """
    model = active_severity_model()
    if model is None:
        return None
    predictor = joblib.load(artifact_path(model))  # FileNotFoundError when the file is missing on this machine
    with connection.cursor() as cursor:
        cursor.execute(TO_SCORE_SQL, {"rescore": rescore, "model": model.pk})
        ids = [row[0] for row in cursor.fetchall()]

    for start in range(0, len(ids), BATCH_SIZE):
        data = m1.load_features(connection, ids[start:start + BATCH_SIZE])
        classes, confidences = predictor.predict(data)
        now = timezone.now()
        SeverityPrediction.objects.bulk_create(
            [
                SeverityPrediction(
                    model=model, vulnerability_id=vulnerability_id, created_at=now,
                    predicted_severity=str(severity), confidence=round(float(confidence), 4),
                )
                for vulnerability_id, severity, confidence in zip(data.id, classes, confidences)
            ],
            update_conflicts=True,
            unique_fields=["model", "vulnerability"],
            update_fields=["predicted_severity", "confidence", "created_at"],
        )
    return ScoringResult(model=model, scored=len(ids))
