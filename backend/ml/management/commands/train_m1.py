"""Train model M1 (FR-23, FR-26) on the CVEs of the database and register it as a new version.

    python manage.py train_m1              # new version, not active
    python manage.py train_m1 --activate   # new version, used by the next scoring
    python manage.py train_m1 --quick      # without the quarter-by-quarter measure (about 3 times faster)

The settings are chosen on the validation period; the test period is measured with a strict split and with
a model retrained each quarter; then the model is refit on every labelled CVE (ml/m1.py: train).
The file goes to ml/models/ (git-ignored), the version and its metrics to ml_mlmodel.
The notebook ml/notebooks/m1_final.ipynb explains the choices with the same code.
Retrain every quarter: the scoring habits of the CNAs change and new CNAs appear.
"""

import json

import joblib
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone

from ml import m1
from ml.models import MLModel, MLTask

NAME = "m1-severity"
ALGORITHM = "TF-IDF + logistic regression: severity class and CVSS base metrics (official CVSS formula), combined"


class Command(BaseCommand):
    help = "Train model M1 (severity of a CVE) and register it as a new model version."

    def add_arguments(self, parser):
        parser.add_argument("--since", default=m1.SINCE, help=f"first publication date used (default {m1.SINCE})")
        parser.add_argument("--valid-from", default=m1.VALID_FROM, help=f"start of the validation period (default {m1.VALID_FROM})")
        parser.add_argument("--test-from", default=m1.TEST_FROM, help=f"start of the test period (default {m1.TEST_FROM})")
        parser.add_argument("--activate", action="store_true", help="use this version for scoring")
        parser.add_argument("--quick", action="store_true", help="skip the measure with a model retrained each quarter")

    def handle(self, *args, **options):
        data = m1.load_labelled(connection, options["since"])
        self.stdout.write(f"{data.cve_id.nunique():,} CVEs with a CVSS 3.x severity since {options['since']}")
        model, metrics = m1.train(
            data, valid_from=options["valid_from"], test_from=options["test_from"],
            each_quarter=not options["quick"], log=self.stdout.write,
        )

        versions = MLModel.objects.filter(name=NAME).values_list("version", flat=True)
        version = str(max((int(v) for v in versions if v.isdigit()), default=0) + 1)
        folder = settings.ML_MODELS_DIR
        folder.mkdir(parents=True, exist_ok=True)
        artifact = f"m1_severity_v{version}.joblib"
        joblib.dump(model, folder / artifact, compress=3)
        (folder / f"m1_severity_v{version}_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

        registered = MLModel.objects.create(
            name=NAME, task=MLTask.SEVERITY, version=version, artifact=artifact, metrics=metrics,
            algorithm=ALGORITHM, trained_at=timezone.now(),
        )
        if options["activate"]:
            registered.activate()

        quarters = metrics.get("retrained_each_quarter")
        self.stdout.write(self.style.SUCCESS(
            f"{registered} saved in ml/models/{artifact}: test macro-F1 {metrics['macro_f1']} with the strict split"
            + (f", {quarters['macro_f1']} retrained each quarter" if quarters else "")
            + f" (target {m1.TARGET_MACRO_F1}); right or one class away {metrics['right_or_one_class_away']:.1%}"
        ))
        if options["activate"]:
            self.stdout.write(f"{registered} is active. Predict now: python manage.py score_m1")
        else:
            self.stdout.write("Not active: run again with --activate to use it for scoring")
