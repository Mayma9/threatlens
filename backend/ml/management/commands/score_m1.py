"""Predict the severity of the CVEs without CVSS score with the active M1 version (UC19), outside a pipeline run.

    python manage.py score_m1          # CVEs not predicted yet by the active version, or updated since
    python manage.py score_m1 --all    # every CVE without CVSS score

Then refreshes the effective severity (FR-06) and the priority of the open alerts (FR-10).
The pipeline does the same at each run; the warehouse is refreshed by the pipeline or refresh_warehouse.
"""

from django.core.management.base import BaseCommand, CommandError

from alerts.priority import refresh_priority_scores
from cti.services import refresh_effective_severity
from ml.scoring import score_severity


class Command(BaseCommand):
    help = "Predict the severity of the CVEs without CVSS score with the active M1 version."

    def add_arguments(self, parser):
        parser.add_argument("--all", action="store_true", help="predict again every CVE without CVSS score")

    def handle(self, *args, **options):
        result = score_severity(rescore=options["all"])
        if result is None:
            raise CommandError("No active M1 version: python manage.py train_m1 --activate")
        self.stdout.write(f"{result.model}: severity predicted for {result.scored} CVEs without CVSS score")
        self.stdout.write(f"effective severity: {refresh_effective_severity()} CVEs updated")
        self.stdout.write(f"priority of {refresh_priority_scores()} open alerts refreshed")
        self.stdout.write(self.style.SUCCESS("Done. Power BI: python manage.py refresh_warehouse"))
