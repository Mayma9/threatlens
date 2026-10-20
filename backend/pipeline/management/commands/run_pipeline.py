"""Run the ETL pipeline (UC15). Used by the daily scheduler and by the administrator.

    python manage.py run_pipeline                    # every active source, in order
    python manage.py run_pipeline --source cve       # one source
    python manage.py run_pipeline --source cve --file data/staging/manual.zip   # local file instead of a download
    python manage.py run_pipeline --full             # ignore the incremental watermark
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from pipeline.connectors import REGISTRY
from pipeline.models import RunStatus
from pipeline.services import run_pipeline


class Command(BaseCommand):
    help = "Run the CTI ETL pipeline and log the run (PipelineRun + one IngestionTask per source)."

    def add_arguments(self, parser):
        parser.add_argument("--source", action="append", choices=list(REGISTRY), help="source to run (repeatable)")
        parser.add_argument("--file", help="local snapshot to load instead of downloading (one source only)")
        parser.add_argument("--full", action="store_true", help="reload every record, not only the new ones")
        parser.add_argument("--triggered-by", help="username of the administrator who starts the run")

    def handle(self, *args, **options):
        if options["file"] and len(options["source"] or []) != 1:
            raise CommandError("--file needs exactly one --source")
        user = None
        if options["triggered_by"]:
            user = get_user_model().objects.filter(username=options["triggered_by"]).first()
            if user is None:
                raise CommandError(f"Unknown user {options['triggered_by']}")

        run = run_pipeline(
            sources=options["source"],
            local_file=options["file"],
            full=options["full"],
            triggered_by=user,
            stdout=self.stdout,
        )
        style = self.style.SUCCESS if run.status == RunStatus.SUCCESS else self.style.WARNING
        self.stdout.write(style(f"Pipeline run {run.pk}: {run.status}"))
        if run.status == RunStatus.FAILED:
            raise CommandError("Every source failed, see the IngestionTask error messages in the admin.")
