"""Pipeline monitoring pages (US16, UC14, FR-17).

The administrator sees every run with its status, duration and per-source counts, opens a run to read the
error messages and the quality reports, and starts a run manually. Only the administrator role reaches them.
"""

import logging
import threading
from datetime import timedelta

from django.contrib import messages
from django.db import connection, transaction
from django.db.models import Prefetch
from django.shortcuts import redirect
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView, ListView

from accounts.models import Role
from accounts.permissions import RoleRequiredMixin
from alerts.models import AlertGeneration

from .models import IngestionTask, PipelineRun, RunStatus
from .services import run_pipeline

logger = logging.getLogger(__name__)

RUNS_PER_PAGE = 20
# A run still RUNNING after this delay is stuck (e.g. the web container restarted during the run):
# it no longer blocks a new manual run.
STUCK_AFTER = timedelta(hours=12)


class AdminRequiredMixin(RoleRequiredMixin):
    allowed_roles = [Role.ADMIN]


def format_duration(delta: timedelta) -> str:
    seconds = max(int(delta.total_seconds()), 0)
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours} h {minutes:02d} min"
    if minutes:
        return f"{minutes} min {seconds:02d} s"
    return f"{seconds} s"


def run_duration(run: PipelineRun, now=None) -> str:
    """Duration of a finished run, or how long a running run has been going."""
    if run.ended_at:
        return format_duration(run.ended_at - run.started_at)
    if run.status == RunStatus.RUNNING:
        return "running for " + format_duration((now or timezone.now()) - run.started_at)
    return "unknown"


def running_run():
    """The run in progress, if any. A run started more than STUCK_AFTER ago does not count."""
    return PipelineRun.objects.filter(
        status=RunStatus.RUNNING, started_at__gte=timezone.now() - STUCK_AFTER
    ).first()


# Sources whose rejected rows are IOCs: the page never shows their example keys (risk R9).
IOC_SOURCES = {"threatfox"}
EXAMPLES_SHOWN = 10


def report_rows(report, source_name: str = "") -> list[dict]:
    """The quality report as label / value rows.

    It holds counts, dates, versions, rejection reasons with their counts, and up to 200 rejected examples
    ({"key", "reason"}). The page shows at most EXAMPLES_SHOWN examples, and none for an IOC source (R9).
    """
    rows = []
    for key, value in (report or {}).items():
        row = {"label": str(key).replace("_", " ").capitalize()}
        if key == "rejected_examples" and isinstance(value, list) and value:
            if source_name in IOC_SOURCES:
                row["value"] = f"{len(value)} kept, not shown on this page (IOC data, R9)"
            else:
                row["entries"] = [(item.get("key", "?"), item.get("reason", "")) for item in value[:EXAMPLES_SHOWN]]
                row["more"] = max(len(value) - EXAMPLES_SHOWN, 0)
        elif isinstance(value, dict) and value:
            row["entries"] = list(value.items())  # e.g. rejected_by_reason: reason -> count
        elif isinstance(value, (dict, list, tuple)) and not value:
            row["value"] = "none"
        elif isinstance(value, (list, tuple)):
            row["value"] = ", ".join(str(item) for item in value)
        else:
            row["value"] = value
        rows.append(row)
    return rows


def execute_run(run_pk: int) -> None:
    """Body of the background thread: run the pipeline on the run that the page created."""
    try:
        run_pipeline(run=PipelineRun.objects.get(pk=run_pk))
    except Exception:  # noqa: BLE001 - a crash outside the sources must not leave the run RUNNING forever
        logger.exception("Pipeline run %s crashed", run_pk)
        PipelineRun.objects.filter(pk=run_pk, status=RunStatus.RUNNING).update(
            status=RunStatus.FAILED, ended_at=timezone.now()
        )
    finally:
        connection.close()  # the thread opened its own database connection


def start_in_background(run: PipelineRun) -> None:
    """A full run takes minutes: the page answers at once and the run goes on in a thread."""
    threading.Thread(target=execute_run, args=(run.pk,), name=f"pipeline-run-{run.pk}", daemon=True).start()


class RunListView(AdminRequiredMixin, ListView):
    """Criterion 1: each run with its status, duration and per-source counts, newest first."""

    template_name = "pipeline/run_list.html"
    context_object_name = "runs"
    paginate_by = RUNS_PER_PAGE

    def get_queryset(self):
        tasks = IngestionTask.objects.select_related("source").order_by("started_at", "pk")
        return PipelineRun.objects.select_related("triggered_by").prefetch_related(Prefetch("tasks", queryset=tasks))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        now = timezone.now()
        runs = list(context["runs"])
        for run in runs:
            run.duration_text = run_duration(run, now)
        context["runs"] = runs
        context["running"] = running_run()
        return context


class RunDetailView(AdminRequiredMixin, DetailView):
    """Criterion 2: the error message and the quality report of each source of a run."""

    template_name = "pipeline/run_detail.html"
    context_object_name = "run"

    def get_queryset(self):
        return PipelineRun.objects.select_related("triggered_by")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        run = self.object
        tasks = list(run.tasks.select_related("source").order_by("started_at", "pk"))
        for task in tasks:
            task.report_rows = report_rows(task.quality_report, task.source.name)
            task.duration_text = format_duration(task.ended_at - task.started_at) if task.ended_at else ""
        context.update(
            {
                "tasks": tasks,
                "failed_tasks": sum(1 for task in tasks if task.status == RunStatus.FAILED),
                "alert_errors": list(AlertGeneration.objects.filter(run=run, error_message__gt="")),
                "duration_text": run_duration(run),
            }
        )
        return context


class RunStartView(AdminRequiredMixin, View):
    """Criterion 3: the administrator starts a run, recorded with her as trigger."""

    http_method_names = ["post"]

    def post(self, request):
        current = running_run()
        if current is not None:
            messages.warning(
                request,
                f"Run #{current.pk} is still running: wait for it to end before starting another one.",
                extra_tags="Not started",
            )
            return redirect("runs:list")
        run = PipelineRun.objects.create(triggered_by=request.user)
        transaction.on_commit(lambda: start_in_background(run))  # the thread must see the committed run
        messages.success(request, f"Run #{run.pk} started. Refresh the page to follow it.")
        return redirect("runs:list")
