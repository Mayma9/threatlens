"""Run the ETL pipeline: one IngestionTask per active source, a failing source never stops the others."""

from __future__ import annotations

import traceback
from datetime import timedelta

from django.utils import timezone

from alerts.models import AlertGeneration
from alerts.priority import refresh_priority_scores
from alerts.services import cve_watermark, generate_alerts
from cti.models import Vulnerability
from cti.services import refresh_effective_severity
from ml.scoring import score_severity

from .connectors import REGISTRY
from .models import IngestionTask, PipelineRun, RunStatus, Source
from .warehouse import refresh_warehouse

# Delay between two runs of a source (FR-15). An unknown value counts as daily.
FREQUENCIES = {"hourly": timedelta(hours=1), "daily": timedelta(days=1), "weekly": timedelta(days=7)}
# A scheduler fires a little before the end of the previous run's delay (the previous run lasted some minutes):
# 90 % of the delay is enough, otherwise a daily source would only run every other day.
DUE_RATIO = 0.9


def ensure_sources() -> None:
    """Create the Source rows of the registered connectors (the admin can then disable them)."""
    for name, connector in REGISTRY.items():
        Source.objects.get_or_create(name=name, defaults={"label": connector.label, "url": connector.url})


def source_is_due(source: Source, now=None) -> bool:
    """True when the last successful task of the source is older than its frequency (a failed task does not count)."""
    now = now or timezone.now()
    last = (
        source.tasks.filter(status=RunStatus.SUCCESS, ended_at__isnull=False)
        .order_by("-ended_at")
        .values_list("ended_at", flat=True)
        .first()
    )
    if last is None:
        return True
    delay = FREQUENCIES.get((source.frequency or "").strip().lower(), FREQUENCIES["daily"])
    return now - last >= delay * DUE_RATIO


def run_pipeline(
    *, sources=None, local_file=None, full=False, scheduled=False, triggered_by=None, stdout=None, run=None
) -> PipelineRun:
    ensure_sources()
    selected = [name for name in REGISTRY if not sources or name in sources]
    if run is None:  # the monitoring page creates the run first, then runs it in the background (US16)
        run = PipelineRun.objects.create(triggered_by=triggered_by)
    watermark = cve_watermark()  # CVEs updated after it are the new or updated ones of this run

    for name in selected:
        source = Source.objects.get(name=name)
        if not source.is_active:
            if stdout:
                stdout.write(f"{name}: source disabled, skipped")
            continue
        if scheduled and not source_is_due(source):  # a manual run is never skipped
            if stdout:
                stdout.write(f"{name}: not due ({source.frequency}), skipped")
            continue
        task = IngestionTask.objects.create(run=run, source=source)
        if stdout:
            stdout.write(f"{name}: started")
        connector = REGISTRY[name](local_file=local_file, full=full, stdout=stdout)
        try:
            result = connector.run()
            task.extracted, task.loaded, task.rejected = result.extracted, result.loaded, result.rejected
            task.quality_report = result.report
            task.status = RunStatus.SUCCESS
        except Exception as exc:  # noqa: BLE001 - logged in the task, the next source still runs
            task.status = RunStatus.FAILED
            task.error_message = f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc(limit=5)}"
            task.quality_report = {**task.quality_report, **dict(connector.counters)}
        task.ended_at = timezone.now()
        task.save()
        if stdout:
            stdout.write(
                f"{name}: {task.status} - extracted {task.extracted}, loaded {task.loaded}, rejected {task.rejected}"
            )
            if task.status == RunStatus.FAILED:  # the full traceback stays in the admin (Ingestion tasks)
                stdout.write(f"{name}: error - {task.error_message.splitlines()[0]}")

    statuses = set(run.tasks.values_list("status", flat=True))
    scoring_ok = alerts_ok = warehouse_ok = True
    if RunStatus.SUCCESS in statuses:
        scoring_ok = _score(stdout)  # UC19, before the effective severity that falls back on the prediction
        changed = refresh_effective_severity()  # FR-06, before the alerts that use it
        if stdout:
            stdout.write(f"effective severity: {changed} CVEs updated")
        alerts_ok = _generate_alerts(run, watermark, stdout)
        warehouse_ok = _refresh_warehouse(stdout)  # UC21: last step, after the data and the alerts
    if not statuses or statuses == {RunStatus.SUCCESS}:
        run.status = RunStatus.SUCCESS
    elif statuses == {RunStatus.FAILED}:
        run.status = RunStatus.FAILED
    else:
        run.status = RunStatus.PARTIAL
    if run.status == RunStatus.SUCCESS and not (scoring_ok and alerts_ok and warehouse_ok):
        run.status = RunStatus.PARTIAL
    run.ended_at = timezone.now()
    run.save()
    return run


def _score(stdout=None) -> bool:
    """Scoring step (UC19, FR-23): the active M1 version predicts the severity of the CVEs without CVSS score.

    No active version: nothing to do. A failure (e.g. model file missing) makes the run PARTIAL,
    the previous predictions stay in place.
    """
    try:
        result = score_severity()
    except Exception as exc:  # noqa: BLE001 - logged, the loaded data stays valid
        if stdout:
            stdout.write(f"scoring: FAILED - {type(exc).__name__}: {exc}")
        return False
    if stdout:
        if result is None:
            stdout.write("scoring: no active M1 version, skipped (python manage.py train_m1 --activate)")
        else:
            stdout.write(f"scoring: {result.model} predicted the severity of {result.scored} CVEs without CVSS score")
    return True


def _generate_alerts(run, watermark, stdout=None) -> bool:
    """Alert step (FR-08, FR-10), after loading: new or updated CVEs of this run against every watchlist,
    then the priority score of every open alert (EPSS, KEV and severity change at each run)."""
    new_or_updated = Vulnerability.objects.all()
    if watermark:
        new_or_updated = new_or_updated.filter(source_updated_at__gt=watermark)
    try:
        result = generate_alerts(new_or_updated, run=run)
        scored = refresh_priority_scores()
    except Exception as exc:  # noqa: BLE001 - logged, the loaded data stays valid
        AlertGeneration.objects.create(run=run, error_message=f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc(limit=5)}")
        if stdout:
            stdout.write(f"alerts: FAILED - {type(exc).__name__}: {exc}")
        return False
    if stdout:
        stdout.write(
            f"alerts: {result.alerts_created} created for {result.cves_checked} new or updated CVEs, "
            f"{len(result.unmatched_names)} unmatched names to review, priority of {scored} open alerts refreshed"
        )
    return True


def _refresh_warehouse(stdout=None) -> bool:
    """Warehouse step (UC21, FR-16), last: rebuild the dw schema by SQL. A failure makes the run PARTIAL."""
    try:
        counts = refresh_warehouse()
    except Exception as exc:  # noqa: BLE001 - the loaded data stays valid, the dw keeps its previous content
        if stdout:
            stdout.write(f"warehouse: FAILED - {type(exc).__name__}: {exc}")
        return False
    if stdout:
        stdout.write("warehouse: refreshed - " + ", ".join(f"{table} {count}" for table, count in counts.items()))
    return True
