"""Run the ETL pipeline: one IngestionTask per active source, a failing source never stops the others."""

from __future__ import annotations

import traceback

from django.utils import timezone

from .connectors import REGISTRY
from .models import IngestionTask, PipelineRun, RunStatus, Source


def ensure_sources() -> None:
    """Create the Source rows of the registered connectors (the admin can then disable them)."""
    for name, connector in REGISTRY.items():
        Source.objects.get_or_create(name=name, defaults={"label": connector.label, "url": connector.url})


def run_pipeline(*, sources=None, local_file=None, full=False, triggered_by=None, stdout=None) -> PipelineRun:
    ensure_sources()
    selected = [name for name in REGISTRY if not sources or name in sources]
    run = PipelineRun.objects.create(triggered_by=triggered_by)

    for name in selected:
        source = Source.objects.get(name=name)
        if not source.is_active:
            if stdout:
                stdout.write(f"{name}: source disabled, skipped")
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

    statuses = set(run.tasks.values_list("status", flat=True))
    if not statuses or statuses == {RunStatus.SUCCESS}:
        run.status = RunStatus.SUCCESS
    elif statuses == {RunStatus.FAILED}:
        run.status = RunStatus.FAILED
    else:
        run.status = RunStatus.PARTIAL
    run.ended_at = timezone.now()
    run.save()
    return run
