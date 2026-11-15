"""Weekly remediation plan (US13, FR-12): the analyst selects open alerts, the CISO approves the plan
or requests changes with a comment. The preparer, the approval date and the approver are recorded.

Rules (team decisions, Sprint 3):
- one plan per organization and week (Monday to Sunday);
- an alert is in at most one plan (alerts.plan); an open alert of an earlier week's plan can be moved
  into a later plan, so a fix that slipped is planned again;
- the plan can be changed while it is DRAFT or CHANGES_REQUESTED, and is locked once submitted;
- only a CISO approves or requests changes, and never on a plan they prepared (four-eyes principle).
"""

from __future__ import annotations

from datetime import date, timedelta

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from .models import OPEN_STATUSES, Alert, PlanStatus, RemediationPlan


class PlanError(ValueError):
    """An action refused by the workflow; the message is shown to the user."""


def week_of(day: date) -> tuple[date, date]:
    monday = day - timedelta(days=day.weekday())
    return monday, monday + timedelta(days=6)


def create_plan(organization, user, day: date) -> RemediationPlan:
    start, end = week_of(day)
    try:
        with transaction.atomic():
            return RemediationPlan.objects.create(organization=organization, period_start=start, period_end=end,
                                                  prepared_by=user)
    except IntegrityError as exc:
        raise PlanError(f"A plan already exists for the week of {start:%d %b %Y}.") from exc


def selectable_alerts(plan: RemediationPlan):
    """Open alerts of the organization that are in no plan, or in the plan of an earlier week."""
    return (
        Alert.objects.filter(watchlist_item__organization=plan.organization, status__in=OPEN_STATUSES)
        .filter(Q(plan__isnull=True) | Q(plan__period_end__lt=plan.period_start))
        .select_related("vulnerability__kev_entry", "watchlist_item__product", "plan")
        .order_by("-priority_score", "due_date", "pk")
    )


def _check_editable(plan: RemediationPlan) -> None:
    if not plan.is_editable:
        raise PlanError(f"This plan is {plan.get_status_display().lower()}: it can no longer be changed.")


def add_alerts(plan: RemediationPlan, alert_ids) -> int:
    _check_editable(plan)
    return selectable_alerts(plan).filter(pk__in=alert_ids).update(plan=plan)


def remove_alerts(plan: RemediationPlan, alert_ids) -> int:
    _check_editable(plan)
    return Alert.objects.filter(plan=plan, pk__in=alert_ids).update(plan=None)


def submit(plan: RemediationPlan) -> None:
    _check_editable(plan)
    if not plan.alerts.exists():
        raise PlanError("Add at least one alert before submitting the plan.")
    plan.status = PlanStatus.SUBMITTED
    plan.submitted_at = timezone.now()
    plan.save(update_fields=["status", "submitted_at"])


def _check_reviewer(plan: RemediationPlan, user) -> None:
    if plan.status != PlanStatus.SUBMITTED:
        raise PlanError("Only a submitted plan can be approved or sent back.")
    if not user.is_ciso:
        raise PlanError("Only a CISO can approve a plan or request changes.")
    if user.pk == plan.prepared_by_id:
        raise PlanError("You prepared this plan: another CISO must review it.")


def approve(plan: RemediationPlan, user, comment: str = "") -> None:
    _check_reviewer(plan, user)
    plan.status = PlanStatus.APPROVED
    plan.validated_at = timezone.now()
    plan.validated_by = user
    plan.ciso_comment = comment.strip()
    plan.save(update_fields=["status", "validated_at", "validated_by", "ciso_comment"])


def request_changes(plan: RemediationPlan, user, comment: str) -> None:
    _check_reviewer(plan, user)
    if not comment.strip():
        raise PlanError("Explain the changes you request in the comment.")
    plan.status = PlanStatus.CHANGES_REQUESTED
    plan.ciso_comment = comment.strip()
    plan.save(update_fields=["status", "ciso_comment"])
