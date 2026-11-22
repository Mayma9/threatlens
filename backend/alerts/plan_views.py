"""Weekly remediation plan pages (US13, FR-12). Analysts prepare the plan, a CISO approves it.

Each user only sees the plans of their own organization.
"""

from django.contrib import messages
from django.db.models import Count, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from . import plans
from .forms import PlanCreateForm, PlanReviewForm
from .models import OPEN_STATUSES, AlertStatus, RemediationPlan
from .views import AlertAccessMixin

SELECTABLE_SHOWN = 50


class PlanListView(AlertAccessMixin, View):
    template_name = "alerts/plan_list.html"

    def plans(self):
        return (
            RemediationPlan.objects.filter(organization=self.request.user.organization)
            .select_related("prepared_by", "validated_by")
            .annotate(alert_count=Count("alerts"),
                      fixed_count=Count("alerts", filter=Q(alerts__status=AlertStatus.FIXED)))
        )

    def get(self, request):
        return self.render(PlanCreateForm(initial={"week": timezone.localdate()}))

    def post(self, request):
        form = PlanCreateForm(request.POST)
        if form.is_valid():
            try:
                plan = plans.create_plan(request.user.organization, request.user, form.cleaned_data["week"])
            except plans.PlanError as exc:
                messages.warning(request, str(exc), extra_tags="Not created")
                return self.render(form, status=400)
            messages.success(request, f"Plan for the week of {plan.period_start:%d %b %Y} created. Add the alerts to fix.")
            return redirect("plans:detail", pk=plan.pk)
        messages.error(request, "Choose a date for the week of the plan.", extra_tags="Not created")
        return self.render(form, status=400)

    def render(self, form, status=200):
        context = {"form": form, "plans": self.plans(), "organization": self.request.user.organization}
        return render(self.request, self.template_name, context, status=status)


class PlanDetailView(AlertAccessMixin, View):
    template_name = "alerts/plan_detail.html"

    def get_plan(self, pk) -> RemediationPlan:
        try:
            pk = int(pk)
        except (TypeError, ValueError):
            raise Http404("Unknown plan")
        queryset = RemediationPlan.objects.filter(organization=self.request.user.organization)
        return get_object_or_404(queryset.select_related("prepared_by", "validated_by"), pk=pk)

    def get(self, request, pk):
        return self.render(self.get_plan(pk), PlanReviewForm())

    def post(self, request, pk):
        plan = self.get_plan(pk)
        action = request.POST.get("action")
        review_form = PlanReviewForm(request.POST if action in ("approve", "request_changes") else None)
        ids = request.POST.getlist("alerts")
        try:
            if action == "add":
                count = plans.add_alerts(plan, ids)
                message = f"{count} alert{'s' if count != 1 else ''} added to the plan."
            elif action == "remove":
                count = plans.remove_alerts(plan, ids)
                message = f"{count} alert{'s' if count != 1 else ''} removed from the plan."
            elif action == "submit":
                plans.submit(plan)
                message = "Plan submitted: a CISO can now approve it or request changes."
            elif action in ("approve", "request_changes") and review_form.is_valid():
                comment = review_form.cleaned_data["comment"]
                if action == "approve":
                    plans.approve(plan, request.user, comment)
                    message = "Plan approved."
                else:
                    plans.request_changes(plan, request.user, comment)
                    message = "Changes requested: the analysts can edit the plan again."
            else:
                raise plans.PlanError("Unknown action.")
        except plans.PlanError as exc:
            messages.warning(request, str(exc), extra_tags="Not saved")
            return self.render(plan, review_form, status=400)
        messages.success(request, message)
        return redirect("plans:detail", pk=plan.pk)

    def render(self, plan, review_form, status=200):
        user = self.request.user
        planned = list(
            plan.alerts.select_related("vulnerability__kev_entry", "watchlist_item__product", "assignee")
            .order_by("-priority_score", "due_date", "pk")
        )
        selectable = list(plans.selectable_alerts(plan)[:SELECTABLE_SHOWN + 1]) if plan.is_editable else []
        context = {
            "plan": plan,
            "planned": planned,
            "open_count": sum(1 for alert in planned if alert.status in OPEN_STATUSES),
            "fixed_count": sum(1 for alert in planned if alert.status == AlertStatus.FIXED),
            "selectable": selectable[:SELECTABLE_SHOWN],
            "more_selectable": len(selectable) > SELECTABLE_SHOWN,
            "review_form": review_form,
            "can_review": plan.status == "SUBMITTED" and user.is_ciso and user.pk != plan.prepared_by_id,
            "today": timezone.localdate(),
        }
        return render(self.request, self.template_name, context, status=status)
