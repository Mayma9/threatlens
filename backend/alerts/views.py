"""Prioritized alert list and alert page (US11, FR-09 to FR-11).

Analysts (and CISOs, who inherit the analyst role) only see the alerts of their own organization.
"""

from urllib.parse import urlencode

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from accounts.models import Role
from accounts.permissions import RoleRequiredMixin
from cti.search import NO_SCORE

from .forms import OPEN, AlertFilterForm, StatusChangeForm
from .models import OPEN_STATUSES, Alert
from .priority import factors
from .services import change_status

PAGE_SIZE = 25


class AlertAccessMixin(RoleRequiredMixin):
    allowed_roles = [Role.ANALYST]

    def dispatch(self, request, *args, **kwargs):
        user = request.user
        if user.is_authenticated and user.has_any_role(*self.allowed_roles) and user.organization_id is None:
            messages.error(request, "Your account is not linked to an organization. Ask an administrator to set it.")
            return redirect("home")
        return super().dispatch(request, *args, **kwargs)

    def alerts(self):
        return Alert.objects.filter(watchlist_item__organization=self.request.user.organization).select_related(
            "vulnerability__kev_entry", "watchlist_item__product", "assignee")


class AlertListView(AlertAccessMixin, View):
    """FR-11: open alerts sorted by priority score, with filters on status, product, severity and KEV."""

    template_name = "alerts/alert_list.html"

    def get(self, request):
        items = request.user.organization.watchlist.select_related("product").order_by("product__vendor", "product__name")
        form = AlertFilterForm(request.GET or None, items=items)
        alerts = self.alerts()
        status = OPEN
        if form.is_valid():
            data = form.cleaned_data
            status = data["status"] or OPEN
            if data["item"]:
                alerts = alerts.filter(watchlist_item_id=data["item"])
            if data["severity"] == NO_SCORE:
                alerts = alerts.filter(vulnerability__effective_score__isnull=True)
            elif data["severity"]:
                alerts = alerts.filter(vulnerability__effective_severity=data["severity"])
            if data["kev"] == "yes":
                alerts = alerts.filter(vulnerability__kev_entry__isnull=False)
            elif data["kev"] == "no":
                alerts = alerts.filter(vulnerability__kev_entry__isnull=True)
        if status == OPEN:
            alerts = alerts.filter(status__in=OPEN_STATUSES)
        elif status != "all":
            alerts = alerts.filter(status=status)
        alerts = alerts.order_by("-priority_score", "due_date", "pk")
        page = Paginator(alerts, PAGE_SIZE).get_page(request.GET.get("page"))
        filters = {key: value for key, value in request.GET.items() if key != "page" and value}
        context = {
            "form": form, "page": page, "query_string": urlencode(filters), "today": timezone.localdate(),
            "showing_open": status == OPEN, "organization": request.user.organization,
        }
        return render(request, self.template_name, context)


class AlertDetailView(AlertAccessMixin, View):
    """FR-09: status, assignee and history of one alert; the priority score is explained (FR-10)."""

    template_name = "alerts/alert_detail.html"

    def get_alert(self, pk) -> Alert:
        try:
            pk = int(pk)
        except (TypeError, ValueError):
            raise Http404("Unknown alert")
        return get_object_or_404(self.alerts(), pk=pk)  # another organization's alert gives 404

    def get(self, request, pk):
        alert = self.get_alert(pk)
        form = StatusChangeForm(organization=request.user.organization,
                                initial={"status": alert.status, "assignee": alert.assignee})
        return self.render(alert, form)

    def post(self, request, pk):
        alert = self.get_alert(pk)
        form = StatusChangeForm(request.POST, organization=request.user.organization)
        if form.is_valid():
            data = form.cleaned_data
            try:
                changes = change_status(alert, new_status=data["status"], user=request.user,
                                        comment=data["comment"], assignee=data["assignee"])
            except ValueError as exc:
                messages.warning(request, str(exc), extra_tags="Not saved")
                return self.render(alert, form, status=400)
            messages.success(request, f"{alert.vulnerability.cve_id} on {alert.watchlist_item.product}: "
                                      + ", ".join(changes) + ".")
            return redirect("alerts:detail", pk=alert.pk)
        messages.error(request, "Some fields are not valid. Check the highlighted fields and try again.",
                       extra_tags="Not saved")
        return self.render(alert, form, status=400)

    def render(self, alert, form, status=200):
        context = {
            "alert": alert,
            "form": form,
            "factors": factors(alert.vulnerability, alert.watchlist_item.criticality),
            "history": alert.history.select_related("changed_by").order_by("-changed_at", "-pk"),
            "today": timezone.localdate(),
        }
        return render(self.request, self.template_name, context, status=status)
