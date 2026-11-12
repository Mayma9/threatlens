"""Vulnerability search (US03) and enriched CVE record (US04). Analysts and CISOs (who inherit the analyst role)."""

from urllib.parse import urlencode

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Prefetch
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views import View

from accounts.models import Role
from accounts.permissions import RoleRequiredMixin

from .forms import VulnerabilitySearchForm
from .models import AffectedProduct, Vulnerability, VulnerabilityWeakness
from .search import search

PAGE_SIZE = 25


class VulnerabilitySearchView(RoleRequiredMixin, View):
    allowed_roles = [Role.ANALYST]
    template_name = "cti/search.html"

    def get(self, request):
        # Without any filter the page lists the newest CVEs
        form = VulnerabilitySearchForm(request.GET)
        context = {"form": form, "total": Vulnerability.objects.count()}
        if not form.is_valid():
            errors = form.non_field_errors()
            messages.error(request, errors[0] if errors else "Some filters are not valid. Check the highlighted fields.",
                           extra_tags="Search not run")
            return render(request, self.template_name, context, status=400)

        results = search(form.cleaned_data).select_related("kev_entry").prefetch_related("affected_products__product")
        page = Paginator(results, PAGE_SIZE).get_page(request.GET.get("page"))
        filters = {key: value for key, value in request.GET.items() if key != "page" and value}
        context.update(page=page, query_string=urlencode(filters), cve_searched=form.cleaned_data["cve"].strip().upper())
        return render(request, self.template_name, context)


class VulnerabilityDetailView(RoleRequiredMixin, View):
    """Enriched CVE record (US04, FR-05): description, every CVSS score, effective severity, EPSS, KEV and CWE."""

    allowed_roles = [Role.ANALYST]
    template_name = "cti/detail.html"

    def get(self, request, cve_id):
        cve_id = cve_id.strip().upper()
        vulnerability = (
            Vulnerability.objects.select_related("kev_entry")
            .prefetch_related(
                "cvss_metrics",
                Prefetch("affected_products", queryset=AffectedProduct.objects.select_related("product")
                         .order_by("product__vendor", "product__name")),
                Prefetch("weakness_links", queryset=VulnerabilityWeakness.objects.select_related("weakness")),
            )
            .filter(cve_id=cve_id)
            .first()
        )
        if vulnerability is None:
            # The search page explains why a CVE can be missing (reserved, rejected, published after the last run)
            return redirect(f"{reverse('cti:search')}?{urlencode({'cve': cve_id})}")

        metrics = vulnerability.ordered_metrics()
        context = {
            "vulnerability": vulnerability,
            "kev": getattr(vulnerability, "kev_entry", None),
            "metrics": metrics,
            "effective": metrics[0] if metrics else None,  # FR-06
            "weaknesses": vulnerability.ordered_weaknesses(),
            "affected": vulnerability.affected_products.all(),
            # EPSS values are probabilities (0-1), shown as percentages
            "epss_percent": None if vulnerability.epss_score is None else vulnerability.epss_score * 100,
            "epss_percentile": None if vulnerability.epss_percentile is None else vulnerability.epss_percentile * 100,
        }
        return render(request, self.template_name, context)
