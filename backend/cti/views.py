"""Vulnerability search page (US03). Analysts and CISOs (who inherit the analyst role)."""

from urllib.parse import urlencode

from django.contrib import messages
from django.core.paginator import Paginator
from django.shortcuts import render
from django.views import View

from accounts.models import Role
from accounts.permissions import RoleRequiredMixin

from .forms import VulnerabilitySearchForm
from .models import Vulnerability
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
