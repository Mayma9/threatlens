"""Watchlist pages (US07): list and add products, criticality, aliases, unmatched names.

Only analysts (and CISOs, who inherit the analyst role) can open them, and each user only
sees the watchlist of their own organization.
"""

from urllib.parse import urlencode

from django.contrib import messages
from django.db.models import Count, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View

from accounts.models import Role
from accounts.permissions import RoleRequiredMixin
from alerts.models import OPEN_STATUSES

from .forms import AliasForm, CriticalityForm, WatchlistItemForm
from .matching import affected_cve_count, unmatched_names
from .models import ProductAlias, WatchlistItem, normalize_name


def form_error_message(form) -> str:
    """One sentence for the SweetAlert pop-up: the form-wide error if any, otherwise a pointer to the fields."""
    errors = form.non_field_errors()
    return errors[0] if errors else "Some fields are not valid. Check the highlighted fields and try again."


class WatchlistAccessMixin(RoleRequiredMixin):
    allowed_roles = [Role.ANALYST]

    def dispatch(self, request, *args, **kwargs):
        user = request.user
        if user.is_authenticated and user.has_any_role(*self.allowed_roles) and user.organization_id is None:
            messages.error(request, "Your account is not linked to an organization. Ask an administrator to set it.")
            return redirect("home")
        return super().dispatch(request, *args, **kwargs)

    @property
    def organization(self):
        return self.request.user.organization

    def items(self):
        return WatchlistItem.objects.filter(organization=self.organization).select_related("product")

    def get_item(self, pk) -> WatchlistItem:
        try:
            pk = int(pk)
        except (TypeError, ValueError):
            raise Http404("Unknown watchlist item")
        return get_object_or_404(self.items(), pk=pk)  # another organization's item gives 404


class WatchlistView(WatchlistAccessMixin, View):
    template_name = "watchlist/watchlist.html"

    def get(self, request):
        return self.render(WatchlistItemForm(organization=self.organization))

    def post(self, request):
        form = WatchlistItemForm(request.POST, organization=self.organization)
        if form.is_valid():
            item = form.save()
            messages.success(request, f"{item.product} added to the watchlist.")
            return redirect("watchlist:list")
        messages.error(request, form_error_message(form), extra_tags="Not saved")
        return self.render(form, status=400)

    def render(self, form, status=200):
        rows = []
        items = self.items().prefetch_related("product__aliases").annotate(
            open_alerts=Count("alerts", filter=Q(alerts__status__in=OPEN_STATUSES)))
        for item in items:
            rows.append({"item": item, "aliases": len(item.product.aliases.all()),
                         "cves": affected_cve_count(item.product), "open_alerts": item.open_alerts})
        context = {"form": form, "rows": rows, "organization": self.organization}
        return render(self.request, self.template_name, context, status=status)


class WatchlistItemView(WatchlistAccessMixin, View):
    """One watched product: change its criticality, add or remove aliases."""

    template_name = "watchlist/item_detail.html"

    def get(self, request, pk):
        item = self.get_item(pk)
        return self.render(item, CriticalityForm(instance=item), AliasForm(product=item.product))

    def post(self, request, pk):
        item = self.get_item(pk)
        criticality_form = CriticalityForm(instance=item)
        alias_form = AliasForm(product=item.product)
        if request.POST.get("action") == "criticality":
            criticality_form = CriticalityForm(request.POST, instance=item)
            if criticality_form.is_valid():
                criticality_form.save()
                messages.success(request, f"Criticality of {item.product} set to {item.get_criticality_display()}.")
                return redirect("watchlist:item", pk=item.pk)
            messages.error(request, form_error_message(criticality_form), extra_tags="Not saved")
        else:
            alias_form = AliasForm(request.POST, product=item.product)
            if alias_form.is_valid():
                alias = alias_form.save()
                messages.success(request, f"Alias {alias.raw_vendor} {alias.raw_product} added to {item.product}.")
                return redirect("watchlist:item", pk=item.pk)
            messages.error(request, form_error_message(alias_form), extra_tags="Not saved")
        return self.render(item, criticality_form, alias_form, status=400)

    def render(self, item, criticality_form, alias_form, status=200):
        context = {
            "item": item,
            "aliases": item.product.aliases.all(),
            "cves": affected_cve_count(item.product),
            "criticality_form": criticality_form,
            "alias_form": alias_form,
        }
        return render(self.request, self.template_name, context, status=status)


class WatchlistItemDeleteView(WatchlistAccessMixin, View):
    def post(self, request, pk):
        item = self.get_item(pk)
        item.delete()
        messages.success(request, f"{item.product} removed from the watchlist.")
        return redirect("watchlist:list")


class AliasDeleteView(WatchlistAccessMixin, View):
    def post(self, request, pk):
        # Only aliases of a product the organization watches
        alias = get_object_or_404(
            ProductAlias.objects.filter(product__watchlist_items__organization=self.organization).distinct(), pk=pk
        )
        item = self.items().get(product=alias.product)
        alias.delete()
        messages.success(request, f"Alias {alias.raw_vendor} {alias.raw_product} removed.")
        return redirect("watchlist:item", pk=item.pk)


class UnmatchedNamesView(WatchlistAccessMixin, View):
    """Names found in CVE records that match nothing in the watchlist; one click turns a name into an alias."""

    template_name = "watchlist/unmatched.html"

    def get(self, request):
        query = request.GET.get("q", "")
        context = {
            "query": query,
            "names": unmatched_names(self.organization, query),
            "items": list(self.items()),
        }
        return render(request, self.template_name, context)

    def post(self, request):
        item = self.get_item(request.POST.get("item"))
        form = AliasForm(request.POST, product=item.product)
        if form.is_valid():
            alias = form.save()
            messages.success(request, f"{alias.raw_vendor} {alias.raw_product} is now an alias of {item.product}.")
        else:
            messages.error(request, form_error_message(form), extra_tags="Not saved")
        url = reverse("watchlist:unmatched")
        query = normalize_name(request.POST.get("q", ""))
        return redirect(f"{url}?{urlencode({'q': query})}" if query else url)

