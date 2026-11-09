"""Vulnerability search (US03, FR-04): CVE identifier, vendor, product, severity, KEV status, publication period."""

import re

from django.db.models import F

from .models import AffectedProduct, Product, Vulnerability

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
NO_SCORE = "UNSCORED"


def normalize(value) -> str:
    """Same rule as the names stored by the CVE connector: lowercase, single spaces."""
    return " ".join(str(value or "").split()).lower()


def search(filters: dict):
    """Vulnerabilities matching every filter given, newest publication first."""
    queryset = Vulnerability.objects.all()

    cve = (filters.get("cve") or "").strip().upper()
    if cve:
        # A full identifier finds that CVE; a start ("CVE-2024-3") lists the CVEs that begin with it
        queryset = queryset.filter(cve_id=cve) if CVE_ID.match(cve) else queryset.filter(cve_id__startswith=cve)

    vendor, product = normalize(filters.get("vendor")), normalize(filters.get("product"))
    if vendor or product:
        # Find the products first (small table), then their CVEs through the product index
        products = Product.objects.all()
        if vendor:
            products = products.filter(vendor__contains=vendor)
        if product:
            products = products.filter(name__contains=product)
        affected = AffectedProduct.objects.filter(product__in=products.values("id")).values("vulnerability_id")
        queryset = queryset.filter(id__in=affected)

    severity = filters.get("severity")
    if severity == NO_SCORE:
        queryset = queryset.filter(effective_severity="")
    elif severity:
        queryset = queryset.filter(effective_severity=severity)

    kev = filters.get("kev")
    if kev == "yes":
        queryset = queryset.filter(kev_entry__isnull=False)
    elif kev == "no":
        queryset = queryset.filter(kev_entry__isnull=True)

    if filters.get("published_from"):
        queryset = queryset.filter(published_at__date__gte=filters["published_from"])
    if filters.get("published_to"):
        queryset = queryset.filter(published_at__date__lte=filters["published_to"])

    return queryset.order_by(F("published_at").desc(nulls_last=True), "-id")
