"""Alert generation (US08, FR-08): after each pipeline run, the new or updated CVEs are matched
with every watchlist (product names and aliases) and one alert is created per CVE and watchlist item.

Due date of a new alert (rule proposed by the team, configurable in settings.ALERT_DUE_DAYS):
creation date + a number of days that depends on the effective severity (FR-06); when the CVE is
in the CISA KEV catalog and CISA's due date is earlier, CISA's due date is kept.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from cti.models import AffectedProduct, Product, Severity, Vulnerability
from watchlist.matching import known_names_and_hints, matching_product_ids
from watchlist.models import WatchlistItem

from .models import Alert, AlertGeneration, AlertStatus, AlertStatusChange

UNMATCHED_LIMIT = 50


def cve_watermark():
    """Most recent CVE update already loaded: CVEs updated after it are the new or updated ones of a run."""
    return Vulnerability.objects.aggregate(m=Max("source_updated_at"))["m"]


def due_date_for(vulnerability: Vulnerability, created_at):
    metric = vulnerability.effective_metric()
    severity = metric.severity if metric else "UNKNOWN"
    if severity == Severity.NONE:
        severity = Severity.LOW
    days = settings.ALERT_DUE_DAYS.get(severity, settings.ALERT_DUE_DAYS["UNKNOWN"])
    due = (created_at + timedelta(days=days)).date()
    kev = getattr(vulnerability, "kev_entry", None)
    if kev is not None and kev.due_date and kev.due_date < due:
        due = kev.due_date
    return due


def generate_alerts(vulnerabilities, *, run=None, now=None) -> AlertGeneration:
    """Create the missing alerts for these vulnerabilities and record the result.

    Never creates a second alert for the same CVE and watchlist item (unique constraint + check).
    """
    now = now or timezone.now()
    vulnerability_ids = vulnerabilities.values("id")  # sub-query: works for any number of CVEs
    items = list(WatchlistItem.objects.select_related("product", "organization").prefetch_related("product__aliases"))

    pairs = []  # (vulnerability_id, watchlist_item)
    for item in items:
        product_ids = matching_product_ids(item.product)
        hit_ids = set(
            AffectedProduct.objects.filter(product_id__in=product_ids, vulnerability_id__in=vulnerability_ids)
            .values_list("vulnerability_id", flat=True)
        )
        existing = set(
            Alert.objects.filter(watchlist_item=item, vulnerability_id__in=hit_ids).values_list("vulnerability_id", flat=True)
        )
        pairs += [(vulnerability_id, item) for vulnerability_id in sorted(hit_ids - existing)]

    details = Vulnerability.objects.filter(id__in={v for v, _ in pairs}).prefetch_related("cvss_metrics").select_related("kev_entry")
    details = {v.id: v for v in details}
    origin = f"pipeline run {run.pk}" if run else "the generate_alerts command"

    with transaction.atomic():
        alerts = Alert.objects.bulk_create([
            Alert(vulnerability_id=v, watchlist_item=item, created_at=now, status=AlertStatus.NEW,
                  due_date=due_date_for(details[v], now))
            for v, item in pairs
        ])
        AlertStatusChange.objects.bulk_create([
            AlertStatusChange(alert=alert, old_status="", new_status=AlertStatus.NEW, changed_at=now,
                              comment=f"Created by {origin}.")
            for alert in alerts
        ])
        return AlertGeneration.objects.create(
            run=run, created_at=now, cves_checked=vulnerabilities.count(), alerts_created=len(alerts),
            unmatched_names=unmatched_names_in(vulnerability_ids, items),
        )


def unmatched_names_in(vulnerability_ids, items, limit: int = UNMATCHED_LIMIT) -> list[str]:
    """Names in these CVEs that look like a watched product (any organization) but match no name or alias."""
    known, hints = known_names_and_hints(items)
    if hints is None:
        return []
    candidates = (
        Product.objects.filter(hints, affected_by__vulnerability_id__in=vulnerability_ids)
        .distinct().order_by("vendor", "name").values_list("vendor", "name")
    )
    names = []
    for vendor, name in candidates[: limit + len(known)]:
        if (vendor, name) not in known:
            names.append(f"{vendor} / {name}")
        if len(names) == limit:
            break
    return names
