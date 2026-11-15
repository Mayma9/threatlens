"""Priority score of the alerts (FR-10, US11): a weighted mean of four factors, from 0 to 100.

The weights and the value used for a CVE without CVSS score are in settings.py
(PRIORITY_WEIGHTS, PRIORITY_UNSCORED_SEVERITY). The same function computes the score and
explains it on the alert page, so what the analyst reads is exactly what sorts the list.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings

from .models import OPEN_STATUSES, Alert


@dataclass(frozen=True)
class Factor:
    key: str
    label: str
    shown: str  # value as read by the analyst, e.g. "9.8 (CRITICAL)"
    value: float  # 0-1
    weight: float  # share of the score, 0-1 (weights are normalized to sum to 1)

    @property
    def points(self) -> float:
        return 100 * self.value * self.weight


def factors(vulnerability, criticality: int) -> list[Factor]:
    raw = settings.PRIORITY_WEIGHTS
    total = sum(raw.values()) or 1
    weight = {key: value / total for key, value in raw.items()}

    score = vulnerability.effective_score
    if score is None:
        severity = settings.PRIORITY_UNSCORED_SEVERITY
        severity_shown = "No CVSS score yet (neutral value)"
    else:
        severity = min(max(score / 10, 0), 1)
        severity_shown = f"{score:.1f} ({vulnerability.effective_severity or 'score'})"
    epss = vulnerability.epss_score
    in_kev = getattr(vulnerability, "kev_entry", None) is not None
    return [
        Factor("severity", "Effective severity", severity_shown, severity, weight["severity"]),
        Factor("exploitation", "Exploitation probability (EPSS)",
               "Not in the EPSS file" if epss is None else f"{epss * 100:.2f} %", epss or 0.0, weight["exploitation"]),
        Factor("kev", "In the CISA KEV catalog", "Yes" if in_kev else "No", 1.0 if in_kev else 0.0, weight["kev"]),
        Factor("criticality", "Criticality of the product", f"{criticality} / 4", (criticality - 1) / 3,
               weight["criticality"]),
    ]


def priority_score(vulnerability, criticality: int) -> float:
    return round(sum(f.points for f in factors(vulnerability, criticality)), 1)


def refresh_priority_scores(alerts=None) -> int:
    """Recompute the score of open alerts (EPSS, KEV, severity and criticality change over time).

    Closed alerts keep the score they had when they were closed. Returns the number of alerts scored.
    """
    if alerts is None:
        alerts = Alert.objects.all()
    alerts = list(
        alerts.filter(status__in=OPEN_STATUSES).select_related("vulnerability__kev_entry", "watchlist_item")
    )
    changed = []
    for alert in alerts:
        score = priority_score(alert.vulnerability, alert.watchlist_item.criticality)
        if score != alert.priority_score:
            alert.priority_score = score
            changed.append(alert)
    Alert.objects.bulk_update(changed, ["priority_score"], batch_size=1000)
    return len(alerts)
