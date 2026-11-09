"""Create alerts for CVEs published or updated since a date (first set-up of a watchlist, demonstration).

The pipeline already creates the alerts of its new or updated CVEs at the end of each run;
this command covers CVEs loaded before the products were added to the watchlist.
Existing alerts are never duplicated.

    python manage.py generate_alerts --since 2026-10-01
"""

from datetime import date, datetime, time

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from alerts.services import generate_alerts
from cti.models import Vulnerability


class Command(BaseCommand):
    help = "Create the missing alerts for CVEs published or updated since a date."

    def add_arguments(self, parser):
        parser.add_argument("--since", required=True, help="date YYYY-MM-DD (CVE record updated on or after it)")

    def handle(self, *args, since, **options):
        try:
            day = date.fromisoformat(since)
        except ValueError as exc:
            raise CommandError("--since expects a date such as 2026-10-01") from exc
        start = timezone.make_aware(datetime.combine(day, time.min))
        result = generate_alerts(Vulnerability.objects.filter(source_updated_at__gte=start))
        self.stdout.write(self.style.SUCCESS(
            f"{result.alerts_created} alerts created for {result.cves_checked} CVEs updated since {day}"
        ))
        for name in result.unmatched_names:
            self.stdout.write(f"  unmatched name: {name}")
