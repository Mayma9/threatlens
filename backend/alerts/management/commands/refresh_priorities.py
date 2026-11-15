"""Recompute the priority score of every open alert (FR-10), e.g. after a change of PRIORITY_WEIGHTS.

The pipeline already does it at the end of each run.

    python manage.py refresh_priorities
"""

from django.core.management.base import BaseCommand

from alerts.priority import refresh_priority_scores


class Command(BaseCommand):
    help = "Recompute the priority score of every open alert."

    def handle(self, *args, **options):
        scored = refresh_priority_scores()
        self.stdout.write(self.style.SUCCESS(f"priority of {scored} open alerts refreshed"))
