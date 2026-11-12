"""Rebuild the dw schema from the operational schema (UC21). The pipeline also calls it as its last step."""

from django.core.management.base import BaseCommand

from pipeline.services import ensure_sources
from pipeline.warehouse import refresh_warehouse


class Command(BaseCommand):
    help = "Create the dw tables if needed and rebuild them from the operational schema (ELT)."

    def handle(self, *args, **options):
        ensure_sources()  # dim_source needs the source rows, even before the first pipeline run
        counts = refresh_warehouse()
        rows = ", ".join(f"{table} {count}" for table, count in counts.items())
        self.stdout.write(self.style.SUCCESS(f"warehouse refreshed: {rows}"))
