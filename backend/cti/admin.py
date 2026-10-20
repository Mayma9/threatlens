from django.contrib import admin

from .models import AffectedProduct, CVSSMetric, KEVEntry, Product, Vulnerability


class CVSSMetricInline(admin.TabularInline):
    model = CVSSMetric
    extra = 0


class AffectedProductInline(admin.TabularInline):
    model = AffectedProduct
    extra = 0
    autocomplete_fields = ["product"]


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "published_at", "source_updated_at", "nvd_status", "epss_score")
    search_fields = ("cve_id",)
    date_hierarchy = "published_at"
    inlines = [CVSSMetricInline, AffectedProductInline]
    show_full_result_count = False  # avoids a COUNT(*) on ~300,000 rows at every page


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ("vendor", "name", "cpe_prefix")
    search_fields = ("vendor", "name")
    show_full_result_count = False


@admin.register(KEVEntry)
class KEVEntryAdmin(admin.ModelAdmin):
    list_display = ("vulnerability", "date_added", "due_date", "ransomware_use")
    list_filter = ("ransomware_use",)
    search_fields = ("vulnerability__cve_id",)
    raw_id_fields = ("vulnerability",)


@admin.register(CVSSMetric)
class CVSSMetricAdmin(admin.ModelAdmin):
    list_display = ("vulnerability", "provider", "version", "base_score", "severity")
    list_filter = ("provider", "version", "severity")
    search_fields = ("vulnerability__cve_id",)
    raw_id_fields = ("vulnerability",)
    show_full_result_count = False
