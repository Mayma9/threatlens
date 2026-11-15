from django.contrib import admin

from .models import (
    AffectedProduct,
    CVSSMetric,
    Indicator,
    KEVEntry,
    Malware,
    Product,
    Vulnerability,
    VulnerabilityWeakness,
    Weakness,
)


class CVSSMetricInline(admin.TabularInline):
    model = CVSSMetric
    extra = 0


class AffectedProductInline(admin.TabularInline):
    model = AffectedProduct
    extra = 0
    autocomplete_fields = ["product"]


class VulnerabilityWeaknessInline(admin.TabularInline):
    model = VulnerabilityWeakness
    extra = 0
    autocomplete_fields = ["weakness"]


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "published_at", "source_updated_at", "nvd_status", "epss_score")
    search_fields = ("cve_id",)
    date_hierarchy = "published_at"
    inlines = [CVSSMetricInline, AffectedProductInline, VulnerabilityWeaknessInline]
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


@admin.register(Weakness)
class WeaknessAdmin(admin.ModelAdmin):
    list_display = ("cwe_id", "name", "kind", "abstraction", "status")
    list_filter = ("kind", "abstraction", "status")
    search_fields = ("cwe_id", "name")


@admin.register(Malware)
class MalwareAdmin(admin.ModelAdmin):
    list_display = ("name", "malpedia_id", "category")
    list_filter = ("category",)
    search_fields = ("name", "malpedia_id")


@admin.register(Indicator)
class IndicatorAdmin(admin.ModelAdmin):
    """IOC values are shown as plain text, never as links (risk R9). Read-only: they come from ThreatFox."""

    list_display = ("threatfox_id", "ioc_type", "value", "threat_type", "malware", "confidence", "first_seen")
    list_filter = ("ioc_type", "threat_type")
    search_fields = ("value", "malware__name")
    date_hierarchy = "first_seen"
    raw_id_fields = ("malware",)
    show_full_result_count = False

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
