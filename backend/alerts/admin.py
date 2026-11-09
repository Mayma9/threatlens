from django.contrib import admin

from .models import Alert, AlertGeneration, AlertStatusChange


class AlertStatusChangeInline(admin.TabularInline):
    model = AlertStatusChange
    extra = 0
    can_delete = False
    fields = ("changed_at", "old_status", "new_status", "changed_by", "comment")
    readonly_fields = fields

    def has_add_permission(self, request, obj=None):
        return False  # the history is written by the application, never by hand


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("vulnerability", "product", "organization", "status", "due_date", "created_at")
    list_filter = ("status", "watchlist_item__organization")
    search_fields = ("vulnerability__cve_id", "watchlist_item__product__vendor", "watchlist_item__product__name")
    raw_id_fields = ("vulnerability", "watchlist_item", "assignee")
    inlines = [AlertStatusChangeInline]

    @admin.display(ordering="watchlist_item__product__name")
    def product(self, alert):
        return alert.watchlist_item.product

    @admin.display(ordering="watchlist_item__organization__name")
    def organization(self, alert):
        return alert.watchlist_item.organization

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "vulnerability", "watchlist_item__product", "watchlist_item__organization")


@admin.register(AlertGeneration)
class AlertGenerationAdmin(admin.ModelAdmin):
    list_display = ("created_at", "run", "cves_checked", "alerts_created", "unmatched_count")
    readonly_fields = ("run", "created_at", "cves_checked", "alerts_created", "unmatched_names", "error_message")

    @admin.display(description="unmatched names")
    def unmatched_count(self, generation):
        return len(generation.unmatched_names)

    def has_add_permission(self, request):
        return False
