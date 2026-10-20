from django.contrib import admin

from .models import IngestionTask, PipelineRun, Source


@admin.register(Source)
class SourceAdmin(admin.ModelAdmin):
    list_display = ("name", "label", "frequency", "is_active", "url")
    list_editable = ("frequency", "is_active")


class IngestionTaskInline(admin.TabularInline):
    model = IngestionTask
    extra = 0
    can_delete = False
    fields = ("source", "status", "extracted", "loaded", "rejected", "started_at", "ended_at")
    readonly_fields = fields
    show_change_link = True


@admin.register(PipelineRun)
class PipelineRunAdmin(admin.ModelAdmin):
    list_display = ("id", "started_at", "ended_at", "status", "triggered_by")
    list_filter = ("status",)
    readonly_fields = ("started_at", "ended_at", "status", "triggered_by")
    inlines = [IngestionTaskInline]


@admin.register(IngestionTask)
class IngestionTaskAdmin(admin.ModelAdmin):
    list_display = ("id", "run", "source", "status", "extracted", "loaded", "rejected", "started_at")
    list_filter = ("status", "source")
    readonly_fields = [f.name for f in IngestionTask._meta.fields]
