"""Model versions in the Django admin (US15, FR-26): the administrator reviews the metrics and activates a version.

Versions are created by the training commands (train_m1) and kept as history: they cannot be added, edited
or deleted here. Activating a version deactivates the other versions of the same task; the next scoring
(pipeline run or score_m1) uses it.
"""

import json

from django.contrib import admin, messages
from django.utils.html import format_html, format_html_join

from .models import MLModel, MLTask
from .scoring import artifact_path

# Metrics shown first on the page of a version, when they exist (dotted path, label)
KEY_METRICS = [
    ("macro_f1", "Test macro-F1"),
    ("retrained_each_quarter.macro_f1", "Test macro-F1, retrained each quarter"),
    ("target_macro_f1", "Indicative target (FR-23)"),
    ("accuracy", "Accuracy"),
    ("right_or_one_class_away", "Right or one class away"),
    ("pr_auc", "PR-AUC"),
    ("periods.test", "Test period"),
    ("sizes.test", "Test CVEs"),
    ("features", "Features"),
    ("label", "Label"),
]


CLASS_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def metric(metrics: dict, path: str):
    """metrics["a"]["b"] for the path "a.b"; None when a part is missing."""
    value = metrics
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def shown(value) -> str:
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value:,}"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


@admin.register(MLModel)
class MLModelAdmin(admin.ModelAdmin):
    list_display = ("__str__", "task", "algorithm", "main_metric", "trained_at", "is_active")
    list_filter = ("task", "is_active")
    ordering = ("task", "-trained_at")
    actions = ["activate_version"]
    fieldsets = (
        ("Version", {"fields": ("name", "version", "task", "algorithm", "trained_at", "is_active", "activation",
                                "artifact", "file_on_this_machine")}),
        ("Metrics on the test period", {"fields": ("metrics_summary", "all_metrics")}),
    )
    readonly_fields = ("name", "version", "task", "algorithm", "trained_at", "is_active", "activation", "artifact",
                       "file_on_this_machine", "metrics_summary", "all_metrics")

    # The training commands create the versions; the history is kept (FR-26)
    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def change_view(self, request, object_id, form_url="", extra_context=None):
        # Every field is read-only: no Save button (activation is an action of the list)
        extra_context = {**(extra_context or {}), "show_save": False, "show_save_and_continue": False,
                         "show_save_and_add_another": False}
        return super().change_view(request, object_id, form_url, extra_context)

    @admin.display(description="Activation")
    def activation(self, obj):
        if obj.is_active:
            return "This version is used by the scoring of its task."
        return ("Not used. To activate it: in the list of ML models, tick this version, choose "
                "\"Activate the selected version\" and click Run.")

    @admin.display(description="Main metric")
    def main_metric(self, obj):
        if obj.metrics.get("macro_f1") is not None:
            return f"macro-F1 {obj.metrics['macro_f1']:.3f}"
        if obj.metrics.get("pr_auc") is not None:
            return f"PR-AUC {obj.metrics['pr_auc']:.3f}"
        return "-"

    @admin.display(description="Model file on this machine", boolean=True)
    def file_on_this_machine(self, obj):
        return artifact_path(obj).exists()

    @admin.display(description="Main metrics")
    def metrics_summary(self, obj):
        rows = [(label, shown(value)) for path, label in KEY_METRICS
                if (value := metric(obj.metrics, path)) is not None]
        by_class = obj.metrics.get("f1_by_class")
        if isinstance(by_class, dict):  # PostgreSQL (jsonb) does not keep the order of the keys
            order = {name: i for i, name in enumerate(CLASS_ORDER)}
            ordered = sorted(by_class.items(), key=lambda item: order.get(item[0], len(order)))
            rows.append(("F1 by class", " · ".join(f"{name} {score:.3f}" for name, score in ordered)))
        if not rows:
            return "-"
        return format_html("<table>{}</table>", format_html_join(
            "", "<tr><th style='padding-right:1.5rem'>{}</th><td>{}</td></tr>", rows))

    @admin.display(description="All metrics (JSON)")
    def all_metrics(self, obj):
        return format_html("<pre style='max-height:30rem;overflow:auto'>{}</pre>",
                           json.dumps(obj.metrics, indent=2, ensure_ascii=False, sort_keys=True))

    @admin.action(description="Activate the selected version (used by the next scoring)", permissions=["change"])
    def activate_version(self, request, queryset):
        if queryset.count() != 1:
            self.message_user(request, "Select exactly one version to activate.", messages.ERROR)
            return
        model = queryset.get()
        if model.is_active:
            self.message_user(request, f"Version {model} is already active.", messages.INFO)
            return
        if not artifact_path(model).exists():
            self.message_user(
                request,
                f"Version {model} was not activated: its file {model.artifact} is missing on this machine "
                "(train the model again on this machine).",
                messages.ERROR,
            )
            return
        previous = MLModel.objects.filter(task=model.task, is_active=True).first()
        model.activate()
        self.log_change(request, model, f"Activated (previous active version: {previous or 'none'})")
        now = " To predict now: python manage.py score_m1." if model.task == MLTask.SEVERITY else ""
        self.message_user(
            request,
            f"Version {model} is now active for {model.get_task_display()} (previous: {previous or 'none'}). "
            f"The next pipeline run predicts with it.{now}",
            messages.SUCCESS,
        )
