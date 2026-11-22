from django import forms
from django.contrib.auth import get_user_model
from django.db.models import Q

from accounts.models import Role
from cti.forms import KEV_CHOICES, SEVERITY_CHOICES

from .models import AlertStatus

OPEN = "open"
STATUS_FILTER_CHOICES = [(OPEN, "Open (new or in progress)"), ("all", "All statuses")] + list(AlertStatus.choices)


class AlertFilterForm(forms.Form):
    """Filters of the prioritized list (FR-11): status, product, severity and KEV."""

    status = forms.ChoiceField(choices=STATUS_FILTER_CHOICES, required=False,
                               widget=forms.Select(attrs={"class": "form-select"}))
    item = forms.ChoiceField(label="Product", required=False, widget=forms.Select(attrs={"class": "form-select"}))
    severity = forms.ChoiceField(choices=SEVERITY_CHOICES, required=False,
                                 widget=forms.Select(attrs={"class": "form-select"}))
    kev = forms.ChoiceField(label="KEV status", choices=KEV_CHOICES, required=False,
                            widget=forms.Select(attrs={"class": "form-select"}))

    def __init__(self, *args, items=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["item"].choices = [("", "Every watched product")] + [(str(i.pk), str(i.product)) for i in items]


def assignable_users(organization):
    """Analysts and CISOs of the organization (FR-09: an alert has an assignee)."""
    return (
        get_user_model().objects.filter(organization=organization, is_active=True)
        .filter(Q(role=Role.ANALYST) | Q(role=Role.CISO))
        .order_by("username")
    )


class StatusChangeForm(forms.Form):
    status = forms.ChoiceField(label="Status", choices=AlertStatus.choices,
                               widget=forms.Select(attrs={"class": "form-select"}))
    assignee = forms.ModelChoiceField(queryset=None, required=False, empty_label="Nobody",
                                      widget=forms.Select(attrs={"class": "form-select"}))
    comment = forms.CharField(required=False, max_length=2000, widget=forms.Textarea(
        attrs={"class": "form-control", "rows": 3, "placeholder": "Why this status? e.g. patch planned on 2026-11-20"}))

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["assignee"].queryset = assignable_users(organization)
        self.fields["assignee"].label_from_instance = lambda user: f"{user.get_username()} ({user.get_role_display()})"


class PlanCreateForm(forms.Form):
    week = forms.DateField(label="Week of", widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
                           help_text="Any day of the week: the plan runs from Monday to Sunday.")


class PlanReviewForm(forms.Form):
    comment = forms.CharField(required=False, max_length=2000, widget=forms.Textarea(
        attrs={"class": "form-control", "rows": 3,
               "placeholder": "Required to request changes, e.g. add the KEV alerts on pan-os first"}))
