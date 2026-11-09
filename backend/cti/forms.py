from django import forms

from .models import Severity
from .search import NO_SCORE

SEVERITY_CHOICES = [("", "Any severity")] + [
    (value, label) for value, label in Severity.choices if value != Severity.NONE
] + [(Severity.NONE, "None (score 0)"), (NO_SCORE, "No score yet")]
KEV_CHOICES = [("", "Any"), ("yes", "Exploited (in KEV)"), ("no", "Not in KEV")]


class VulnerabilitySearchForm(forms.Form):
    cve = forms.CharField(label="CVE identifier", required=False, max_length=32,
                          widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. CVE-2024-3400"}))
    vendor = forms.CharField(required=False, max_length=200,
                             widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. palo alto"}))
    product = forms.CharField(required=False, max_length=200,
                              widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. pan-os"}))
    severity = forms.ChoiceField(choices=SEVERITY_CHOICES, required=False,
                                 widget=forms.Select(attrs={"class": "form-select"}))
    kev = forms.ChoiceField(label="KEV status", choices=KEV_CHOICES, required=False,
                            widget=forms.Select(attrs={"class": "form-select"}))
    published_from = forms.DateField(label="Published from", required=False,
                                     widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}))
    published_to = forms.DateField(label="Published to", required=False,
                                   widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}))

    def clean(self):
        data = super().clean()
        start, end = data.get("published_from"), data.get("published_to")
        if start and end and start > end:
            raise forms.ValidationError("The publication period ends before it starts.", code="period")
        return data

    def has_filters(self) -> bool:
        return any(self.cleaned_data.get(name) for name in self.fields)
