from django import forms

from cti.models import Product

from .models import Criticality, ProductAlias, WatchlistItem, normalize_name

TEXT = {"class": "form-control"}


class MarkInvalidMixin:
    """Adds Bootstrap's is-invalid class to the fields that have errors (red border)."""

    def is_valid(self):
        valid = super().is_valid()
        for name in self.errors:
            if name in self.fields:
                widget = self.fields[name].widget
                widget.attrs["class"] = f"{widget.attrs.get('class', '')} is-invalid".strip()
        return valid


class WatchlistItemForm(MarkInvalidMixin, forms.Form):
    """Add a normalized product (vendor, product) with its criticality to the organization's watchlist."""

    vendor = forms.CharField(max_length=200, widget=forms.TextInput(attrs={**TEXT, "placeholder": "e.g. microsoft"}))
    product = forms.CharField(max_length=200, widget=forms.TextInput(attrs={**TEXT, "placeholder": "e.g. exchange server"}))
    criticality = forms.TypedChoiceField(
        choices=Criticality.choices, coerce=int, initial=Criticality.MEDIUM,
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    def __init__(self, *args, organization, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)

    def clean_vendor(self):
        return normalize_name(self.cleaned_data["vendor"])

    def clean_product(self):
        return normalize_name(self.cleaned_data["product"])

    def clean(self):
        data = super().clean()
        vendor, name = data.get("vendor"), data.get("product")
        if vendor and name and WatchlistItem.objects.filter(
            organization=self.organization, product__vendor=vendor, product__name=name
        ).exists():
            raise forms.ValidationError(f"{vendor} {name} is already in your watchlist.", code="duplicate")
        return data

    def save(self) -> WatchlistItem:
        product, _ = Product.objects.get_or_create(vendor=self.cleaned_data["vendor"], name=self.cleaned_data["product"])
        return WatchlistItem.objects.create(
            organization=self.organization, product=product, criticality=self.cleaned_data["criticality"]
        )


class CriticalityForm(MarkInvalidMixin, forms.ModelForm):
    class Meta:
        model = WatchlistItem
        fields = ["criticality"]
        widgets = {"criticality": forms.Select(attrs={"class": "form-select"})}


class AliasForm(MarkInvalidMixin, forms.ModelForm):
    """Raw vendor and product names, as published by a CNA, that designate the watched product."""

    class Meta:
        model = ProductAlias
        fields = ["raw_vendor", "raw_product"]
        labels = {"raw_vendor": "Raw vendor name", "raw_product": "Raw product name"}
        widgets = {
            "raw_vendor": forms.TextInput(attrs={**TEXT, "placeholder": "e.g. microsoft corporation"}),
            "raw_product": forms.TextInput(attrs={**TEXT, "placeholder": "e.g. microsoft exchange server 2019"}),
        }

    def __init__(self, *args, product, **kwargs):
        self.product = product
        super().__init__(*args, **kwargs)

    def clean_raw_vendor(self):
        return normalize_name(self.cleaned_data["raw_vendor"])

    def clean_raw_product(self):
        return normalize_name(self.cleaned_data["raw_product"])

    def clean(self):
        data = super().clean()
        vendor, name = data.get("raw_vendor"), data.get("raw_product")
        if not (vendor and name):
            return data
        if (vendor, name) == (self.product.vendor, self.product.name):
            raise forms.ValidationError("This is already the product's own name.", code="same_name")
        existing = ProductAlias.objects.filter(raw_vendor=vendor, raw_product=name).select_related("product").first()
        if existing:
            raise forms.ValidationError(f"{vendor} {name} is already an alias of {existing.product}.", code="duplicate")
        return data

    def validate_unique(self):
        pass  # checked in clean() with a clearer message

    def save(self, commit=True):
        self.instance.product = self.product
        return super().save(commit=commit)
