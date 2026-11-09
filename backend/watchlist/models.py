"""Watchlist of the organization's products (US07, FR-07) and the CNA name aliases used for matching (FR-08)."""

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from cti.models import Product


def normalize_name(value) -> str:
    """Same rule as the CVE List V5 connector: lowercase, single spaces, at most 200 characters."""
    return " ".join(str(value or "").split()).lower()[:200]


class Criticality(models.IntegerChoices):
    LOW = 1, "1 - Low"
    MEDIUM = 2, "2 - Medium"
    HIGH = 3, "3 - High"
    CRITICAL = 4, "4 - Critical"


class ProductAlias(models.Model):
    """A raw vendor / product name published by a CNA that designates a normalized product.

    Example: the product "fortinet / fortios" also appears as "fortinet, inc. / fortios"
    in some CVE records. With this alias, both spellings match the same watched product.
    """

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="aliases")
    raw_vendor = models.CharField(max_length=200)
    raw_product = models.CharField(max_length=200)

    class Meta:
        verbose_name_plural = "product aliases"
        ordering = ["raw_vendor", "raw_product"]
        constraints = [
            # One raw name designates one product only, otherwise matching would be ambiguous
            models.UniqueConstraint(fields=["raw_vendor", "raw_product"], name="uniq_alias_raw_name"),
        ]

    def save(self, *args, **kwargs):
        self.raw_vendor = normalize_name(self.raw_vendor)
        self.raw_product = normalize_name(self.raw_product)
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.raw_vendor} {self.raw_product} -> {self.product}"


class WatchlistItem(models.Model):
    """A product watched by an organization, with its business criticality (association class of the UML)."""

    organization = models.ForeignKey("accounts.Organization", on_delete=models.CASCADE, related_name="watchlist")
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="watchlist_items")
    criticality = models.PositiveSmallIntegerField(
        choices=Criticality.choices,
        default=Criticality.MEDIUM,
        validators=[MinValueValidator(1), MaxValueValidator(4)],
    )
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-criticality", "product__vendor", "product__name"]
        constraints = [
            models.UniqueConstraint(fields=["organization", "product"], name="uniq_watchlist_org_product"),
            models.CheckConstraint(condition=models.Q(criticality__gte=1, criticality__lte=4),
                                   name="watchlist_criticality_1_4"),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.product} ({self.criticality})"
