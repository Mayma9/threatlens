from django.contrib import admin

from .models import ProductAlias, WatchlistItem


@admin.register(WatchlistItem)
class WatchlistItemAdmin(admin.ModelAdmin):
    list_display = ("product", "organization", "criticality", "added_at")
    list_filter = ("organization", "criticality")
    search_fields = ("product__vendor", "product__name")
    raw_id_fields = ("product",)  # the product table holds more than 100,000 rows


@admin.register(ProductAlias)
class ProductAliasAdmin(admin.ModelAdmin):
    list_display = ("raw_vendor", "raw_product", "product")
    search_fields = ("raw_vendor", "raw_product", "product__vendor", "product__name")
    raw_id_fields = ("product",)
