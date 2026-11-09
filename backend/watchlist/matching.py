"""Matching between the watchlist and the products named in CVE records (FR-08, risk R10).

A watched product matches the CVE-record products whose (vendor, name) is either the
product's own name or one of its aliases. US08 (alerts) reuses these functions.
"""

from functools import reduce
from operator import or_

from django.db.models import Count, Q

from cti.models import AffectedProduct, Product

from .models import ProductAlias, WatchlistItem

UNMATCHED_LIMIT = 50


def names_of(product: Product) -> set[tuple[str, str]]:
    """The product's own (vendor, name) and every alias."""
    names = {(product.vendor, product.name)}
    names.update((a.raw_vendor, a.raw_product) for a in product.aliases.all())
    return names


def _any_name(names) -> Q:
    return reduce(or_, (Q(vendor=v, name=n) for v, n in names), Q(pk__in=[]))


def matching_product_ids(product: Product) -> list[int]:
    """Ids of the CVE-record products designated by this product or its aliases."""
    return list(Product.objects.filter(_any_name(names_of(product))).values_list("id", flat=True))


def affected_cve_count(product: Product) -> int:
    """Number of distinct CVEs that affect the product, through its name or its aliases."""
    return (
        AffectedProduct.objects.filter(product_id__in=matching_product_ids(product))
        .values("vulnerability_id").distinct().count()
    )


def _main_word(text: str) -> str:
    """Longest word of a name, used to find other spellings ("fortinet, inc." -> "fortinet")."""
    words = [w.strip(".,()-_/") for w in text.split()]
    return max(words, key=len, default="")


def unmatched_names(organization, query: str = "", limit: int = UNMATCHED_LIMIT):
    """Names found in CVE records that match no watched product nor alias of the organization.

    Without a query, only names that look like a watched product are listed (same main vendor
    word, or the product name inside), so the analyst reviews likely spellings first.
    """
    items = list(WatchlistItem.objects.filter(organization=organization).select_related("product")
                 .prefetch_related("product__aliases"))
    # A raw name that is already an alias (of any product) cannot become a second alias
    known = set(ProductAlias.objects.values_list("raw_vendor", "raw_product"))
    hints = []
    for item in items:
        known |= names_of(item.product)
        word = _main_word(item.product.vendor)
        if len(word) >= 3:
            hints.append(Q(vendor__icontains=word))
        if len(item.product.name) >= 4:
            hints.append(Q(name__icontains=item.product.name))

    query = " ".join(query.split()).lower()
    if query:
        condition = Q(vendor__icontains=query) | Q(name__icontains=query)
    elif hints:
        condition = reduce(or_, hints)
    else:
        return []

    candidates = (
        Product.objects.filter(condition)
        .annotate(cve_count=Count("affected_by__vulnerability", distinct=True))
        .filter(cve_count__gt=0)
        .order_by("-cve_count", "vendor", "name")
    )
    result = []
    for product in candidates[: limit + len(known)]:
        if (product.vendor, product.name) not in known:
            product.suggested_item_id = _closest_item_id(product, items)
            result.append(product)
        if len(result) == limit:
            break
    return result


def _closest_item_id(product: Product, items) -> int | None:
    """The watched item the name most likely designates: same product name first, then same main vendor word."""
    for item in items:
        if len(item.product.name) >= 4 and item.product.name in product.name:
            return item.pk
    for item in items:
        word = _main_word(item.product.vendor)
        if len(word) >= 3 and word in product.vendor:
            return item.pk
    return None
