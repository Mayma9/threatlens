"""Acceptance tests of US07: the analyst maintains the organization's watchlist (FR-07)."""

from django.test import TestCase
from django.urls import reverse

from accounts.models import Organization, Role
from accounts.tests.test_us01 import make_user
from cti.models import AffectedProduct, Product, Vulnerability
from watchlist.matching import affected_cve_count, unmatched_names
from watchlist.models import ProductAlias, WatchlistItem

LIST = reverse("watchlist:list")
UNMATCHED = reverse("watchlist:unmatched")


def affect(cve_id, vendor, name):
    """A CVE whose record names this (vendor, product)."""
    vulnerability, _ = Vulnerability.objects.get_or_create(cve_id=cve_id, defaults={"description": "test"})
    product, _ = Product.objects.get_or_create(vendor=vendor, name=name)
    AffectedProduct.objects.get_or_create(vulnerability=vulnerability, product=product)
    return product


class WatchlistTestCase(TestCase):
    def setUp(self):
        self.analyst = make_user("analyst", Role.ANALYST)
        self.org = self.analyst.organization
        self.client.force_login(self.analyst)

    def add(self, vendor="Fortinet", product="FortiOS", criticality=4):
        return self.client.post(LIST, {"vendor": vendor, "product": product, "criticality": criticality}, follow=True)


class AddProductTests(WatchlistTestCase):
    def test_product_is_stored_with_its_criticality(self):
        response = self.add(" Fortinet ", "FortiOS", 4)
        item = WatchlistItem.objects.get()
        self.assertEqual((item.product.vendor, item.product.name, item.criticality), ("fortinet", "fortios", 4))
        self.assertEqual(item.organization, self.org)
        self.assertContains(response, "fortinet fortios added to the watchlist.")

    def test_existing_product_is_reused(self):
        product = affect("CVE-2026-0001", "fortinet", "fortios")
        self.add()
        self.assertEqual(WatchlistItem.objects.get().product, product)

    def test_criticality_outside_1_to_4_is_refused(self):
        for value in (0, 5, "high"):
            response = self.add(criticality=value)
            self.assertEqual(response.status_code, 400)
            self.assertContains(response, "Select a valid choice", status_code=400)
        self.assertFalse(WatchlistItem.objects.exists())

    def test_duplicate_product_is_refused(self):
        self.add()
        response = self.add("FORTINET", "fortios", 2)
        self.assertContains(response, "fortinet fortios is already in your watchlist.", status_code=400)
        self.assertContains(response, 'data-level="error"', status_code=400)  # shown as a pop-up
        self.assertEqual(WatchlistItem.objects.count(), 1)

    def test_list_shows_affected_cves(self):
        affect("CVE-2026-0001", "fortinet", "fortios")
        affect("CVE-2026-0002", "fortinet", "fortios")
        self.add()
        response = self.client.get(LIST)
        self.assertContains(response, "fortios")
        self.assertEqual(response.context["rows"][0]["cves"], 2)

    def test_criticality_can_be_changed(self):
        self.add(criticality=2)
        item = WatchlistItem.objects.get()
        self.client.post(reverse("watchlist:item", args=[item.pk]), {"action": "criticality", "criticality": 3})
        item.refresh_from_db()
        self.assertEqual(item.criticality, 3)

    def test_product_can_be_removed(self):
        self.add()
        item = WatchlistItem.objects.get()
        response = self.client.post(reverse("watchlist:remove", args=[item.pk]), follow=True)
        self.assertFalse(WatchlistItem.objects.exists())
        self.assertContains(response, "removed from the watchlist")


class AliasTests(WatchlistTestCase):
    def setUp(self):
        super().setUp()
        self.add()
        self.item = WatchlistItem.objects.get()
        self.url = reverse("watchlist:item", args=[self.item.pk])

    def add_alias(self, vendor, product):
        return self.client.post(self.url, {"action": "alias", "raw_vendor": vendor, "raw_product": product}, follow=True)

    def test_alias_is_stored_and_used_for_matching(self):
        affect("CVE-2026-0001", "fortinet", "fortios")
        affect("CVE-2026-0002", "fortinet, inc.", "fortios")
        self.assertEqual(affected_cve_count(self.item.product), 1)
        response = self.add_alias("Fortinet, Inc.", "FortiOS")
        self.assertContains(response, "Alias fortinet, inc. fortios added")
        alias = ProductAlias.objects.get()
        self.assertEqual((alias.raw_vendor, alias.raw_product, alias.product), ("fortinet, inc.", "fortios", self.item.product))
        self.assertEqual(affected_cve_count(self.item.product), 2)

    def test_alias_cannot_repeat_the_product_name_or_another_alias(self):
        self.assertContains(self.add_alias("fortinet", "fortios"), "already the product", status_code=400)
        self.add_alias("fortinet inc", "fortios")
        self.assertContains(self.add_alias("Fortinet Inc", "FortiOS"), "already an alias of", status_code=400)
        self.assertEqual(ProductAlias.objects.count(), 1)

    def test_alias_can_be_removed(self):
        self.add_alias("fortinet inc", "fortios")
        alias = ProductAlias.objects.get()
        self.client.post(reverse("watchlist:remove-alias", args=[alias.pk]))
        self.assertFalse(ProductAlias.objects.exists())


class UnmatchedNamesTests(WatchlistTestCase):
    def setUp(self):
        super().setUp()
        affect("CVE-2026-0001", "fortinet", "fortios")
        affect("CVE-2026-0002", "fortinet, inc.", "fortios")
        affect("CVE-2026-0003", "fortinet, inc.", "fortios")
        affect("CVE-2026-0004", "apache software foundation", "tomcat")
        self.add()
        self.item = WatchlistItem.objects.get()

    def test_similar_unmatched_names_are_listed(self):
        names = [(p.vendor, p.name, p.cve_count) for p in unmatched_names(self.org)]
        self.assertEqual(names, [("fortinet, inc.", "fortios", 2)])  # the watched name itself and tomcat are not listed

    def test_search_finds_any_unmatched_name(self):
        response = self.client.get(UNMATCHED, {"q": "Tomcat"})
        self.assertContains(response, "apache software foundation")

    def test_unmatched_name_becomes_an_alias(self):
        response = self.client.post(UNMATCHED, {"item": self.item.pk, "raw_vendor": "fortinet, inc.",
                                                "raw_product": "fortios"}, follow=True)
        self.assertContains(response, "is now an alias of fortinet fortios")
        self.assertEqual(affected_cve_count(self.item.product), 3)
        self.assertEqual(unmatched_names(self.org), [])


class AccessTests(TestCase):
    def test_roles(self):
        self.assertEqual(self.client.get(LIST).status_code, 302)  # anonymous: login page
        self.client.force_login(make_user("admin", Role.ADMIN))
        self.assertEqual(self.client.get(LIST).status_code, 403)
        self.client.force_login(make_user("ciso", Role.CISO))  # a CISO is also an analyst
        self.assertEqual(self.client.get(LIST).status_code, 200)

    def test_each_organization_sees_only_its_watchlist(self):
        other = Organization.objects.create(name="Other Bank")
        product = Product.objects.create(vendor="cisco", name="ios xe")
        foreign = WatchlistItem.objects.create(organization=other, product=product, criticality=4)
        self.client.force_login(make_user("analyst", Role.ANALYST))
        self.assertNotContains(self.client.get(LIST), "ios xe")
        self.assertEqual(self.client.get(reverse("watchlist:item", args=[foreign.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse("watchlist:remove", args=[foreign.pk])).status_code, 404)
        self.assertTrue(WatchlistItem.objects.filter(pk=foreign.pk).exists())

    def test_user_without_organization_is_sent_home(self):
        user = make_user("lonely", Role.ANALYST)
        user.organization = None
        user.save()
        self.client.force_login(user)
        response = self.client.get(LIST, follow=True)
        self.assertRedirects(response, reverse("home"))
        self.assertContains(response, "not linked to an organization")


class SuggestionTests(WatchlistTestCase):
    def test_unmatched_name_suggests_the_closest_watched_product(self):
        affect("CVE-2026-0001", "gitlab", "gitlab ai gateway")
        affect("CVE-2026-0002", "red hat", "red hat enterprise linux 9")
        self.add("red hat", "enterprise linux")
        self.add("gitlab", "gitlab")
        items = {i.product.vendor: i.pk for i in WatchlistItem.objects.select_related("product")}
        suggestions = {p.name: p.suggested_item_id for p in unmatched_names(self.org)}
        self.assertEqual(suggestions["gitlab ai gateway"], items["gitlab"])
        self.assertEqual(suggestions["red hat enterprise linux 9"], items["red hat"])
