from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import Organization, User


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "sector", "country")
    search_fields = ("name",)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("username", "email", "role", "organization", "is_active", "last_login")
    list_filter = ("role", "organization", "is_active")
    fieldsets = BaseUserAdmin.fieldsets + (("ThreatLens", {"fields": ("role", "organization")}),)
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ("ThreatLens", {"fields": ("role", "organization")}),
    )
