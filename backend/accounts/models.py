from django.contrib.auth.models import AbstractUser
from django.db import models


class Organization(models.Model):
    """Organization whose products are monitored (reference scenario: a fictitious bank)."""

    name = models.CharField(max_length=200, unique=True)
    sector = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Role(models.TextChoices):
    ANALYST = "ANALYST", "Security analyst"
    CISO = "CISO", "CISO"
    ADMIN = "ADMIN", "Administrator"


# FR-02: the CISO has every analyst permission. The administrator is a separate role.
ROLE_HIERARCHY: dict[str, set[str]] = {
    Role.ANALYST: {Role.ANALYST},
    Role.CISO: {Role.CISO, Role.ANALYST},
    Role.ADMIN: {Role.ADMIN},
}


class User(AbstractUser):
    """Platform user with exactly one role (FR-01, FR-02)."""

    role = models.CharField(max_length=10, choices=Role.choices, default=Role.ANALYST)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.PROTECT,
        related_name="users",
        null=True,
        blank=True,
    )

    def has_role(self, role: str) -> bool:
        """True if the user's role grants `role` (a CISO also has the ANALYST role)."""
        if not self.is_active:
            return False
        return role in ROLE_HIERARCHY.get(self.role, set())

    def has_any_role(self, *roles: str) -> bool:
        return any(self.has_role(role) for role in roles)

    # Shortcuts for templates (templates cannot call methods with arguments)
    @property
    def is_analyst(self) -> bool:
        return self.has_role(Role.ANALYST)

    @property
    def is_ciso(self) -> bool:
        return self.has_role(Role.CISO)

    @property
    def is_platform_admin(self) -> bool:
        return self.has_role(Role.ADMIN)

    def save(self, *args, **kwargs):
        # FR-03: only administrators reach the Django admin, where accounts and roles are managed.
        if self.is_superuser:
            self.role = Role.ADMIN
        self.is_staff = self.role == Role.ADMIN
        super().save(*args, **kwargs)
