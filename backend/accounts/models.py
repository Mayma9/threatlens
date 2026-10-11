from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """Custom user model, defined before the first migration.

    The role (ANALYST / CISO / ADMIN) and the organization are added in US01.
    """
