"""Create the demo organization and the three demo accounts used during validations.

    docker compose exec web python manage.py create_demo_users

The password comes from DEMO_USER_PASSWORD in .env. Running the command again
updates the accounts instead of duplicating them.
"""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from accounts.models import Organization, Role, User

DEMO_ORGANIZATION = {"name": "Demo Bank", "sector": "Banking", "country": "Tunisia"}

DEMO_USERS = [
    {"username": "analyst1", "role": Role.ANALYST, "first_name": "Demo", "last_name": "Analyst"},
    {"username": "ciso1", "role": Role.CISO, "first_name": "Demo", "last_name": "CISO"},
    {"username": "admin1", "role": Role.ADMIN, "first_name": "Demo", "last_name": "Admin"},
]


class Command(BaseCommand):
    help = "Create or update the demo organization and the accounts analyst1, ciso1 and admin1."

    def handle(self, *args, **options):
        password = settings.DEMO_USER_PASSWORD
        if not password:
            raise CommandError("Set DEMO_USER_PASSWORD in .env, then restart the containers.")

        organization, _ = Organization.objects.update_or_create(
            name=DEMO_ORGANIZATION["name"], defaults=DEMO_ORGANIZATION
        )

        for data in DEMO_USERS:
            user, created = User.objects.get_or_create(username=data["username"])
            user.role = data["role"]
            user.first_name = data["first_name"]
            user.last_name = data["last_name"]
            user.email = f"{data['username']}@demo-bank.example"
            user.organization = organization
            user.is_active = True
            # The demo administrator manages every account in the Django admin.
            user.is_superuser = data["role"] == Role.ADMIN
            user.set_password(password)
            user.save()
            action = "created" if created else "updated"
            self.stdout.write(self.style.SUCCESS(f"{user.username} ({user.role}) {action}"))
