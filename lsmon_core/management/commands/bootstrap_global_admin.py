from getpass import getpass

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from lsmon_core.models import MFAProfile, Membership


class Command(BaseCommand):
    help = "Create the first individual Global Admin account without displaying a password or TOTP secret."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)

    def handle(self, *args, **options):
        email = options["email"].strip().lower()
        if "@" not in email:
            raise CommandError("--email must be a valid individual email address.")
        user_model = get_user_model()
        if user_model.objects.filter(username=email).exists():
            raise CommandError("An account with this email already exists; do not overwrite it with this command.")
        password = getpass("Set a new portal password: ")
        confirm_password = getpass("Confirm the new portal password: ")
        if len(password) < 16:
            raise CommandError("Use a password of at least 16 characters.")
        if password != confirm_password:
            raise CommandError("Passwords do not match.")
        user = user_model.objects.create_user(username=email, email=email, password=password)
        Membership.objects.create(user=user, role=Membership.Role.GLOBAL_ADMIN)
        MFAProfile.objects.create(user=user)
        self.stdout.write(self.style.SUCCESS(
            "Global Admin created. Sign in through the HTTPS portal to enroll Google Authenticator; no TOTP secret was printed."
        ))
