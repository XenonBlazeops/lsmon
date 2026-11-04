from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Send a controlled SMTP delivery test without displaying credentials."

    def add_arguments(self, parser):
        parser.add_argument("--to", required=True)

    def handle(self, *args, **options):
        if not settings.EMAIL_HOST or not settings.DEFAULT_FROM_EMAIL or not settings.EMAIL_HOST_PASSWORD:
            raise CommandError("SMTP is not configured.")
        send_mail(
            "TecstaqOps SMTP delivery test",
            "This is a controlled TecstaqOps SMTP test. No action is required.",
            settings.DEFAULT_FROM_EMAIL,
            [options["to"]],
            fail_silently=False,
        )
        self.stdout.write(self.style.SUCCESS("SMTP_DELIVERY_TEST_SENT"))
