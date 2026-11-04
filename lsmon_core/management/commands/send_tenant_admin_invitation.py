from django.core.management.base import BaseCommand, CommandError

from lsmon_core.invitations import issue_and_send
from lsmon_core.models import TenantAdminInvitation


class Command(BaseCommand):
    help = "Issue and email a pending first Tenant Administrator invitation."

    def add_arguments(self, parser):
        parser.add_argument("--tenant", required=True)
        parser.add_argument("--email", required=True)

    def handle(self, *args, **options):
        invitation = TenantAdminInvitation.objects.filter(
            tenant__name__iexact=options["tenant"].strip(), email__iexact=options["email"].strip()
        ).order_by("-created_at").first()
        if not invitation:
            raise CommandError("No pending invitation exists for that tenant and email.")
        try:
            issue_and_send(invitation)
        except RuntimeError as error:
            raise CommandError(str(error)) from error
        self.stdout.write(self.style.SUCCESS("TENANT_ADMIN_INVITATION_SENT"))
