import hashlib
import secrets

from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone


def invitation_token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def issue_and_send(invitation):
    if not settings.EMAIL_HOST or not settings.DEFAULT_FROM_EMAIL or not settings.EMAIL_HOST_PASSWORD:
        raise RuntimeError("SMTP is not configured.")
    if invitation.accepted_at or invitation.revoked_at or invitation.expires_at <= timezone.now():
        raise RuntimeError("Invitation is no longer eligible for delivery.")
    token = secrets.token_urlsafe(32)
    invitation.token_hash = invitation_token_hash(token)
    invitation.save(update_fields=["token_hash"])
    link = "https://app.tecstaqops.com" + reverse("invitation_accept", args=[token])
    subject = f"Join {invitation.tenant.name} on TecstaqOps"
    body = (
        f"You have been invited to become the first Tenant Administrator for {invitation.tenant.name}.\n\n"
        f"Set your portal password and enroll Google Authenticator here:\n{link}\n\n"
        "This invitation expires in seven days. Do not forward this email."
    )
    send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [invitation.email], fail_silently=False)
    invitation.sent_at = timezone.now()
    invitation.save(update_fields=["sent_at"])
