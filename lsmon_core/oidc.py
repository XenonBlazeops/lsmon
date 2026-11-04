"""Small, dependency-free OIDC authorization-code client for the TecstaqOps portal."""

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.db import transaction
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme

from .models import OIDCIdentity


class OIDCAuthenticationError(Exception):
    """A safe, user-facing sign-in failure."""


_JWK_CACHE = {"expires": 0, "keys": []}


def _b64decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_request(url, data=None):
    headers = {
        "Accept": "application/json",
        "User-Agent": settings.LSMON_OIDC_USER_AGENT,
    }
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    # Do not inherit a machine proxy. TLS certificate validation remains enabled.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _endpoints():
    base = settings.LSMON_OIDC_ISSUER.rstrip("/") + "/protocol/openid-connect"
    return {
        "authorization": base + "/auth",
        "token": base + "/token",
        "jwks": base + "/certs",
    }


def _next_url(request):
    candidate = request.GET.get("next") or request.session.get("oidc_next") or ""
    if candidate and url_has_allowed_host_and_scheme(candidate, {request.get_host()}, request.is_secure()):
        return candidate
    return reverse("dashboard")


def start(request):
    if not settings.LSMON_OIDC_ENABLED:
        return redirect("login")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    request.session["oidc_state"] = state
    request.session["oidc_nonce"] = nonce
    request.session["oidc_verifier"] = verifier
    request.session["oidc_next"] = request.GET.get("next", "")
    query = urllib.parse.urlencode({
        "client_id": settings.LSMON_OIDC_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": settings.LSMON_OIDC_REDIRECT_URI,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return redirect(_endpoints()["authorization"] + "?" + query)


def _jwk(kid):
    now = time.time()
    if now >= _JWK_CACHE["expires"]:
        document = _json_request(_endpoints()["jwks"])
        _JWK_CACHE["keys"] = document.get("keys", [])
        _JWK_CACHE["expires"] = now + 3600
    for key in _JWK_CACHE["keys"]:
        if key.get("kid") == kid and key.get("kty") == "RSA":
            return key
    raise OIDCAuthenticationError("The identity signing key was not recognised. Please try again.")


def _validate_id_token(token, expected_nonce):
    try:
        header_part, payload_part, signature_part = token.split(".")
        header = json.loads(_b64decode(header_part))
        claims = json.loads(_b64decode(payload_part))
        signature = _b64decode(signature_part)
    except Exception as exc:
        raise OIDCAuthenticationError("The identity response was invalid.") from exc
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise OIDCAuthenticationError("The identity response used an unsupported signing method.")
    key = _jwk(header["kid"])
    try:
        public_key = rsa.RSAPublicNumbers(
            int.from_bytes(_b64decode(key["e"]), "big"),
            int.from_bytes(_b64decode(key["n"]), "big"),
        ).public_key()
        public_key.verify(signature, (header_part + "." + payload_part).encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        raise OIDCAuthenticationError("The identity signature could not be validated.") from exc
    audience = claims.get("aud", [])
    if isinstance(audience, str):
        audience = [audience]
    now = int(time.time())
    if (
        claims.get("iss") != settings.LSMON_OIDC_ISSUER
        or settings.LSMON_OIDC_CLIENT_ID not in audience
        or claims.get("nonce") != expected_nonce
        or not isinstance(claims.get("exp"), int)
        or claims["exp"] <= now
        or (claims.get("iat") is not None and (not isinstance(claims["iat"], int) or claims["iat"] > now + 120))
    ):
        raise OIDCAuthenticationError("The identity response did not match this sign-in request.")
    if len(audience) > 1 and claims.get("azp") != settings.LSMON_OIDC_CLIENT_ID:
        raise OIDCAuthenticationError("The identity response was not issued to this application.")
    if not claims.get("sub") or not isinstance(claims.get("email"), str) or not claims.get("email_verified"):
        raise OIDCAuthenticationError("A verified email address is required for Portal access.")
    return claims


def _local_user_for_claims(claims):
    User = get_user_model()
    issuer = settings.LSMON_OIDC_ISSUER
    subject = claims["sub"]
    with transaction.atomic():
        identity = OIDCIdentity.objects.select_related("user").filter(issuer=issuer, subject=subject).first()
        if identity:
            return identity.user
        # New identities must match a Portal account provisioned by an administrator.
        user = User.objects.filter(email__iexact=claims["email"], is_active=True).order_by("id").first()
        if not user:
            raise OIDCAuthenticationError("Your Portal account has not been provisioned. Contact TecstaqOps support.")
        try:
            OIDCIdentity.objects.create(user=user, issuer=issuer, subject=subject)
        except Exception:
            identity = OIDCIdentity.objects.select_related("user").get(issuer=issuer, subject=subject)
            return identity.user
        return user


def callback(request):
    expected_state = request.session.pop("oidc_state", "")
    nonce = request.session.pop("oidc_nonce", "")
    verifier = request.session.pop("oidc_verifier", "")
    if not expected_state or not nonce or not verifier or not hmac.compare_digest(request.GET.get("state", ""), expected_state):
        raise OIDCAuthenticationError("This sign-in request has expired or was not recognised. Please start again.")
    code = request.GET.get("code", "")
    if not code:
        raise OIDCAuthenticationError("The identity service did not return a sign-in code.")
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.LSMON_OIDC_REDIRECT_URI,
        "client_id": settings.LSMON_OIDC_CLIENT_ID,
        "client_secret": settings.LSMON_OIDC_CLIENT_SECRET,
        "code_verifier": verifier,
    }).encode("ascii")
    try:
        tokens = _json_request(_endpoints()["token"], data)
    except Exception as exc:
        raise OIDCAuthenticationError("The identity service could not complete this sign-in. Please try again.") from exc
    claims = _validate_id_token(tokens.get("id_token", ""), nonce)
    user = _local_user_for_claims(claims)
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    return redirect(_next_url(request))
