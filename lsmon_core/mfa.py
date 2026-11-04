import pyotp
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def _fernet():
    key = settings.LSMON_MFA_ENCRYPTION_KEY
    if not key:
        raise ImproperlyConfigured("LSMON_MFA_ENCRYPTION_KEY must be set before MFA enrollment.")
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError) as error:
        raise ImproperlyConfigured("LSMON_MFA_ENCRYPTION_KEY is not a valid Fernet key.") from error


def generate_secret():
    return pyotp.random_base32()


def encrypt_secret(secret):
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(ciphertext):
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as error:
        raise ImproperlyConfigured("Stored MFA secret cannot be decrypted with the active key.") from error


def provisioning_uri(secret, account_name):
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name="TecstaqOps")


def verify_code(ciphertext, code):
    normalized = "".join(character for character in code if character.isdigit())
    return len(normalized) == 6 and pyotp.TOTP(decrypt_secret(ciphertext)).verify(normalized, valid_window=1)
