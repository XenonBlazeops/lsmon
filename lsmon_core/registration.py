import hashlib
import hmac
import secrets


ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def generate_registration_code():
    groups = ["".join(secrets.choice(ALPHABET) for _ in range(4)) for _ in range(4)]
    return "LSM-" + "-".join(groups)


def hash_registration_code(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def registration_code_matches(code, expected_hash):
    return hmac.compare_digest(hash_registration_code(code), expected_hash)
