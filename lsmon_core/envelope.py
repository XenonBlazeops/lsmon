"""Public-key envelope helpers; private keys stay on the endpoint."""
import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding as symmetric_padding

PUBLIC_KEY_LENGTH = 32


def _raw(value):
    try:
        return base64.urlsafe_b64decode((value or "") + "=" * (-len(value or "") % 4))
    except (ValueError, TypeError):
        raise ValueError("Invalid endpoint public key.") from None


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_public_key(value, algorithm="x25519"):
    raw = _raw(value)
    if algorithm == "x25519":
        if len(raw) != PUBLIC_KEY_LENGTH:
            raise ValueError("Invalid endpoint public key.")
        return raw
    if algorithm == "rsa-csp-public-v1":
        try:
            data = json.loads(raw.decode("utf-8"))
            if set(data) != {"modulus", "exponent"}:
                raise ValueError
            result = rsa.RSAPublicNumbers(int.from_bytes(_raw(data["exponent"]), "big"), int.from_bytes(_raw(data["modulus"]), "big")).public_key()
        except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
            raise ValueError("Invalid endpoint public key.") from None
        if result.key_size < 3072:
            raise ValueError("Invalid endpoint public key.")
        return result
    if algorithm == "rsa-pem-public-v1":
        try:
            result = serialization.load_pem_public_key(_raw(value))
        except (TypeError, ValueError):
            raise ValueError("Invalid endpoint public key.") from None
        if not isinstance(result, rsa.RSAPublicKey) or result.key_size < 3072:
            raise ValueError("Invalid endpoint public key.")
        return result
    raise ValueError("Invalid endpoint key algorithm.")


def public_key_fingerprint(value, algorithm="x25519"):
    raw = _raw(value)
    decode_public_key(value, algorithm)
    return hashlib.sha256(raw).hexdigest()


def generate_delivery_token():
    return secrets.token_urlsafe(32)


def hash_delivery_token(token):
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def seal_configuration(endpoint_public_key, configuration, *, context, algorithm="x25519"):
    """Return an encrypted transport envelope without logging plaintext."""
    if algorithm in {"rsa-csp-public-v1", "rsa-pem-public-v1"}:
        recipient = decode_public_key(endpoint_public_key, algorithm)
        aad = f"lsmon-agent-delivery-v1:{context}".encode("utf-8")
        encryption_key, mac_key, iv = secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_bytes(16)
        padder = symmetric_padding.PKCS7(128).padder()
        plaintext = json.dumps(configuration, separators=(",", ":"), sort_keys=True).encode("utf-8")
        encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padder.update(plaintext) + padder.finalize()) + encryptor.finalize()
        authenticator = hmac.HMAC(mac_key, hashes.SHA256())
        authenticator.update(aad + iv + ciphertext)
        wrapped = recipient.encrypt(encryption_key + mac_key, asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return json.dumps({"version": 2, "algorithm": "rsa-oaep-sha256+a256cbc-hs256", "encrypted_key": _b64(wrapped), "iv": _b64(iv), "ciphertext": _b64(ciphertext), "tag": _b64(authenticator.finalize())}, separators=(",", ":"), sort_keys=True)
    if algorithm != "x25519":
        raise ValueError("Unsupported endpoint key algorithm.")
    recipient = X25519PublicKey.from_public_bytes(decode_public_key(endpoint_public_key))
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    shared = ephemeral.exchange(recipient)
    aad = f"lsmon-agent-delivery-v1:{context}".encode("utf-8")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=aad).derive(shared)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(configuration, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return json.dumps({"version": 1, "ephemeral_public_key": _b64(ephemeral_public), "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)}, separators=(",", ":"), sort_keys=True)
