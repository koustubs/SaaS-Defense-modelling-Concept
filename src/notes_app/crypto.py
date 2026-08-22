"""Domain-separated cryptographic operations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DataProtectionError(RuntimeError):
    """Raised when encrypted application data cannot be authenticated."""


def _derive_key(master_key: bytes, purpose: bytes) -> bytes:
    return hmac.new(master_key, b"notes-demo:" + purpose, hashlib.sha256).digest()


def keyed_hash(master_key: bytes, purpose: bytes, value: str) -> bytes:
    key = _derive_key(master_key, purpose)
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


def short_safe_hash(master_key: bytes, purpose: bytes, value: str) -> str:
    return keyed_hash(master_key, purpose, value).hex()[:24]


def random_token(byte_count: int = 32) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(byte_count)).rstrip(b"=").decode("ascii")


def new_signed_csrf(master_key: bytes) -> str:
    random_part = random_token()
    signature = keyed_hash(master_key, b"csrf-signature", random_part)
    signature_part = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{random_part}.{signature_part}"


def valid_signed_csrf(master_key: bytes, value: str) -> bool:
    try:
        random_part, supplied_signature = value.split(".", maxsplit=1)
    except ValueError:
        return False
    if not random_part or not supplied_signature:
        return False
    expected = (
        base64.urlsafe_b64encode(keyed_hash(master_key, b"csrf-signature", random_part))
        .rstrip(b"=")
        .decode("ascii")
    )
    return hmac.compare_digest(expected, supplied_signature)


class NoteCipher:
    """AES-256-GCM field encryption with owner/note/field binding."""

    key_version = 1

    def __init__(self, master_key: bytes) -> None:
        self._cipher = AESGCM(master_key)

    @staticmethod
    def _aad(owner_id: int, note_id: str, field_name: str, key_version: int) -> bytes:
        return f"notes-demo:v{key_version}:{owner_id}:{note_id}:{field_name}".encode()

    def encrypt(
        self, plaintext: str, owner_id: int, note_id: str, field_name: str
    ) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        ciphertext = self._cipher.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            self._aad(owner_id, note_id, field_name, self.key_version),
        )
        return nonce, ciphertext

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        owner_id: int,
        note_id: str,
        field_name: str,
        key_version: int,
    ) -> str:
        if key_version != self.key_version:
            raise DataProtectionError("unsupported note key version")
        try:
            plaintext = self._cipher.decrypt(
                nonce,
                ciphertext,
                self._aad(owner_id, note_id, field_name, key_version),
            )
        except InvalidTag as exc:
            raise DataProtectionError("note authentication failed") from exc
        return plaintext.decode("utf-8")
