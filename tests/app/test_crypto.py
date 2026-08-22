from __future__ import annotations

import base64

import pytest

from notes_app.config import ConfigurationError, Settings, decode_master_key
from notes_app.crypto import DataProtectionError, NoteCipher


def test_note_cipher_uses_unique_nonces_for_identical_plaintext() -> None:
    cipher = NoteCipher(b"K" * 32)
    first_nonce, first_ciphertext = cipher.encrypt("same text", 7, "note-a", "body")
    second_nonce, second_ciphertext = cipher.encrypt("same text", 7, "note-a", "body")

    assert first_nonce != second_nonce
    assert first_ciphertext != second_ciphertext
    assert cipher.decrypt(first_nonce, first_ciphertext, 7, "note-a", "body", 1) == "same text"


@pytest.mark.parametrize(
    ("owner_id", "note_id", "field_name", "key_version"),
    [
        (8, "note-a", "body", 1),
        (7, "note-b", "body", 1),
        (7, "note-a", "title", 1),
        (7, "note-a", "body", 2),
    ],
)
def test_note_cipher_rejects_changed_authenticated_context(
    owner_id: int, note_id: str, field_name: str, key_version: int
) -> None:
    cipher = NoteCipher(b"K" * 32)
    nonce, ciphertext = cipher.encrypt("private text", 7, "note-a", "body")

    with pytest.raises(DataProtectionError):
        cipher.decrypt(nonce, ciphertext, owner_id, note_id, field_name, key_version)


def test_master_key_configuration_requires_urlsafe_base64_and_32_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = b"E" * 32
    encoded = base64.urlsafe_b64encode(key).decode("ascii")
    assert decode_master_key(encoded) == key
    with pytest.raises(ConfigurationError, match="valid URL-safe base64"):
        decode_master_key("not base64!")
    with pytest.raises(ConfigurationError, match="exactly 32 bytes"):
        decode_master_key(base64.urlsafe_b64encode(b"short").decode("ascii"))

    monkeypatch.delenv("NOTES_MASTER_KEY", raising=False)
    with pytest.raises(ConfigurationError, match="NOTES_MASTER_KEY is required"):
        Settings.from_env()
