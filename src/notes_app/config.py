"""Application configuration loaded from explicit environment values."""

from __future__ import annotations

import base64
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(ValueError):
    """Raised when required configuration is missing or invalid."""


def decode_master_key(value: str) -> bytes:
    """Decode a URL-safe base64 master key and require exactly 256 bits."""
    try:
        key = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ConfigurationError("NOTES_MASTER_KEY must be valid URL-safe base64") from exc
    if len(key) != 32:
        raise ConfigurationError("NOTES_MASTER_KEY must decode to exactly 32 bytes")
    return key


def _positive_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigurationError(f"{name} must be at least {minimum}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated runtime settings.

    Tests construct this object directly with an ephemeral key. Runtime startup uses
    :meth:`from_env` so the encryption key is never supplied by source code.
    """

    master_key: bytes
    database_url: str = "sqlite+pysqlite:///notes-demo.db"
    environment: str = "development"
    session_idle_seconds: int = 900
    session_absolute_seconds: int = 28_800
    login_max_failures: int = 5
    login_window_seconds: int = 300
    lockout_seconds: int = 900
    max_request_bytes: int = 20_000
    max_notes_per_user: int = 100
    max_title_chars: int = 120
    max_note_chars: int = 10_000
    page_size: int = 20
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 65_536
    argon2_parallelism: int = 4
    cookie_name: str = "notes_session"
    csrf_cookie_name: str = "notes_csrf"
    template_dir: Path | None = None
    static_dir: Path | None = None

    def __post_init__(self) -> None:
        if len(self.master_key) != 32:
            raise ConfigurationError("master_key must contain exactly 32 bytes")
        if self.environment not in {"development", "test", "production"}:
            raise ConfigurationError("environment must be development, test, or production")
        positive_fields = (
            "session_idle_seconds",
            "session_absolute_seconds",
            "login_max_failures",
            "login_window_seconds",
            "lockout_seconds",
            "max_request_bytes",
            "max_notes_per_user",
            "max_title_chars",
            "max_note_chars",
            "page_size",
            "argon2_time_cost",
            "argon2_memory_cost_kib",
            "argon2_parallelism",
        )
        for field_name in positive_fields:
            if getattr(self, field_name) < 1:
                raise ConfigurationError(f"{field_name} must be positive")
        if self.session_idle_seconds > self.session_absolute_seconds:
            raise ConfigurationError("idle timeout cannot exceed absolute timeout")

    @property
    def secure_cookies(self) -> bool:
        """Only explicit development mode permits cookies over loopback HTTP."""
        return self.environment != "development"

    def validate_bind_host(self, host: str) -> None:
        """Reject a non-loopback development or test binding."""
        candidate = host.strip().removeprefix("[").removesuffix("]")
        if candidate.casefold() == "localhost":
            return
        try:
            is_loopback = ipaddress.ip_address(candidate).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback and self.environment != "production":
            raise ConfigurationError(
                "non-loopback binding requires NOTES_ENV=production and external HTTPS"
            )

    @classmethod
    def from_env(cls) -> Settings:
        encoded_key = os.getenv("NOTES_MASTER_KEY")
        if not encoded_key:
            raise ConfigurationError(
                "NOTES_MASTER_KEY is required; run scripts/generate_development_key.py"
            )
        return cls(
            master_key=decode_master_key(encoded_key),
            database_url=os.getenv("NOTES_DATABASE_URL", "sqlite+pysqlite:///notes-demo.db"),
            environment=os.getenv("NOTES_ENV", "development").lower(),
            session_idle_seconds=_positive_int("NOTES_SESSION_IDLE_SECONDS", 900),
            session_absolute_seconds=_positive_int("NOTES_SESSION_ABSOLUTE_SECONDS", 28_800),
            login_max_failures=_positive_int("NOTES_LOGIN_MAX_FAILURES", 5),
            lockout_seconds=_positive_int("NOTES_LOCKOUT_SECONDS", 900),
            max_request_bytes=_positive_int("NOTES_MAX_REQUEST_BYTES", 20_000),
            max_notes_per_user=_positive_int("NOTES_MAX_NOTES_PER_USER", 100),
        )


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]
