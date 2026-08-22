"""Password, session, CSRF, and login-throttling controls."""

from __future__ import annotations

import hmac
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type
from fastapi import Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from notes_app.audit import client_address
from notes_app.config import Settings
from notes_app.crypto import keyed_hash, new_signed_csrf, random_token, valid_signed_csrf
from notes_app.models import LoginThrottle, User, UserSession

GENERIC_LOGIN_ERROR = "Unable to sign in with those credentials."


def normalize_username(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold()


def valid_username(value: str) -> bool:
    if not 3 <= len(value) <= 64:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
    return all(character in allowed for character in value)


def password_policy_error(password: str) -> str | None:
    if len(password) < 12:
        return "Password must contain at least 12 characters."
    if len(password) > 128:
        return "Password must contain no more than 128 characters."
    return None


def password_hasher(settings: Settings) -> PasswordHasher:
    return PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost_kib,
        parallelism=settings.argon2_parallelism,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )


def verify_password(hasher: PasswordHasher, stored_hash: str, supplied_password: str) -> bool:
    try:
        return hasher.verify(stored_hash, supplied_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


@dataclass(slots=True)
class AuthenticatedSession:
    user: User
    record: UserSession


def create_session(
    db: Session,
    settings: Settings,
    user: User,
    now: datetime,
) -> tuple[UserSession, str, str]:
    raw_token = random_token()
    csrf_token = new_signed_csrf(settings.master_key)
    record = UserSession(
        token_hash=keyed_hash(settings.master_key, b"session-token", raw_token),
        csrf_hash=keyed_hash(settings.master_key, b"csrf-session", csrf_token),
        user_id=user.id,
        created_at=now,
        last_seen_at=now,
        absolute_expires_at=now + timedelta(seconds=settings.session_absolute_seconds),
    )
    db.add(record)
    db.flush()
    return record, raw_token, csrf_token


def authenticate_session(
    db: Session,
    settings: Settings,
    raw_token: str | None,
    now: datetime,
    *,
    touch: bool = True,
) -> AuthenticatedSession | None:
    if not raw_token:
        return None
    token_hash = keyed_hash(settings.master_key, b"session-token", raw_token)
    record = db.scalar(
        select(UserSession).where(
            UserSession.token_hash == token_hash,
            UserSession.revoked_at.is_(None),
        )
    )
    if record is None:
        return None
    idle_deadline = record.last_seen_at + timedelta(seconds=settings.session_idle_seconds)
    if now >= record.absolute_expires_at or now >= idle_deadline:
        record.revoked_at = now
        db.commit()
        return None
    user = db.get(User, record.user_id)
    if user is None:
        record.revoked_at = now
        db.commit()
        return None
    if touch:
        record.last_seen_at = now
        db.commit()
    return AuthenticatedSession(user=user, record=record)


def revoke_session(db: Session, record: UserSession, now: datetime) -> None:
    record.revoked_at = now
    db.flush()


def csrf_is_valid(
    settings: Settings,
    record: UserSession | None,
    cookie_value: str | None,
    form_value: str | None,
) -> bool:
    if not cookie_value or not form_value:
        return False
    if not hmac.compare_digest(cookie_value, form_value):
        return False
    if not valid_signed_csrf(settings.master_key, form_value):
        return False
    if record is None:
        return True
    supplied_hash = keyed_hash(settings.master_key, b"csrf-session", form_value)
    return hmac.compare_digest(record.csrf_hash, supplied_hash)


def throttle_hash(settings: Settings, scope: str, value: str) -> bytes:
    return keyed_hash(settings.master_key, f"login-{scope}".encode(), value)


def throttle_keys(request: Request, username: str) -> tuple[tuple[str, bytes], tuple[str, bytes]]:
    settings: Settings = request.app.state.settings
    return (
        ("account", throttle_hash(settings, "account", username)),
        ("address", throttle_hash(settings, "address", client_address(request))),
    )


def is_login_locked(db: Session, keys: tuple[tuple[str, bytes], ...], now: datetime) -> bool:
    for scope, identifier_hash in keys:
        record = db.scalar(
            select(LoginThrottle).where(
                LoginThrottle.scope == scope,
                LoginThrottle.identifier_hash == identifier_hash,
            )
        )
        if record and record.locked_until and now < record.locked_until:
            return True
    return False


def record_login_failure(
    db: Session,
    settings: Settings,
    keys: tuple[tuple[str, bytes], ...],
    now: datetime,
) -> None:
    window = timedelta(seconds=settings.login_window_seconds)
    for scope, identifier_hash in keys:
        record = db.scalar(
            select(LoginThrottle).where(
                LoginThrottle.scope == scope,
                LoginThrottle.identifier_hash == identifier_hash,
            )
        )
        if record is None:
            record = LoginThrottle(
                scope=scope,
                identifier_hash=identifier_hash,
                window_started_at=now,
                failures=0,
            )
            db.add(record)
        elif now >= record.window_started_at + window:
            record.window_started_at = now
            record.failures = 0
            record.locked_until = None
        record.failures += 1
        if record.failures >= settings.login_max_failures:
            record.locked_until = now + timedelta(seconds=settings.lockout_seconds)
    db.flush()


def clear_account_throttle(db: Session, settings: Settings, username: str) -> None:
    db.execute(
        delete(LoginThrottle).where(
            LoginThrottle.scope == "account",
            LoginThrottle.identifier_hash == throttle_hash(settings, "account", username),
        )
    )
