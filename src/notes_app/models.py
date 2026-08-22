"""SQLAlchemy models for application state and security records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(16), default="user")
    created_at: Mapped[datetime]

    notes: Mapped[list[Note]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True, index=True)
    csrf_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    absolute_expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)

    user: Mapped[User] = relationship(back_populates="sessions")


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title_nonce: Mapped[bytes] = mapped_column(LargeBinary(12))
    title_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    body_nonce: Mapped[bytes] = mapped_column(LargeBinary(12))
    body_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]

    owner: Mapped[User] = relationship(back_populates="notes")

    __table_args__ = (Index("ix_notes_owner_updated", "owner_id", "updated_at"),)


class LoginThrottle(Base):
    __tablename__ = "login_throttles"

    id: Mapped[int] = mapped_column(primary_key=True)
    scope: Mapped[str] = mapped_column(String(16))
    identifier_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    window_started_at: Mapped[datetime]
    failures: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (UniqueConstraint("scope", "identifier_hash"),)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime]
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(16))
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_address_hash: Mapped[str] = mapped_column(String(64))
    correlation_id: Mapped[str] = mapped_column(String(36), index=True)
    event_data: Mapped[str] = mapped_column(Text, default="{}")
