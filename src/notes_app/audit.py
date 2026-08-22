"""Safe, structured application audit events."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from notes_app.crypto import short_safe_hash
from notes_app.models import AuditEvent

ALLOWED_DATA_KEYS = frozenset({"reason", "role", "page", "count"})


def client_address(request: Request) -> str:
    # Forwarded headers are deliberately ignored unless a trusted proxy layer normalizes them.
    return request.client.host if request.client else "unknown"


def record_event(
    db: Session,
    request: Request,
    *,
    now: datetime,
    event_type: str,
    outcome: str,
    actor_user_id: int | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    data: Mapping[str, Any] | None = None,
) -> AuditEvent:
    if data and not set(data).issubset(ALLOWED_DATA_KEYS):
        raise ValueError("audit event contains a disallowed data field")
    settings = request.app.state.settings
    event = AuditEvent(
        occurred_at=now,
        event_type=event_type,
        outcome=outcome,
        actor_user_id=actor_user_id,
        target_type=target_type,
        target_id=target_id,
        client_address_hash=short_safe_hash(
            settings.master_key, b"audit-client", client_address(request)
        ),
        correlation_id=request.state.correlation_id,
        event_data=json.dumps(data or {}, sort_keys=True, separators=(",", ":")),
    )
    db.add(event)
    return event
