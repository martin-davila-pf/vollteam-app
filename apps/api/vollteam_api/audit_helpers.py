"""Audit helper: every administrative mutation calls this once.

Centralizing keeps the format uniform so future dashboards can filter by
action without column archaeology.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session as DBSession

from vollteam_api.audit import AuditEvent
from vollteam_api.models import User


def record_audit(
    db: DBSession | None,
    *,
    actor: User | None = None,
    action: str = "",
    target_type: str = "",
    target_id: str = "",
    detail: dict[str, Any] | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Append an audit event, in one of two modes.

    - db given  → the row joins the caller's transaction; success-path audits
                  (CREATE_USER with its business change) commit atomically.
    - db None   → the helper opens its own session and commits. Used for
      audits that must SURVIVE request rejection: the 401 login makes the
      request transaction roll back, and a in-transaction audit row would
      die with it — but a rejected login IS the event worth recording.
    """
    event = AuditEvent(
        id=uuid.uuid4().hex,
        actor_id=actor.id if actor else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
        ip=ip,
        user_agent=user_agent,
    )
    if db is not None:
        db.add(event)
        db.flush()
        return
    from vollteam_api.db import SessionFactory

    standalone = SessionFactory()
    try:
        standalone.add(event)
        standalone.commit()
    finally:
        standalone.close()
