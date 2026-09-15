"""Core domain models: users, roles, opaque sessions.

Design rules from Phase 0/Plan.md:
- roles are an enum (player/admin/sysadmin), extensions pending approval
- sessions store a HASH of the token, never the token itself
- sessions are revocable; expiry + revoked_at drive validity
- user-facing timestamps in UTC
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, Enum, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from vollteam_api.db import Base

RoleEnum = Enum("player", "admin", "sysadmin", name="role_enum")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    # argon2id encoded hash (~97 chars)
    password_hash: Mapped[str] = mapped_column(String(97), nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str] = mapped_column(String(32), nullable=False)
    role: Mapped[str] = mapped_column(RoleEnum, nullable=False, default="player")
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # NOTE: onupdate is app-side only; DB-side maintenance arrives with the
    # trigger migration in the Phase 2 hardening pass.
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), onupdate=func.now(), default=func.now()
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # sha256 hex digest of the issued token; the raw token exists ONLY in the cookie
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def is_live(self, now: dt.datetime) -> bool:
        """A session is valid only if not expired and not revoked."""
        return self.revoked_at is None and self.expires_at > now
