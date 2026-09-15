"""Password hashing (Argon2id) and opaque session token services.

Security decisions from Plan.md §10:
- Argon2id via argon2-cffi defaults (memory- and time-hardened)
- generic failure response: when the user does not exist, we still run a
  dummy hash verify to keep constant-ish timing and prevent user enumeration
- session token: 32 random bytes -> urlsafe base64 (43 chars); only the
  sha256 hex digest is persisted
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session

from vollteam_api.models import Session as SessionRow
from vollteam_api.models import User

ph = PasswordHasher()  # argon2id defaults: t=3, m=64MiB, p=4 (OWASP-aligned)

# Fake hash used when the user does not exist, so login timing does not leak
# whether an email is registered.
_DUMMY_HASH = ph.hash(secrets.token_urlsafe(16))

SESSION_TTL = dt.timedelta(days=30)


def hash_password(plain: str) -> str:
    return ph.hash(plain)


def verify_password(plain: str, password_hash: str | None) -> bool:
    """Return True only on a matching hash; dummy-verify on None/missing user."""
    target = password_hash or _DUMMY_HASH
    try:
        ph.verify(target, plain)
    except VerifyMismatchError:
        return False
    return True


def rehash_if_needed(password_hash: str, plain: str) -> str | None:
    """Return an upgraded hash when parameters changed (transparent rehash)."""
    try:
        if ph.check_needs_rehash(password_hash):
            return ph.hash(plain)
    except Exception:
        return None
    return None


def issue_session(db: Session, user_id: str) -> tuple[str, SessionRow]:
    """Create a session row; return (raw_token, row). Raw token never stored."""
    raw = secrets.token_urlsafe(32)
    row = SessionRow(
        id=str(uuid.uuid4()),
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        user_id=user_id,
        expires_at=dt.datetime.now(dt.UTC) + SESSION_TTL,
    )
    db.add(row)
    db.flush()
    return raw, row


def resolve_session(db: Session, raw_token: str) -> tuple[User, SessionRow] | None:
    """Look up a live session by raw token; returns (user, session) or None."""
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    stmt = select(SessionRow).where(SessionRow.token_hash == token_hash)
    row = db.execute(stmt).scalar_one_or_none()
    if row is None or not row.is_live(dt.datetime.now(dt.UTC)):
        return None
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        return None
    return user, row


def revoke_session(db: Session, session_row: SessionRow) -> None:
    if session_row.revoked_at is None:
        session_row.revoked_at = dt.datetime.now(dt.UTC)
        db.flush()
