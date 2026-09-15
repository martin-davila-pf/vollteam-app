"""RBAC dependency and current-user resolution for FastAPI.

The permission matrix from Phase 0:
  player   : self-registration for games, manage own guests (Phase 3)
  admin    : manage users (create/deactivate), manage games (Phase 3)
  sysadmin : everything admin does + assign roles + app status (Phase 6 UI)

Server-side enforcement only — the frontend is a UX aid, never the gate.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session as DBSession

from vollteam_api.db import get_db
from vollteam_api.models import User
from vollteam_api.security import resolve_session

ROLE = {"player": 0, "admin": 1, "sysadmin": 2}


def current_user(
    vollteam_session: str | None = Cookie(default=None),
    db: DBSession = Depends(get_db),
) -> User:
    """Resolve the user from the opaque session cookie; 401 otherwise."""
    if not vollteam_session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    resolved = resolve_session(db, vollteam_session)
    if resolved is None:
        # invalid, expired, revoked, or user disabled — same generic response
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return resolved[0]


def require_role(minimum: str) -> Callable[..., User]:
    """Dependency factory: require a.minimum role level (player<admin<sysadmin)."""

    def checker(user: User = Depends(current_user)) -> User:
        if ROLE[user.role] < ROLE[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Not authorized")
        return user

    return checker
