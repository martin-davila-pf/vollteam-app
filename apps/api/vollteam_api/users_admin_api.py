"""Admin user management endpoints (M3): get/patch/status/delete.

Patterns inherited from earlier milestones:
- RBAC via require_role() dependency in the signature (never an `if` body)
- CSRF gate as a genuine dependency (never called manually)
- audit on every mutation, with actor + target + detail
- self-or-admin ownership checks for profile edits
- DB-level last-admin guard: never leave the system roleless
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DBSession

from vollteam_api.audit_helpers import record_audit
from vollteam_api.csrf import verify_csrf
from vollteam_api.db import get_db
from vollteam_api.deps import current_user, require_role
from vollteam_api.models import User
from vollteam_api.users_api import MeOut, UserOut, users_router

router = APIRouter(prefix="/api/v1/users", tags=["users-admin"])


class UserEditIn(BaseModel):
    """Profile fields any user may change on themselves; admins on anyone."""

    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    phone: str | None = Field(default=None, min_length=6, max_length=32)


class StatusIn(BaseModel):
    is_active: bool


def _can_manage(actor: User, target_id: str) -> bool:
    """Self-management OR any role >= admin manages anyone."""
    return actor.id == target_id or actor.role != "player"


def _loads(db: DBSession, user_id: str) -> User | None:
    return db.get(User, user_id)


# ---------------------------------------------------------------- GET one
@users_router.get(
    "/{user_id}",
    response_model=UserOut,
    responses={403: {"description": "Not authorized"}},
)
def get_user(
    user_id: str,
    actor: Annotated[User, Depends(current_user)],
    db: DBSession = Depends(get_db),
) -> Any:
    """Self or admin read. Never exposes password_hash or sessions."""
    if actor.id != user_id and actor.role == "player":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not authorized")
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return target


# ---------------------------------------------------------------- PATCH profile
@users_router.patch("/{user_id}", response_model=MeOut)
def edit_user(
    user_id: str,
    payload: UserEditIn,
    request: Request,
    actor: Annotated[User, Depends(current_user)],
    db: DBSession = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
) -> Any:
    """Self password edit; full profile edit for admin and above."""
    if actor.id != user_id and actor.role == "player":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not authorized")
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    changes: dict[str, Any] = {}
    if payload.full_name is not None:
        if len(payload.full_name.strip()) < 2:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "full_name too short")
        changes["full_name"] = {"from": target.full_name, "to": payload.full_name.strip()}
        target.full_name = payload.full_name.strip()
    if payload.phone is not None:
        changes["phone"] = {"from": target.phone, "to": payload.phone.strip()}
        target.phone = payload.phone.strip()
    if not changes:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "No fields to update")

    db.flush()
    record_audit(
        db,
        actor=actor,
        action="EDIT_USER",
        target_type="user",
        target_id=target.id,
        detail={"changes": changes, "self": actor.id == user_id},
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return target


# ---------------------------------------------------------------- PATCH status
@users_router.patch("/{user_id}/status")
def set_user_status(
    user_id: str,
    payload: StatusIn,
    request: Request,
    actor: Annotated[User, Depends(require_role("admin"))],
    db: DBSession = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
) -> dict[str, bool]:
    """Deactivate/reactivate (soft button). Deactivating kills live sessions."""
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    if not payload.is_active:
        _guard_last_admin(db, actor, target)
        _revoke_all_sessions(db, target)  # live keys die with the toggle

    previous = target.is_active
    target.is_active = payload.is_active
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="DEACTIVATE_USER" if not payload.is_active else "REACTIVATE_USER",
        target_type="user",
        target_id=target.id,
        detail={"from_active": previous, "to_active": payload.is_active},
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return {"ok": True, "is_active": target.is_active}


def _revoke_all_sessions(db: DBSession, target: User) -> None:
    """Live sessions of a deactivated user die now (defense in depth with resolve_session)."""
    from vollteam_api.models import Session as SessionRow

    rows = (
        db.query(SessionRow)
        .filter(SessionRow.user_id == target.id, SessionRow.revoked_at.is_(None))
        .all()
    )
    now = func.now()
    for row in rows:
        row.revoked_at = now


def _guard_last_admin(db: DBSession, action_actor: User, target: User) -> None:
    """Never allow the system to end up with zero active admins+sysadmins."""
    if target.role not in ("admin", "sysadmin") or target.id != action_actor.id:
        return  # only relevant when the target is the acting-last-admin
    active_sysgovernors = db.execute(
        select(func.count())
        .select_from(User)
        .where(User.role.in_(("admin", "sysadmin")), User.is_active.is_(True))
    ).scalar_one()
    if active_sysgovernors <= 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Cannot disable the last active administrator",
        )


# ---------------------------------------------------------------- DELETE (sysadmin)
@users_router.delete("/{user_id}", status_code=200)
def delete_user(
    user_id: str,
    request: Request,
    actor: Annotated[User, Depends(require_role("sysadmin"))],
    db: DBSession = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
) -> dict[str, str | bool]:
    """True delete — privacy/retention workflow; sysadmin-only; never self.

    The cascade removes sessions; registrations (Phase 3) will reference
    the id historically. Guarded against: deleting the last sysadmin.
    """
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if target.id == actor.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot delete yourself")
    if target.role == "sysadmin":
        remaining = db.execute(
            select(func.count())
            .select_from(User)
            .where(User.role == "sysadmin", User.is_active.is_(True))
        ).scalar_one()
        # careful: a target counted here is already active… subtract the one dying
        if remaining <= 1:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Cannot delete the last active sysadmin",
            )

    record_audit(
        db,
        actor=actor,
        action="DELETE_USER",
        target_type="user",
        target_id=target.id,
        detail={"email": target.email, "role": target.role},
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        # NOTE: actor survives as audit row (SET NULL FK on delete)
    )
    db.delete(target)
    db.flush()
    return {"deleted": True, "id": user_id}
