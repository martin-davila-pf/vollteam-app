"""Auth + user administration API (v1).

Endpoints follow Plan.md §11: resource-oriented REST under /api/v1,
explicit commands, Pydantic schemas, generic auth errors (no enumeration).
Login sets an opaque session cookie; logout revokes it server-side.
Admin creates users; sysadmin assigns roles (per Phase 0 matrix).
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DBSession

from vollteam_api import ratelimit
from vollteam_api.audit_helpers import record_audit
from vollteam_api.csrf import new_csrf_token, set_csrf_cookie, verify_csrf
from vollteam_api.db import get_db
from vollteam_api.deps import current_user, require_role
from vollteam_api.models import User
from vollteam_api.security import (
    hash_password,
    issue_session,
    rehash_if_needed,
    resolve_session,
    verify_password,
)

router = APIRouter(prefix="/api/v1", tags=["auth"])
users_router = APIRouter(prefix="/api/v1/users", tags=["users"])

SESSION_COOKIE = "vollteam_session"
MIN_PASSWORD = 10


# ---------------------------------------------------------------- schemas
class LoginIn(BaseModel):
    email: EmailStr
    password: str


class MeOut(BaseModel):
    id: str
    email: str
    full_name: str
    phone: str
    role: str


class UserCreateIn(BaseModel):
    email: EmailStr
    password: str
    full_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=6, max_length=32)
    role: str = "player"


class UserOut(MeOut):
    is_active: bool


class PasswordResetIn(BaseModel):
    new_password: str


def _check_password_strength(pw: str) -> None:
    if len(pw) < MIN_PASSWORD:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Password must be at least {MIN_PASSWORD} characters",
        )


# ---------------------------------------------------------------- auth
@router.post("/auth/login")
def login(
    payload: LoginIn,
    response: Response,
    request: Request,
    db: DBSession = Depends(get_db),
) -> dict[str, bool | str]:
    client_ip = request.client.host if request.client else "unknown"
    email_key = payload.email.strip().lower()

    if ratelimit.is_rate_limited(client_ip, email_key):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts")

    user = db.execute(
        select(User).where(User.email == email_key)
    ).scalar_one_or_none()

    password_ok = verify_password(payload.password, user.password_hash if user else None)
    if user is None or not user.is_active or not password_ok:
        # single generic message: never reveals which part failed
        ratelimit.record_failure(client_ip, email_key)
        record_audit(
            None,  # standalone: must survive the rolled-back 401 transaction
            action="LOGIN_FAILURE",
            target_type="auth",
            target_id=email_key,
            detail={"reason": "invalid_credentials"},
            ip=client_ip,
            user_agent=request.headers.get("user-agent"),
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    ratelimit.reset_failures(client_ip, email_key)
    raw, _session_row = issue_session(db, user.id)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=raw,
        httponly=True,
        secure=False,  # local dev; True behind HTTPS in Phase 5 deploys
        samesite="lax",
        max_age=int(dt.timedelta(days=30).total_seconds()),
        path="/",
    )
    csrf = new_csrf_token()
    set_csrf_cookie(response, csrf)
    return {"ok": True, "role": user.role, "csrf_token": csrf}


@router.post("/auth/logout")
def logout(
    response: Response,
    vollteam_session: str | None = Cookie(default=None),
    db: DBSession = Depends(get_db),
) -> dict[str, bool]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    if vollteam_session:
        resolved = resolve_session(db, vollteam_session)
        if resolved:
            _, row = resolved
            row.revoked_at = dt.datetime.now(dt.UTC)
            db.flush()
    return {"ok": True}


@router.get("/auth/me", response_model=MeOut)
def whoami(user: User = Depends(current_user)) -> Any:
    return user


# ---------------------------------------------------------------- users
@users_router.post("", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreateIn,
    request: Request,
    actor: Annotated[User, Depends(require_role("admin"))],
    db: DBSession = Depends(get_db),
    _csrf: None = Depends(verify_csrf),  # state-changing ⇒ CSRF gate
) -> Any:
    _check_password_strength(payload.password)
    email = payload.email.strip().lower()
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    # only sysadmin may mint admins/sysadmins
    if payload.role != "player" and actor.role != "sysadmin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not authorized")

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name.strip(),
        phone=payload.phone.strip(),
        role=payload.role if payload.role in ("player", "admin", "sysadmin") else "player",
    )
    db.add(user)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="CREATE_USER",
        target_type="user",
        target_id=user.id,
        detail={"email": email, "role": user.role},
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return user


@users_router.get("", response_model=list[UserOut])
def list_users(
    _actor: Annotated[User, Depends(require_role("admin"))],
    db: DBSession = Depends(get_db),
) -> Any:
    users = db.execute(select(User).order_by(func.lower(User.email))).scalars().all()
    return list(users)


@users_router.patch("/{user_id}/password", status_code=200)
def reset_password(
    user_id: str,
    payload: PasswordResetIn,
    request: Request,
    actor: Annotated[User, Depends(current_user)],
    db: DBSession = Depends(get_db),
    _csrf: None = Depends(verify_csrf),  # state-changing ⇒ CSRF gate
) -> dict[str, bool]:
    _check_password_strength(payload.new_password)
    self_reset = actor.id == user_id
    if not (self_reset or actor.role == "sysadmin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not authorized")

    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    target.password_hash = hash_password(payload.new_password)
    db.flush()
    # transparent rehash upgrade for the actor mutating own password
    upgraded = rehash_if_needed(target.password_hash, payload.new_password)
    if upgraded:
        target.password_hash = upgraded
    record_audit(
        db,
        actor=actor,
        action="RESET_PASSWORD",
        target_type="user",
        target_id=target.id,
        detail={"self_reset": self_reset},
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return {"ok": True}
