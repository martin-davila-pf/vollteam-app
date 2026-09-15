"""Bootstrap endpoint for the FIRST sysadmin.

The chicken-and-egg problem: empty DB has no admin to mint an admin.
Solution: a one-shot endpoint gated by an env-stored secret:

  .env: BOOTSTRAP_TOKEN=<random once>   (never committed)
  POST /api/v1/auth/bootstrap-sysadmin {email, password, full_name, phone,
                                        bootstrap_token}
  - succeeds ONLY while zero sysadmins exist
  - DB-arbitrated single-win: a concurrent double request cannot mint two
  - after the first success, any future call returns 403 forever

Default bootstrap_token for local dev only; production value comes from
.env (to be rotated per deploy after use).
"""

from __future__ import annotations

import os
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from vollteam_api.audit_helpers import record_audit
from vollteam_api.csrf import new_csrf_token, set_csrf_cookie
from vollteam_api.db import get_db
from vollteam_api.models import User
from vollteam_api.security import hash_password, issue_session

router = APIRouter(prefix="/api/v1/auth", tags=["bootstrap"])


class BootstrapIn(BaseModel):
    email: EmailStr
    password: str
    full_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=6, max_length=32)
    bootstrap_token: str


@router.post("/bootstrap-sysadmin", status_code=201)
def bootstrap_sysadmin(
    payload: BootstrapIn,
    response: Response,
    request: Request,
    db: DBSession = Depends(get_db),
) -> dict[str, str | bool]:
    expected = os.environ.get("BOOTSTRAP_TOKEN", "")
    if not expected:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Bootstrap disabled: no BOOTSTRAP_TOKEN configured",
        )
    if not secrets.compare_digest(payload.bootstrap_token, expected):
        # same generic message as wrong creds: no oracle about the token
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid bootstrap token")

    sysadmins = db.execute(
        select(User).where(User.role == "sysadmin")
    ).scalars().all()
    if sysadmins:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "A sysadmin already exists; bootstrap is closed",
        )

    if len(payload.password) < 10:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Password too short")

    email = payload.email.strip().lower()
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name.strip(),
        phone=payload.phone.strip(),
        role="sysadmin",
    )
    db.add(user)
    db.flush()

    record_audit(
        db,
        actor=None,
        action="BOOTSTRAP_SYSA",
        target_type="user",
        target_id=user.id,
        detail={"email": email},
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    raw, _row = issue_session(db, user.id)
    csrf = new_csrf_token()
    set_csrf_cookie(response, csrf)
    response.set_cookie(
        key="vollteam_session",
        value=raw,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
        path="/",
    )
    return {"ok": True, "role": "sysadmin", "csrf_token": csrf}
