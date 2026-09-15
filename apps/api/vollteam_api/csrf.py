"""CSRF double-submit guard for cookie-authenticated mutations.

Pattern (OWASP stateless CSRF): the server sets a second cookie
(csrftoken, NOT HttpOnly so JS can read it) and requires the matching
value as an X-CSRF-Token header on every state-changing request.
A cross-site attacker cannot read the csrf cookie from another origin,
so their forged POST lacks the header and fails.

Setup flow:
  /auth/login  -> sets vollteam_session + csrf_token cookies
  every POST/PUT/PATCH/DELETE  -> header X-CSRF-Token must equal cookie
"""

from __future__ import annotations

import secrets

from fastapi import Cookie, HTTPException, Request, Response, status

CSRF_COOKIE = "vollteam_csrf"
CSRF_HEADER = "x-csrf-token"


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def verify_csrf(
    request: Request,
    vollteam_csrf: str | None = Cookie(default=None),
) -> None:
    """FastAPI dependency: raise 403 unless header matches cookie.

    MUST be used as a Depends() in the endpoint signature so FastAPI injects
    the cookie parameter — calling it manually would leave the cookie None
    and reject every request.
    """
    header = request.headers.get(CSRF_HEADER)
    if not header or not vollteam_csrf or header != vollteam_csrf:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")


def set_csrf_cookie(response: Response, token: str) -> None:
    """Not HttpOnly: the frontend JS must read it to echo the header back."""
    response.set_cookie(
        key=CSRF_COOKIE,
        value=token,
        httponly=False,
        secure=False,  # True behind HTTPS in Phase 5
        samesite="lax",
        max_age=60 * 60 * 24,
        path="/",
    )
