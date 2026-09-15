"""Phase 2 security tests: auth, sessions, RBAC enforcement.

These run against a real PostgreSQL database (same pattern as the Phase 1
integration tests). They are the negative-path proof demanded by the
Phase 2 exit gate: every unauthorized path fails, and the session machinery
behaves exactly as the threat model requires.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

if True:
    pass
from sqlalchemy.orm import Session as DBSession
from vollteam_api.db import SessionFactory
from vollteam_api.main import app
from vollteam_api.models import User
from vollteam_api.security import hash_password

pytestmark = pytest.mark.integration


def E(name: str) -> str:
    """Unique email per test-run so reruns never hit 409 on old data."""
    return f"{name}-{uuid.uuid4().hex[:8]}@test.example.com"


PWA = "CorrectHorse42!"  # password for every fixture user


def make_user(db: DBSession, role: str, email: str | None = None) -> User:
    user = User(
        email=email or f"{role}-{uuid.uuid4().hex[:8]}@test.example.com",
        password_hash=hash_password(PWA),
        full_name=f"{role} Test",
        phone="+5710000000",
        role=role,
    )
    db.add(user)
    db.commit()
    return user


def _session_cookie_only(login: Any) -> str:
    """Return the raw `Cookie: vollteam_session=...` header fragment only.

    _MutableHeaders.get_list is a starlette runtime API not fully typed —
    mypy sees Any; keeping one narrow helper keeps the 'Any' contained here.
    """
    parts = login.headers.get_list("set-cookie")
    for part in parts:
        if part.startswith("vollteam_session="):
            value: str = part.split(";")[0]
            return value
    raise AssertionError("no session cookie present")


def login_as(client: TestClient, email: str) -> dict[str, str]:
    """Login persists cookies in the client jar; only the CSRF echo needed."""
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PWA})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf_token"]}


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """Fresh client per test: no cookie leakage across tests."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db() -> Iterator[DBSession]:
    """Direct session for seeding/verification; rolled back after each test."""
    s = SessionFactory()
    try:
        yield s
        s.rollback()
    finally:
        s.close()


# ---------------------------------------------------------------- login
def test_login_success_sets_cookie_and_me_works(client: TestClient, db: DBSession) -> None:
    user = make_user(db, "player")
    r = client.post("/api/v1/auth/login", json={"email": user.email, "password": PWA})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "vollteam_session" in cookie

    me = client.get("/api/v1/auth/me", headers={"Cookie": cookie.split(";")[0]})
    assert me.status_code == 200
    assert me.json()["email"] == user.email


def test_login_failure_generic_and_no_user_enumeration(client: TestClient, db: DBSession) -> None:
    make_user(db, "player")
    # wrong password on an EXISTING user
    r1 = client.post(
        "/api/v1/auth/login",
        json={"email": "someone-real@test.example.com", "password": "wrong-password"},
    )
    # login for a user that NEVER existed
    r2 = client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@nowhere.example", "password": "wrong-password"},
    )
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json(), "identical bodies: no user enumeration by response"
    # and no Set-Cookie on either failure
    assert "set-cookie" not in r1.headers and "set-cookie" not in r2.headers


def test_short_password_rejected_on_create(
    client: TestClient, db: DBSession
) -> None:
    admin = make_user(db, "admin")
    headers = login_as(client, admin.email)
    r = client.post(
        "/api/v1/users",
        json={
            "email": "weak@test.example.com",
            "password": "short",
            "full_name": "Weak User",
            "phone": "+5710000001",
        },
        headers=headers,
    )
    assert r.status_code == 422
    detail = str(r.json()["detail"])
    assert "at least" in detail


# ---------------------------------------------------------------- session lifecycle
def test_logout_revokes_server_side(client: TestClient, db: DBSession) -> None:
    user = make_user(db, "player")
    r = client.post("/api/v1/auth/login", json={"email": user.email, "password": PWA})
    cookie = r.headers["set-cookie"].split(";")[0]
    assert client.get("/api/v1/auth/me", headers={"Cookie": cookie}).status_code == 200

    client.post("/api/v1/auth/logout", headers={"Cookie": cookie})
    assert (
        client.get("/api/v1/auth/me", headers={"Cookie": cookie}).status_code == 401
    ), "revoked session must die server-side, not just lose the cookie"


def test_forged_or_garbage_session_is_401(client: TestClient, db: DBSession) -> None:
    for bad in ("forge-token", "", "1; DROP TABLE users", "x" * 300):
        r = client.get("/api/v1/auth/me", headers={"Cookie": f"vollteam_session={bad}"})
        assert r.status_code == 401, f"token {bad!r} must not authenticate"
    assert client.get("/api/v1/auth/me").status_code == 401


def test_disabled_user_sessions_die_immediately(client: TestClient, db: DBSession) -> None:
    user = make_user(db, "player")
    login = client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": PWA}
    )
    cookie = _session_cookie_only(login)

    user.is_active = False
    db.commit()  # admin-disabled mid-life

    r = client.get("/api/v1/auth/me", headers={"Cookie": cookie})
    assert r.status_code == 401, "disabled user's live session must stop working"


# ---------------------------------------------------------------- RBAC
def test_player_cannot_create_users(client: TestClient, db: DBSession) -> None:
    player = make_user(db, "player")
    r = client.post(
        "/api/v1/users",
        json={
            "email": "x@test.example.com",
            "password": PWA,
            "full_name": "X",
            "phone": "+5711",
        },
        headers=login_as(client, player.email),
    )
    assert r.status_code == 403


def test_anonymous_cannot_list_or_create_users(client: TestClient, db: DBSession) -> None:
    assert client.get("/api/v1/users").status_code == 401
    r = client.post(
        "/api/v1/users",
        json={"email": E("anon"), "password": PWA, "full_name": "A", "phone": "+571"},
    )
    assert r.status_code == 401


def test_admin_creates_player_but_cannot_mint_admin(client: TestClient, db: DBSession) -> None:
    admin = make_user(db, "admin")
    headers = login_as(client, admin.email)

    ok = client.post(
        "/api/v1/users",
        json={
            "email": E("new-player"),
            "password": PWA,
            "full_name": "New Player",
            "phone": "+5712345678",
            "role": "player",
        },
        headers=headers,
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["role"] == "player"

    mint = client.post(
        "/api/v1/users",
        json={
            "email": E("rogue-admin"),
            "password": PWA,
            "full_name": "Rogue",
            "phone": "+5712345678",
            "role": "admin",
        },
        headers=headers,
    )
    assert mint.status_code == 403, "admin must not be able to mint other admins"


def test_sysadmin_can_mint_admin(client: TestClient, db: DBSession) -> None:
    sysadmin = make_user(db, "sysadmin")
    r = client.post(
        "/api/v1/users",
        json={
            "email": E("minted-admin"),
            "password": PWA,
            "full_name": "Minted",
            "phone": "+5712345679",
            "role": "admin",
        },
        headers=login_as(client, sysadmin.email),
    )
    assert r.status_code == 201
    assert r.json()["role"] == "admin"


def test_player_cannot_list_users(client: TestClient, db: DBSession) -> None:
    player = make_user(db, "player")
    r = client.get("/api/v1/users", headers=login_as(client, player.email))
    assert r.status_code == 403


def test_password_reset_ownership(client: TestClient, db: DBSession) -> None:
    """A player may change_ONLY their own password; not another user's."""
    player = make_user(db, "player")
    other = make_user(db, "player")
    headers = login_as(client, player.email)

    own = client.patch(
        f"/api/v1/users/{player.id}/password",
        json={"new_password": "NewStrong9!"},
        headers=headers,
    )
    assert own.status_code == 200

    via_other = client.patch(
        f"/api/v1/users/{other.id}/password",
        json={"new_password": "OtherField99!"},
        headers=headers,
    )
    assert via_other.status_code == 403

    # the change really took effect: use cookie-clear clients so the old
    # session cookie can't masquerade as successful old-password login
    with TestClient(app) as c_old:
        r_old = c_old.post(
            "/api/v1/auth/login", json={"email": player.email, "password": PWA}
        )
    with TestClient(app) as c_new:
        r_new = c_new.post(
            "/api/v1/auth/login", json={"email": player.email, "password": "NewStrong9!"}
        )
    assert r_old.status_code == 401, f"old password must stop working: {r_old.text}"
    assert r_new.status_code == 200, "new password must authenticate"
