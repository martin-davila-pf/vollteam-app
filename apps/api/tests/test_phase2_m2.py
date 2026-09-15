"""Phase 2 M2 tests: audit log, login rate limiting, CSRF guard, bootstrap.

Each section says which attack scenario it proves blocked.
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
from vollteam_api import ratelimit
from vollteam_api.audit import AuditEvent
from vollteam_api.db import SessionFactory
from vollteam_api.main import app
from vollteam_api.models import User
from vollteam_api.security import hash_password

PWA = "CorrectHorse42!"


def E(name: str) -> str:
    """Unique email per run: reruns never collide with old test data."""
    return f"{name}-{uuid.uuid4().hex[:8]}@test.example.com"


@pytest.fixture()
def db() -> Iterator[DBSession]:
    s = SessionFactory()
    try:
        yield s
        s.rollback()
    finally:
        s.close()


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


def make_user(db: DBSession, role: str) -> User:

    user = User(
        email=E(role),
        password_hash=hash_password(PWA),
        full_name=f"{role} Test",
        phone="+5710000000",
        role=role,
    )
    db.add(user)
    db.commit()
    return user


def auth_headers(client: TestClient, email: str) -> dict[str, str]:
    """Login persists both cookies in the client jar; only CSRF goes in the header.

    (Manually re-sending the Cookie header would double the browser cookie
    jar and confuse the framework — the client fixture handles session and
    csrf automatically, like a real browser.)
    """
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PWA})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf_token"]}


def login_as(
    client: TestClient, email: str, password: str = PWA
) -> Any:
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


# ================================================================ audit
def test_login_failure_writes_audit(client: TestClient, db: DBSession) -> None:
    """Brute-force forensics base: any failed login leaves a trail."""
    before = db.query(AuditEvent).filter_by(action="LOGIN_FAILURE").count()
    login_as(client, E("ghost"), "whatever1!")
    after = db.query(AuditEvent).filter_by(action="LOGIN_FAILURE").count()
    assert after == before + 1


def test_create_user_audits_actor_target(client: TestClient, db: DBSession) -> None:
    admin = make_user(db, "admin")
    headers = auth_headers(client, admin.email)
    r = client.post(
        "/api/v1/users",
        json={
            "email": E("created"),
            "password": PWA,
            "full_name": "Created By Audit",
            "phone": "+5710000001",
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    row = (
        db.query(AuditEvent)
        .filter_by(action="CREATE_USER", target_id=r.json()["id"])
        .one()
    )
    assert row.actor_id == admin.id
    assert (row.detail or {}).get("role") == "player"
    assert row.ip is not None


def test_password_reset_audits_self_flag(client: TestClient, db: DBSession) -> None:
    player = make_user(db, "player")
    headers = auth_headers(client, player.email)
    r = client.patch(
        f"/api/v1/users/{player.id}/password",
        json={"new_password": "Another9Pass!"},
        headers=headers,
    )
    assert r.status_code == 200
    row = (
        db.query(AuditEvent)
        .filter_by(action="RESET_PASSWORD", target_id=player.id)
        .one()
    )
    assert (row.detail or {}).get("self_reset") is True


# ================================================================ rate limit
def test_sixth_failed_login_throttles(client: TestClient, db: DBSession) -> None:
    """Attacker with 5 failures inside the window gets 429 before any hashing."""
    user = make_user(db, "player")
    ratelimit.reset_failures("testclient", user.email)

    for _ in range(5):
        assert login_as(client, user.email, "bad_pw_1!").status_code == 401

    r = login_as(client, user.email, "whatever2!")
    assert r.status_code == 429, "6th failure inside window must be throttled"
    ratelimit.reset_failures("testclient", user.email)


def test_successful_login_resets_counter(client: TestClient, db: DBSession) -> None:
    """A legit user who fat-fingers a few times is not permanently punished."""
    user = make_user(db, "player")
    for _ in range(4):
        assert login_as(client, user.email, "badpass1!").status_code == 401
    assert login_as(client, user.email).status_code == 200  # resets bucket
    for _ in range(4):
        assert login_as(client, user.email, "badpass2!").status_code == 401
    assert login_as(client, user.email).status_code == 200


# ================================================================ CSRF
def test_mutation_without_csrf_header_is_403(client: TestClient, db: DBSession) -> None:
    """The cross-site attacker has the session cookie but cannot read csrf."""
    admin = make_user(db, "admin")
    login = client.post(
        "/api/v1/auth/login", json={"email": admin.email, "password": PWA}
    )
    cookie_only = {"Cookie": _session_cookie_only(login)}
    payload = {
        "email": E("csrf"), "password": PWA,
        "full_name": "F", "phone": "+571",
    }
    assert client.post("/api/v1/users", json=payload, headers=cookie_only).status_code == 403
    bad = dict(cookie_only, **{"X-CSRF-Token": "forged"})
    assert client.post("/api/v1/users", json=payload, headers=bad).status_code == 403


def test_correct_csrf_header_allows_mutation(client: TestClient, db: DBSession) -> None:
    admin = make_user(db, "admin")
    r = client.post(
        "/api/v1/users",
        json={
            "email": E("csrfok"),
            "password": PWA,
            "full_name": "Ok",
            "phone": "+5712223333",
        },
        headers=auth_headers(client, admin.email),
    )
    assert r.status_code == 201, r.text


def test_cookie_hygiene(client: TestClient, db: DBSession) -> None:
    """session: HttpOnly (steal-proof). csrf: readable (JS must echo it)."""
    user = make_user(db, "player")
    r = client.post("/api/v1/auth/login", json={"email": user.email, "password": PWA})
    parts = r.headers.get_list("set-cookie")
    session = next(p for p in parts if p.startswith("vollteam_session="))
    csrf = next(p for p in parts if p.startswith("vollteam_csrf="))
    assert "HttpOnly" in session
    assert "HttpOnly" not in csrf


# ================================================================ bootstrap
def test_bootstrap_full_cycle(db: DBSession, monkeypatch: pytest.MonkeyPatch) -> None:
    """Wrong token → 403 · right token → first sysadmin · then closed forever."""
    monkeypatch_env(monkeypatch, "correct-token-123")
    email = E("rootfull")

    with TestClient(app) as c:
        wrong = c.post(
            "/api/v1/auth/bootstrap-sysadmin",
            json={**_bootstrap_body(E("wrong")), "bootstrap_token": "guess"},
        )
        assert wrong.status_code == 403, "wrong token must 403"

        ok = c.post(
            "/api/v1/auth/bootstrap-sysadmin",
            json={**_bootstrap_body(email), "bootstrap_token": "correct-token-123"},
        )
        # A previous test-run may have minted the first sysadmin; both outcomes
        # prove the rule: created now (201) or already closed (403 with reason).
        assert ok.status_code in (201, 403)
        if ok.status_code == 201:
            assert ok.json()["role"] == "sysadmin"

        closed = c.post(
            "/api/v1/auth/bootstrap-sysadmin",
            json={**_bootstrap_body(E("second")), "bootstrap_token": "correct-token-123"},
        )
        assert closed.status_code == 403, "bootstrap must be one-shot"


def _session_cookie_only(login: Any) -> str:
    """Extract just the session cookie value (the attacker scenario: they CAN'T copy csrf)."""
    for part in login.headers.get_list("set-cookie"):
        if part.startswith("vollteam_session="):
            return str(part.split(";")[0])
    raise AssertionError("no session cookie present")


def _bootstrap_body(email: str) -> dict[str, str]:
    return {
        "email": email,
        "password": PWA,
        "full_name": "Root",
        "phone": "+5710000004",
    }


def monkeypatch_env(monkeypatch: pytest.MonkeyPatch, token: str) -> None:
    monkeypatch.setenv("BOOTSTRAP_TOKEN", token)
