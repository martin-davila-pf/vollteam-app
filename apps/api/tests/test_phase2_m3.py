"""Phase 2 M3 tests: user management endpoints (get/edit/status/delete).

Every test names its scenario — the negative/RBAC paths are the point:
the admin panel is the most user-facing admin surface, so unauthorized
or accidental state changes get caught here first.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as DBSession
from vollteam_api.audit import AuditEvent
from vollteam_api.db import SessionFactory
from vollteam_api.main import app
from vollteam_api.models import User
from vollteam_api.security import hash_password

PWA = "CorrectHorse42!"

pytestmark = pytest.mark.integration


def E(name: str) -> str:
    """Unique email per run so reruns never collide with old data."""
    return f"{name}-{uuid.uuid4().hex[:8]}@test.example.com"


@pytest.fixture()
def db() -> Iterator[DBSession]:
    s = SessionFactory()
    try:
        yield s
        # M3 tests mutate users; commit is needed for e.g. status changes.
        # Keep the session open for queries after requests:
        s.rollback()
    finally:
        s.close()


class CSRFClient(TestClient):
    """ remembers the last login's csrf token to echo it in mutations."""

    csrf_token: str = ""

    def login(self, email: str, pw: str = PWA) -> Any:
        r = self.post("/api/v1/auth/login", json={"email": email, "password": pw})
        if r.status_code == 200 and r.json() and r.json().get("csrf_token"):
            self.csrf_token = r.json()["csrf_token"]
        return r

    def request(self, *args: Any, **kwargs: Any) -> Any:
        """Echo X-CSRF-Token on every request, like a real frontend."""
        kwargs.setdefault("headers", {})
        if self.csrf_token:
            headers = dict(kwargs["headers"] or {})
            headers.setdefault("X-CSRF-Token", self.csrf_token)
            kwargs["headers"] = headers
        return super().request(*args, **kwargs)


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with CSRFClient(app) as c:
        yield c


def make_user(db: DBSession, role: str, active: bool = True) -> User:
    user = User(
        email=E(role),
        password_hash=hash_password(PWA),
        full_name=f"{role} Test",
        phone="+5710000000",
        role=role,
        is_active=active,
    )
    db.add(user)
    db.commit()
    return user


def login(client: Any, email: str, pw: str = PWA) -> Any:
    """Login persists both cookies (session + csrf) in the client jar."""
    return client.login(email, pw)


# ================================================================ GET /users/{id}
def test_anonymous_cannot_read_users(client: TestClient, db: DBSession) -> None:
    me = make_user(db, "player")
    with TestClient(app) as fresh:  # anonymous: no cookie jar at all
        r = fresh.get(f"/api/v1/users/{me.id}")
        assert r.status_code == 401


def test_player_reads_self_but_not_others(client: TestClient, db: DBSession) -> None:
    me = make_user(db, "player")
    other = make_user(db, "player")
    login(client, me.email)

    own = client.get(f"/api/v1/users/{me.id}")
    assert own.status_code == 200
    body = own.json()
    assert body["email"] == me.email
    # data minimization: no hash, no sessions inside the payload
    assert "password_hash" not in body

    other_read = client.get(f"/api/v1/users/{other.id}")
    assert other_read.status_code == 403


def test_admin_reads_any_user(client: TestClient, db: DBSession) -> None:
    admin = make_user(db, "admin")
    player = make_user(db, "player")
    login(client, admin.email)

    r = client.get(f"/api/v1/users/{player.id}")
    assert r.status_code == 200
    assert r.json()["role"] == "player"


def test_get_unknown_user_is_404(client: TestClient, db: DBSession) -> None:
    admin = make_user(db, "admin")
    login(client, admin.email)
    r = client.get("/api/v1/users/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


# ================================================================ PATCH profile
def test_player_edits_own_profile(client: TestClient, db: DBSession) -> None:
    player = make_user(db, "player")
    login(client, player.email)
    r = client.patch(
        f"/api/v1/users/{player.id}",
        json={"full_name": "Player Renamed", "phone": "+5712223344"},
    )
    assert r.status_code == 200
    db.expire_all()
    fresh = db.get(User, player.id)
    assert fresh is not None, "user must exist after edit"
    assert fresh.full_name == "Player Renamed"
    assert fresh.phone == "+5712223344"


def test_admin_edits_anyone_audited(client: TestClient, db: DBSession) -> None:
    admin = make_user(db, "admin")
    player = make_user(db, "player")
    login(client, admin.email)
    r = client.patch(
        f"/api/v1/users/{player.id}",
        json={"full_name": "Admin Edited"},
    )
    assert r.status_code == 200
    row = db.query(AuditEvent).filter_by(action="EDIT_USER", target_id=player.id).one()
    assert (row.detail or {}).get("self") is False
    changes = (row.detail or {}).get("changes", {})
    assert changes.get("full_name", {}).get("from") == player.full_name


def test_player_cannot_edit_others(client: TestClient, db: DBSession) -> None:
    player = make_user(db, "player")
    other = make_user(db, "player")
    login(client, player.email)
    r = client.patch(f"/api/v1/users/{other.id}", json={"full_name": "Hijack"})
    assert r.status_code == 403


def test_edit_with_no_fields_is_422(client: TestClient, db: DBSession) -> None:
    me = make_user(db, "player")
    login(client, me.email)
    r = client.patch(f"/api/v1/users/{me.id}", json={})
    assert r.status_code == 422


# ================================================================ PATCH status
def test_admin_deactivates_player_sessions_die(client: TestClient, db: DBSession) -> None:
    admin = make_user(db, "admin")
    player = make_user(db, "player")

    # independent browser: the player's own live session (to kill later)
    player_client = TestClient(app)
    player_client.post(
        "/api/v1/auth/login", json={"email": player.email, "password": PWA}
    )
    r_active = player_client.get(f"/api/v1/users/{player.id}")
    assert r_active.status_code == 200

    login(client, admin.email)
    off = client.patch(
        f"/api/v1/users/{player.id}/status",
        json={"is_active": False},
    )
    assert off.status_code == 200

    # the player's live session must die NOW
    r_after = player_client.get(f"/api/v1/users/{player.id}")
    assert r_after.status_code == 401, "deactivation kills live sessions"

    audit = db.query(AuditEvent).filter_by(action="DEACTIVATE_USER", target_id=player.id).one()
    assert (audit.detail or {}).get("to_active") is False


def test_reactivate_works(client: TestClient, db: DBSession) -> None:
    admin = make_user(db, "admin")
    player = make_user(db, "player")
    player.is_active = False
    db.commit()

    login(client, admin.email)
    on = client.patch(
        f"/api/v1/users/{player.id}/status",
        json={"is_active": True},
    )
    assert on.status_code == 200
    audit = db.query(AuditEvent).filter_by(action="REACTIVATE_USER", target_id=player.id).one()
    assert (audit.detail or {}).get("to_active") is True


def test_player_cannot_deactivate_users(client: TestClient, db: DBSession) -> None:
    player = make_user(db, "player")
    other = make_user(db, "player")
    login(client, player.email)
    r = client.patch(
        f"/api/v1/users/{other.id}/status",
        json={"is_active": False},
    )
    assert r.status_code == 403


def test_last_admin_cannot_self_deactivate(client: TestClient, db: DBSession) -> None:
    # make OUR admin the only active admin/sysadmin in this test run
    db.query(User).filter(
        User.role.in_(("admin", "sysadmin")), User.is_active.is_(True)
    ).update({User.is_active: False}, synchronize_session=False)
    admin = make_user(db, "admin")
    db.commit()
    login(client, admin.email)
    r = client.patch(
        f"/api/v1/users/{admin.id}/status",
        json={"is_active": False},
    )
    assert r.status_code == 409, r.text
    body = r.json()["detail"]
    assert "last" in str(body).lower(), "the reason must be explicit for ops"
    admin_fresh = db.get(User, admin.id)
    assert admin_fresh is not None
    db.refresh(admin_fresh)
    assert admin_fresh.is_active is True


# ================================================================ DELETE
def test_sysadmin_can_delete_player(client: TestClient, db: DBSession) -> None:
    sysadmin = make_user(db, "sysadmin")
    player = make_user(db, "player")
    login(client, sysadmin.email)
    r = client.delete(f"/api/v1/users/{player.id}")
    assert r.status_code == 200
    player_id = player.id  # capture before the session expires the deleted object
    db.expire_all()
    assert db.get(User, player_id) is None
    audit = (
        db.query(AuditEvent).filter_by(action="DELETE_USER", target_id=player_id).one()
    )
    assert (audit.detail or {}).get("role") == "player"


def test_admin_cannot_delete(client: TestClient, db: DBSession) -> None:
    admin = make_user(db, "admin")
    player = make_user(db, "player")
    login(client, admin.email)
    r = client.delete(f"/api/v1/users/{player.id}")
    assert r.status_code == 403
    assert db.get(User, player.id) is not None


def test_cannot_delete_yourself(client: TestClient, db: DBSession) -> None:
    sysadmin = make_user(db, "sysadmin")
    login(client, sysadmin.email)
    r = client.delete(f"/api/v1/users/{sysadmin.id}")
    assert r.status_code == 409


def test_cannot_delete_last_sysadmin(client: TestClient, db: DBSession) -> None:
    sysadmin = make_user(db, "sysadmin")
    player = make_user(db, "sysadmin")  # second, to leave one behind
    # now delete the second one — allowed; then try the first → 409 last-guard
    login(client, sysadmin.email)
    r = client.delete(f"/api/v1/users/{player.id}")
    assert r.status_code == 200
    r2 = client.delete(f"/api/v1/users/{sysadmin.id}")
    assert r2.status_code == 409, "cannot delete the last active sysadmin"
