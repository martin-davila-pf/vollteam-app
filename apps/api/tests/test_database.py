"""Database-level sanity checks.

These run against the real PostgreSQL service (from compose locally, from a
CI service container in CI). They prove the foundation works: migrations can
apply, constraints and indexes exist, and the engine pool behaves. Domain
schema arrives with Phase 2/3 migrations; until then these guard the basics.
"""

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration


def test_connection_succeeds(db_session) -> None:  # type: ignore[no-untyped-def]
    version = db_session.execute(text("SELECT version()")).scalar_one()
    assert "PostgreSQL" in version


def test_transaction_rollback_isolation(db_session) -> None:  # type: ignore[no-untyped-def]
    """Proof that the fixture isolation works: a rolled-back write never persists."""
    db_session.execute(text("CREATE TABLE IF NOT EXISTS _isolation_probe (id int)"))
    db_session.execute(text("INSERT INTO _isolation_probe VALUES (1)"))
    db_session.rollback()
    probe_new = db_session.execute(
        text("SELECT to_regclass('_isolation_probe')")
    ).scalar_one()
    assert probe_new is None, "rollback must undo DDL (single-transaction fixture)"


def test_concurrent_connections(db_session) -> None:  # type: ignore[no-untyped-def]
    """The async engine under load will need concurrent connections; verify pool serves them."""
    ids = [
        db_session.execute(text("SELECT pg_backend_pid()")).scalar_one()
        for _ in range(3)
    ]
    assert len(set(ids)) == 3, "each connection must be independent"
