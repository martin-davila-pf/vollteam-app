"""Database-level sanity checks.

These run against the real PostgreSQL service (from compose locally, from a
CI service container in CI). They prove the foundation works and that the
test infrastructure itself is sound: reachable engine, rollback-isolated
fixture, and a connection pool that serves independent connections.
"""

from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from .conftest import engine

pytestmark = pytest.mark.integration


def test_connection_succeeds(db_session: Session) -> None:
    version = db_session.execute(text("SELECT version()")).scalar_one()
    assert "PostgreSQL" in version


def test_transaction_rollback_isolation(db_session: Session) -> None:
    """Proof the fixture isolation works: a rolled-back write never persists."""
    db_session.execute(text("CREATE TABLE IF NOT EXISTS _isolation_probe (id int)"))
    db_session.execute(text("INSERT INTO _isolation_probe VALUES (1)"))
    db_session.rollback()
    probe_new = db_session.execute(
        text("SELECT to_regclass('_isolation_probe')")
    ).scalar_one()
    assert probe_new is None, "rollback must undo DDL (single-transaction fixture)"


def test_pool_serves_independent_connections(db_session: Session) -> None:
    """Three distinct pooled connections must have distinct backend pids.

    Sequential queries on one Session reuse one connection — correct but not
    what this test measures. Parallel checkouts from the engine pool measure
    the thing that matters for the FIFO concurrency algorithm in Phase 3:
    that N simultaneous workers each get their own backend.
    """

    def backend_pid(_: int) -> int:
        with engine.connect() as conn:
            return int(conn.execute(text("SELECT pg_backend_pid()")).scalar_one())

    with ThreadPoolExecutor(max_workers=3) as pool:
        pids = list(pool.map(backend_pid, range(3)))

    assert len(set(pids)) == 3, f"expected 3 distinct backends, got {pids}"
