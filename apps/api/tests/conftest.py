"""Integration test fixtures.

Tests that require PostgreSQL pull DATABASE_URL from the environment (used
both by `docker compose up db` locally and by the CI integration job) and skip
when no database is reachable — unit runs stay green everywhere, while the
integration job fails loudly if the DB misbehaves.
"""

import os
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://vollteam:vollteam@localhost:5432/vollteam",
)

# One engine per test process. connect_args keeps unreachable-DB failures fast
# (3s) instead of hanging the suite when no database is up.
engine = sa.create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"connect_timeout": 3},
)


def database_available() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except sa.exc.OperationalError:
        return False


def skip_if_no_db(reason: str = "PostgreSQL not reachable at DATABASE_URL") -> None:
    if not database_available():
        pytest.skip(reason)


@pytest.fixture()
def db_session() -> Iterator[Session]:
    """Transaction-scoped session: rolled back after each test, full isolation."""
    skip_if_no_db()
    factory = sessionmaker(bind=engine)
    session = factory()
    try:
        yield session
        session.rollback()
    finally:
        session.close()
