"""Declarative base + engine/session wiring for the API.

Async-first: the app runs on asyncpg; tests use the same URL env var.
The driver is selected from DATABASE_URL (psycopg for sync test code,
asyncpg when an async engine is constructed via create_async_engine).
"""

from __future__ import annotations

import os
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://vollteam:vollteam_dev_pw@localhost:5432/vollteam",
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# Sync engine for CLI/Migrations/tests. The FastAPI app receives Session
# dependencies from this same factory — the app is sync-first until the
# async pool work in Phase 3 justifies the switch.
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"connect_timeout": 3},
    future=True,
)

SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, always closed."""
    db = SessionFactory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
