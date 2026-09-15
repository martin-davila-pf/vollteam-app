"""Vollteam API entrypoint.

Minimal FastAPI application for Phase 1: proves the tooling chain
(ruff, mypy strict, pytest) against real code before feature work begins.
"""

from fastapi import FastAPI

app = FastAPI(
    title="Vollteam API",
    version="0.1.0",
    description="Volleyball game scheduling with capacity-limited roster and FIFO waitlist.",
)


@app.get("/healthz", tags=["ops"])
async def healthz() -> dict[str, str]:
    """Liveness probe: process is up. Readiness checks arrive with the DB layer."""
    return {"status": "ok"}
