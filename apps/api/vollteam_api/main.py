"""Vollteam API entrypoint.

Phase 2: auth (opaque sessions), user administration, RBAC enforcement.
Health endpoint stays minimal; readiness is judged by CI against real Postgres.
"""

from fastapi import FastAPI

from vollteam_api.bootstrap import router as bootstrap_router
from vollteam_api.users_api import router, users_router

app = FastAPI(
    title="Vollteam API",
    version="0.1.0",
    description="Volleyball game scheduling with capacity-limited roster and FIFO waitlist.",
)
for _r in (router, users_router, bootstrap_router):
    app.include_router(_r)


@app.get("/healthz", tags=["ops"])
async def healthz() -> dict[str, str]:
    """Liveness probe: process is up. Readiness checks arrive with the DB layer."""
    return {"status": "ok"}
