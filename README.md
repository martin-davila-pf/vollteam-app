# Vollteam

Volleyball game scheduling web app: administrators create games, players sign
up with up to 2 guests, and a strict FIFO waitlist promotes the oldest
registration the moment a spot frees up — atomically, under concurrent load.

FastAPI + PostgreSQL backend, React + TypeScript frontend, opaque server-side
sessions with RBAC, transactional roster/waitlist correctness tests,
Docker Compose for local development, CI quality gates (lint, strict typing, tests).

## Status

Work in progress. Current: repository bootstrap, backend skeleton with
healthcheck, tooling and CI pipeline.

Architecture decisions land in [docs/](docs/).

## Repository layout

- `apps/api` — backend API (FastAPI)
- `apps/web` — frontend (React + TypeScript, planned)
- `tests` — integration and E2E tests
- `docs` — architecture decisions and public documentation

## Local development

```bash
cp .env.example .env          # set POSTGRES_PASSWORD
docker compose up -d db       # PostgreSQL 16
pip install -e "apps/api[dev]"
cd apps/api && pytest && ruff check . && mypy .
```
