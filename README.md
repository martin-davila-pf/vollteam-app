# 🏐 Vollteam

Mobile-first volleyball game management: administrators schedule games, players
register (with up to 2 guests), overflow goes to a strict FIFO waitlist, and
cancellations promote the oldest waitlisted registration atomically.

## Status

Phase 1 in progress — repository bootstrap. No application code yet.

Planned stack: Python/FastAPI API, PostgreSQL, React + TypeScript + Vite +
Tailwind frontend, server-side opaque sessions with RBAC.

## Repository layout

- `apps/api` — backend API (planned)
- `apps/web` — frontend (planned)
- `tests` — integration and E2E tests (planned)
- `docs` — public documentation (planned, English)

## Development (planned)

Docker Compose based local environment will be added in Phase 1 milestones.

## License

All rights reserved. Private project.

## Security

Private execution context lives under `prompts/` and is never versioned or
published. Report issues directly to the maintainer.
