"""In-memory sliding-window rate limiter, keyed by (ip, email).

Design (per Plan.md §17 and OWASP auth cheatsheet):
- key includes BOTH ip and email: one actor/IP gets throttled, but a legit
  user on that shared IP still gets their own budget
- sliding window: each failed attempt is a timestamp; window = last N minutes
- MAX 5 failures per key per 15-minute window before 429
- thread-safe for dev (single worker); Redis backend deferred to multi-worker
  deploy decision in Phase 5 — the interface here matches that swap
"""

from __future__ import annotations

import threading
import time

_MAX_FAILURES = 5
_WINDOW_SECONDS = 15 * 60

_lock = threading.Lock()
_failures: dict[tuple[str, str], list[float]] = {}


def _now() -> float:
    return time.monotonic()


def is_rate_limited(key_ip: str, key_email: str) -> bool:
    """True when the key already has MAX failures inside the window."""
    with _lock:
        bucket = _failures.get((key_ip, key_email), [])
        cutoff = _now() - _WINDOW_SECONDS
        live = [t for t in bucket if t > cutoff]
        return len(live) >= _MAX_FAILURES


def record_failure(key_ip: str, key_email: str) -> None:
    with _lock:
        _failures.setdefault((key_ip, key_email), []).append(_now())


def reset_failures(key_ip: str, key_email: str) -> None:
    with _lock:
        _failures.pop((key_ip, key_email), None)


def _remaining_capacity(key_ip: str, key_email: str) -> int:
    """Remaining allowed failures before throttle (used by tests)."""
    with _lock:
        bucket = [t for t in _failures.get((key_ip, key_email), []) if t > _now() - _WINDOW_SECONDS]
        return max(0, _MAX_FAILURES - len(bucket))
