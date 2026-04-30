"""Five-tier in-memory sliding-window rate limiter for SMS-OTP sends.

Tiers (each with one or more windows):
    per_number: hour, day      — defends harassment, fatigue, mistype
    per_user:   hour           — defends compromised account as relay
    per_ip:     hour           — defends spray from one source
    per_app:    hour           — caps blast radius of one misbehaving app
    global:     hour, day      — logic-bug backstop

`check_and_record(...)` returns either Allowed() or a Tripped(tier, window,
current, limit). The first tripped tier wins so the access_log entry has a
specific reason. On Allowed, the timestamp is recorded against every tier.
"""
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

from gatekeeper.config import SMSRateLimits


Tier = Literal["per_number", "per_user", "per_ip", "per_app", "global"]
Window = Literal["hour", "day"]


@dataclass(frozen=True)
class Allowed:
    pass


@dataclass(frozen=True)
class Tripped:
    tier: Tier
    window: Window
    current: int
    limit: int


_HOUR = 3600.0
_DAY = 86400.0

# Per-tier rolling logs of timestamps. Keys are "<tier>:<scope_value>",
# e.g. "per_number:+61412345678", "global:_". Values are sorted-ish lists
# of float timestamps.
_log: dict[str, list[float]] = defaultdict(list)


def _prune(key: str, cutoff: float) -> list[float]:
    entries = [t for t in _log[key] if t > cutoff]
    _log[key] = entries
    return entries


def _check(key: str, window_seconds: float, limit: int) -> tuple[bool, int]:
    """Returns (would_exceed_after_record, current_count_in_window)."""
    if limit <= 0:
        return False, 0
    now = time.time()
    entries = _prune(key, now - window_seconds)
    return len(entries) >= limit, len(entries)


def check_and_record(
    *,
    e164: str,
    user_id: int,
    ip: str,
    app_slug: str,
    cfg: SMSRateLimits,
) -> Allowed | Tripped:
    """Validate every tier; record on success against every tier.

    Tiers are checked in order of specificity (number → user → ip → app →
    global). The first that trips wins, so the access_log entry says
    "per_number" rather than "global" when both would have stopped it.
    """
    checks: list[tuple[Tier, Window, str, float, int]] = [
        ("per_number", "hour", f"per_number_h:{e164}",  _HOUR, cfg.per_number_hour),
        ("per_number", "day",  f"per_number_d:{e164}",  _DAY,  cfg.per_number_day),
        ("per_user",   "hour", f"per_user:{user_id}",   _HOUR, cfg.per_user_hour),
        ("per_ip",     "hour", f"per_ip:{ip}",          _HOUR, cfg.per_ip_hour),
        ("per_app",    "hour", f"per_app:{app_slug}",   _HOUR, cfg.per_app_hour),
        ("global",     "hour", "global_h:_",            _HOUR, cfg.global_hour),
        ("global",     "day",  "global_d:_",            _DAY,  cfg.global_day),
    ]
    for tier, window, key, secs, limit in checks:
        tripped, current = _check(key, secs, limit)
        if tripped:
            return Tripped(tier=tier, window=window, current=current, limit=limit)

    now = time.time()
    for _, _, key, _, limit in checks:
        if limit > 0:
            _log[key].append(now)
    return Allowed()


def cleanup_old_entries():
    """Periodically prune anything older than the longest window we track
    (1 day). Called from app.py's periodic_cleanup."""
    now = time.time()
    cutoff = now - _DAY
    stale = [k for k, ts in _log.items() if not ts or ts[-1] < cutoff]
    for k in stale:
        del _log[k]


def reset_for_tests():
    """Clear all in-memory state. Test fixtures call this."""
    _log.clear()
