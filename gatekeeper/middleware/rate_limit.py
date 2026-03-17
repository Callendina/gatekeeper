"""In-memory sliding window rate limiter per IP and per API key."""
import time
from collections import defaultdict
from gatekeeper.config import RateLimitConfig


# Store timestamps of recent requests per IP
_request_log: dict[str, list[float]] = defaultdict(list)

# Separate tracker for per-API-key rate limiting
_api_key_log: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(
    ip: str, config: RateLimitConfig, authenticated: bool = False
) -> tuple[bool, int, int]:
    """Returns (allowed, current_count, limit)."""
    now = time.time()
    window = 60.0

    cutoff = now - window
    _request_log[ip] = [t for t in _request_log[ip] if t > cutoff]

    limit = config.requests_per_minute
    if authenticated and config.authenticated_requests_per_minute > 0:
        limit = config.authenticated_requests_per_minute

    count = len(_request_log[ip])
    if count >= limit:
        return False, count, limit

    _request_log[ip].append(now)
    return True, count + 1, limit


def check_api_key_rate_limit(
    api_key: str, limit_per_minute: int
) -> tuple[bool, int, int]:
    """Returns (allowed, current_count, limit)."""
    now = time.time()
    window = 60.0

    cutoff = now - window
    _api_key_log[api_key] = [t for t in _api_key_log[api_key] if t > cutoff]

    count = len(_api_key_log[api_key])
    if count >= limit_per_minute:
        return False, count, limit_per_minute

    _api_key_log[api_key].append(now)
    return True, count + 1, limit_per_minute


def cleanup_old_entries():
    """Periodically clean up stale entries from both trackers."""
    now = time.time()
    cutoff = now - 300  # 5 minutes

    stale = [k for k, ts in _request_log.items() if not ts or ts[-1] < cutoff]
    for k in stale:
        del _request_log[k]

    stale = [k for k, ts in _api_key_log.items() if not ts or ts[-1] < cutoff]
    for k in stale:
        del _api_key_log[k]
