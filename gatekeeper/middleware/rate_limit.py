"""In-memory sliding window rate limiter per IP and per API key."""
import time
from collections import defaultdict
from gatekeeper.config import RateLimitConfig


# Store timestamps of recent requests per IP
_request_log: dict[str, list[float]] = defaultdict(list)

# Separate tracker for per-API-key rate limiting
_api_key_log: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(ip: str, config: RateLimitConfig, authenticated: bool = False) -> bool:
    """Returns True if request is allowed, False if rate limited."""
    now = time.time()
    window = 60.0  # 1 minute

    # Clean old entries
    timestamps = _request_log[ip]
    cutoff = now - window
    _request_log[ip] = [t for t in timestamps if t > cutoff]

    limit = config.requests_per_minute
    if authenticated and config.authenticated_requests_per_minute > 0:
        limit = config.authenticated_requests_per_minute

    if len(_request_log[ip]) >= limit:
        return False

    _request_log[ip].append(now)
    return True


def check_api_key_rate_limit(api_key: str, limit_per_minute: int) -> bool:
    """Per-API-key rate limit. Returns True if allowed, False if rate limited."""
    now = time.time()
    window = 60.0

    cutoff = now - window
    _api_key_log[api_key] = [t for t in _api_key_log[api_key] if t > cutoff]

    if len(_api_key_log[api_key]) >= limit_per_minute:
        return False

    _api_key_log[api_key].append(now)
    return True


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
