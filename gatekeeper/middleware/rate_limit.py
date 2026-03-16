"""In-memory sliding window rate limiter per IP."""
import time
from collections import defaultdict
from gatekeeper.config import RateLimitConfig


# Store timestamps of recent requests per IP
_request_log: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(ip: str, config: RateLimitConfig) -> bool:
    """Returns True if request is allowed, False if rate limited."""
    now = time.time()
    window = 60.0  # 1 minute

    # Clean old entries
    timestamps = _request_log[ip]
    cutoff = now - window
    _request_log[ip] = [t for t in timestamps if t > cutoff]

    if len(_request_log[ip]) >= config.requests_per_minute:
        return False

    _request_log[ip].append(now)
    return True


def cleanup_old_entries():
    """Periodically clean up IPs that haven't been seen recently."""
    now = time.time()
    cutoff = now - 300  # 5 minutes
    stale = [ip for ip, ts in _request_log.items() if not ts or ts[-1] < cutoff]
    for ip in stale:
        del _request_log[ip]
