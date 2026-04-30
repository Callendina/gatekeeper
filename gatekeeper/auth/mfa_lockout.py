"""Shared per-IP failure tracker for all MFA verifies (TOTP + SMS OTP).

The tracker is intentionally cross-method: the IP-level limiter cares
about the source IP, not which factor was attempted, so a mixed-method
attacker shouldn't get 2x the budget. After N failures within the rolling
window, the IP is added to the existing block list (via block_ip).
"""
import time


_failures: dict[str, list[float]] = {}

FAIL_WINDOW_SECONDS = 600       # 10-minute rolling window
FAIL_BLOCK_THRESHOLD = 10       # auto-block after this many failures in window


def record_failure(ip: str) -> int:
    """Returns the count of failures from this IP within the window."""
    now = time.time()
    cutoff = now - FAIL_WINDOW_SECONDS
    entries = [t for t in _failures.get(ip, []) if t > cutoff]
    entries.append(now)
    _failures[ip] = entries
    return len(entries)


def clear(ip: str) -> None:
    _failures.pop(ip, None)


def reset_for_tests() -> None:
    _failures.clear()
