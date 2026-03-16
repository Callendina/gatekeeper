"""Tests for rate limiting."""
import pytest


@pytest.mark.asyncio
async def test_rate_limit_allows_within_limit(client):
    """Requests within the rate limit should be allowed."""
    for i in range(10):
        resp = await client.get("/_auth/verify", headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/",
            "x-forwarded-for": "10.1.0.1",
        })
        assert resp.status_code in (200, 403), f"Request {i + 1} unexpected status"


@pytest.mark.asyncio
async def test_rate_limit_blocks_after_limit(client):
    """Requests beyond the rate limit should return 429."""
    # Config sets requests_per_minute=10
    for i in range(10):
        await client.get("/_auth/verify", headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/",
            "x-forwarded-for": "10.1.1.1",
        })

    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "x-forwarded-for": "10.1.1.1",
    })
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_rate_limit_per_ip(client):
    """Different IPs should have independent rate limits."""
    # Exhaust rate limit for one IP
    for i in range(11):
        await client.get("/_auth/verify", headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/",
            "x-forwarded-for": "10.1.2.1",
        })

    # Different IP should still work
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "x-forwarded-for": "10.1.2.2",
    })
    assert resp.status_code == 200
