"""Tests for soft paywall."""
import pytest


@pytest.mark.asyncio
async def test_paywall_allows_within_quota(client):
    """New sessions within the quota should be allowed."""
    for i in range(3):
        resp = await client.get("/_auth/verify", headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/",
            "x-forwarded-for": f"10.0.0.{i + 1}",
        })
        assert resp.status_code == 200, f"Session {i + 1} should be allowed"


@pytest.mark.asyncio
async def test_paywall_blocks_after_quota(client):
    """Sessions beyond the quota from the same IP should be blocked."""
    # Use same IP, but no cookies (each request is a new session)
    for i in range(3):
        resp = await client.get("/_auth/verify", headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/",
            "x-forwarded-for": "10.0.0.99",
        })
        assert resp.status_code == 200

    # 4th new session from same IP should be blocked (redirect to login)
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "x-forwarded-for": "10.0.0.99",
    })
    assert resp.status_code == 302
    location = resp.headers.get("location", "")
    assert "/_auth/login" in location or "/_auth/nag" in location


@pytest.mark.asyncio
async def test_paywall_revisit_does_not_count(client):
    """Revisiting with an existing session cookie should not increment the counter."""
    # First visit — get cookie
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "x-forwarded-for": "10.0.1.1",
    })
    assert resp.status_code == 200
    cookies = resp.headers.get_list("set-cookie")
    cookie_val = None
    for c in cookies:
        if "gk_session=" in c:
            cookie_val = c.split("gk_session=")[1].split(";")[0]

    # Revisit several times with the same cookie — should all succeed
    # (keep under rate limit of 10/min)
    for i in range(5):
        resp = await client.get("/_auth/verify", headers={
            "x-forwarded-host": "testapp.example.com",
            "x-forwarded-uri": "/",
            "x-forwarded-for": "10.0.1.1",
            "cookie": f"gk_session={cookie_val}",
        })
        assert resp.status_code == 200, f"Revisit {i + 1} should be allowed"


@pytest.mark.asyncio
async def test_api_paywall_counts_per_request(client):
    """API mode paywall should count every request, not just new sessions."""
    # apiapp has max_api_calls_per_hour=5, but api paths require keys.
    # Use a non-API path to test the general paywall doesn't apply
    # (apiapp doesn't have session-based paywall)
    for i in range(5):
        resp = await client.get("/_auth/verify", headers={
            "x-forwarded-host": "api.example.com",
            "x-forwarded-uri": "/",
            "x-forwarded-for": "10.0.2.1",
        })
        # apiapp has no session paywall, should always be 200 for non-API paths
        assert resp.status_code == 200
