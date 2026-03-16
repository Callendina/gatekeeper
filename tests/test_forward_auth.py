"""Tests for the forward_auth verify endpoint."""
import pytest


@pytest.mark.asyncio
async def test_unknown_host_returns_403(client):
    resp = await client.get("/_auth/verify", headers={"x-forwarded-host": "unknown.com"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_valid_host_returns_200(client):
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
    })
    assert resp.status_code == 200
    assert resp.headers.get("x-gatekeeper-user") == ""
    assert resp.headers.get("x-gatekeeper-role") == ""


@pytest.mark.asyncio
async def test_protected_path_without_auth_returns_401(client):
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/protected/secret",
    })
    assert resp.status_code == 401
    assert "x-gatekeeper-login-url" in resp.headers


@pytest.mark.asyncio
async def test_unprotected_path_allowed_anonymous(client):
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/public/page",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_session_cookie_set_on_first_visit(client):
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
    })
    assert resp.status_code == 200
    cookies = resp.headers.get_list("set-cookie")
    assert any("gk_session" in c for c in cookies)


@pytest.mark.asyncio
async def test_session_cookie_reused_on_revisit(client):
    # First visit — get cookie
    resp1 = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
    })
    cookies = resp1.headers.get_list("set-cookie")
    cookie_val = None
    for c in cookies:
        if "gk_session=" in c:
            cookie_val = c.split("gk_session=")[1].split(";")[0]

    assert cookie_val is not None

    # Second visit — use cookie, should NOT get a new one
    resp2 = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "cookie": f"gk_session={cookie_val}",
    })
    assert resp2.status_code == 200
    new_cookies = resp2.headers.get_list("set-cookie")
    assert not any("gk_session" in c for c in new_cookies)
