"""Basic smoke tests."""
import pytest


@pytest.mark.asyncio
async def test_health_endpoint(client):
    resp = await client.get("/_auth/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_login_page_renders(client):
    resp = await client.get("/_auth/login?app=testapp")
    assert resp.status_code == 200
    assert "Test App" in resp.text
    assert "Sign in" in resp.text.lower() or "Sign In" in resp.text
