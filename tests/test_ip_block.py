"""Tests for IP blocking."""
import pytest
from gatekeeper.middleware.ip_block import block_ip, unblock_ip


@pytest.mark.asyncio
async def test_blocked_ip_returns_403(client, db):
    await block_ip(db, "10.2.0.1", reason="test", blocked_by="test")

    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "x-forwarded-for": "10.2.0.1",
    })
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unblocked_ip_allowed(client, db):
    await block_ip(db, "10.2.1.1", reason="test", blocked_by="test")
    await unblock_ip(db, "10.2.1.1")

    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "x-forwarded-for": "10.2.1.1",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_non_blocked_ip_allowed(client):
    resp = await client.get("/_auth/verify", headers={
        "x-forwarded-host": "testapp.example.com",
        "x-forwarded-uri": "/",
        "x-forwarded-for": "10.2.2.1",
    })
    assert resp.status_code == 200
