"""Main FastAPI application for Gatekeeper."""
import asyncio
import datetime
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.sessions import SessionMiddleware

from gatekeeper._time import utcnow
from gatekeeper.config import load_config
from gatekeeper.database import init_db, backfill_mfa_method
from gatekeeper.auth.forward_auth import router as forward_auth_router, init_forward_auth
from gatekeeper.auth.login import router as login_router, init_login_routes
from gatekeeper.auth.oauth import setup_oauth
from gatekeeper.auth.api_keys import router as api_key_router, init_api_key_routes, cleanup_expired_keys
from gatekeeper.auth.invites import router as invite_router, init_invite_routes
from gatekeeper.auth.magic_link import router as magic_link_router, init_magic_link_routes, cleanup_expired_magic_links
from gatekeeper.auth.totp import router as totp_router, init_totp_routes
from gatekeeper.auth.sms_otp import router as sms_otp_router, init_sms_otp_routes
from gatekeeper.auth.mfa_picker import router as mfa_picker_router, init_mfa_picker_routes
from gatekeeper.admin.routes import router as admin_router, init_admin_routes
from gatekeeper.middleware.rate_limit import cleanup_old_entries
from gatekeeper.auth.sessions import cleanup_expired_sessions
from gatekeeper.database import get_db

config = load_config()


async def periodic_cleanup():
    """Background task to clean up expired sessions and stale rate limit data."""
    from gatekeeper.sms.challenges import cleanup_old_challenges, cleanup_debug_outbox
    from gatekeeper.sms.rate_limit import cleanup_old_entries as cleanup_sms_rate_limit
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        cleanup_old_entries()
        cleanup_sms_rate_limit()
        async for db in get_db():
            await cleanup_expired_sessions(db)
            await cleanup_expired_keys(db)
            await cleanup_expired_magic_links(db)
            await cleanup_old_challenges(db)
            await cleanup_debug_outbox(db)


_started_at = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _started_at
    _started_at = datetime.datetime.now(datetime.timezone.utc)
    await init_db(config.database_path)
    await backfill_mfa_method(config)
    init_forward_auth(config)
    init_login_routes(config)
    init_admin_routes(config)
    init_api_key_routes(config)
    init_invite_routes(config)
    init_magic_link_routes(config)
    init_totp_routes(config)
    init_sms_otp_routes(config)
    init_mfa_picker_routes(config)
    from gatekeeper.sms.providers import warn_if_real_provider_active
    warn_if_real_provider_active(config.sms)
    setup_oauth(config)

    cleanup_task = asyncio.create_task(periodic_cleanup())

    yield

    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Gatekeeper", docs_url=None, redoc_url=None, lifespan=lifespan)

# Trust X-Forwarded-Proto/Host from Caddy so url_for() generates correct URLs
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=["127.0.0.1", "localhost"])

# Session middleware needed for OAuth state
app.add_middleware(SessionMiddleware, secret_key=config.secret_key)

app.include_router(forward_auth_router)
app.include_router(login_router)
app.include_router(api_key_router)
app.include_router(invite_router)
app.include_router(magic_link_router)
app.include_router(totp_router)
app.include_router(sms_otp_router)
app.include_router(mfa_picker_router)
app.include_router(admin_router)


@app.get("/")
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/_auth/admin")


@app.get("/_auth/health")
async def health():
    return {"status": "ok"}


@app.get("/_auth/version")
async def version():
    import subprocess
    try:
        count = subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=str(Path(__file__).parent.parent),
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        ver = int(count)
    except Exception:
        ver = 0
    return {
        "version": ver,
        "running_since": _started_at.isoformat() if _started_at else None,
    }


@app.get("/_auth/status/{app_slug}")
async def status(app_slug: str, db: AsyncSession = Depends(get_db)):
    from gatekeeper.auth.api_keys import count_active_keys
    if app_slug not in config.apps:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "Unknown app"}, status_code=404)
    counts = await count_active_keys(db, app_slug)
    return {
        "app": app_slug,
        "active_keys": counts,
    }


@app.get("/_auth/status/{app_slug}/keys")
async def status_keys(app_slug: str, request: Request, db: AsyncSession = Depends(get_db)):
    """List all active API keys for an app. Requires admin_api_key in X-Admin-Key header."""
    from fastapi.responses import JSONResponse
    from gatekeeper.models import APIKey, User
    import datetime

    if app_slug not in config.apps:
        return JSONResponse({"error": "Unknown app"}, status_code=404)

    app_config = config.apps[app_slug]
    if not app_config.admin_api_key:
        return JSONResponse({"error": "admin_api_key not configured for this app"}, status_code=403)

    provided_key = request.headers.get("x-admin-key", "")
    if not provided_key or provided_key != app_config.admin_api_key:
        return JSONResponse({"error": "Invalid or missing X-Admin-Key"}, status_code=401)

    now = utcnow()
    stmt = select(APIKey).where(
        APIKey.app_slug == app_slug,
        APIKey.expires_at > now,
    ).order_by(APIKey.created_at.desc())
    result = await db.execute(stmt)
    keys = result.scalars().all()

    key_list = []
    for k in keys:
        # Look up user email if authenticated key
        user_email = None
        if k.user_id:
            user_result = await db.execute(select(User).where(User.id == k.user_id))
            user_obj = user_result.scalar_one_or_none()
            if user_obj:
                user_email = user_obj.email

        tier = "registered" if k.key_type == "registered" else (
            "temp_authenticated" if k.user_id else "temp_anonymous"
        )
        key_list.append({
            "key": k.key,
            "tier": tier,
            "user_email": user_email,
            "ip_address": k.ip_address,
            "created_at": k.created_at.isoformat() + "Z",
            "expires_at": k.expires_at.isoformat() + "Z",
            "rate_limit_override": k.rate_limit_override,
        })

    return {"app": app_slug, "keys": key_list}
