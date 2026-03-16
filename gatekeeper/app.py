"""Main FastAPI application for Gatekeeper."""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from gatekeeper.config import load_config
from gatekeeper.database import init_db
from gatekeeper.auth.forward_auth import router as forward_auth_router, init_forward_auth
from gatekeeper.auth.login import router as login_router, init_login_routes
from gatekeeper.auth.oauth import setup_oauth
from gatekeeper.auth.api_keys import router as api_key_router, init_api_key_routes, cleanup_expired_keys
from gatekeeper.admin.routes import router as admin_router, init_admin_routes
from gatekeeper.middleware.rate_limit import cleanup_old_entries
from gatekeeper.auth.sessions import cleanup_expired_sessions
from gatekeeper.database import get_db

config = load_config()


async def periodic_cleanup():
    """Background task to clean up expired sessions and stale rate limit data."""
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        cleanup_old_entries()
        async for db in get_db():
            await cleanup_expired_sessions(db)
            await cleanup_expired_keys(db)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db(config.database_path)
    init_forward_auth(config)
    init_login_routes(config)
    init_admin_routes(config)
    init_api_key_routes(config)
    setup_oauth(config)

    cleanup_task = asyncio.create_task(periodic_cleanup())

    yield

    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Gatekeeper", docs_url=None, redoc_url=None, lifespan=lifespan)

# Session middleware needed for OAuth state
app.add_middleware(SessionMiddleware, secret_key=config.secret_key)

app.include_router(forward_auth_router)
app.include_router(login_router)
app.include_router(api_key_router)
app.include_router(admin_router)


@app.get("/")
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/_auth/admin")


@app.get("/_auth/health")
async def health():
    return {"status": "ok"}
