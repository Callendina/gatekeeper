"""Login, registration, and logout routes served by gatekeeper."""
from fastapi import APIRouter, Request, Response, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import User, OAuthAccount, UserAppRole
from gatekeeper.auth.passwords import hash_password, verify_password
from gatekeeper.auth.sessions import create_session, delete_session
from gatekeeper.auth.oauth import oauth

from pathlib import Path

router = APIRouter(prefix="/_auth")
_config: GatekeeperConfig = None
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def init_login_routes(config: GatekeeperConfig):
    global _config
    _config = config


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


@router.get("/login")
async def login_page(request: Request, app: str = "", next: str = "/"):
    app_config = _config.apps.get(app)
    app_name = app_config.name if app_config else "Application"
    has_google = bool(_config.google_client_id)
    return templates.TemplateResponse("auth/login.html", {
        "request": request,
        "app": app,
        "app_name": app_name,
        "next": next,
        "has_google": has_google,
        "error": None,
    })


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    app: str = Form(""),
    next: str = Form("/"),
    db: AsyncSession = Depends(get_db),
):
    app_config = _config.apps.get(app)
    app_name = app_config.name if app_config else "Application"

    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None or user.password_hash is None or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("auth/login.html", {
            "request": request,
            "app": app,
            "app_name": app_name,
            "next": next,
            "has_google": bool(_config.google_client_id),
            "error": "Invalid email or password",
        }, status_code=400)

    ip = _get_client_ip(request)
    token = await create_session(db, user.id, app, ip)

    # Determine redirect: if there's a domain for this app, redirect there
    redirect_url = next
    if app_config and app_config.domains:
        redirect_url = f"https://{app_config.domains[0]}{next}"

    response = RedirectResponse(url=redirect_url, status_code=302)
    response.set_cookie(
        "gk_session", token,
        httponly=True, secure=True, samesite="lax",
        max_age=86400 * 7,
    )
    return response


@router.get("/register")
async def register_page(request: Request, app: str = ""):
    app_config = _config.apps.get(app)
    app_name = app_config.name if app_config else "Application"
    has_google = bool(_config.google_client_id)
    return templates.TemplateResponse("auth/register.html", {
        "request": request,
        "app": app,
        "app_name": app_name,
        "has_google": has_google,
        "error": None,
    })


@router.post("/register")
async def register_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(""),
    app: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    app_config = _config.apps.get(app)
    app_name = app_config.name if app_config else "Application"

    # Check if user already exists
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing:
        return templates.TemplateResponse("auth/register.html", {
            "request": request,
            "app": app,
            "app_name": app_name,
            "has_google": bool(_config.google_client_id),
            "error": "An account with this email already exists",
        }, status_code=400)

    user = User(
        email=email,
        password_hash=hash_password(password),
        display_name=display_name or email.split("@")[0],
    )
    db.add(user)
    await db.flush()

    # Assign default role for the app
    if app_config:
        role = UserAppRole(
            user_id=user.id,
            app_slug=app,
            role=app_config.default_role,
        )
        db.add(role)

    await db.commit()

    ip = _get_client_ip(request)
    token = await create_session(db, user.id, app, ip)

    redirect_url = "/"
    if app_config and app_config.domains:
        redirect_url = f"https://{app_config.domains[0]}/"

    response = RedirectResponse(url=redirect_url, status_code=302)
    response.set_cookie(
        "gk_session", token,
        httponly=True, secure=True, samesite="lax",
        max_age=86400 * 7,
    )
    return response


@router.get("/oauth/google")
async def google_login(request: Request, app: str = "", next: str = "/"):
    redirect_uri = str(request.url_for("google_callback"))
    # Store app and next in session for the callback
    request.session["oauth_app"] = app
    request.session["oauth_next"] = next
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/oauth/google/callback")
async def google_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo")
    email = userinfo["email"]
    google_id = userinfo["sub"]
    name = userinfo.get("name", email.split("@")[0])

    app_slug = request.session.pop("oauth_app", "")
    next_url = request.session.pop("oauth_next", "/")
    app_config = _config.apps.get(app_slug)

    # Check if OAuth account already linked
    stmt = select(OAuthAccount).where(
        OAuthAccount.provider == "google",
        OAuthAccount.provider_user_id == google_id,
    )
    result = await db.execute(stmt)
    oauth_account = result.scalar_one_or_none()

    if oauth_account:
        user_id = oauth_account.user_id
    else:
        # Check if user exists by email
        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if user is None:
            user = User(email=email, display_name=name)
            db.add(user)
            await db.flush()

            if app_config:
                role = UserAppRole(
                    user_id=user.id,
                    app_slug=app_slug,
                    role=app_config.default_role,
                )
                db.add(role)

        # Link OAuth account
        oauth_link = OAuthAccount(
            user_id=user.id,
            provider="google",
            provider_user_id=google_id,
        )
        db.add(oauth_link)
        await db.commit()
        user_id = user.id

    ip = _get_client_ip(request)
    session_token = await create_session(db, user_id, app_slug, ip)

    redirect_url = next_url
    if app_config and app_config.domains:
        redirect_url = f"https://{app_config.domains[0]}{next_url}"

    response = RedirectResponse(url=redirect_url, status_code=302)
    response.set_cookie(
        "gk_session", session_token,
        httponly=True, secure=True, samesite="lax",
        max_age=86400 * 7,
    )
    return response


@router.get("/logout")
async def logout(
    request: Request,
    app: str = "",
    db: AsyncSession = Depends(get_db),
):
    token = request.cookies.get("gk_session")
    if token:
        await delete_session(db, token)

    app_config = _config.apps.get(app)
    redirect_url = "/"
    if app_config and app_config.domains:
        redirect_url = f"https://{app_config.domains[0]}/"

    response = RedirectResponse(url=redirect_url, status_code=302)
    response.delete_cookie("gk_session")
    return response
