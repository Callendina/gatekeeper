"""OAuth login and logout routes served by gatekeeper."""
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.database import get_db
from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import User, OAuthAccount, UserAppRole
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

    # If the app has a custom login HTML file, serve it with placeholders replaced
    if app_config and app_config.login_html_file:
        try:
            with open(app_config.login_html_file) as f:
                html = f.read()
            html = html.replace("{{APP_NAME}}", app_name)
            html = html.replace("{{GOOGLE_URL}}", f"/_auth/oauth/google?app={app}&next={next}")
            html = html.replace("{{GITHUB_URL}}", f"/_auth/oauth/github?app={app}&next={next}")
            return HTMLResponse(html)
        except FileNotFoundError:
            pass  # Fall through to default template

    return templates.TemplateResponse("auth/login.html", {
        "request": request,
        "app": app,
        "app_name": app_name,
        "next": next,
        "has_google": bool(_config.google_client_id),
        "has_github": bool(_config.github_client_id),
    })


@router.get("/nag")
async def nag_page(request: Request, app: str = "", next: str = "/"):
    app_config = _config.apps.get(app)
    app_name = app_config.name if app_config else "Application"

    # If the app has a custom nag HTML file, serve it with placeholders replaced
    if app_config and app_config.paywall.nag_html_file:
        try:
            with open(app_config.paywall.nag_html_file) as f:
                html = f.read()
            html = html.replace("{{APP_NAME}}", app_name)
            google_url = f"/_auth/oauth/google?app={app}&next={next}"
            github_url = f"/_auth/oauth/github?app={app}&next={next}"
            html = html.replace("{{LOGIN_GOOGLE_URL}}", google_url)
            html = html.replace("{{LOGIN_GITHUB_URL}}", github_url)
            html = html.replace("{{GOOGLE_URL}}", google_url)
            html = html.replace("{{GITHUB_URL}}", github_url)
            html = html.replace("{{DISMISS_URL}}", f"/_auth/nag/dismiss?next={next}")
            return HTMLResponse(html)
        except FileNotFoundError:
            pass  # Fall through to default template

    return templates.TemplateResponse("auth/nag.html", {
        "request": request,
        "app": app,
        "app_name": app_name,
        "next": next,
        "has_google": bool(_config.google_client_id),
        "has_github": bool(_config.github_client_id),
    })


@router.get("/nag/dismiss")
async def nag_dismiss(request: Request, next: str = "/"):
    """Set a cookie to suppress the nag for 1 hour and redirect to the original page."""
    response = RedirectResponse(url=next, status_code=302)
    response.set_cookie(
        "gk_nag_dismissed", "1",
        httponly=True, secure=True, samesite="lax",
        max_age=3600,  # 1 hour
    )
    return response


# --- Google OAuth ---

@router.get("/oauth/google")
async def google_login(request: Request, app: str = "", next: str = "/"):
    redirect_uri = str(request.url_for("google_callback"))
    request.session["oauth_app"] = app
    request.session["oauth_next"] = next
    request.session["oauth_origin_host"] = request.headers.get("host", "")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/oauth/google/callback")
async def google_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo")
    email = userinfo["email"]
    provider_id = userinfo["sub"]
    name = userinfo.get("name", email.split("@")[0])

    return await _handle_oauth_callback(
        request, db, "google", provider_id, email, name
    )


# --- GitHub OAuth ---

@router.get("/oauth/github")
async def github_login(request: Request, app: str = "", next: str = "/", origin: str = ""):
    current_host = request.headers.get("host", "")

    # GitHub only allows one callback URL per OAuth App, so if a fixed
    # callback domain is configured, redirect there first
    if _config.github_callback_domain and current_host != _config.github_callback_domain:
        # Pass the origin host in the URL so it survives the cross-domain redirect
        from urllib.parse import quote
        target = (
            f"https://{_config.github_callback_domain}/_auth/oauth/github"
            f"?app={app}&next={quote(next)}&origin={current_host}"
        )
        return RedirectResponse(url=target, status_code=302)

    if _config.github_callback_domain:
        redirect_uri = f"https://{_config.github_callback_domain}/_auth/oauth/github/callback"
    else:
        redirect_uri = str(request.url_for("github_callback"))

    request.session["oauth_app"] = app
    request.session["oauth_next"] = next
    # Use origin param if provided (cross-domain redirect), otherwise current host
    request.session["oauth_origin_host"] = origin or current_host
    return await oauth.github.authorize_redirect(request, redirect_uri)


@router.get("/oauth/github/callback")
async def github_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    token = await oauth.github.authorize_access_token(request)

    # Get user profile
    resp = await oauth.github.get("user", token=token)
    profile = resp.json()

    # GitHub doesn't always include email in profile — fetch from emails API
    email = profile.get("email")
    if not email:
        email_resp = await oauth.github.get("user/emails", token=token)
        emails = email_resp.json()
        primary = next((e for e in emails if e.get("primary")), None)
        email = primary["email"] if primary else emails[0]["email"]

    provider_id = str(profile["id"])
    name = profile.get("name") or profile.get("login") or email.split("@")[0]

    return await _handle_oauth_callback(
        request, db, "github", provider_id, email, name
    )


# --- Shared OAuth logic ---

async def _handle_oauth_callback(
    request: Request,
    db: AsyncSession,
    provider: str,
    provider_id: str,
    email: str,
    name: str,
):
    app_slug = request.session.pop("oauth_app", "")
    next_url = request.session.pop("oauth_next", "/")
    origin_host = request.session.pop("oauth_origin_host", "")
    app_config = _config.apps.get(app_slug)

    # Check allowed_emails whitelist
    if app_config and app_config.allowed_emails and email not in app_config.allowed_emails:
        return HTMLResponse(
            "<h2>Access denied</h2><p>Your account is not authorised for this application.</p>",
            status_code=403,
        )

    # Check if OAuth account already linked
    stmt = select(OAuthAccount).where(
        OAuthAccount.provider == provider,
        OAuthAccount.provider_user_id == provider_id,
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
            provider=provider,
            provider_user_id=provider_id,
        )
        db.add(oauth_link)
        await db.commit()
        user_id = user.id

    ip = _get_client_ip(request)
    session_token = await create_session(db, user_id, app_slug, ip)

    # Redirect back to where the user started the OAuth flow
    if origin_host:
        redirect_url = f"https://{origin_host}{next_url}"
    elif app_config and app_config.domains:
        redirect_url = f"https://{app_config.domains[0]}{next_url}"
    else:
        redirect_url = next_url

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
