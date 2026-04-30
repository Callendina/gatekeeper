"""MFA method picker — only renders when an app's `mfa.methods` lists
more than one option. For single-method apps the forward_auth gate
auto-binds without ever sending the user here.

Once the user picks a method, the choice is recorded on UserAppRole
(per-(user, app)) and is admin-resettable only — by design, to remove
the downgrade-attack class that arises when both methods stay
simultaneously valid.

The `_system` pseudo-app handles the system-admin gate. We materialise
the UserAppRole row on demand for `_system` since admins don't normally
have one for it.
"""
import logging
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper._time import utcnow
from gatekeeper.config import GatekeeperConfig
from gatekeeper.database import get_db
from gatekeeper.models import Session, User, UserAppRole, UserPhone, UserTOTP


router = APIRouter(prefix="/_auth/mfa")
_config: GatekeeperConfig = None
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
logger = logging.getLogger("gatekeeper.mfa_picker")


SYSTEM_PSEUDO_APP = "_system"


METHOD_DESCRIPTIONS = {
    "totp": {
        "id": "totp",
        "label": "Authenticator app (TOTP)",
        "description": (
            "Use a free authenticator app like Google Authenticator, "
            "1Password, or Authy. Recommended — it doesn't depend on your "
            "carrier or signal strength."
        ),
    },
    "sms_otp": {
        "id": "sms_otp",
        "label": "Text message (SMS)",
        "description": (
            "We'll text a 6-digit code to your phone. Australian mobile "
            "numbers only at this stage."
        ),
    },
}


def init_mfa_picker_routes(config: GatekeeperConfig):
    global _config
    _config = config


async def _resolve_session_user(
    db: AsyncSession, session_token: str | None
) -> tuple[Session | None, User | None]:
    if not session_token:
        return None, None
    session = await db.scalar(
        select(Session).where(
            Session.token == session_token,
            Session.expires_at > utcnow(),
        )
    )
    if session is None or session.user_id is None:
        return session, None
    user = await db.scalar(select(User).where(User.id == session.user_id))
    return session, user


def _safe_next(next_url: str | None) -> str:
    if not next_url:
        return "/"
    if next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return "/"


def _login_redirect(request: Request, next_url: str) -> RedirectResponse:
    host = request.headers.get("host", "")
    app_for_host = _config.app_for_domain(host)
    app_slug = app_for_host.slug if app_for_host else next(iter(_config.apps), "")
    return RedirectResponse(
        url=f"/_auth/login?app={app_slug}&next={quote(next_url)}", status_code=302
    )


def _methods_for(app_slug: str) -> list[str]:
    if app_slug == SYSTEM_PSEUDO_APP:
        return list(_config.system_admin_mfa_methods)
    app = _config.apps.get(app_slug)
    if app is None:
        return []
    return list(app.mfa.methods)


def _app_label(app_slug: str) -> str:
    if app_slug == SYSTEM_PSEUDO_APP:
        return "Gatekeeper Admin"
    app = _config.apps.get(app_slug)
    return app.name if app else app_slug


@router.get("/choose")
async def choose_get(
    request: Request,
    next: str = "/",
    app: str = "",
    db: AsyncSession = Depends(get_db),
):
    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None:
        return _login_redirect(request, request.url.path + f"?next={quote(next)}&app={app}")

    methods = _methods_for(app)
    if not methods:
        return HTMLResponse("Unknown app.", status_code=400)
    if len(methods) == 1:
        # Single-method app shouldn't have hit the picker; forward_auth
        # auto-binds in that case. Be liberal and bind here too rather
        # than 4xx.
        return await _bind_and_redirect(
            db=db, user=user, app=app, method=methods[0],
            next_url=next,
        )

    return templates.TemplateResponse("auth/mfa_choose.html", {
        "request": request,
        "user_email": user.email,
        "next": _safe_next(next),
        "app_slug": app,
        "app_name": _app_label(app),
        "methods": [METHOD_DESCRIPTIONS[m] for m in methods if m in METHOD_DESCRIPTIONS],
    })


@router.post("/choose")
async def choose_post(
    request: Request,
    method: str = Form(...),
    next: str = Form("/"),
    app: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    session_token = request.cookies.get("gk_session")
    session, user = await _resolve_session_user(db, session_token)
    if user is None:
        return _login_redirect(request, "/_auth/mfa/choose")

    methods = _methods_for(app)
    if method not in methods:
        return HTMLResponse("That method isn't allowed for this app.", status_code=400)

    return await _bind_and_redirect(
        db=db, user=user, app=app, method=method, next_url=next,
    )


async def _bind_and_redirect(
    *, db: AsyncSession, user: User, app: str, method: str, next_url: str
) -> RedirectResponse:
    """Persist UserAppRole.mfa_method (creating the `_system` row if it
    doesn't exist), then send the user to the right enrol/verify URL for
    the chosen method."""
    role = await db.scalar(
        select(UserAppRole).where(
            UserAppRole.user_id == user.id, UserAppRole.app_slug == app,
        )
    )
    if role is None:
        if app == SYSTEM_PSEUDO_APP:
            role = UserAppRole(
                user_id=user.id, app_slug=SYSTEM_PSEUDO_APP,
                role="admin", pending_invite=False, mfa_method=method,
            )
            db.add(role)
        else:
            return HTMLResponse(
                "No role for this app — sign in to the app first.",
                status_code=400,
            )
    else:
        role.mfa_method = method
    await db.commit()

    safe_next = _safe_next(next_url)
    if method == "totp":
        # Reuse the existing TOTP enrol/verify flow; it figures out
        # whether the user has a confirmed UserTOTP and routes accordingly.
        target = await db.scalar(select(UserTOTP).where(UserTOTP.user_id == user.id))
        if target is None or target.confirmed_at is None:
            return RedirectResponse(
                url=f"/_auth/totp/enroll?next={quote(safe_next)}", status_code=302,
            )
        return RedirectResponse(
            url=f"/_auth/totp/verify?next={quote(safe_next)}", status_code=302,
        )

    if method == "sms_otp":
        phone = await db.scalar(select(UserPhone).where(UserPhone.user_id == user.id))
        if phone is None or phone.confirmed_at is None:
            return RedirectResponse(
                url=f"/_auth/phone/enroll?next={quote(safe_next)}&app={app}",
                status_code=302,
            )
        return RedirectResponse(
            url=f"/_auth/sms-otp/verify?next={quote(safe_next)}&app={app}",
            status_code=302,
        )

    return HTMLResponse(f"Unknown method: {method}", status_code=400)
