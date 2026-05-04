"""WhatsApp webhook router.

Incoming WhatsApp messages arrive from Twilio as form-encoded POSTs.
The app config is resolved from the Host header — each app registers
its domain in Gatekeeper's config, and Twilio is pointed at that
domain's `/_auth/whatsapp/webhook` URL.

Twilio signs each request with X-Twilio-Signature (HMAC-SHA1). We
verify this signature using the app-level Twilio auth token from
SMSConfig. The webhook URL path has no embedded secret (unlike the SMS
OTP delivery webhook) — the Twilio signature is the auth mechanism.

Flow:
  1. POST arrives from Twilio (user sent WhatsApp message to our number).
  2. Validate X-Twilio-Signature (constant-time).
  3. Return 200 immediately (Twilio requires < 15s response).
  4. Dispatch handle_message() as a FastAPI BackgroundTask.
     handle_message resolves user identity, calls the app's chat
     endpoint, and sends the reply via Twilio.
"""
import logging

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import PlainTextResponse

from gatekeeper.config import GatekeeperConfig
from gatekeeper.database import get_db
from gatekeeper.sms.providers import verify_twilio_signature

router = APIRouter()
logger = logging.getLogger("gatekeeper.whatsapp")

_config: GatekeeperConfig = None
_http_client = None   # set by app.py on lifespan startup


def init_whatsapp_routes(config: GatekeeperConfig, http_client) -> None:
    global _config, _http_client
    _config = config
    _http_client = http_client


@router.post("/_auth/whatsapp/webhook")
async def whatsapp_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Receive an inbound WhatsApp message from Twilio."""
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host", "")).split(":")[0]
    app_cfg = _config.app_for_domain(host)
    if app_cfg is None or app_cfg.whatsapp is None:
        # No WhatsApp config for this domain — accept silently.
        return PlainTextResponse("OK")

    # Signature verification
    if _config.sms.twilio_auth_token:
        sig = request.headers.get("x-twilio-signature", "")
        # Reconstruct the public URL Twilio signed — use forwarded proto/host
        # so it matches what Twilio sees, not the internal http://localhost URL.
        proto = request.headers.get("x-forwarded-proto", "https")
        fwd_host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
        url = f"{proto}://{fwd_host}{request.url.path}"
        form = await request.form()
        params = {k: v for k, v in form.items()}
        if not verify_twilio_signature(_config.sms.twilio_auth_token, sig, url, params):
            logger.warning("Invalid X-Twilio-Signature on WhatsApp webhook (app %s)", app_cfg.slug)
            return PlainTextResponse("Forbidden", status_code=403)
    else:
        form = await request.form()
        params = {k: v for k, v in form.items()}

    # Extract message fields. Twilio uses "From" = "whatsapp:+61..."
    from_field = params.get("From", "")
    phone = from_field.removeprefix("whatsapp:") if from_field.startswith("whatsapp:") else from_field
    text = params.get("Body", "").strip()

    if not phone or not text:
        return PlainTextResponse("OK")

    # Return 200 immediately; do the heavy work in the background.
    from gatekeeper.database import async_session_factory
    from gatekeeper.whatsapp.handler import handle_message

    async def _task():
        async with async_session_factory() as db:
            await handle_message(
                app_cfg=app_cfg,
                phone=phone,
                text=text,
                db=db,
                http_client=_http_client,
                gk_config=_config,
            )

    background_tasks.add_task(_task)
    return PlainTextResponse("OK")
