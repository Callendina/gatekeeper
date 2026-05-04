"""WhatsApp message handler — core business logic.

Resolves phone → user identity, calls the app's chat endpoint, sends
reply via Twilio. Designed to run as a FastAPI BackgroundTask so the
webhook can return 200 to Twilio immediately (< 15s requirement).
"""
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.config import AppConfig, GatekeeperConfig
from gatekeeper.models import UserAppRole, UserPhone
from gatekeeper.sms.providers import get_provider
from gatekeeper.whatsapp import formatter, session as wa_session

logger = logging.getLogger("gatekeeper.whatsapp")

_RESET_KEYWORDS = {"reset", "new", "start over", "restart"}


async def handle_message(
    *,
    app_cfg: AppConfig,
    phone: str,
    text: str,
    db: AsyncSession,
    http_client: httpx.AsyncClient,
    gk_config: GatekeeperConfig,
) -> None:
    """Process one inbound WhatsApp message. All errors are caught and
    logged — never raised, since we're in a BackgroundTask."""
    try:
        await _handle(
            app_cfg=app_cfg, phone=phone, text=text,
            db=db, http_client=http_client, gk_config=gk_config,
        )
    except Exception:
        logger.exception(
            "Unhandled error processing WhatsApp message from %s for app %s",
            phone[-4:], app_cfg.slug,
        )


async def _handle(
    *,
    app_cfg: AppConfig,
    phone: str,
    text: str,
    db: AsyncSession,
    http_client: httpx.AsyncClient,
    gk_config: GatekeeperConfig,
) -> None:
    wa_cfg = app_cfg.whatsapp
    if wa_cfg is None:
        logger.warning("handle_message called for app %s with no whatsapp config", app_cfg.slug)
        return

    import cyclops

    # Resolve phone → confirmed UserPhone
    user_phone = await db.scalar(
        select(UserPhone).where(
            UserPhone.e164 == phone,
            UserPhone.confirmed_at.isnot(None),
        )
    )
    if user_phone is None:
        cyclops.event("gatekeeper.whatsapp.message", outcome="ignored",
                      reason="unregistered_phone", app_slug=app_cfg.slug, phone_tail=phone[-4:])
        return

    # Check role in this app
    app_role = await db.scalar(
        select(UserAppRole).where(
            UserAppRole.user_id == user_phone.user_id,
            UserAppRole.app_slug == app_cfg.slug,
        )
    )
    if app_role is None:
        cyclops.event("gatekeeper.whatsapp.message", outcome="ignored",
                      reason="no_role", app_slug=app_cfg.slug, phone_tail=phone[-4:])
        return

    # Reset command
    if text.strip().lower() in _RESET_KEYWORDS:
        await wa_session.clear_session(db, phone, app_cfg.slug)
        cyclops.event("gatekeeper.whatsapp.message", outcome="reset",
                      app_slug=app_cfg.slug, phone_tail=phone[-4:])
        await _send_whatsapp(
            gk_config=gk_config, app_cfg=app_cfg, to=phone,
            text="Starting a new conversation.", http_client=http_client,
        )
        return

    # Build chat request
    conv_id = await wa_session.get_conversation_id(db, phone, app_cfg.slug)
    body: dict = {"message": text}
    if wa_cfg.default_comp:
        body["default_comp"] = wa_cfg.default_comp
    if conv_id is not None:
        body["conversation_id"] = conv_id

    # Resolve identity for X-Gatekeeper-* headers.
    # email may be None for phone-only users — fall back to redacted phone.
    from gatekeeper.models import User
    user = await db.scalar(select(User).where(User.id == user_phone.user_id))
    user_header = user.email if (user and user.email) else f"phone:{phone[-4:]}"

    headers = {
        "X-Gatekeeper-User": user_header,
        "X-Gatekeeper-Role": app_role.role or "user",
        "X-Gatekeeper-Group": app_role.group or "",
    }

    cyclops.event("gatekeeper.whatsapp.message", outcome="dispatched",
                  app_slug=app_cfg.slug, phone_tail=phone[-4:],
                  has_conversation=conv_id is not None)

    try:
        resp = await http_client.post(
            wa_cfg.chat_endpoint, json=body, headers=headers, timeout=120.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        logger.exception("Chat endpoint error for app %s", app_cfg.slug)
        cyclops.event("gatekeeper.whatsapp.chat_error", app_slug=app_cfg.slug,
                      phone_tail=phone[-4:], endpoint=wa_cfg.chat_endpoint)
        await _send_whatsapp(
            gk_config=gk_config, app_cfg=app_cfg, to=phone,
            text="Sorry, I couldn't reach the chat service right now. Please try again.",
            http_client=http_client,
        )
        return

    new_conv_id = data.get("conversation_id")
    if new_conv_id is not None:
        await wa_session.set_conversation_id(db, phone, app_cfg.slug, int(new_conv_id))

    reply_md = data.get("response") or ""
    reply_text = formatter.to_whatsapp(reply_md) if reply_md else "(no response)"

    cyclops.event("gatekeeper.whatsapp.reply_sent", app_slug=app_cfg.slug,
                  phone_tail=phone[-4:], reply_chars=len(reply_text))

    await _send_whatsapp(
        gk_config=gk_config, app_cfg=app_cfg, to=phone,
        text=reply_text, http_client=http_client,
    )


async def _send_whatsapp(
    *,
    gk_config: GatekeeperConfig,
    app_cfg: AppConfig,
    to: str,
    text: str,
    http_client: httpx.AsyncClient,
) -> None:
    """Send a WhatsApp reply via Twilio using the app's whatsapp_from number."""
    wa_cfg = app_cfg.whatsapp
    if wa_cfg is None or not wa_cfg.whatsapp_from:
        logger.warning("No whatsapp_from configured for app %s", app_cfg.slug)
        return

    provider = get_provider(gk_config.sms)
    # Pass a fake DB session — FakeSmsProvider writes to DB, but TwilioProvider
    # doesn't use db in send(). WhatsApp path always uses Twilio in production.
    # We use a null-object pattern: db is not needed for Twilio sends.
    class _NullDb:
        def add(self, _): pass
        async def commit(self): pass

    result = await provider.send(
        to_e164=to,
        body=text,
        idempotency_key=f"wa-{app_cfg.slug}-{to}",
        db=_NullDb(),
        from_override=wa_cfg.whatsapp_from,
    )
    if not result.accepted:
        logger.warning(
            "WhatsApp send failed for app %s to %s: %s (%s)",
            app_cfg.slug, to[-4:], result.error_message, result.error_category,
        )
