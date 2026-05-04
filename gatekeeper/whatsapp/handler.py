"""WhatsApp message handler — multi-app routing.

A single Twilio WABA number is shared across all apps that declare a
`whatsapp:` block in their config. Incoming messages are routed to the
right app by looking up which apps the caller's phone number is enrolled
in. The routing state (selected app + menu state) is persisted in the
`whatsapp_phone_state` table.

State machine per phone:
  0 eligible apps → reply "not registered"
  1 eligible app  → auto-route (no menu)
  2+ eligible apps, no selection → send numbered menu, state="selecting"
  2+ eligible apps, state="selecting" → parse reply (1/2/…), confirm selection
  2+ eligible apps, app selected → route to selected app

"reset" always clears selection and all conversation_ids, then routes
to a fresh start.
"""
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.config import AppConfig, GatekeeperConfig
from gatekeeper.models import UserAppRole, UserPhone, User
from gatekeeper.sms.providers import get_provider
from gatekeeper.whatsapp import formatter, session as wa_session

logger = logging.getLogger("gatekeeper.whatsapp")

_RESET_KEYWORDS = {"reset", "new", "start over", "restart"}


async def handle_message(
    *,
    phone: str,
    text: str,
    db: AsyncSession,
    http_client: httpx.AsyncClient,
    gk_config: GatekeeperConfig,
) -> None:
    """Process one inbound WhatsApp message. All errors are caught and
    logged — never raised, since we're in a BackgroundTask."""
    try:
        await _handle(phone=phone, text=text, db=db, http_client=http_client, gk_config=gk_config)
    except Exception:
        logger.exception("Unhandled error processing WhatsApp message from %s", phone[-4:])


async def _handle(
    *,
    phone: str,
    text: str,
    db: AsyncSession,
    http_client: httpx.AsyncClient,
    gk_config: GatekeeperConfig,
) -> None:
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
                      reason="unregistered_phone", phone_tail=phone[-4:])
        return

    # Find all apps with whatsapp config that this user has a role in
    wa_app_slugs = [slug for slug, cfg in gk_config.apps.items() if cfg.whatsapp]
    if not wa_app_slugs:
        return

    app_roles = {
        r.app_slug: r
        for r in await db.scalars(
            select(UserAppRole).where(
                UserAppRole.user_id == user_phone.user_id,
                UserAppRole.app_slug.in_(wa_app_slugs),
            )
        )
    }
    eligible_apps: list[tuple[AppConfig, UserAppRole]] = [
        (gk_config.apps[slug], role)
        for slug, role in app_roles.items()
    ]

    cyclops.event(
        "gatekeeper.whatsapp.message",
        outcome="received",
        phone_tail=phone[-4:],
        eligible_app_count=len(eligible_apps),
    )

    # Reset command — clears everything regardless of state
    if text.strip().lower() in _RESET_KEYWORDS:
        await wa_session.clear_phone_state(db, phone, [cfg.slug for cfg, _ in eligible_apps])
        cyclops.event("gatekeeper.whatsapp.message", outcome="reset", phone_tail=phone[-4:])
        await _send(gk_config=gk_config, to=phone, text="Starting a new conversation.",
                    http_client=http_client)
        return

    # 0 eligible apps
    if not eligible_apps:
        cyclops.event("gatekeeper.whatsapp.message", outcome="ignored",
                      reason="no_eligible_apps", phone_tail=phone[-4:])
        await _send(
            gk_config=gk_config, to=phone, http_client=http_client,
            text="Your phone number isn't registered for any apps. Please contact your administrator.",
        )
        return

    # 1 eligible app — auto-route, no menu
    if len(eligible_apps) == 1:
        app_cfg, app_role = eligible_apps[0]
        # Ensure selection is recorded (idempotent)
        selected_slug, _ = await wa_session.get_phone_state(db, phone)
        if selected_slug != app_cfg.slug:
            await wa_session.set_phone_state(db, phone, selected_app_slug=app_cfg.slug, state=None)
        await _chat(
            app_cfg=app_cfg, app_role=app_role, phone=phone, text=text,
            user_phone=user_phone, db=db, http_client=http_client, gk_config=gk_config,
        )
        return

    # 2+ eligible apps — check routing state
    selected_slug, state = await wa_session.get_phone_state(db, phone)

    if state == "selecting":
        # User is replying to the app-selection menu
        choice = text.strip()
        if choice.isdigit() and 1 <= int(choice) <= len(eligible_apps):
            app_cfg, app_role = eligible_apps[int(choice) - 1]
            await wa_session.set_phone_state(db, phone, selected_app_slug=app_cfg.slug, state=None)
            cyclops.event("gatekeeper.whatsapp.app_selected",
                          phone_tail=phone[-4:], app_slug=app_cfg.slug)
            await _send(
                gk_config=gk_config, to=phone, http_client=http_client,
                text=f"Connected to {app_cfg.name}. How can I help?",
            )
        else:
            # Invalid input — re-send menu
            await _send_menu(gk_config=gk_config, to=phone,
                             apps=eligible_apps, http_client=http_client)
        return

    if selected_slug:
        # User has a previously selected app — look it up
        app_cfg_role = next(
            ((cfg, role) for cfg, role in eligible_apps if cfg.slug == selected_slug),
            None,
        )
        if app_cfg_role:
            app_cfg, app_role = app_cfg_role
            await _chat(
                app_cfg=app_cfg, app_role=app_role, phone=phone, text=text,
                user_phone=user_phone, db=db, http_client=http_client, gk_config=gk_config,
            )
            return
        # Previously selected app no longer available — fall through to menu

    # No selection yet (or stale selection) — send menu
    await wa_session.set_phone_state(db, phone, selected_app_slug=None, state="selecting")
    await _send_menu(gk_config=gk_config, to=phone, apps=eligible_apps, http_client=http_client)


async def _send_menu(
    *,
    gk_config: GatekeeperConfig,
    to: str,
    apps: list[tuple[AppConfig, UserAppRole]],
    http_client: httpx.AsyncClient,
) -> None:
    lines = ["You have access to multiple apps. Reply with a number to choose:"]
    for i, (app_cfg, _) in enumerate(apps, 1):
        lines.append(f"{i}. {app_cfg.name}")
    await _send(gk_config=gk_config, to=to, text="\n".join(lines), http_client=http_client)


async def _chat(
    *,
    app_cfg: AppConfig,
    app_role: UserAppRole,
    phone: str,
    text: str,
    user_phone: UserPhone,
    db: AsyncSession,
    http_client: httpx.AsyncClient,
    gk_config: GatekeeperConfig,
) -> None:
    """Route a message to the app's chat endpoint and send the reply."""
    import cyclops

    wa_cfg = app_cfg.whatsapp

    # Per-(user, app) staging redirect: route this tester's traffic at
    # the app's configured staging chat backend without redeploying.
    # See issue #14. Falls back to prod (with a warning) if the admin
    # toggled the flag on but no staging URL is configured for the app.
    if app_role.redirect_to_staging and wa_cfg.chat_endpoint_staging:
        endpoint = wa_cfg.chat_endpoint_staging
        staging_active = True
    else:
        endpoint = wa_cfg.chat_endpoint
        staging_active = False
        if app_role.redirect_to_staging:
            logger.warning(
                "redirect_to_staging set on (user=%s, app=%s) but no "
                "chat_endpoint_staging configured — falling back to prod",
                user_phone.user_id, app_cfg.slug,
            )

    # Build chat request body
    conv_id = await wa_session.get_conversation_id(db, phone, app_cfg.slug)
    body: dict = {"message": text}
    if wa_cfg.default_comp:
        body["default_comp"] = wa_cfg.default_comp
    if conv_id is not None:
        body["conversation_id"] = conv_id

    # Resolve user identity for X-Gatekeeper-* headers
    user = await db.scalar(select(User).where(User.id == user_phone.user_id))
    user_header = user.email if (user and user.email) else f"phone:{phone[-4:]}"

    headers = {
        "X-Gatekeeper-User": user_header,
        "X-Gatekeeper-Role": app_role.role or "user",
        "X-Gatekeeper-Group": app_role.group or "",
    }

    cyclops.event("gatekeeper.whatsapp.message", outcome="dispatched",
                  app_slug=app_cfg.slug, phone_tail=phone[-4:],
                  has_conversation=conv_id is not None,
                  endpoint=endpoint, staging=staging_active)

    try:
        resp = await http_client.post(
            endpoint, json=body, headers=headers, timeout=120.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        logger.exception("Chat endpoint error for app %s", app_cfg.slug)
        cyclops.event("gatekeeper.whatsapp.chat_error", app_slug=app_cfg.slug,
                      phone_tail=phone[-4:], endpoint=endpoint,
                      staging=staging_active)
        await _send(
            gk_config=gk_config, to=phone, http_client=http_client,
            text="Sorry, I couldn't reach the chat service right now. Please try again.",
        )
        return

    new_conv_id = data.get("conversation_id")
    if new_conv_id is not None:
        await wa_session.set_conversation_id(db, phone, app_cfg.slug, int(new_conv_id))

    reply_md = data.get("response") or ""
    reply_text = formatter.to_whatsapp(reply_md) if reply_md else "(no response)"
    if staging_active:
        reply_text = f"[staging] {reply_text}"

    cyclops.event("gatekeeper.whatsapp.reply_sent", app_slug=app_cfg.slug,
                  phone_tail=phone[-4:], reply_chars=len(reply_text),
                  staging=staging_active)

    await _send(gk_config=gk_config, to=phone, text=reply_text, http_client=http_client)


async def _send(
    *,
    gk_config: GatekeeperConfig,
    to: str,
    text: str,
    http_client: httpx.AsyncClient,
) -> None:
    """Send a WhatsApp reply via Twilio using the server-level WABA number."""
    whatsapp_from = gk_config.sms.whatsapp_from
    if not whatsapp_from:
        logger.warning("No sms.whatsapp_from configured — cannot send WhatsApp reply")
        return

    provider = get_provider(gk_config.sms)

    class _NullDb:
        def add(self, _): pass
        async def commit(self): pass

    result = await provider.send(
        to_e164=to,
        body=text,
        idempotency_key=f"wa-{to}-{hash(text) & 0xFFFFFF}",
        db=_NullDb(),
        from_override=whatsapp_from,
    )
    import cyclops
    cyclops.event(
        "gatekeeper.whatsapp.twilio_send",
        phone_tail=to[-4:],
        accepted=result.accepted,
        message_id=result.provider_message_id,
        error_category=result.error_category,
        error_message=result.error_message,
        raw_response=result.raw_response,
    )
    if not result.accepted:
        logger.warning(
            "WhatsApp send failed to %s: %s (%s)",
            to[-4:], result.error_message, result.error_category,
        )
