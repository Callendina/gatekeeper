"""Email sending via transactional email API (Resend)."""
import logging
import httpx
from gatekeeper.config import EmailConfig

logger = logging.getLogger("gatekeeper.email")


async def send_magic_link_email(
    to: str, link: str, app_name: str, config: EmailConfig
) -> bool:
    """Send a magic link sign-in email. Returns True on success."""
    if not config.enabled:
        logger.error("Email not configured — cannot send magic link")
        return False

    html = (
        f"<p>Click the link below to sign in to <strong>{app_name}</strong>:</p>"
        f'<p><a href="{link}">Sign in to {app_name}</a></p>'
        f"<p>This link expires in 15 minutes. If you didn't request this, ignore this email.</p>"
    )

    if config.provider == "resend":
        return await _send_resend(to, f"Sign in to {app_name}", html, config)

    logger.error(f"Unknown email provider: {config.provider}")
    return False


async def _send_resend(
    to: str, subject: str, html: str, config: EmailConfig
) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {config.api_key}"},
                json={
                    "from": config.from_address,
                    "to": [to],
                    "subject": subject,
                    "html": html,
                },
            )
        if resp.status_code in (200, 201):
            logger.info(f"Magic link email sent to {to}")
            return True
        logger.error(f"Resend API error {resp.status_code}: {resp.text}")
        return False
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {e}")
        return False
