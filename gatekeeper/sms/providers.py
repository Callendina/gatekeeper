"""SMS provider abstraction.

Two concrete providers ship today:
  - FakeSmsProvider: writes plaintext to debug_sms_outbox + stdout.
    Selected when sms.provider == "fake". Used in dev/CI.
  - TwilioProvider: real provider. Selected when sms.provider == "twilio".
    Handles both plain SMS (From=+61...) and WhatsApp (From=whatsapp:+61...)
    via the same API endpoint — caller passes from_override for WhatsApp.
    test_mode=True uses Twilio's separate test credentials (separate SID/token
    from the console) which only accept Twilio's magic test numbers and never
    bill or deliver.

The interface keeps `send` returning enough metadata (provider message id,
cost, error category) that the caller can record it in the challenge row
without re-querying the provider.
"""
import base64
import hashlib
import hmac
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.config import SMSConfig
from gatekeeper.models import DebugSmsOutbox


# Error categories from the design's taxonomy. Mapping to action:
#   InvalidNumber       — fail visibly, do not retry, do not consume slot
#   CountryNotAllowed   — security event, generic user error, do not retry
#   InsufficientCredit  — operator alert, 5xx, do not consume challenge
#   ProviderRateLimit   — backoff + jitter, retry once, then 5xx
#   TransientUnknown    — log full response, retry once, then fail
ErrorCategory = Literal[
    "invalid_number",
    "country_not_allowed",
    "insufficient_credit",
    "provider_rate_limit",
    "transient_unknown",
]


@dataclass
class SendResult:
    accepted: bool
    provider_message_id: str | None
    cost_cents: int | None        # provider charge in cents, if known
    cost_currency: str | None     # ISO 4217 (e.g. "USD"); None if unknown
    error_category: ErrorCategory | None
    raw_response: str | None      # opaque blob, useful for debugging
    error_message: str | None = None


@dataclass
class DeliveryStatus:
    state: Literal["pending", "delivered", "failed", "unknown"]
    failed_at: str | None = None
    error_category: ErrorCategory | None = None


class SmsProvider(ABC):
    """One concrete implementation per provider. Stateless — instances
    can be safely reused across requests."""

    name: str = "base"

    @abstractmethod
    async def send(
        self,
        *,
        to_e164: str,
        body: str,
        idempotency_key: str,
        db: AsyncSession,
        from_override: str | None = None,
    ) -> SendResult:
        """Send a single SMS or WhatsApp message.

        `idempotency_key` is the challenge id — callers ensure each challenge
        maps to at most one outbound send.

        `from_override` replaces the provider's configured sender. Used by the
        WhatsApp path to pass "whatsapp:+61xxxxxxxxx" instead of the plain
        SMS sender number.
        """

    @abstractmethod
    async def lookup_status(
        self, provider_message_id: str
    ) -> DeliveryStatus:
        """Used by the reconciliation/admin UI when the webhook hasn't
        fired (or the deployment doesn't have one wired up yet)."""


class FakeSmsProvider(SmsProvider):
    """Writes the plaintext (to, code, body) to the DebugSmsOutbox table
    and stdout. Selected when `sms.provider == "fake"`. Never used in
    production — Caddy never gets in front of a fake provider since the
    config flip alone activates it.

    The "code" stored in DebugSmsOutbox is parsed back out of the body —
    callers don't pass it separately because the abstraction must work
    for TwilioProvider too. We pull it out of the body via a small heuristic
    (first 6-digit run) only for the dev/test convenience field; tests
    that want to be precise should generate the body themselves and grep
    for known markers.
    """

    name = "fake"

    def __init__(self):
        self._logger = logging.getLogger("gatekeeper.sms.fake")
        self._counter = 0

    async def send(
        self,
        *,
        to_e164: str,
        body: str,
        idempotency_key: str,
        db: AsyncSession,
        from_override: str | None = None,
    ) -> SendResult:
        self._counter += 1
        message_id = f"fake-{idempotency_key}-{self._counter}"
        code = _extract_code(body)
        outbox = DebugSmsOutbox(
            challenge_id=idempotency_key,
            to_e164=to_e164,
            code=code,
            body=body,
        )
        db.add(outbox)
        await db.commit()
        # Stdout line lets devs running locally see the code without
        # opening the DB. We deliberately log the *plaintext* code here
        # only because this provider is the dev/test fake.
        self._logger.warning(
            "FakeSmsProvider send → to=%s from_override=%s code=%s id=%s",
            to_e164, from_override, code, message_id,
        )
        return SendResult(
            accepted=True,
            provider_message_id=message_id,
            cost_cents=0,
            cost_currency=None,
            error_category=None,
            raw_response="fake-accepted",
        )

    async def lookup_status(self, provider_message_id: str) -> DeliveryStatus:
        return DeliveryStatus(state="delivered")


def _extract_code(body: str) -> str:
    """Pull the first 6-digit run out of the message body. Used only by
    FakeSmsProvider's debug outbox — never on the verify path."""
    run = ""
    for ch in body:
        if ch.isdigit():
            run += ch
            if len(run) == 6:
                return run
        else:
            run = ""
    return ""


# --- Twilio ------------------------------------------------------------------

# Map Twilio numeric error codes to our error taxonomy.
# Full catalogue: https://www.twilio.com/docs/api/errors
# Anything not in this map → transient_unknown so an unrecognised failure
# doesn't get silently treated as success.
_TWILIO_ERROR_CODE_MAP: dict[int, ErrorCategory] = {
    20003: "transient_unknown",    # auth failed — config error, not caller fault
    21211: "invalid_number",       # invalid 'To' number
    21212: "invalid_number",       # invalid 'To' number (alternate)
    21214: "invalid_number",       # 'To' number cannot receive SMS
    21610: "invalid_number",       # unsubscribed recipient (opted out)
    21614: "invalid_number",       # 'To' number is not a mobile number
    21408: "country_not_allowed",  # permission to send to this region not enabled
    21421: "country_not_allowed",  # phone number is not allowed
    30007: "country_not_allowed",  # carrier filtering / violation
    30006: "invalid_number",       # landline or unreachable carrier
    21617: "insufficient_credit",  # message body exceeds limit (edge case)
    20429: "provider_rate_limit",  # Twilio account rate limited
    14107: "provider_rate_limit",  # too many requests
}

# Twilio message status values that indicate the message was accepted.
_TWILIO_ACCEPTED_STATUSES = {"queued", "accepted", "sending", "sent", "delivered"}
_TWILIO_FAILED_STATUSES = {"failed", "undelivered"}


class TwilioProvider(SmsProvider):
    """Twilio REST API SMS (and WhatsApp) adapter.

    Network calls go through an injectable `httpx.AsyncClient` so tests
    can mock the wire without involving the real API. In production the
    client is constructed once at provider-instantiation time and reused
    across requests (httpx connection pooling).

    `test_mode=True` authenticates with separate Twilio test credentials
    (test_account_sid / test_auth_token from the Twilio console). Test
    credentials only accept Twilio's magic test numbers (e.g. +15005550006
    for success) and never bill or deliver. Country allowlist should be
    bypassed by callers when test_mode=True since magic numbers use +1.

    WhatsApp: pass `from_override="whatsapp:+61xxxxxxxxx"` on send(). The
    To address is automatically prefixed with "whatsapp:" by the caller or
    this method. Twilio's API uses the same endpoint for both SMS and
    WhatsApp — only the From/To format differs.
    """

    name = "twilio"

    def __init__(
        self,
        *,
        account_sid: str,
        auth_token: str,
        from_number: str,
        test_mode: bool = False,
        test_account_sid: str = "",
        test_auth_token: str = "",
        client: httpx.AsyncClient | None = None,
    ):
        if not account_sid or not auth_token:
            raise ValueError(
                "TwilioProvider requires sms.twilio_account_sid and "
                "sms.twilio_auth_token"
            )
        self._test_mode = test_mode
        if test_mode:
            sid = test_account_sid or account_sid
            token = test_auth_token or auth_token
        else:
            sid = account_sid
            token = auth_token
        self._account_sid = sid
        self._auth_token = token
        self._from_number = from_number
        self._send_url = (
            f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        )
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._logger = logging.getLogger("gatekeeper.sms.twilio")
        creds = base64.b64encode(f"{sid}:{token}".encode()).decode()
        self._auth_header = f"Basic {creds}"

    async def send(
        self,
        *,
        to_e164: str,
        body: str,
        idempotency_key: str,
        db: AsyncSession,
        from_override: str | None = None,
    ) -> SendResult:
        sender = from_override or self._from_number
        # WhatsApp To addresses require the "whatsapp:" prefix.
        to = f"whatsapp:{to_e164}" if sender.startswith("whatsapp:") else to_e164
        data = {
            "To": to,
            "From": sender,
            "Body": body,
        }
        try:
            response = await self._client.post(
                self._send_url,
                headers={"Authorization": self._auth_header},
                data=data,  # form-encoded, not JSON
            )
        except httpx.HTTPError as exc:
            self._logger.warning("Twilio transport error: %r", exc)
            return SendResult(
                accepted=False,
                provider_message_id=None,
                cost_cents=None,
                cost_currency=None,
                error_category="transient_unknown",
                raw_response=None,
                error_message=str(exc),
            )

        return self._parse_response(response)

    def _parse_response(self, response: httpx.Response) -> SendResult:
        try:
            data = response.json()
        except ValueError:
            return SendResult(
                accepted=False, provider_message_id=None,
                cost_cents=None, cost_currency=None,
                error_category="transient_unknown",
                raw_response=response.text[:500],
                error_message=f"Twilio non-JSON response (HTTP {response.status_code})",
            )

        if response.status_code == 429:
            return SendResult(
                accepted=False, provider_message_id=None,
                cost_cents=None, cost_currency=None,
                error_category="provider_rate_limit",
                raw_response=str(data)[:500],
                error_message="Twilio HTTP rate limit",
            )

        # HTTP 400 responses have a top-level `code` field; message-level
        # errors (even on HTTP 200) use `error_code`. Check both.
        error_code = data.get("error_code") or data.get("code")
        if error_code is not None:
            category = _TWILIO_ERROR_CODE_MAP.get(int(error_code), "transient_unknown")
            return SendResult(
                accepted=False,
                provider_message_id=data.get("sid"),
                cost_cents=None, cost_currency=None,
                error_category=category,
                raw_response=str(data)[:500],
                error_message=f"Twilio error {error_code}: {data.get('message', '')}",
            )

        # `status` may be an integer on error responses — cast to str.
        status = str(data.get("status") or "").lower()
        message_id = data.get("sid") or None

        # Twilio returns price as a negative string (e.g. "-0.0400") in price_unit.
        cost_cents = None
        cost_currency = None
        price = data.get("price")
        if price is not None:
            try:
                cost_cents = int(round(-float(price) * 100))
                cost_currency = data.get("price_unit")
            except (TypeError, ValueError):
                pass

        if status in _TWILIO_ACCEPTED_STATUSES:
            return SendResult(
                accepted=True,
                provider_message_id=message_id,
                cost_cents=cost_cents,
                cost_currency=cost_currency,
                error_category=None,
                raw_response=str(data)[:500],
            )

        return SendResult(
            accepted=False,
            provider_message_id=message_id,
            cost_cents=cost_cents,
            cost_currency=cost_currency,
            error_category="transient_unknown",
            raw_response=str(data)[:500],
            error_message=f"Twilio status: {status}",
        )

    async def lookup_status(self, provider_message_id: str) -> DeliveryStatus:
        url = (
            f"https://api.twilio.com/2010-04-01/Accounts/"
            f"{self._account_sid}/Messages/{provider_message_id}.json"
        )
        try:
            response = await self._client.get(
                url, headers={"Authorization": self._auth_header}
            )
            data = response.json()
        except Exception:
            return DeliveryStatus(state="unknown")
        status = (data.get("status") or "").lower()
        if status == "delivered":
            return DeliveryStatus(state="delivered")
        if status in _TWILIO_FAILED_STATUSES:
            error_code = data.get("error_code")
            category = (
                _TWILIO_ERROR_CODE_MAP.get(int(error_code), "transient_unknown")
                if error_code else "transient_unknown"
            )
            return DeliveryStatus(state="failed", error_category=category)
        return DeliveryStatus(state="pending")


def verify_twilio_signature(
    auth_token: str, signature: str, url: str, params: dict[str, str]
) -> bool:
    """Verify an X-Twilio-Signature header.

    Algorithm: HMAC-SHA1(auth_token, url + sorted(k+v for k,v in params))
    encoded as base64. See https://www.twilio.com/docs/usage/webhooks/webhooks-security
    """
    s = url + "".join(k + v for k, v in sorted(params.items()))
    expected = base64.b64encode(
        hmac.new(auth_token.encode(), s.encode(), hashlib.sha1).digest()
    ).decode()
    return hmac.compare_digest(expected, signature)


# --- factory -----------------------------------------------------------------

_provider_singleton: SmsProvider | None = None
_provider_signature: tuple | None = None


def _signature(cfg: SMSConfig) -> tuple:
    return (
        cfg.provider, cfg.test_mode,
        cfg.twilio_account_sid, cfg.twilio_auth_token, cfg.twilio_from,
    )


def get_provider(cfg: SMSConfig) -> SmsProvider:
    """Lazy singleton keyed by the relevant config fields. If the config
    changes between calls (e.g. a test fixture flips provider), the
    singleton is rebuilt."""
    global _provider_singleton, _provider_signature
    sig = _signature(cfg)
    if _provider_singleton is not None and _provider_signature == sig:
        return _provider_singleton
    if cfg.provider == "fake":
        _provider_singleton = FakeSmsProvider()
    elif cfg.provider == "twilio":
        _provider_singleton = TwilioProvider(
            account_sid=cfg.twilio_account_sid,
            auth_token=cfg.twilio_auth_token,
            from_number=cfg.twilio_from,
            test_mode=cfg.test_mode,
            test_account_sid=cfg.twilio_test_account_sid,
            test_auth_token=cfg.twilio_test_auth_token,
        )
    else:
        raise ValueError(
            f"Unknown sms.provider: {cfg.provider!r}. Valid: 'fake', 'twilio'."
        )
    _provider_signature = sig
    return _provider_singleton


def reset_singleton_for_tests() -> None:
    """Tests that inject custom httpx clients install via this hook."""
    global _provider_singleton, _provider_signature
    _provider_singleton = None
    _provider_signature = None


def install_provider_for_tests(provider: SmsProvider) -> None:
    global _provider_singleton, _provider_signature
    _provider_singleton = provider
    _provider_signature = ("test_override",)


def warn_if_real_provider_active(cfg: SMSConfig) -> None:
    """Loud-log when the real provider will be doing real sends. Called
    once at startup so operators can spot a misconfigured non-prod env."""
    logger = logging.getLogger("gatekeeper.sms")
    if cfg.provider == "twilio" and not cfg.test_mode:
        logger.warning(
            "*** SMS provider = twilio, test_mode = False — "
            "real sends will be billed. Country allowlist: %s ***",
            cfg.country_allowlist,
        )
    elif cfg.provider == "twilio" and cfg.test_mode:
        logger.info("SMS provider = twilio (test_mode=True; using test credentials)")
    else:
        logger.info("SMS provider = %s", cfg.provider)
