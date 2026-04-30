"""SMS provider abstraction.

Two concrete providers ship today:
  - FakeSmsProvider: writes plaintext to debug_sms_outbox + stdout.
    Selected when sms.provider == "fake". Used in dev/CI.
  - ClickSendProvider: real provider, with optional `is_test` mode that
    short-circuits delivery without billing. Selected when
    sms.provider == "clicksend".

The interface intentionally keeps `send` returning enough metadata
(provider message id, cost, error category) that the caller can record
the lot in the challenge row without re-querying the provider.
"""
import base64
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
    ) -> SendResult:
        """Send a single SMS. `idempotency_key` is the challenge id —
        callers ensure each challenge maps to at most one outbound send."""

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
    for ClickSend too. We pull it out of the body via a small heuristic
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
            "FakeSmsProvider send → to=%s code=%s id=%s",
            to_e164, code, message_id,
        )
        return SendResult(
            accepted=True,
            provider_message_id=message_id,
            cost_cents=0,
            error_category=None,
            raw_response="fake-accepted",
        )

    async def lookup_status(self, provider_message_id: str) -> DeliveryStatus:
        # Fake provider never reports failure.
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


# --- ClickSend ---------------------------------------------------------------

# Mapping of ClickSend per-message status strings to our error taxonomy.
# Anything not in this map → TransientUnknown so an unrecognised failure
# doesn't get silently treated as success.
_CLICKSEND_STATUS_MAP: dict[str, ErrorCategory | None] = {
    "SUCCESS": None,
    "QUEUED": None,
    "INVALID_RECIPIENT": "invalid_number",
    "INVALID_PHONE_NUMBER_LENGTH": "invalid_number",
    "INVALID_RECIPIENT_FORMAT": "invalid_number",
    "INSUFFICIENT_CREDIT": "insufficient_credit",
    "MISSING_BALANCE": "insufficient_credit",
    "RATE_LIMIT_EXCEEDED": "provider_rate_limit",
    "THROTTLED": "provider_rate_limit",
}


class ClickSendProvider(SmsProvider):
    """ClickSend REST v3 SMS adapter.

    Network calls go through an injectable `httpx.AsyncClient` so tests
    can mock the wire without involving the real API. In production the
    client is constructed once at provider-instantiation time and reused
    across requests (httpx connection pooling).

    `test_mode` makes ClickSend short-circuit at their end — the call
    returns SUCCESS with a synthetic message_id but no SMS is sent and
    no charge is incurred. We rely on this for staging smoke tests and
    keep `test_mode: false` for prod.
    """

    name = "clicksend"

    SEND_URL = "https://rest.clicksend.com/v3/sms/send"

    def __init__(
        self,
        *,
        username: str,
        api_key: str,
        sender_id: str,
        test_mode: bool = False,
        client: httpx.AsyncClient | None = None,
    ):
        if not username or not api_key:
            raise ValueError(
                "ClickSendProvider requires sms.clicksend_username and "
                "sms.clicksend_api_key"
            )
        self._username = username
        self._api_key = api_key
        self._sender_id = sender_id
        self._test_mode = test_mode
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._logger = logging.getLogger("gatekeeper.sms.clicksend")
        creds = base64.b64encode(f"{username}:{api_key}".encode()).decode()
        self._auth_header = f"Basic {creds}"

    async def send(
        self, *, to_e164: str, body: str, idempotency_key: str,
        db: AsyncSession,
    ) -> SendResult:
        message: dict[str, object] = {
            "source": "gatekeeper",
            "body": body,
            "to": to_e164,
            "custom_string": idempotency_key,
        }
        if self._sender_id:
            message["from"] = self._sender_id
        if self._test_mode:
            # ClickSend accepts is_test on each message; setting it here
            # makes the call non-billing and non-delivering.
            message["is_test"] = 1

        payload = {"messages": [message]}
        try:
            response = await self._client.post(
                self.SEND_URL,
                headers={
                    "Authorization": self._auth_header,
                    "Content-Type": "application/json",
                },
                json=payload,
            )
        except httpx.HTTPError as exc:
            self._logger.warning("ClickSend transport error: %r", exc)
            return SendResult(
                accepted=False,
                provider_message_id=None,
                cost_cents=None,
                error_category="transient_unknown",
                raw_response=None,
                error_message=str(exc),
            )

        return self._parse_response(response, idempotency_key)

    def _parse_response(
        self, response: httpx.Response, idempotency_key: str,
    ) -> SendResult:
        # ClickSend returns 200 even for some per-message failures; rely
        # on the per-message `status` field, not the HTTP status, for the
        # accepted/rejected decision.
        try:
            data = response.json()
        except ValueError:
            return SendResult(
                accepted=False, provider_message_id=None, cost_cents=None,
                error_category="transient_unknown",
                raw_response=response.text[:500],
                error_message=f"ClickSend non-JSON response (HTTP {response.status_code})",
            )

        if response.status_code == 401 or response.status_code == 403:
            return SendResult(
                accepted=False, provider_message_id=None, cost_cents=None,
                error_category="transient_unknown",
                raw_response=str(data)[:500],
                error_message="ClickSend authentication failed — check clicksend_username/api_key",
            )
        if response.status_code == 429:
            return SendResult(
                accepted=False, provider_message_id=None, cost_cents=None,
                error_category="provider_rate_limit",
                raw_response=str(data)[:500],
                error_message="ClickSend HTTP rate limit",
            )

        messages = data.get("data", {}).get("messages") or []
        # We send one message per request, so the response list has one entry.
        msg = messages[0] if messages else {}
        status_str = (msg.get("status") or "").upper()
        category = _CLICKSEND_STATUS_MAP.get(status_str, "transient_unknown")
        message_id = msg.get("message_id") or None
        # message_price comes back as a decimal string in dollars (e.g.
        # "0.0734"). Convert to integer cents for stable accounting.
        cost_cents = None
        price = msg.get("message_price")
        if price is not None:
            try:
                cost_cents = int(round(float(price) * 100))
            except (TypeError, ValueError):
                cost_cents = None

        if category is None:
            return SendResult(
                accepted=True, provider_message_id=message_id,
                cost_cents=cost_cents, error_category=None,
                raw_response=str(data)[:500],
            )

        return SendResult(
            accepted=False, provider_message_id=message_id,
            cost_cents=cost_cents, error_category=category,
            raw_response=str(data)[:500],
            error_message=f"ClickSend status: {status_str}",
        )

    async def lookup_status(self, provider_message_id: str) -> DeliveryStatus:
        # GET /v3/sms/history/{id} returns the latest delivery state.
        # Full implementation isn't needed for phase 3 — webhook carries
        # the same data and is the primary path. Stub kept here so
        # SmsProvider's interface stays consistent.
        return DeliveryStatus(state="unknown")


# --- factory ----------------------------------------------------------------

_provider_singleton: SmsProvider | None = None
_provider_signature: tuple | None = None


def _signature(cfg: SMSConfig) -> tuple:
    return (
        cfg.provider, cfg.test_mode, cfg.clicksend_username,
        cfg.clicksend_api_key, cfg.sender_id,
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
    elif cfg.provider == "clicksend":
        _provider_singleton = ClickSendProvider(
            username=cfg.clicksend_username,
            api_key=cfg.clicksend_api_key,
            sender_id=cfg.sender_id,
            test_mode=cfg.test_mode,
        )
    else:
        raise ValueError(
            f"Unknown sms.provider: {cfg.provider!r}. Valid: 'fake', 'clicksend'."
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
    if cfg.provider == "clicksend" and not cfg.test_mode:
        logger.warning(
            "*** SMS provider = clicksend, test_mode = False — "
            "real SMS sends will be billed. Country allowlist: %s ***",
            cfg.country_allowlist,
        )
    elif cfg.provider == "clicksend" and cfg.test_mode:
        logger.info("SMS provider = clicksend (test_mode=True; no real sends)")
    else:
        logger.info("SMS provider = %s", cfg.provider)
