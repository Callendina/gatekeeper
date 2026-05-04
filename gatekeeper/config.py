import os
import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class PaywallConfig:
    max_sessions_per_week: int = 0
    max_api_calls_per_hour: int = 0
    # Optional nag threshold: when session count exceeds this but is below
    # max_sessions_per_week, show a dismissable nag screen instead of blocking.
    # Set to 0 to disable nag (goes straight from allowed to blocked).
    nag_after_sessions: int = 0
    # Optional path to a custom nag HTML file. If set, this file is served
    # as the nag page instead of gatekeeper's default template.
    # The HTML can use these placeholders (replaced at serve time):
    #   {{LOGIN_GOOGLE_URL}} - Google OAuth login link
    #   {{LOGIN_GITHUB_URL}} - GitHub OAuth login link
    #   {{DISMISS_URL}} - "Not right now" link (sets cookie, redirects back)
    #   {{APP_NAME}} - the app's display name
    nag_html_file: str = ""

    @property
    def enabled(self) -> bool:
        return self.max_sessions_per_week > 0 or self.max_api_calls_per_hour > 0

    @property
    def nag_enabled(self) -> bool:
        return self.nag_after_sessions > 0 and self.nag_after_sessions < self.max_sessions_per_week


@dataclass
class APIRateLimits:
    temp_anonymous_per_minute: int = 500
    temp_authenticated_per_minute: int = 1500
    registered_per_minute: int = 100
    # Max active (non-expired) keys per tier
    max_temp_anonymous: int = 10
    max_temp_authenticated: int = 50
    max_registered: int = 500


@dataclass
class APIAccessConfig:
    # "open" = no key needed, IP tracking only
    # "key_required" = API paths need an X-API-Key header
    mode: str = "open"
    # Glob patterns for paths that are considered API paths
    paths: list[str] = field(default_factory=list)
    # Paths exempt from API key requirement (even if they match paths above)
    exempt_paths: list[str] = field(default_factory=list)
    # Per-path rate limit weights: {"pattern": weight}. Default weight is 1.
    # e.g. {"/api/v1/heavy-operation": 50} means one call counts as 50 towards the limit.
    path_weights: dict[str, int] = field(default_factory=dict)
    # Default temp key duration (used if per-type overrides not set)
    temp_key_duration_minutes: int = 30
    # Optional per-type overrides (0 = use temp_key_duration_minutes)
    temp_key_duration_minutes_anonymous: int = 0
    temp_key_duration_minutes_authenticated: int = 0
    # Maximum total lifetime for temp keys regardless of auto-extends (hours, 0 = unlimited)
    temp_key_max_lifetime_hours: int = 24
    # How long a registered user's key lasts (hours takes precedence if set)
    registered_key_duration_days: int = 365
    registered_key_duration_hours: int = 0  # 0 = use days

    @property
    def registered_key_duration_seconds(self) -> int:
        if self.registered_key_duration_hours > 0:
            return self.registered_key_duration_hours * 3600
        return self.registered_key_duration_days * 86400

    def temp_key_duration_for(self, authenticated: bool) -> int:
        """Return temp key duration in minutes for the given user type."""
        if authenticated and self.temp_key_duration_minutes_authenticated > 0:
            return self.temp_key_duration_minutes_authenticated
        if not authenticated and self.temp_key_duration_minutes_anonymous > 0:
            return self.temp_key_duration_minutes_anonymous
        return self.temp_key_duration_minutes
    # Per-key rate limits for API paths
    api_rate_limits: APIRateLimits = field(default_factory=APIRateLimits)

    @property
    def enabled(self) -> bool:
        return self.mode == "key_required" and len(self.paths) > 0


@dataclass
class RateLimitConfig:
    requests_per_minute: int = 500
    authenticated_requests_per_minute: int = 2000  # 0 = use requests_per_minute


@dataclass
class PersonalInviteConfig:
    enabled: bool = True
    max_per_user: int = 5
    expiry_days: int = 7


@dataclass
class InviteConfig:
    mode: str = "open"  # "open" | "invite_only"
    invite_html_file: str = ""
    waitlist: bool = False
    url_param: str = "invite"
    cookie_max_age_days: int = 30
    public_paths: list[str] = field(default_factory=list)
    personal_invites: PersonalInviteConfig = field(default_factory=PersonalInviteConfig)

    @property
    def enabled(self) -> bool:
        return self.mode == "invite_only"


_VALID_MFA_METHODS = ("totp", "sms_otp")


@dataclass
class MFAConfig:
    """Per-app MFA gating.

    - required_for_roles: any user whose role for this app is in this list
      is forced to enroll on sign-in (eager) and must verify according to
      the step-up cadence on every gated request.
    - required_for_paths: glob patterns; any matching path triggers MFA for
      authenticated users hitting it (lazy enrollment if not yet enrolled).
    - methods: which MFA methods this app offers. Default ["totp"]. The
      user picks one at first MFA encounter (per-(user, app) binding); the
      picker is shown only when len(methods) > 1.
    - method_change_locked: when True (the MVP default), users cannot
      change their bound method themselves — admin reset only.
    - step_up_minutes / step_up_days: how long an MFA verification stays
      valid within a session. 0 (the default) means once-per-session.
      step_up_minutes takes precedence if both are set > 0.
    """
    required_for_roles: list[str] = field(default_factory=list)
    required_for_paths: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=lambda: ["totp"])
    method_change_locked: bool = True
    step_up_minutes: int = 0
    step_up_days: int = 0

    @property
    def enabled(self) -> bool:
        return bool(self.required_for_roles or self.required_for_paths)

    @property
    def step_up_seconds(self) -> int:
        if self.step_up_minutes > 0:
            return self.step_up_minutes * 60
        if self.step_up_days > 0:
            return self.step_up_days * 86400
        return 0


@dataclass
class MagicLinkConfig:
    enabled: bool = False
    link_expiry_minutes: int = 15
    rate_limit_per_email_minutes: int = 2  # min interval between sends to same email
    rate_limit_per_ip_per_10min: int = 5   # max requests from one IP in 10 minutes
    pending_html_file: str = ""   # custom pending/waiting room page
    sent_html_file: str = ""      # custom "check your inbox" page


@dataclass
class EmailConfig:
    provider: str = ""       # "resend" (or empty = disabled)
    api_key: str = ""
    from_address: str = ""

    @property
    def enabled(self) -> bool:
        return bool(self.provider and self.api_key and self.from_address)


@dataclass
class SMSRateLimits:
    """Layered SMS-OTP send rate limits. All defaults are the design's
    hobby-tier ceilings; override per deployment."""
    per_number_hour: int = 5
    per_number_day: int = 20
    per_user_hour: int = 10
    per_ip_hour: int = 10
    per_app_hour: int = 100
    global_hour: int = 200
    global_day: int = 1000


@dataclass
class SMSConfig:
    """Server-level SMS configuration."""
    provider: str = "fake"            # "fake" | "twilio"
    # When True, use Twilio test credentials (test_account_sid / test_auth_token)
    # which only accept Twilio's magic test numbers and never bill or deliver.
    test_mode: bool = False
    # Country allowlist for destination numbers (E.164 prefix match).
    # Default ["+61"] — Australia only at MVP. Never broaden to "all".
    country_allowlist: list[str] = field(default_factory=lambda: ["+61"])
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from: str = ""              # E.164 sender number, e.g. "+61412345678"
    twilio_test_account_sid: str = ""  # Twilio test credentials (optional)
    twilio_test_auth_token: str = ""
    # Path secret embedded in the webhook URL — Twilio will also sign with
    # X-Twilio-Signature, but the URL secret is an additional layer.
    # (e.g. /_auth/sms/webhook/<webhook_secret>). Generate with:
    #   python -c "import secrets; print(secrets.token_urlsafe(32))"
    webhook_secret: str = ""
    rate_limits: SMSRateLimits = field(default_factory=SMSRateLimits)
    # Shared WhatsApp WABA sender number ("whatsapp:+61..."). When set, enables
    # the WhatsApp webhook at /_auth/whatsapp/webhook with multi-app routing.
    whatsapp_from: str = ""

    @property
    def enabled(self) -> bool:
        return self.provider in ("fake", "twilio")


@dataclass
class WhatsAppConfig:
    """Per-app WhatsApp chat integration.

    The shared Twilio WABA sender number lives in SMSConfig.whatsapp_from.
    Each app declares only its chat endpoint and optional default_comp so
    Gatekeeper knows how to reach it and what to pass through.
    """
    chat_endpoint: str = ""        # e.g. "http://host.docker.internal:9002/api/chat"
    default_comp: str | None = None  # passed as default_comp in chat body
    # Optional staging URL. When set, admins can flip individual
    # (user, app) rows to redirect_to_staging=true and route only that
    # user's traffic at this endpoint. Leave empty to disable the toggle.
    chat_endpoint_staging: str = ""


@dataclass
class AppConfig:
    slug: str
    name: str
    domains: list[str]
    protected_paths: list[str] = field(default_factory=list)
    paywall: PaywallConfig = field(default_factory=PaywallConfig)
    api_access: APIAccessConfig = field(default_factory=APIAccessConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    invite: InviteConfig = field(default_factory=InviteConfig)
    magic_link: MagicLinkConfig = field(default_factory=MagicLinkConfig)
    mfa: MFAConfig = field(default_factory=MFAConfig)
    login_html_file: str = ""
    admin_api_key: str = ""  # secret key for app-level admin API (e.g. listing active keys)
    allowed_emails: list[str] = field(default_factory=list)  # empty = anyone can sign in
    roles: list[str] = field(default_factory=lambda: ["user", "admin"])
    default_role: str = "user"
    whatsapp: WhatsAppConfig | None = None


@dataclass
class GatekeeperConfig:
    host: str = "127.0.0.1"
    port: int = 9100
    secret_key: str = ""
    environment: str = ""  # e.g. "STAGING" — shown as a banner in admin UI
    # When True, /_auth/verify-system-admin is enabled and the admin UI
    # surfaces a "Terminal" link to /_term/. Intended for staging only.
    terminal_enabled: bool = False
    # Issuer name shown in users' authenticator apps (otpauth URI). If
    # `environment` is set, it is appended (e.g. "Gatekeeper - STAGING").
    totp_issuer: str = "Gatekeeper"
    # When True, system-admin gates (/_auth/admin/*, /_term/) require an
    # MFA second factor in addition to is_system_admin.
    system_admin_requires_mfa: bool = False
    # Methods accepted at the system-admin gate. Per-(user, "_system")
    # binding picks one at first encounter; default ["totp"] keeps the
    # gate's posture aligned with NIST guidance for highest-trust paths.
    system_admin_mfa_methods: list[str] = field(default_factory=lambda: ["totp"])
    database_path: str = "gatekeeper.db"
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    # GitHub only allows one callback URL per OAuth App.
    # Set this to the domain where the callback is registered.
    # If set, all GitHub OAuth flows route through this domain.
    github_callback_domain: str = ""
    email: EmailConfig = field(default_factory=EmailConfig)
    sms: SMSConfig = field(default_factory=SMSConfig)
    apps: dict[str, AppConfig] = field(default_factory=dict)

    def app_for_domain(self, domain: str) -> AppConfig | None:
        for app in self.apps.values():
            if domain in app.domains:
                return app
        return None


def _parse_api_rate_limits(raw: dict) -> APIRateLimits:
    if not raw:
        return APIRateLimits()
    return APIRateLimits(
        temp_anonymous_per_minute=raw.get("temp_anonymous_per_minute", 500),
        temp_authenticated_per_minute=raw.get("temp_authenticated_per_minute", 1500),
        registered_per_minute=raw.get("registered_per_minute", 100),
        max_temp_anonymous=raw.get("max_temp_anonymous", 10),
        max_temp_authenticated=raw.get("max_temp_authenticated", 50),
        max_registered=raw.get("max_registered", 500),
    )


def _parse_app_config(slug: str, app_raw: dict) -> AppConfig:
    paywall_raw = app_raw.get("paywall", {})
    paywall = PaywallConfig(
        max_sessions_per_week=paywall_raw.get("max_sessions_per_week", 0),
        max_api_calls_per_hour=paywall_raw.get("max_api_calls_per_hour", 0),
        nag_after_sessions=paywall_raw.get("nag_after_sessions", 0),
        nag_html_file=paywall_raw.get("nag_html_file", ""),
    )
    api_raw = app_raw.get("api_access", {})
    api_access = APIAccessConfig(
        mode=api_raw.get("mode", "open"),
        paths=api_raw.get("paths", []),
        exempt_paths=api_raw.get("exempt_paths", []),
        path_weights=api_raw.get("path_weights", {}),
        temp_key_duration_minutes=api_raw.get("temp_key_duration_minutes", 30),
        temp_key_duration_minutes_anonymous=api_raw.get("temp_key_duration_minutes_anonymous", 0),
        temp_key_duration_minutes_authenticated=api_raw.get("temp_key_duration_minutes_authenticated", 0),
        temp_key_max_lifetime_hours=api_raw.get("temp_key_max_lifetime_hours", 24),
        registered_key_duration_days=api_raw.get("registered_key_duration_days", 365),
        registered_key_duration_hours=api_raw.get("registered_key_duration_hours", 0),
        api_rate_limits=_parse_api_rate_limits(api_raw.get("api_rate_limits", {})),
    )
    rl_raw = app_raw.get("rate_limit", {})
    rate_limit = RateLimitConfig(
        requests_per_minute=rl_raw.get("requests_per_minute", 120),
        authenticated_requests_per_minute=rl_raw.get("authenticated_requests_per_minute", 0),
    )
    invite_raw = app_raw.get("invite", {}) or {}
    pi_raw = invite_raw.get("personal_invites", {}) or {}
    invite = InviteConfig(
        mode=invite_raw.get("mode", "open"),
        invite_html_file=invite_raw.get("invite_html_file", ""),
        waitlist=invite_raw.get("waitlist", False),
        url_param=invite_raw.get("url_param", "invite"),
        cookie_max_age_days=invite_raw.get("cookie_max_age_days", 30),
        public_paths=invite_raw.get("public_paths", []),
        personal_invites=PersonalInviteConfig(
            enabled=pi_raw.get("enabled", True),
            max_per_user=pi_raw.get("max_per_user", 5),
            expiry_days=pi_raw.get("expiry_days", 7),
        ),
    )
    ml_raw = app_raw.get("magic_link", {}) or {}
    magic_link = MagicLinkConfig(
        enabled=ml_raw.get("enabled", False),
        link_expiry_minutes=ml_raw.get("link_expiry_minutes", 15),
        rate_limit_per_email_minutes=ml_raw.get("rate_limit_per_email_minutes", 2),
        rate_limit_per_ip_per_10min=ml_raw.get("rate_limit_per_ip_per_10min", 5),
        pending_html_file=ml_raw.get("pending_html_file", ""),
        sent_html_file=ml_raw.get("sent_html_file", ""),
    )
    mfa_raw = app_raw.get("mfa", {}) or {}
    methods = mfa_raw.get("methods", ["totp"]) or ["totp"]
    for m in methods:
        if m not in _VALID_MFA_METHODS:
            raise ValueError(
                f"app '{slug}' mfa.methods contains unknown method '{m}'; "
                f"valid: {list(_VALID_MFA_METHODS)}"
            )
    mfa = MFAConfig(
        required_for_roles=mfa_raw.get("required_for_roles", []) or [],
        required_for_paths=mfa_raw.get("required_for_paths", []) or [],
        methods=methods,
        method_change_locked=mfa_raw.get("method_change_locked", True),
        step_up_minutes=mfa_raw.get("step_up_minutes", 0),
        step_up_days=mfa_raw.get("step_up_days", 0),
    )
    wa_raw = app_raw.get("whatsapp") or {}
    whatsapp = None
    if wa_raw:
        whatsapp = WhatsAppConfig(
            chat_endpoint=wa_raw.get("chat_endpoint", ""),
            default_comp=wa_raw.get("default_comp"),
            chat_endpoint_staging=wa_raw.get("chat_endpoint_staging", ""),
        )
    return AppConfig(
        slug=slug,
        name=app_raw.get("name", slug),
        domains=app_raw.get("domains", []),
        protected_paths=app_raw.get("protected_paths", []),
        paywall=paywall,
        api_access=api_access,
        rate_limit=rate_limit,
        invite=invite,
        magic_link=magic_link,
        mfa=mfa,
        roles=app_raw.get("roles", ["user", "admin"]),
        login_html_file=app_raw.get("login_html_file", ""),
        admin_api_key=app_raw.get("admin_api_key", ""),
        allowed_emails=app_raw.get("allowed_emails", []),
        default_role=app_raw.get("default_role", "user"),
        whatsapp=whatsapp,
    )


def _interpolate_env(text: str) -> str:
    """Replace ${VAR} references with values from os.environ.

    Allows YAML config files to reference secrets via environment variables
    without embedding them literally. Unknown variables expand to "".
    """
    return re.sub(r"\$\{([^}]+)\}", lambda m: os.environ.get(m.group(1), ""), text)


def load_config(path: str = "config.yaml") -> GatekeeperConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(config_path) as f:
        raw = yaml.safe_load(_interpolate_env(f.read()))

    server = raw.get("server", {})
    if "system_admin_requires_totp" in server:
        raise ValueError(
            "config: server.system_admin_requires_totp has been replaced. "
            "Set server.system_admin_requires_mfa: true and "
            'server.system_admin_mfa_methods: ["totp"] instead.'
        )
    sa_methods = server.get("system_admin_mfa_methods", ["totp"]) or ["totp"]
    for m in sa_methods:
        if m not in _VALID_MFA_METHODS:
            raise ValueError(
                f"server.system_admin_mfa_methods contains unknown method '{m}'; "
                f"valid: {list(_VALID_MFA_METHODS)}"
            )
    db = raw.get("database", {})
    oauth_google = raw.get("oauth", {}).get("google", {})
    oauth_github = raw.get("oauth", {}).get("github", {})
    apps = {}
    for slug, app_raw in raw.get("apps", {}).items():
        apps[slug] = _parse_app_config(slug, app_raw)

    # Load per-app config fragments from config.d/
    config_d = config_path.parent / "config.d"
    if config_d.is_dir():
        import logging
        logger = logging.getLogger("gatekeeper.config")
        for fragment_path in sorted(config_d.glob("*.yaml")):
            slug = fragment_path.stem
            with open(fragment_path) as f:
                app_raw = yaml.safe_load(_interpolate_env(f.read()))
            if app_raw and isinstance(app_raw, dict):
                apps[slug] = _parse_app_config(slug, app_raw)
                logger.info(f"Loaded app config fragment: {fragment_path.name} (slug: {slug})")

    email_raw = raw.get("email", {}) or {}
    email_config = EmailConfig(
        provider=email_raw.get("provider", ""),
        api_key=email_raw.get("api_key", ""),
        from_address=email_raw.get("from_address", ""),
    )

    sms_raw = raw.get("sms", {}) or {}
    sms_rl_raw = sms_raw.get("rate_limits", {}) or {}
    sms_config = SMSConfig(
        provider=sms_raw.get("provider", "fake"),
        test_mode=sms_raw.get("test_mode", False),
        country_allowlist=sms_raw.get("country_allowlist", ["+61"]) or ["+61"],
        twilio_account_sid=sms_raw.get("twilio_account_sid", ""),
        twilio_auth_token=sms_raw.get("twilio_auth_token", ""),
        twilio_from=sms_raw.get("twilio_from", ""),
        twilio_test_account_sid=sms_raw.get("twilio_test_account_sid", ""),
        twilio_test_auth_token=sms_raw.get("twilio_test_auth_token", ""),
        webhook_secret=sms_raw.get("webhook_secret", ""),
        whatsapp_from=sms_raw.get("whatsapp_from", ""),
        rate_limits=SMSRateLimits(
            per_number_hour=sms_rl_raw.get("per_number_hour", 5),
            per_number_day=sms_rl_raw.get("per_number_day", 20),
            per_user_hour=sms_rl_raw.get("per_user_hour", 10),
            per_ip_hour=sms_rl_raw.get("per_ip_hour", 10),
            per_app_hour=sms_rl_raw.get("per_app_hour", 100),
            global_hour=sms_rl_raw.get("global_hour", 200),
            global_day=sms_rl_raw.get("global_day", 1000),
        ),
    )

    config = GatekeeperConfig(
        host=server.get("host", "127.0.0.1"),
        port=server.get("port", 9100),
        secret_key=server.get("secret_key", ""),
        environment=server.get("environment", ""),
        terminal_enabled=server.get("terminal_enabled", False),
        totp_issuer=server.get("totp_issuer", "Gatekeeper"),
        system_admin_requires_mfa=server.get("system_admin_requires_mfa", False),
        system_admin_mfa_methods=sa_methods,
        database_path=db.get("path", "gatekeeper.db"),
        google_client_id=oauth_google.get("client_id", ""),
        google_client_secret=oauth_google.get("client_secret", ""),
        github_client_id=oauth_github.get("client_id", ""),
        github_client_secret=oauth_github.get("client_secret", ""),
        github_callback_domain=oauth_github.get("callback_domain", ""),
        email=email_config,
        sms=sms_config,
        apps=apps,
    )
    if not config.secret_key:
        raise ValueError(
            "server.secret_key must be set in config.yaml — "
            'generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    return config
