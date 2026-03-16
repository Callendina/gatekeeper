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
class APIAccessConfig:
    # "open" = no key needed, IP tracking only
    # "key_required" = API paths need an X-API-Key header
    mode: str = "open"
    # Glob patterns for paths that are considered API paths
    paths: list[str] = field(default_factory=list)
    # How long a temp key lasts (for anonymous frontend users)
    temp_key_duration_minutes: int = 30
    # How long a registered user's key lasts
    registered_key_duration_days: int = 365

    @property
    def enabled(self) -> bool:
        return self.mode == "key_required" and len(self.paths) > 0


@dataclass
class AppConfig:
    slug: str
    name: str
    domains: list[str]
    protected_paths: list[str] = field(default_factory=list)
    paywall: PaywallConfig = field(default_factory=PaywallConfig)
    api_access: APIAccessConfig = field(default_factory=APIAccessConfig)
    login_html_file: str = ""
    allowed_emails: list[str] = field(default_factory=list)  # empty = anyone can sign in
    roles: list[str] = field(default_factory=lambda: ["user", "admin"])
    default_role: str = "user"


@dataclass
class RateLimitConfig:
    requests_per_minute: int = 120
    authenticated_requests_per_minute: int = 0  # 0 = use requests_per_minute
    burst: int = 30


@dataclass
class GatekeeperConfig:
    host: str = "127.0.0.1"
    port: int = 9100
    secret_key: str = ""
    environment: str = ""  # e.g. "STAGING" — shown as a banner in admin UI
    database_path: str = "gatekeeper.db"
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    # GitHub only allows one callback URL per OAuth App.
    # Set this to the domain where the callback is registered.
    # If set, all GitHub OAuth flows route through this domain.
    github_callback_domain: str = ""
    apps: dict[str, AppConfig] = field(default_factory=dict)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)

    def app_for_domain(self, domain: str) -> AppConfig | None:
        for app in self.apps.values():
            if domain in app.domains:
                return app
        return None


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
        temp_key_duration_minutes=api_raw.get("temp_key_duration_minutes", 30),
        registered_key_duration_days=api_raw.get("registered_key_duration_days", 365),
    )
    return AppConfig(
        slug=slug,
        name=app_raw.get("name", slug),
        domains=app_raw.get("domains", []),
        protected_paths=app_raw.get("protected_paths", []),
        paywall=paywall,
        api_access=api_access,
        roles=app_raw.get("roles", ["user", "admin"]),
        login_html_file=app_raw.get("login_html_file", ""),
        allowed_emails=app_raw.get("allowed_emails", []),
        default_role=app_raw.get("default_role", "user"),
    )


def load_config(path: str = "config.yaml") -> GatekeeperConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    server = raw.get("server", {})
    db = raw.get("database", {})
    oauth_google = raw.get("oauth", {}).get("google", {})
    oauth_github = raw.get("oauth", {}).get("github", {})
    rl = raw.get("rate_limit", {})

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
                app_raw = yaml.safe_load(f)
            if app_raw and isinstance(app_raw, dict):
                apps[slug] = _parse_app_config(slug, app_raw)
                logger.info(f"Loaded app config fragment: {fragment_path.name} (slug: {slug})")

    return GatekeeperConfig(
        host=server.get("host", "127.0.0.1"),
        port=server.get("port", 9100),
        secret_key=server.get("secret_key", ""),
        environment=server.get("environment", ""),
        database_path=db.get("path", "gatekeeper.db"),
        google_client_id=oauth_google.get("client_id", ""),
        google_client_secret=oauth_google.get("client_secret", ""),
        github_client_id=oauth_github.get("client_id", ""),
        github_client_secret=oauth_github.get("client_secret", ""),
        github_callback_domain=oauth_github.get("callback_domain", ""),
        apps=apps,
        rate_limit=RateLimitConfig(
            requests_per_minute=rl.get("requests_per_minute", 120),
            authenticated_requests_per_minute=rl.get("authenticated_requests_per_minute", 0),
            burst=rl.get("burst", 30),
        ),
    )
