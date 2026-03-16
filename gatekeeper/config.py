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
    roles: list[str] = field(default_factory=lambda: ["user", "admin"])
    default_role: str = "user"


@dataclass
class RateLimitConfig:
    requests_per_minute: int = 120
    burst: int = 30


@dataclass
class GatekeeperConfig:
    host: str = "127.0.0.1"
    port: int = 9100
    secret_key: str = ""
    database_path: str = "gatekeeper.db"
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    apps: dict[str, AppConfig] = field(default_factory=dict)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)

    def app_for_domain(self, domain: str) -> AppConfig | None:
        for app in self.apps.values():
            if domain in app.domains:
                return app
        return None


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
        paywall_raw = app_raw.get("paywall", {})
        paywall = PaywallConfig(
            max_sessions_per_week=paywall_raw.get("max_sessions_per_week", 0),
            max_api_calls_per_hour=paywall_raw.get("max_api_calls_per_hour", 0),
            nag_after_sessions=paywall_raw.get("nag_after_sessions", 0),
        )
        api_raw = app_raw.get("api_access", {})
        api_access = APIAccessConfig(
            mode=api_raw.get("mode", "open"),
            paths=api_raw.get("paths", []),
            temp_key_duration_minutes=api_raw.get("temp_key_duration_minutes", 30),
            registered_key_duration_days=api_raw.get("registered_key_duration_days", 365),
        )

        apps[slug] = AppConfig(
            slug=slug,
            name=app_raw.get("name", slug),
            domains=app_raw.get("domains", []),
            protected_paths=app_raw.get("protected_paths", []),
            paywall=paywall,
            api_access=api_access,
            roles=app_raw.get("roles", ["user", "admin"]),
            default_role=app_raw.get("default_role", "user"),
        )

    return GatekeeperConfig(
        host=server.get("host", "127.0.0.1"),
        port=server.get("port", 9100),
        secret_key=server.get("secret_key", ""),
        database_path=db.get("path", "gatekeeper.db"),
        google_client_id=oauth_google.get("client_id", ""),
        google_client_secret=oauth_google.get("client_secret", ""),
        github_client_id=oauth_github.get("client_id", ""),
        github_client_secret=oauth_github.get("client_secret", ""),
        apps=apps,
        rate_limit=RateLimitConfig(
            requests_per_minute=rl.get("requests_per_minute", 120),
            burst=rl.get("burst", 30),
        ),
    )
