# Gatekeeper

Centralized authentication, authorization, rate limiting, and soft paywall service. Sits behind [Caddy](https://caddyserver.com/) using `forward_auth` to protect multiple apps from a single service.

## Features

- **Unified authentication** — OAuth-only (Google and GitHub), shared across all apps
- **Per-app roles** — `user`, `admin`, `guest` (configurable per app)
- **Soft paywall** — let anonymous users access apps freely up to a limit (sessions/week or API calls/hour), then prompt registration
- **IP blocklist** — manual blocking via admin UI, with one-click block from access logs
- **Rate limiting** — per-IP sliding window rate limiter
- **Admin dashboard** — manage users, view access logs, block IPs

## How It Works

```
Internet -> Caddy (HTTPS) -> forward_auth -> Gatekeeper (localhost:9100)
                                                |
                                          200 + headers -> Caddy proxies to app
                                          401 -> redirect to login
                                          403 -> blocked or paywall
                                          429 -> rate limited
```

Every request passes through gatekeeper before reaching your app. Gatekeeper checks (in order):

1. IP blocklist
2. Rate limit
3. Session cookie
4. Protected path (requires login?)
5. Soft paywall (anonymous usage limit exceeded?)

If allowed, gatekeeper sets headers that Caddy copies to your app:

| Header | Description |
|--------|-------------|
| `X-Gatekeeper-User` | Email of authenticated user (empty if anonymous) |
| `X-Gatekeeper-Role` | User's role for this app (`user`, `admin`, `guest`) |
| `X-Gatekeeper-System-Admin` | `"true"` if gatekeeper admin |

Your app reads these headers instead of doing its own auth. See [INTEGRATION.md](INTEGRATION.md) for detailed migration instructions.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure
cp config.example.yaml config.yaml
# Edit config.yaml with your app domains, Google OAuth credentials, etc.

# Run
python run.py
```

## Create Admin User

Sign in via Google or GitHub first, then promote:

```bash
python create_admin.py your@email.com
```

## Caddy Configuration

Add `forward_auth` to each app's Caddy config. The `/_auth/*` handler **must** come first:

```caddyfile
myapp.example.com {
    handle /_auth/* {
        reverse_proxy localhost:9100
    }

    handle {
        forward_auth localhost:9100 {
            uri /_auth/verify
            copy_headers X-Gatekeeper-User X-Gatekeeper-Role X-Gatekeeper-System-Admin
        }

        reverse_proxy localhost:8001
    }
}
```

See [caddy/example.Caddyfile](caddy/example.Caddyfile) for more examples.

## Configuration

See [config.example.yaml](config.example.yaml). Key sections:

- **`apps`** — each app has a slug, domain list, protected paths, paywall settings, and available roles
- **`oauth.google`** / **`oauth.github`** — OAuth provider credentials
- **`rate_limit`** — global per-IP rate limit settings

## Deployment

One gatekeeper instance runs per server (so the Caddy-to-gatekeeper call is always localhost). Each instance has its own SQLite database. User data is separate per app and per environment by design.

## Tech Stack

- Python 3.11+ / FastAPI / uvicorn
- SQLite via SQLAlchemy async
- authlib (Google + GitHub OAuth)
- Jinja2 (templates)

## Integrating Your App

See [INTEGRATION.md](INTEGRATION.md) for a complete guide on how to migrate your app to use gatekeeper, including code examples for Flask, FastAPI, and JavaScript frontends.
