# Gatekeeper

Centralized authentication, authorization, rate limiting, and soft paywall service for all apps in this ecosystem.

## Architecture

Gatekeeper is a FastAPI service that sits behind Caddy via `forward_auth`. Every HTTP request to any protected app passes through gatekeeper before reaching the app. Gatekeeper decides whether to allow, block, or redirect the request.

Authentication is **OAuth-only** (Google and GitHub). No email/password — the servers have no outbound SMTP.

### Request flow

```
Internet -> Caddy (HTTPS) -> forward_auth -> Gatekeeper (localhost:9100)
                                                |
                                          200 + headers -> Caddy proxies to app
                                          302 -> redirect to login or nag page
                                          403 -> IP blocked
                                          429 -> rate limited
```

When gatekeeper returns 200, it sets these headers that Caddy copies to the upstream app:
- `X-Gatekeeper-User`: email of authenticated user (empty string if anonymous)
- `X-Gatekeeper-Role`: role for this app (`user`, `admin`, `guest`, or empty)
- `X-Gatekeeper-System-Admin`: `"true"` if the user is a gatekeeper system admin

### Check order (in forward_auth verify endpoint)
1. IP blocklist (403 if blocked)
2. Rate limit (429 if exceeded, per-IP, in-memory)
3. API key check (for apps with `api_access.mode: "key_required"`)
4. Session validation (cookie-based)
5. Protected path check (302 redirect to login if auth required)
6. Soft paywall — three states:
   - **allowed**: within free quota, pass through
   - **nag**: exceeded `nag_after_sessions` threshold, 302 redirect to dismissable nag page
   - **blocked**: exceeded `max_sessions_per_week`, 302 redirect to login (no dismiss option)
7. Allow + set headers

### Caddy config ordering

**IMPORTANT**: In the Caddyfile, the `handle /_auth/*` block MUST come before `forward_auth`. Auth UI routes (login, OAuth callbacks, nag page, API key endpoints) must NOT go through forward_auth — they are served directly by gatekeeper.

```caddyfile
myapp.example.com {
    handle /_auth/* {
        reverse_proxy localhost:9100
    }
    handle {
        forward_auth localhost:9100 { ... }
        reverse_proxy localhost:APP_PORT
    }
}
```

## Tech stack

- **Python 3.11+** with **FastAPI** and **uvicorn**
- **SQLite** via SQLAlchemy async (aiosqlite)
- **authlib** for OAuth (Google, GitHub)
- **httpx** for OAuth provider API calls
- **Jinja2** templates for login/nag/admin UI

## Project structure

```
gatekeeper/
  app.py              - FastAPI app setup, lifespan, routers
  config.py           - YAML config loading
  database.py         - SQLAlchemy async engine/session setup
  models.py           - All database models
  auth/
    forward_auth.py   - The /_auth/verify endpoint (core of the system)
    login.py          - Login page, nag page, OAuth flows, logout
    oauth.py          - Google + GitHub OAuth setup
    sessions.py       - Session create/validate/delete
    api_keys.py       - API key issuance and validation
  middleware/
    ip_block.py       - IP blocklist (DB + in-memory cache)
    rate_limit.py     - In-memory sliding window rate limiter
    paywall.py        - Anonymous usage tracking (allowed/nag/blocked)
  admin/
    routes.py         - Admin UI routes (users, IP blocklist, access log)
  templates/          - Jinja2 HTML templates
troll/                - Integration test app
```

## Running

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml  # edit with your values
python run.py
```

## Config

See `config.example.yaml`. Each app is identified by a slug and mapped to domain(s). The app slug is the key for all per-app state (users, roles, sessions, paywall counters).

### Paywall config

```yaml
paywall:
  nag_after_sessions: 5      # sessions 1-5: pass through
  max_sessions_per_week: 10   # sessions 6-10: nag, 11+: blocked
  nag_html_file: ""           # optional: path to custom nag page HTML
  max_api_calls_per_hour: 0   # for API-only apps (0 = use session tracking)
```

If `nag_html_file` is set, gatekeeper serves that file as the nag page. The HTML can use these placeholders: `{{LOGIN_GOOGLE_URL}}`, `{{LOGIN_GITHUB_URL}}`, `{{DISMISS_URL}}`, `{{APP_NAME}}`. If not set, gatekeeper's default nag template is used.

## Key decisions

- **OAuth-only** — no email/password, no password reset, no SMTP dependency.
- **One gatekeeper instance per server** (always localhost for Caddy). Each instance has its own SQLite DB. User data is per-app and per-environment by design.
- **Apps identify requests by reading headers**, not by doing their own auth. Apps should trust `X-Gatekeeper-User` and `X-Gatekeeper-Role` headers (they can only come from gatekeeper via Caddy's forward_auth).
- **Session cookies** are named `gk_session`, set httponly/secure/samesite=lax.
- **Nag dismissal cookie** is `gk_nag_dismissed`, lasts 1 hour.
- **Admin UI** is at `/_auth/admin` on any app domain. Only accessible to users with `is_system_admin=True`.
- **Access log** is stored in SQLite — this is the log admins review to block IPs. It is NOT a replacement for Caddy's access log.

## Creating the first admin user

Sign in via OAuth first, then promote:

```bash
python create_admin.py your@email.com
```
