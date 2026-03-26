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
2. Invite gate (if `invite.mode: "invite_only"` — see Invite System below)
3. Session validation (cookie-based, done early for rate limit)
4. Rate limit (429 if exceeded, per-IP, in-memory; authenticated users can get a higher limit)
5. API key check (for apps with `api_access.mode: "key_required"`)
6. Protected path check (302 redirect to login if auth required)
7. Soft paywall — three states:
   - **allowed**: within free quota, pass through
   - **nag**: exceeded `nag_after_sessions` threshold, 302 redirect to dismissable nag page
   - **blocked**: exceeded `max_sessions_per_week`, 302 redirect to login (no dismiss option)
8. Allow + set headers

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
- **ProxyHeadersMiddleware** to trust X-Forwarded-Proto/Host from Caddy (so OAuth callback URLs are generated correctly)

## Project structure

```
gatekeeper/
  app.py              - FastAPI app setup, lifespan, routers
  config.py           - YAML config loading (main + config.d/ fragments)
  database.py         - SQLAlchemy async engine/session setup
  models.py           - All database models
  auth/
    forward_auth.py   - The /_auth/verify endpoint (core of the system)
    login.py          - Login page, nag page, OAuth flows, logout
    oauth.py          - Google + GitHub OAuth setup
    sessions.py       - Session create/validate/delete
    api_keys.py       - API key issuance and validation
    invites.py        - Invite code management, cookie signing, waitlist
  middleware/
    ip_block.py       - IP blocklist (DB + in-memory cache)
    rate_limit.py     - In-memory sliding window rate limiter
    paywall.py        - Anonymous usage tracking (allowed/nag/blocked)
  admin/
    routes.py         - Admin UI routes (users, IP blocklist, access log, analytics)
  templates/          - Jinja2 HTML templates
config.d/             - Per-app config fragments (gitignored)
config.d.example/     - Example app config fragment
```

## Running

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml  # edit with your values
python run.py
```

## Config

See `config.example.yaml` for the main config structure. Each app is identified by a slug and mapped to domain(s). The app slug is the key for all per-app state (users, roles, sessions, paywall counters).

### config.d/ fragments

Apps can be defined in individual files under `config.d/` instead of (or in addition to) the main config. Each file is named `<app-slug>.yaml` and contains the app config at the top level (not nested under `apps:`). See `config.d.example/myapp-prod.yaml` for the format. Fragments override the main config if the same slug appears in both.

### Per-app config options

```yaml
name: "My App"
domains: ["myapp.example.com"]
protected_paths: ["/admin/*"]       # paths requiring authentication
allowed_emails: []                   # restrict sign-in to these emails (empty = anyone)
login_html_file: ""                  # custom login page HTML (placeholders: {{APP_NAME}}, {{GOOGLE_URL}}, {{GITHUB_URL}})
admin_api_key: ""                    # secret for /_auth/status/{slug}/keys endpoint
default_role: "user"                 # role assigned on first sign-in
roles: ["user", "admin"]
paywall:
  nag_after_sessions: 5             # sessions before nag screen (0 = no nag)
  max_sessions_per_week: 10          # hard limit (0 = no paywall)
  nag_html_file: ""                  # custom nag page HTML (placeholders: {{APP_NAME}}, {{LOGIN_GOOGLE_URL}}, {{LOGIN_GITHUB_URL}}, {{DISMISS_URL}})
  max_api_calls_per_hour: 0          # for API-only apps (0 = use session tracking)
rate_limit:                              # per-app rate limit (per IP)
  requests_per_minute: 500               # anonymous users (default 500)
  authenticated_requests_per_minute: 2000 # logged-in users (0 = use default)
api_access:
  mode: "open"                       # "open" or "key_required"
  paths: ["/api/*"]
  exempt_paths: ["/api/v1/health"]   # skip key check for these paths
  temp_key_duration_minutes: 3       # default temp key duration (auto-extends on use)
  temp_key_duration_minutes_anonymous: 0      # override for anon (0 = use default)
  temp_key_duration_minutes_authenticated: 60 # override for logged-in users
  registered_key_duration_days: 365  # or use registered_key_duration_hours (takes precedence)
  # registered_key_duration_hours: 3 # alternative to days
  api_rate_limits:
    temp_anonymous_per_minute: 500   # per-key rate limit
    temp_authenticated_per_minute: 1500
    registered_per_minute: 100
    max_temp_anonymous: 10           # max active keys per tier (concurrent user cap)
    max_temp_authenticated: 50
    max_registered: 500
```

**Temp key auto-extend:** temp keys have their expiry bumped by `temp_key_duration_minutes` on every successful API call. Short-lived keys (e.g. 3 min) stay alive while actively used, but free up slots quickly when abandoned. This makes `max_temp_anonymous` act as a concurrent user cap.

**Exempt paths:** paths in `exempt_paths` bypass API key validation, rate limiting, and session slot consumption entirely, even if they match `paths`.

All **429** responses return JSON with `type`, `current`, and `limit` fields:
- `ip_rate_limit`: per-IP rate limit exceeded (includes `ip`)
- `api_key_rate_limit`: per-key rate limit exceeded (includes `tier`)
- `max_active_keys`: max active keys for tier reached (includes `tier`)

Admins can boost individual key limits or revoke temp keys via the admin UI (`/_auth/admin/api-keys`).

### Server config

```yaml
server:
  host: "127.0.0.1"
  port: 9100
  secret_key: "..."
  environment: "STAGING"              # optional: shown as banner in admin UI
```

## Invite system

Apps can require invite codes to access any content. When `invite.mode: "invite_only"`, the invite gate in forward_auth blocks all unauthenticated requests that don't have a valid `gk_invite_granted` cookie.

### Invite flow
1. Anon visits any page → forward_auth redirects to `/_auth/invite?app=X&next=PATH`
2. User enters a code (or arrives via `?invite=CODE` link) → code validated, `gk_invite_granted` cookie set
3. User can now browse anonymously with the cookie
4. When user signs in via OAuth → invite use is linked to their email in `invite_uses`

### Bypasses (skip invite gate)
- Authenticated users with a valid session
- Requests with an `X-API-Key` header (validated later in the chain)
- Paths matching `api_access.exempt_paths`

### Code types
- **Bulk codes**: admin-created, reusable (e.g. `BETA_2026`, max 100 uses)
- **Personal invites**: created by authenticated users, single-use, tracks inviter→invitee

### Waitlist
When `invite.waitlist: true`, the invite page shows a "join waitlist" option. Admins review waitlist entries in `/_auth/admin/invites` and can approve (generates a single-use code) or deny (blocks the requester's IP).

### Config
```yaml
invite:
  mode: "open"              # "open" | "invite_only"
  invite_html_file: ""      # custom front door page
  waitlist: true
  url_param: "invite"       # query param for link-based invites
  cookie_max_age_days: 30
  personal_invites:
    enabled: true
    max_per_user: 5
    expiry_days: 7
```

### Custom invite page placeholders
`{{APP_NAME}}`, `{{INVITE_SUBMIT_URL}}`, `{{WAITLIST_SUBMIT_URL}}`, `{{LOGIN_URL}}`

## Key decisions

- **OAuth-only** — no email/password, no password reset, no SMTP dependency.
- **One gatekeeper instance per server** (always localhost for Caddy). Each instance has its own SQLite DB. User data is per-app and per-environment by design.
- **Apps identify requests by reading headers**, not by doing their own auth. Apps should trust `X-Gatekeeper-User` and `X-Gatekeeper-Role` headers (they can only come from gatekeeper via Caddy's forward_auth).
- **Session cookies** are named `gk_session`, set httponly/secure/samesite=lax.
- **Nag dismissal cookie** is `gk_nag_dismissed`, lasts 1 hour.
- **Admin UI** is at `/_auth/admin` on any app domain (or a dedicated gatekeeper domain). Only accessible to users with `is_system_admin=True`. Admin auth validates the session cookie directly (not via headers) since `/_auth/*` bypasses forward_auth.
- **Access log** is stored in SQLite — this is the log admins review to block IPs. It is NOT a replacement for Caddy's access log. Each log entry also stores `session_token`, `referrer`, and `user_agent` for analytics.
- **Analytics** are at `/_auth/admin/analytics`. Shows daily session counts, per-session detail (IP, signed-in status, duration, referrer, user agent). Filterable by app and time range.
- **OAuth callbacks redirect to origin host** — if a user starts login from `gatekeeper.callendina.com`, they're redirected back there after OAuth, not to the app's domain.

## Status and monitoring endpoints

| Endpoint | Auth | Returns |
|----------|------|---------|
| `GET /_auth/health` | None | `{"status": "ok"}` |
| `GET /_auth/version` | None | `{"version": N}` (git commit count, auto-increments) |
| `GET /_auth/status/{app_slug}` | None | Active key counts by tier (no sensitive data) |
| `GET /_auth/status/{app_slug}/keys` | `X-Admin-Key` header | Full list of active keys with emails, IPs, expiry |

The `/keys` endpoint requires `admin_api_key` to be set in the app's config and the matching key in the `X-Admin-Key` request header.

## Creating the first admin user

Sign in via OAuth first, then promote:

```bash
python create_admin.py your@email.com
```
