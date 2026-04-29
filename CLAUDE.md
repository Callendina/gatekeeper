# Gatekeeper

Centralized authentication, authorization, rate limiting, and soft paywall service for all apps in this ecosystem.

## Architecture

Gatekeeper is a FastAPI service that sits behind Caddy via `forward_auth`. Every HTTP request to any protected app passes through gatekeeper before reaching the app. Gatekeeper decides whether to allow, block, or redirect the request.

Authentication is **OAuth** (Google and GitHub) and **magic link** (passwordless email sign-in via Resend API).

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
3a. Pending invite check (302 redirect to `/_auth/pending` if user's role has `pending_invite=True`)
4. Rate limit (429 if exceeded, per-IP, in-memory; authenticated users can get a higher limit)
5. API key check (for apps with `api_access.mode: "key_required"`)
6. Protected path check — requires authentication via **either** method:
   - Valid session cookie (interactive user) → allow
   - Valid API key with an associated user (registered key) → allow
   - Valid API key but anonymous (temp key, no user) → redirect to login
   - No session and no API key → redirect to login
   - Invalid API key → 401
   Note: API key fallback only applies when the app has `api_access.mode: "key_required"`
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
- **httpx** for OAuth provider API calls and transactional email (Resend API)
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
    magic_link.py     - Magic link (passwordless email) login, pending page
    email.py          - Transactional email via Resend API
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
protected_paths: ["/admin/*"]       # paths requiring auth (session OR registered API key)
allowed_emails: []                   # restrict sign-in to these emails (empty = anyone)
login_html_file: ""                  # custom login page HTML (placeholders: {{APP_NAME}}, {{GOOGLE_URL}}, {{GITHUB_URL}}, {{MAGIC_LINK_FORM}}, {{MAGIC_LINK_URL}})
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
magic_link:
  enabled: false                     # opt-in per app (requires email config)
  link_expiry_minutes: 15            # how long the magic link is valid
  rate_limit_per_email_minutes: 2    # min interval between sends to same email
  rate_limit_per_ip_per_10min: 5     # max requests from one IP in 10 min
  pending_html_file: ""              # custom pending/waiting room page (placeholders: {{APP_NAME}}, {{CODE_SUBMIT_URL}}, {{WAITLIST_SUBMIT_URL}}, {{LOGOUT_URL}}, {{USER_EMAIL}})
  sent_html_file: ""                 # custom "check your inbox" page (placeholders: {{APP_NAME}}, {{MESSAGE}}, {{LOGIN_URL}})
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
  terminal_enabled: false             # see "Web terminal" below — staging only

# Required for magic link login
email:
  provider: "resend"                  # currently only "resend" supported
  api_key: "re_..."                   # Resend API key
  from_address: "noreply@callendina.com"
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

## Magic link login

Passwordless email-based sign-in. Users enter their email address, receive a link, click it, and get a session. No passwords involved.

### Setup
1. Configure the `email` section in `config.yaml` (Resend API key + from address)
2. Enable per-app with `magic_link.enabled: true`

### Flow
1. User enters email on login page → `POST /_auth/magic-link`
2. Gatekeeper sends a signed, single-use link via Resend API
3. User clicks link → `GET /_auth/magic-link/verify?token=X`
4. Token validated, user created (or found by email), session created
5. Cookie set, redirect to app

### Rate limiting
- **Per-email**: max 1 link per `rate_limit_per_email_minutes` (default 2 min) per app
- **Per-IP**: max `rate_limit_per_ip_per_10min` (default 5) requests in a 10-minute window
- Both silently drop the request (always returns "check your inbox" to prevent enumeration)

### Account merging
Email is the shared identity key. If a user signs in with Google first and later uses magic link (or vice versa), they resolve to the same User record. No explicit merge step needed.

### Interaction with invite-only mode
- **Returning users** (have a UserAppRole for this app): can always request a magic link, even without an invite cookie
- **New users with invite cookie**: magic link sent, account created normally
- **New users without invite**: silently ignored (no email sent)

## TOTP (two-factor authentication)

Gatekeeper has native TOTP (RFC 6238) support, configurable per-app and
applied regardless of how the user originally authenticated (OAuth or
magic link). The TOTP gate sits between the pending-invite check and the
rate limiter in forward_auth, so any authenticated request that matches
a configured trigger must clear it.

### Triggers

- **Role-based**: any user whose role for the app is in `mfa.required_for_roles`.
  Forces *eager* enrollment — the moment such a user signs in, the next
  request to the app redirects to `/_auth/totp/enroll`.
- **Path-based**: any path matching a pattern in `mfa.required_for_paths`.
  Forces *lazy* enrollment — the user is only redirected to enroll the
  first time they hit such a path.

System-admin gates (`/_auth/admin/*` and `/_term/`) are governed by a
separate server-level `system_admin_requires_totp` flag.

### Step-up cadence

`mfa.step_up_minutes` (or `mfa.step_up_days` for readability) controls
how long a TOTP verification stays valid within a session.

- `0` (default) = **once per session**: verify on first gated request,
  then no re-prompt until the session cookie expires (6 months) or the
  user signs out.
- `> 0` = **periodic step-up**: re-prompt N minutes/days after the last
  successful verification, even within the same session.

`step_up_minutes` takes precedence over `step_up_days` if both are set > 0.

A common pattern: `step_up_days: 90` for sensitive admin tools — once a
quarter, re-prove TOTP, but stay signed in continuously between prompts.

### Per-user secret derivation

There is no per-user secret stored in the database. Each user's TOTP
secret is derived deterministically from `(server.secret_key, user_id, key_num)`
via HMAC-SHA256 (with a `"totp-v1|"` domain-separation tag). This means:

- Backups of `gatekeeper.db` alone reveal nothing about TOTP secrets.
- Admin reset bumps `key_num` in `user_totp`, which invalidates the
  previous secret and forces re-enrollment with a fresh derivation.
- The DB stores only: `key_num`, `confirmed_at`, `last_counter` (anti-replay).
- Per-user storage = ~24 bytes; no encryption library dependency.

### Issuer name

The string shown in users' authenticator apps comes from
`server.totp_issuer` (default `"Gatekeeper"`). If `server.environment`
is set, it is appended — e.g. `"Callendina Gatekeeper - STAGING"`.

### Routes

| Endpoint | Purpose |
|---|---|
| `GET /_auth/totp/enroll` | Render QR + secret string (creates UserTOTP if missing) |
| `POST /_auth/totp/enroll/confirm` | Verify first code, set `confirmed_at` |
| `GET /_auth/totp/verify` | Step-up prompt |
| `POST /_auth/totp/verify` | Update `session.totp_verified_at` on success |

All four are reachable from any app's domain. They look up the user by
the global `gk_session` cookie, not by app slug. After a successful POST,
the user is redirected to a same-host relative `next` path (absolute URLs
are stripped to `/` to prevent open redirects).

### Rate limiting

Failed TOTP attempts are tracked per IP in memory; after 10 failures in
10 minutes the IP is added to the blocklist (same `block_ip` mechanism
as bad invite codes).

### Admin reset

The admin users page (`/_auth/admin/users`) shows enrollment status per
user and exposes a **Reset MFA** button. Reset:
1. Bumps `user_totp.key_num` and clears `confirmed_at` and `last_counter`
2. Clears `session.totp_verified_at` on every active session for that user

The user must re-enroll on next protected access — the old authenticator
entry stops working immediately.

### Interaction with `/_term/`

The web terminal stays gated by sshd/PAM (linux password + optional
`pam_google_authenticator`) regardless. Setting
`system_admin_requires_totp: true` adds gatekeeper TOTP as an additional
layer in front of the ttyd handoff; both must clear.

## Pending invite system

When an invite-only app receives a new user who signed up via OAuth or magic link **without a valid invite code**, the user gets a real account but with `pending_invite=True` on their UserAppRole. They are redirected to a waiting room page (`/_auth/pending`) where they can:

1. Enter an invite code (if they get one later) → clears pending status immediately
2. Join the waitlist (if enabled) → admin reviews and approves
3. Wait for admin to approve them via `/_auth/admin/users`

### How it works
- `UserAppRole.pending_invite` (boolean) — `True` = user created but not yet admitted
- forward_auth checks this flag after session validation and redirects to `/_auth/pending`
- Admin UI shows pending users with **Approve** / **Deny** buttons
- Approving sets `pending_invite=False`, denying deletes the UserAppRole

### Custom pending page
Set `magic_link.pending_html_file` to a custom HTML file with placeholders:
`{{APP_NAME}}`, `{{CODE_SUBMIT_URL}}`, `{{WAITLIST_SUBMIT_URL}}`, `{{LOGOUT_URL}}`, `{{USER_EMAIL}}`

## Key decisions

- **OAuth + magic link** — no passwords. Magic link requires a transactional email provider (Resend).
- **One gatekeeper instance per server** (always localhost for Caddy). Each instance has its own SQLite DB. User data is per-app and per-environment by design.
- **Apps identify requests by reading headers**, not by doing their own auth. Apps should trust `X-Gatekeeper-User` and `X-Gatekeeper-Role` headers (they can only come from gatekeeper via Caddy's forward_auth). These headers are set identically whether the user authenticated via session cookie or API key.
- **Protected paths accept either auth method** — session cookie (interactive users) or registered API key (API clients). Anonymous temp keys are rejected on protected paths since they have no user identity. This allows the same endpoints to serve both browser users and API consumers without config changes.
- **Session cookies** are named `gk_session`, set httponly/secure/samesite=lax. Sessions last 6 months.
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

## Web terminal (`/_term/`)

When `server.terminal_enabled: true`, Caddy can be configured to expose
ttyd at `/_term/*` on the gatekeeper domain itself. Used on staging to get
a browser-based shell without setting up a separate subdomain.

- Caddy uses `forward_auth → /_auth/verify-system-admin` (not the per-app
  `/_auth/verify`) since the gatekeeper domain isn't registered as an app.
- Only users with `is_system_admin=true` get through; a 404 is returned
  when `terminal_enabled` is false.
- ttyd's process is just `ssh jonnosan@localhost`, so the linux password
  (and ideally TOTP via `pam_google_authenticator`) is the second factor.
- Admin nav surfaces a "Terminal" link only when `terminal_enabled` is true.

See `caddy/TERMINAL.md` for the full server install (ttyd, systemd unit,
PAM TOTP setup) and `caddy/example.Caddyfile` for the Caddy block.

## Creating the first admin user

Sign in via OAuth first, then promote:

```bash
python create_admin.py your@email.com
```
