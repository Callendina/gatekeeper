# Gatekeeper

Centralized authentication, authorization, rate limiting, and soft paywall service for all apps in this ecosystem.

## Architecture

Gatekeeper is a FastAPI service that sits behind Caddy via `forward_auth`. Every HTTP request to any protected app passes through gatekeeper before reaching the app. Gatekeeper decides whether to allow, block, or redirect the request.

### Request flow

```
Internet -> Caddy (HTTPS) -> forward_auth -> Gatekeeper (localhost:9100)
                                                |
                                          200 + headers -> Caddy proxies to app
                                          401 -> redirect to login
                                          403 -> blocked or paywall
                                          429 -> rate limited
```

When gatekeeper returns 200, it sets these headers that Caddy copies to the upstream app:
- `X-Gatekeeper-User`: email of authenticated user (empty string if anonymous)
- `X-Gatekeeper-Role`: role for this app (`user`, `admin`, `guest`, or empty)
- `X-Gatekeeper-System-Admin`: `"true"` if the user is a gatekeeper system admin

### Check order (in forward_auth verify endpoint)
1. IP blocklist
2. Rate limit (per-IP, in-memory)
3. Session validation (cookie-based)
4. Protected path check (requires auth)
5. Soft paywall (anonymous usage limits)
6. Allow + set headers

## Tech stack

- **Python 3.11+** with **FastAPI** and **uvicorn**
- **SQLite** via SQLAlchemy async (aiosqlite)
- **authlib** for Google OAuth
- **passlib[bcrypt]** for password hashing
- **Jinja2** templates for login/register/admin UI

## Project structure

```
gatekeeper/
  app.py              - FastAPI app setup, lifespan, routers
  config.py           - YAML config loading
  database.py         - SQLAlchemy async engine/session setup
  models.py           - All database models
  auth/
    forward_auth.py   - The /_auth/verify endpoint (core of the system)
    login.py          - Login, register, OAuth, logout routes
    oauth.py          - Google OAuth setup
    passwords.py      - bcrypt hashing
    sessions.py       - Session create/validate/delete
  middleware/
    ip_block.py       - IP blocklist (DB + in-memory cache)
    rate_limit.py     - In-memory sliding window rate limiter
    paywall.py        - Anonymous usage tracking
  admin/
    routes.py         - Admin UI routes (users, IP blocklist, access log)
  templates/          - Jinja2 HTML templates
```

## Running

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml  # edit with your values
python run.py
```

## Config

See `config.example.yaml`. Each app is identified by a slug and mapped to domain(s). The app slug is the key for all per-app state (users, roles, sessions, paywall counters).

## Key decisions

- **One gatekeeper instance per server** (always localhost for Caddy). Each instance has its own SQLite DB. User data is per-app and per-environment by design.
- **Apps identify requests by reading headers**, not by doing their own auth. Apps should trust `X-Gatekeeper-User` and `X-Gatekeeper-Role` headers (they can only come from gatekeeper via Caddy's forward_auth).
- **Session cookies** are named `gk_session`, set httponly/secure/samesite=lax.
- **Admin UI** is at `/_auth/admin` on any app domain. Only accessible to users with `is_system_admin=True`.
- **Access log** is stored in SQLite — this is the log admins review to block IPs. It is NOT a replacement for Caddy's access log.

## Creating the first admin user

After initial setup, manually set `is_system_admin=True` in the SQLite database:

```bash
sqlite3 gatekeeper.db "UPDATE users SET is_system_admin = 1 WHERE email = 'your@email.com';"
```

Or add a management command later.
