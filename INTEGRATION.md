# Integrating Your App with Gatekeeper

This document is for Claude Code sessions (or developers) working on apps that need to integrate with gatekeeper for authentication and authorization.

## Overview

Gatekeeper handles all authentication centrally. Your app does NOT need to:
- Manage user accounts or passwords
- Handle OAuth flows (Google, GitHub) or magic link login
- Enforce TOTP / MFA — gatekeeper redirects to enrollment / step-up before requests reach your app
- Implement login pages
- Check session cookies
- Rate limit or block IPs

Instead, your app reads **HTTP headers** set by gatekeeper on every request.

## The Headers

Every request that reaches your app will have these headers (set by gatekeeper via Caddy):

| Header | Value | Example |
|--------|-------|---------|
| `X-Gatekeeper-User` | Email of authenticated user, or empty string if anonymous | `alice@example.com` |
| `X-Gatekeeper-Role` | User's role for this specific app, or empty string | `user`, `admin`, `guest` |
| `X-Gatekeeper-System-Admin` | `"true"` if gatekeeper system admin, absent otherwise | `true` |

## How to Read the Headers

### Flask

```python
from flask import request

def get_current_user():
    """Returns (email, role) or (None, None) for anonymous users."""
    email = request.headers.get("X-Gatekeeper-User", "")
    role = request.headers.get("X-Gatekeeper-Role", "")
    if not email:
        return None, None
    return email, role

# Usage in a route
@app.route("/dashboard")
def dashboard():
    email, role = get_current_user()
    if not email:
        # This shouldn't normally happen for protected paths
        # (gatekeeper would have redirected to login)
        return redirect("/_auth/login?app=YOUR_APP_SLUG&next=/dashboard")
    # ...
```

### FastAPI

```python
from fastapi import Request

def get_current_user(request: Request) -> tuple[str | None, str | None]:
    """Returns (email, role) or (None, None) for anonymous users."""
    email = request.headers.get("x-gatekeeper-user", "")
    role = request.headers.get("x-gatekeeper-role", "")
    if not email:
        return None, None
    return email, role

# Or as a dependency
from fastapi import Depends, HTTPException

async def require_user(request: Request) -> tuple[str, str]:
    email, role = get_current_user(request)
    if not email:
        raise HTTPException(status_code=401)
    return email, role

async def require_admin(request: Request) -> tuple[str, str]:
    email, role = get_current_user(request)
    if role != "admin":
        raise HTTPException(status_code=403)
    return email, role

@app.get("/admin/settings")
async def admin_settings(user: tuple = Depends(require_admin)):
    email, role = user
    # ...
```

### Raw Python (handrolled HTTP handler)

```python
# If your app uses a custom HTTP handler
email = headers.get("X-Gatekeeper-User", "")
role = headers.get("X-Gatekeeper-Role", "")
```

### JavaScript Frontend

The headers are only on the server-side request. Your JS frontend doesn't see them directly. Two patterns:

**Pattern A: Server passes user info to frontend via API**
```python
# Add an endpoint your JS can call
@app.route("/api/me")
def get_me():
    email, role = get_current_user()
    return jsonify({"email": email, "role": role})
```

```javascript
// Frontend calls this on load
const resp = await fetch("/api/me");
const user = await resp.json();
if (!user.email) {
    // User is anonymous
}
```

**Pattern B: Server embeds user info in the HTML template**
```html
<script>
    window.currentUser = {
        email: "{{ current_user_email }}",
        role: "{{ current_user_role }}"
    };
</script>
```

## API Keys (for apps with `api_access.mode: "key_required"`)

Some apps have a JS frontend that also exposes a backend API usable directly. For these apps, gatekeeper enforces that API paths (e.g. `/api/*`) require an `X-API-Key` header. This distinguishes frontend users (who get a key automatically) from direct API callers (who must register).

### How it works

1. **Anonymous frontend user** loads the page — gatekeeper gives them a session cookie
2. The JS frontend calls `POST /_auth/api-key/temp` to get a short-lived API key (default: 30 minutes)
3. The frontend includes `X-API-Key: <key>` in all API calls
4. When the temp key expires, the frontend requests a new one
5. **Registered users** call `POST /_auth/api-key` to get a long-lived key (default: 365 days)
6. **Direct API callers** without a session cookie can't get a temp key — they must register, log in, and get a registered key

### Frontend JavaScript integration

```javascript
let apiKey = null;
let apiKeyExpires = null;

async function getApiKey() {
    // Reuse key if still valid (with 60s buffer)
    if (apiKey && apiKeyExpires && Date.now() < apiKeyExpires - 60000) {
        return apiKey;
    }
    const resp = await fetch("/_auth/api-key/temp", { method: "POST" });
    if (!resp.ok) {
        // Session expired or paywall hit — redirect to login/register
        window.location.href = "/_auth/login?app=YOUR_APP_SLUG";
        return null;
    }
    const data = await resp.json();
    apiKey = data.api_key;
    apiKeyExpires = new Date(data.expires_at).getTime();
    return apiKey;
}

async function apiCall(path, options = {}) {
    const key = await getApiKey();
    if (!key) return null;
    const headers = { ...options.headers, "X-API-Key": key };
    return fetch(path, { ...options, headers });
}

// Usage
const resp = await apiCall("/api/data");
```

### Caddy config for API key forwarding

For apps using API keys, Caddy must forward the client's `X-API-Key` header to gatekeeper:

```caddyfile
webapp.example.com {
    handle /_auth/* {
        reverse_proxy localhost:9100
    }

    handle {
        forward_auth localhost:9100 {
            uri /_auth/verify
            header_up X-Forwarded-API-Key {header.X-API-Key}
            copy_headers X-Gatekeeper-User X-Gatekeeper-Role X-Gatekeeper-System-Admin
        }

        reverse_proxy localhost:YOUR_APP_PORT
    }
}
```

### API key endpoints

| Endpoint | Method | Requires | Returns |
|----------|--------|----------|---------|
| `/_auth/api-key` | POST | Authenticated session cookie | Long-lived key (JSON) |
| `/_auth/api-key/temp` | POST | Session cookie (auto-creates one if none exists) | Short-lived key (JSON) |

Response format (200):
```json
{
    "api_key": "abc123...",
    "expires_at": "2026-03-16T12:00:00Z",
    "type": "temp",
    "duration_minutes": 30
}
```

Possible error responses:

| Code | When | Body |
|------|------|------|
| 400 | Unknown app domain, or API keys not enabled | `{"error": "..."}` |
| 429 | Max active keys for this tier reached | `{"error": "...", "type": "max_active_keys", "tier": "temp_anonymous", "current": 10, "limit": 10}` |
| 500 | Session creation failed (shouldn't happen) | `{"error": "..."}` |

API calls with a rate-limited key return 429 from `/_auth/verify` with details:
```json
{"error": "API key rate limit exceeded", "type": "api_key_rate_limit", "tier": "temp_anonymous", "current": 500, "limit": 500}
```

Per-IP rate limit exceeded returns:
```json
{"error": "Rate limited", "type": "ip_rate_limit", "current": 501, "limit": 500, "ip": "1.2.3.4"}
```

All 429 responses include `type` (what limit was hit), `current` (count at time of rejection), and `limit` (the threshold).

### Active key limits

Gatekeeper limits the number of active (non-expired) keys per tier per app:

| Tier | Default max active keys |
|------|----------------------|
| Temp anonymous | 10 |
| Temp authenticated | 50 |
| Registered | 500 |

Configurable via `api_access.api_rate_limits.max_temp_anonymous`, `max_temp_authenticated`, `max_registered`. With short temp key durations (e.g. 3 min) and auto-extend, `max_temp_anonymous` acts as a concurrent user cap — slots free up quickly when users leave.

### Temp key auto-extend

Temp keys automatically extend their expiry on every successful API call. The extension uses the configured duration for the key type:
- `temp_key_duration_minutes` (default, or `temp_key_duration_minutes_anonymous` if set)
- `temp_key_duration_minutes_authenticated` (for signed-in users, if set)

This means a 3-minute key stays alive indefinitely while the user is active, but frees its slot 3 minutes after the last API call.

### Exempt paths

Paths listed in `api_access.exempt_paths` bypass API key validation, rate limiting, and session slot consumption entirely — even if they match `api_access.paths`. Use this for public endpoints like health checks or config endpoints:

```yaml
api_access:
  paths: ["/api/*"]
  exempt_paths: ["/api/v1/health", "/api/v1/env"]
```

### Per-key rate limits

Each API key has its own rate limit (requests per minute), separate from the per-app per-IP limit:

| Tier | Default rate limit |
|------|-------------------|
| Temp anonymous | 500/min |
| Temp authenticated | 1500/min |
| Registered | 100/min |

Configurable via `api_access.api_rate_limits`. Admins can also boost individual keys via the admin UI.

### Handling 429 in your frontend

```javascript
async function apiCall(path, options = {}) {
    const key = await getApiKey();
    if (!key) return null;
    const headers = { ...options.headers, "X-API-Key": key };
    const resp = await fetch(path, { ...options, headers });
    if (resp.status === 429) {
        const data = await resp.json().catch(() => null);
        if (data?.type === "max_active_keys") {
            showError(`Service busy (${data.current}/${data.limit} slots in use)`);
        } else if (data?.type === "api_key_rate_limit") {
            showError(`Slow down (${data.current}/${data.limit} requests/min)`);
        } else {
            showError(data?.error || "Too many requests. Please try again later.");
        }
        return null;
    }
    return resp;
}
```

## What to Remove from Your App

When migrating to gatekeeper, remove:

1. **Login routes** — gatekeeper serves the OAuth login page at `/_auth/login`
2. **Session management** — gatekeeper handles cookies and session validation
3. **OAuth configuration** — gatekeeper handles Google and GitHub OAuth
5. **Caddy basicauth directives** — replaced by `forward_auth`
6. **User database tables** — user identity is now managed by gatekeeper. Your app may still store app-specific user preferences keyed by email.

## What to Keep in Your App

- **Authorization logic** — your app still decides what each role can do. Gatekeeper tells you WHO the user is and their ROLE; your app enforces what that role means.
- **App-specific user data** — if your app stores preferences, settings, or data per user, keep that. Use the email from `X-Gatekeeper-User` as the key.
- **The "guest" workflow** — if your app has a guest approval process, gatekeeper assigns the `guest` role on registration (configurable per app). Your app checks for `role == "guest"` and shows appropriate UI.

## Auth-Related URLs

These are served by gatekeeper through Caddy. You can link to them from your app:

| URL | Purpose |
|-----|---------|
| `/_auth/login?app=SLUG&next=/path` | Login page with OAuth provider buttons |
| `/_auth/logout?app=SLUG` | Logout (clears session, redirects to app root) |
| `/_auth/oauth/google?app=SLUG&next=/path` | Direct Google OAuth login |
| `/_auth/oauth/github?app=SLUG&next=/path` | Direct GitHub OAuth login |
| `/_auth/nag?app=SLUG&next=/path` | Paywall nag page (auto-redirected to by gatekeeper) |
| `/_auth/nag/dismiss?next=/path` | Dismiss nag for 1 hour and continue |
| `/_auth/totp/enroll?next=/path` | TOTP enrollment (QR + secret) |
| `/_auth/totp/verify?next=/path` | TOTP step-up prompt |
| `/_auth/health` | Health check (`{"status": "ok"}`) |
| `/_auth/version` | Version check (`{"version": 1}`) |
| `/_auth/status/SLUG` | Active key counts by tier (no auth required, no sensitive data) |
| `/_auth/status/SLUG/keys` | Full active key list (requires `X-Admin-Key` header matching `admin_api_key` in app config) |

Replace `SLUG` with your app's slug as defined in gatekeeper's `config.yaml`.

## Caddy Configuration

Your app's Caddy config should look like this. **IMPORTANT**: the `handle /_auth/*` block MUST come first — auth UI routes must bypass `forward_auth`, otherwise users can't reach the login page.

```caddyfile
myapp.example.com {
    # Auth UI routes go directly to gatekeeper (no forward_auth)
    handle /_auth/* {
        reverse_proxy localhost:9100
    }

    # Everything else: auth check, then proxy to app
    handle {
        forward_auth localhost:9100 {
            uri /_auth/verify
            copy_headers X-Gatekeeper-User X-Gatekeeper-Role X-Gatekeeper-System-Admin
        }

        reverse_proxy localhost:YOUR_APP_PORT
    }
}
```

For apps with API key support, also add `header_up X-Forwarded-API-Key {header.X-API-Key}` inside the `forward_auth` block.

### Analytics headers (optional)

To enable referrer and user-agent tracking in gatekeeper's analytics dashboard, add these headers to the `forward_auth` block:

```caddyfile
forward_auth localhost:9100 {
    uri /_auth/verify
    copy_headers X-Gatekeeper-User X-Gatekeeper-Role X-Gatekeeper-System-Admin
    header_up X-Forwarded-User-Agent {http.request.header.User-Agent}
    header_up X-Forwarded-Referer {http.request.header.Referer}
}
```

Without these, session tracking and duration still work, but the referrer and user-agent columns in analytics will be empty.

## Migration Checklist

- [ ] Add your app config: either in gatekeeper's `config.yaml` under `apps:`, or as a fragment at `config.d/<app-slug>.yaml` (see `config.d.example/` for format)
- [ ] Update your Caddyfile to use `forward_auth` (see above)
- [ ] Add a helper function to read `X-Gatekeeper-User` and `X-Gatekeeper-Role` headers
- [ ] Replace all auth checks in your routes with header-based checks
- [ ] Remove login routes and templates
- [ ] Remove password hashing, session management, and OAuth code
- [ ] If your app stores user data, migrate the key from internal user ID to email
- [ ] If your JS frontend needs user info, add a `/api/me` endpoint or embed in template
- [ ] If your app uses API keys: add `header_up X-Forwarded-API-Key {header.X-API-Key}` to Caddy config
- [ ] If your app uses API keys: add frontend JS to fetch temp keys and include `X-API-Key` in API calls
- [ ] Test: anonymous access works (for unprotected paths)
- [ ] Test: login redirect works (for protected paths)
- [ ] Test: role-based access works
- [ ] Test: API key flow works (if applicable) — temp key for anonymous, registered key for authenticated
- [ ] Remove old user management database tables (after confirming migration is complete)

## Security Notes

- **Trust the headers** — they can only be set by gatekeeper via Caddy's forward_auth. External clients cannot forge them because Caddy overwrites them with gatekeeper's response.
- **Don't expose gatekeeper's port** — gatekeeper should only be accessible on localhost. Caddy is the only thing that talks to it.
- **Email is the user identifier** — use it as the stable key for per-user data in your app.
