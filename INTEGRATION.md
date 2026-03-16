# Integrating Your App with Gatekeeper

This document is for Claude Code sessions (or developers) working on apps that need to integrate with gatekeeper for authentication and authorization.

## Overview

Gatekeeper handles all authentication centrally. Your app does NOT need to:
- Manage user accounts or passwords
- Handle OAuth flows
- Implement login/register pages
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

## What to Remove from Your App

When migrating to gatekeeper, remove:

1. **Login/register routes** — gatekeeper serves these at `/_auth/login` and `/_auth/register`
2. **Password storage/hashing** — gatekeeper handles this
3. **Session management** — gatekeeper handles cookies and session validation
4. **OAuth configuration** — gatekeeper handles Google OAuth
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
| `/_auth/login?app=SLUG&next=/path` | Login page (redirects back to `next` after login) |
| `/_auth/register?app=SLUG` | Registration page |
| `/_auth/logout?app=SLUG` | Logout (clears session, redirects to app root) |
| `/_auth/oauth/google?app=SLUG&next=/path` | Direct Google OAuth login |

Replace `SLUG` with your app's slug as defined in gatekeeper's `config.yaml`.

## Caddy Configuration

Your app's Caddy config should look like this:

```caddyfile
myapp.example.com {
    # Auth check on every request
    forward_auth localhost:9100 {
        uri /_auth/verify
        copy_headers X-Gatekeeper-User X-Gatekeeper-Role X-Gatekeeper-System-Admin
    }

    # Auth UI routes go to gatekeeper
    handle /_auth/* {
        reverse_proxy localhost:9100
    }

    # App routes go to your app
    handle {
        reverse_proxy localhost:YOUR_APP_PORT
    }
}
```

## Migration Checklist

- [ ] Add your app to gatekeeper's `config.yaml` with appropriate slug, domains, and settings
- [ ] Update your Caddyfile to use `forward_auth` (see above)
- [ ] Add a helper function to read `X-Gatekeeper-User` and `X-Gatekeeper-Role` headers
- [ ] Replace all auth checks in your routes with header-based checks
- [ ] Remove login/register routes and templates
- [ ] Remove password hashing and session management code
- [ ] Remove OAuth configuration
- [ ] If your app stores user data, migrate the key from internal user ID to email
- [ ] If your JS frontend needs user info, add a `/api/me` endpoint or embed in template
- [ ] Test: anonymous access works (for unprotected paths)
- [ ] Test: login redirect works (for protected paths)
- [ ] Test: role-based access works
- [ ] Remove old user management database tables (after confirming migration is complete)

## Security Notes

- **Trust the headers** — they can only be set by gatekeeper via Caddy's forward_auth. External clients cannot forge them because Caddy overwrites them with gatekeeper's response.
- **Don't expose gatekeeper's port** — gatekeeper should only be accessible on localhost. Caddy is the only thing that talks to it.
- **Email is the user identifier** — use it as the stable key for per-user data in your app.
