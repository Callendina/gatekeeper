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

System-admin gates (`/_auth/admin/*` and `/_term/`) are governed by
separate server-level `system_admin_requires_mfa` (bool) and
`system_admin_mfa_methods` (list, default `["totp"]`) flags.

### Method choice (per-(user, app))

Per-app `mfa.methods` (default `["totp"]`) lists the MFA factors an app
will accept. When >1 method is offered, each user picks one at first MFA
encounter; the choice is recorded on `UserAppRole.mfa_method` and is
admin-resettable only (`mfa.method_change_locked: true` at MVP). Today
the only available method is TOTP — SMS OTP rolls out in subsequent
phases of the SMS-OTP feature.

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

Failed MFA attempts (TOTP and SMS OTP combined) are tracked per IP in
memory; after 10 failures in 10 minutes the IP is added to the
blocklist (same `block_ip` mechanism as bad invite codes). Sharing the
counter across methods prevents a mixed-method attacker from doubling
their budget.

## SMS OTP

SMS one-time codes are an alternative MFA method. Enable per-app by
listing `"sms_otp"` in `mfa.methods`. Provider config lives under
top-level `sms:` in `config.yaml`.

```yaml
sms:
  provider: "fake"             # "fake" (dev/test) | "twilio"
  country_allowlist: ["+61"]   # E.164 prefixes — AU only at MVP
  twilio_account_sid: "${TWILIO_ACCOUNT_SID}"   # env-var refs expanded at load
  twilio_auth_token: "${TWILIO_AUTH_TOKEN}"
  twilio_from: "+61412345678"                   # Twilio sender number
  webhook_secret: ""                            # random token embedded in webhook URL
  rate_limits:                 # five-tier sliding-window limits
    per_number_hour: 5
    per_number_day: 20
    per_user_hour: 10
    per_ip_hour: 10
    per_app_hour: 100
    global_hour: 200
    global_day: 1000
```

### Routes

| Endpoint | Purpose |
|---|---|
| `GET /_auth/phone/enroll` | Number entry form |
| `POST /_auth/phone/enroll` | Validate + send confirmation OTP |
| `POST /_auth/phone/enroll/confirm` | Verify confirmation OTP, bind UserPhone |
| `POST /_auth/phone/enroll/resend` | Invalidate in-flight, send a fresh code |
| `GET /_auth/sms-otp/verify` | Issue + render step-up prompt |
| `POST /_auth/sms-otp/verify` | Verify, update `session.totp_verified_at` |
| `POST /_auth/sms-otp/resend` | Invalidate in-flight, send a fresh code |

### Storage

- Codes are 6 digits, generated via `secrets.randbelow`, zero-padded
  once at the boundary; never stored in plaintext.
- Storage form: `HMAC-SHA256(secret_key, "smsotp-v1|" + challenge_id + "|" + code)`.
  The challenge-id binding ensures the same code in two different
  challenges produces different HMACs.
- Phone numbers stored as E.164 in `user_phone.e164`. Admin reset bumps
  `key_num` (parallel with `user_totp.key_num`) to invalidate any
  in-flight challenges and force re-confirmation.

### Constraints

- 5-min TTL per challenge; 5 attempts; single-use enforced via atomic
  `UPDATE … WHERE status='pending'` rowcount.
- Each verify is bound to the `gk_session` token that requested it.
- Resend invalidates any in-flight pending challenge for
  (user, app, session), so attempts can't accumulate across re-sends.
- Default validation rejects: invalid format, non-mobile lines, VoIP,
  numbers outside `country_allowlist`. AU-only at MVP.

### Method choice (per-(user, app))

When `mfa.methods` lists more than one method, users hit
`/_auth/mfa/choose` on first MFA encounter. Their choice is recorded on
`UserAppRole.mfa_method` and is admin-resettable only
(`mfa.method_change_locked: true` at MVP). Single-method apps skip the
picker. Users with an existing confirmed `UserTOTP` are auto-bound to
TOTP if it's offered, so adding `sms_otp` to an app's methods doesn't
force existing TOTP users through the picker.

### Provider abstraction

`SmsProvider` is the swap-friendly interface (see `sms/providers.py`).
Two providers ship today:

- `FakeSmsProvider` (`sms.provider: "fake"`): writes plaintext sends to
  the `debug_sms_outbox` table and stdout. Default in dev / CI.
- `TwilioProvider` (`sms.provider: "twilio"`): Twilio REST API. Handles
  both plain SMS (`From=+61...`) and WhatsApp (`From=whatsapp:+61...`)
  via the same endpoint — caller passes `from_override` for WhatsApp.
  Honours `sms.test_mode: true` to use Twilio's separate test credentials
  (magic numbers only, no billing).

Startup logs a loud warning when `twilio` is selected with
`test_mode: false`, so a misconfigured non-prod env is hard to miss.

Config values may reference environment variables as `${VAR}` — they are
substituted before YAML parsing. This lets `config.d/` fragments include
secrets from `.env` without embedding them literally.

#### Twilio setup

1. Create a Twilio account, buy a number, register it for SMS. For
   WhatsApp, register the same number in Twilio's WABA (WhatsApp Business
   API console).
2. Generate a webhook secret:
   `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
3. Set secrets on the host (values piped via SSH stdin, never on
   command line):
   ```
   python manage.py set-secret gk-prod TWILIO_ACCOUNT_SID
   python manage.py set-secret gk-prod TWILIO_AUTH_TOKEN
   python manage.py set-secret gk-prod TWILIO_FROM
   python manage.py set-secret gk-prod SMS_WEBHOOK_SECRET
   ```
4. Add to `config.yaml` (or a `config.d/` fragment):
   ```yaml
   sms:
     provider: "twilio"
     test_mode: true              # flip to false only when ready for live sends
     country_allowlist: ["+61"]
     twilio_account_sid: "${TWILIO_ACCOUNT_SID}"
     twilio_auth_token: "${TWILIO_AUTH_TOKEN}"
     twilio_from: "${TWILIO_FROM}"
     webhook_secret: "${SMS_WEBHOOK_SECRET}"
   ```
5. In Twilio's console, set the SMS *status callback URL* to
   `https://gatekeeper.example.com/_auth/sms/webhook/<webhook_secret>`.
   Twilio signs with `X-Twilio-Signature` (HMAC-SHA1); when
   `twilio_auth_token` is set the handler verifies that header.

### Delivery webhook

`POST /_auth/sms/webhook/{secret}` accepts Twilio status callbacks
(form-encoded or JSON). Idempotent — replays are no-ops.

Auth: URL path secret (constant-time) + `X-Twilio-Signature` HMAC when
`twilio_auth_token` is configured.

- `MessageStatus: delivered` → set `delivered_at` on the matching challenge.
- `MessageStatus: failed / undelivered` → if challenge is still pending,
  flip it to `invalidated` so the next user action gets a fresh code.
- Unknown `MessageSid` → silent 200 (no info-leak).

### Threat model (apps that opt in inherit this)

**Defends:** OAuth credential takeover where the attacker has email
access but not the phone; basic phishing; single-device session
compromise.

**Does not defend:**
- **SIM swap** — carrier moves the number to an attacker's SIM. TOTP
  is strictly stronger here.
- **SMS interception via SS7** — protocol-level attack on the carrier
  signalling network.
- **Real-time phishing proxies** (Evilginx-style) — they relay the code
  in real time. Only WebAuthn defends against this.
- **Phone malware with SMS-read permission**.
- **Carrier social engineering**.

**Why ship it anyway:** users without authenticator apps can still get
MFA; recoverable via the carrier (lose phone, keep number); works on a
borrowed device. NIST SP 800-63B classifies SMS as RESTRICTED — the
posture above is informed by, not bound to, that guidance. The
VoIP-rejection check is cheap and worth applying.

**Stronger settings for sensitive paths:** apps that genuinely need
SIM-swap-resistant MFA should set `mfa.methods: ["totp"]` rather than
`["totp", "sms_otp"]`, or apply that posture only to `required_for_paths`
that match the sensitive routes.

### Operator alerting

Gatekeeper emits structured events into `access_log` rather than firing
emails / pages itself; alert delivery is the future dashboard tool's
job (see the design doc's "Out of scope" deliberations). Event types
relevant to operators:

| Status string | When |
|---|---|
| `sms_otp_issued` | Challenge row inserted (status=pending) |
| `sms_otp_sent_to_provider:<provider>:cost=<cents>` | Provider accepted the send |
| `sms_otp_send_failed:<error_category>` | Provider rejected — categories: `invalid_number`, `country_not_allowed`, `insufficient_credit`, `provider_rate_limit`, `transient_unknown` |
| `sms_otp_delivered` | Webhook reported successful delivery |
| `sms_otp_undeliverable:<provider_status>` | Webhook reported terminal failure |
| `sms_otp_rate_limited:<tier>:<window>` | Local rate limiter tripped before provider call |
| `sms_otp_enroll_rejected:<code>` | Validation rejected at enrol time (e.g. `country_not_allowed` ⇒ allowlist bypass attempt — should always be 0 in steady state) |

Suggested alert thresholds for the dashboard tool (per design):
- Hourly cost > $1 (sum `cost=` from `sms_otp_sent_to_provider:*` over 1h)
- Daily cost > $5 (same, 24h)
- Any `sms_otp_enroll_rejected:country_not_allowed` event
- 3+ `sms_otp_issued` to the same number within 1h (enable `per_number_hour: 3` to surface as `sms_otp_rate_limited:per_number:hour`)
- `sms_otp_send_failed:*` rate > 10% in any 10-min window

### Admin reset

The admin users page (`/_auth/admin/users`) shows enrollment status per
user and exposes a **Reset MFA** button. Reset:
1. Bumps `user_totp.key_num` and clears `confirmed_at` and `last_counter`
2. Clears `session.totp_verified_at` on every active session for that user

The user must re-enroll on next protected access — the old authenticator
entry stops working immediately.

### Self-recovery via SSH (admin lockout)

If you're locked out of `/_auth/admin/*` because you lost your TOTP
device and there's no other system admin to click **Reset MFA**, you
need shell access to the gatekeeper server. Two options:

**Option 1 — disable the gate, re-enroll, re-enable:**
```bash
# 1. Edit config.yaml: set system_admin_requires_mfa: false
# 2. Restart so the change takes effect
sudo systemctl restart gatekeeper
# 3. Sign in to /_auth/admin in your browser, hit Reset MFA on yourself,
#    then visit any admin page → redirected to /_auth/totp/enroll
# 4. Re-edit config.yaml: set system_admin_requires_mfa: true
sudo systemctl restart gatekeeper
```

**Option 2 — bump key_num directly in SQLite (faster):**
```bash
sqlite3 gatekeeper.db \
  "UPDATE user_totp SET key_num = key_num + 1, confirmed_at = NULL, last_counter = 0 WHERE user_id = (SELECT id FROM users WHERE email = 'you@example.com');"
sqlite3 gatekeeper.db \
  "UPDATE sessions SET totp_verified_at = NULL WHERE user_id = (SELECT id FROM users WHERE email = 'you@example.com');"
```
Next visit to `/_auth/admin` redirects to `/_auth/totp/enroll` with a
fresh secret. No restart needed — the secret is derived on each request.

### Interaction with `/_term/`

Layered auth for the web terminal:

1. **Gatekeeper** at the edge — OAuth/magic-link, system-admin flag, and
   (when `system_admin_requires_mfa: true` with `"totp"` in
   `system_admin_mfa_methods`) gatekeeper TOTP.
2. **sshd** — linux password for `jonnosan` on the localhost handoff.

PAM TOTP (`pam_google_authenticator.so`) is intentionally skipped for
the localhost handoff so the user isn't TOTP-prompted twice on the
terminal path — gatekeeper has already covered that. PAM TOTP still
fires for any *external* keyboard-interactive SSH session (defense in
depth for the rare case where someone bypasses pubkey auth). The skip
is implemented in `/etc/pam.d/sshd` via:

```
auth [success=2 default=ignore] pam_succeed_if.so quiet user = jonnosan rhost = 127.0.0.1
auth [success=1 default=ignore] pam_succeed_if.so quiet user = jonnosan rhost = ::1
auth required pam_google_authenticator.so nullok
```

Both IPv4 and IPv6 forms are needed because `ssh jonnosan@localhost`
inside ttyd resolves to `::1` first on dual-stack hosts.

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
- ttyd runs `ssh jonnosan@localhost tmux new-session -A -s web`, so the
  linux password (and ideally TOTP via `pam_google_authenticator`) is the
  second factor. The `tmux new-session -A -s web` wrapper makes the shell
  persistent across websocket disconnects — laptop sleep / network change
  detaches the tmux client but the session keeps running, and reopening
  `/_term/` reattaches to it.
- Admin nav surfaces a "Terminal" link only when `terminal_enabled` is true.

See `caddy/TERMINAL.md` for the full server install (ttyd, systemd unit,
PAM TOTP setup) and `caddy/example.Caddyfile` for the Caddy block.

## Creating the first admin user

Sign in via OAuth first, then promote:

```bash
python create_admin.py your@email.com
```
