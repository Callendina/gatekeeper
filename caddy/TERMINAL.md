# Web terminal at `/_term/` (staging)

Browser-based terminal protected by gatekeeper + sshd. Intended for the
staging gatekeeper deployment only; from staging you can SSH onward to
prod if you need it.

## Architecture

```
Browser
  │  HTTPS to gatekeeper-staging.callendina.com/_term/
  ▼
Caddy
  │  forward_auth → /_auth/verify-system-admin (gatekeeper)
  │     → 200 only if signed in via OAuth/magic-link AND is_system_admin
  │  reverse_proxy → 127.0.0.1:7681 (ttyd)
  ▼
ttyd  (running as 'ttyd' user, no shell, no sudo)
  │  exec: ssh jonnosan@localhost
  ▼
sshd  prompts for jonnosan's linux password (+ optional TOTP via PAM)
  ▼
shell as jonnosan — sudo etc work normally
```

Three layers of auth:

1. **Gatekeeper**: OAuth/magic link, system_admin flag.
2. **sshd**: linux password for `jonnosan`.
3. **PAM TOTP** (recommended): 6-digit code from Google Authenticator / 1Password.

## Server install (run on `gatekeeper-staging.callendina.com`)

### 1. Install ttyd

```bash
# Debian/Ubuntu — package is usually current enough
sudo apt-get update
sudo apt-get install -y ttyd

# Or download the latest static binary from
# https://github.com/tsl0922/ttyd/releases and place it at /usr/local/bin/ttyd.
```

### 2. Create the unprivileged ttyd user

```bash
sudo useradd --system --shell /usr/sbin/nologin \
    --home-dir /var/lib/ttyd --create-home ttyd
sudo chown ttyd:ttyd /var/lib/ttyd
```

### 3. Install the systemd unit

```bash
sudo cp caddy/ttyd.service /etc/systemd/system/ttyd.service
sudo systemctl daemon-reload
sudo systemctl enable --now ttyd
sudo systemctl status ttyd
```

### 4. Update gatekeeper config

In `config.yaml` on staging, set:

```yaml
server:
  # ... existing fields ...
  terminal_enabled: true
```

Restart gatekeeper. The "Terminal" link should now appear in the admin nav
when signed in as a system admin.

### 5. Update the Caddyfile

Add the `gatekeeper-staging.callendina.com` block from
`caddy/example.Caddyfile` (the one with `handle /_term/*`). Reload Caddy:

```bash
sudo systemctl reload caddy
```

### 6. (Recommended) Enable TOTP on jonnosan@localhost

```bash
sudo apt-get install -y libpam-google-authenticator

# Run as jonnosan to set up the secret + scan the QR code into your phone
google-authenticator -t -d -f -r 3 -R 30 -W

# Add this line to /etc/pam.d/sshd above @include common-auth:
#   auth required pam_google_authenticator.so nullok
# (nullok lets users without TOTP still log in; remove once you've enrolled.)

# In /etc/ssh/sshd_config:
#   ChallengeResponseAuthentication yes
#   UsePAM yes
#   AuthenticationMethods publickey password,keyboard-interactive
# (Adjust to taste — the goal is: password OR (password AND TOTP) for jonnosan.)

sudo systemctl restart sshd
```

## Verifying

1. Sign out of gatekeeper. Visit `https://gatekeeper-staging.callendina.com/_term/`
   → should redirect to login.
2. Sign in as a non-admin → should get 403 "System admin access required".
3. Sign in as a system admin → ttyd loads, you get an `ssh` password prompt.
4. Enter password (+ TOTP) → shell as `jonnosan`.

## Locking it down further

- **Don't use `--writable`** if you only need read-only access (e.g. tailing logs).
- **`--max-clients 4`** caps concurrent terminals; tune as needed.
- **Audit**: ttyd connections are logged via systemd journal; sshd logins are
  in `/var/log/auth.log`. Both also flow through gatekeeper's access log
  with `app_slug="_system"`.
- **Disabling**: set `terminal_enabled: false` in gatekeeper config and reload.
  The `/_auth/verify-system-admin` endpoint then returns 404 for everyone,
  so even a leaked admin session can't reach ttyd.
