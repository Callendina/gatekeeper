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
  │     → and (when system_admin_requires_totp: true) gatekeeper TOTP
  │  reverse_proxy → 127.0.0.1:7681 (ttyd)
  ▼
ttyd  (running as 'ttyd' user, no shell, no sudo)
  │  exec: ssh jonnosan@localhost
  ▼
sshd  prompts for jonnosan's linux password
  │  (PAM TOTP intentionally skipped on localhost — gatekeeper already
  │   covered the second factor)
  ▼
shell as jonnosan — sudo etc work normally
```

Three layers of auth:

1. **Gatekeeper**: OAuth/magic link, system_admin flag, gatekeeper TOTP.
2. **sshd**: linux password for `jonnosan`.
3. **PAM TOTP**: still fires for *external* keyboard-interactive SSH —
   skipped only for `jonnosan@127.0.0.1` (the ttyd handoff) so users
   aren't TOTP-prompted twice.

## Server install (run on `gatekeeper-staging.callendina.com`)

### 1. Install ttyd and tmux

```bash
# Debian/Ubuntu — package is usually current enough
sudo apt-get update
sudo apt-get install -y ttyd tmux

# Or download the latest static binary from
# https://github.com/tsl0922/ttyd/releases and place it at /usr/local/bin/ttyd.
```

`tmux` is what makes the web terminal session persistent across websocket
drops — see [Persistent sessions](#persistent-sessions) below.

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

### 6. (Recommended) Enable PAM TOTP for *external* SSH (optional)

The web terminal already gets a TOTP factor via gatekeeper
(`system_admin_requires_totp: true`), so PAM TOTP isn't strictly needed
for the `/_term/` path. It's still useful as belt-and-braces for direct
SSH-by-password from outside.

```bash
sudo apt-get install -y libpam-google-authenticator

# Run as jonnosan to set up the secret + scan the QR code into your phone
google-authenticator -t -d -f -r 3 -R 30 -W

# Edit /etc/pam.d/sshd. Insert these three lines after @include common-auth.
# The two pam_succeed_if lines skip TOTP for the ttyd handoff (jonnosan@
# localhost, either IPv4 or IPv6); the pam_google_authenticator line
# enforces TOTP for all other ssh sessions.
#   auth [success=2 default=ignore] pam_succeed_if.so quiet user = jonnosan rhost = 127.0.0.1
#   auth [success=1 default=ignore] pam_succeed_if.so quiet user = jonnosan rhost = ::1
#   auth required pam_google_authenticator.so nullok
# (nullok lets users without TOTP still log in; remove once you've enrolled.)

# In /etc/ssh/sshd_config:
#   KbdInteractiveAuthentication yes
#   UsePAM yes
#   AuthenticationMethods publickey keyboard-interactive
# (Pubkey is sufficient on its own; password+TOTP is the fallback.)

# No sshd restart is needed for PAM changes — PAM is consulted per-auth.
```

## Verifying

1. Sign out of gatekeeper. Visit `https://gatekeeper-staging.callendina.com/_term/`
   → should redirect to login.
2. Sign in as a non-admin → should get 403 "System admin access required".
3. Sign in as a system admin → if `system_admin_requires_totp: true` and
   you're not yet TOTP-verified, redirect to `/_auth/totp/verify`. Enter
   the gatekeeper TOTP code → ttyd loads with an `ssh` password prompt.
4. Enter the linux password → shell as `jonnosan` (no second TOTP, since
   PAM is configured to skip TOTP on the localhost handoff).

## Persistent sessions

ttyd launches `ssh jonnosan@localhost tmux new-session -A -s web` per
websocket. The shell runs inside tmux session `web`, so when the websocket
dies (laptop sleep, network change, accidental tab close) the tmux server
keeps the session alive in the background. Reopening `/_term/` reattaches
to the same session — running commands continue, scrollback is preserved.

`tmux new-session -A -s web`:
- `-A` = attach to session named `web` if one exists, else create it.
- All ttyd connections share the single `web` session, so a second tab
  mirrors the first (synchronised view). For independent terminals, open
  new windows inside tmux (`Ctrl-b c`).

Useful tmux bindings (default prefix `Ctrl-b`):
- `Ctrl-b c` — new window
- `Ctrl-b n` / `Ctrl-b p` — next / previous window
- `Ctrl-b [` — enter copy mode (scrollback); `q` to exit
- `Ctrl-b d` — detach (the tmux server keeps the session running)

Resetting the session (e.g. after a runaway process):
```bash
ssh jonnosan@localhost tmux kill-session -t web
# or, from inside the session:
tmux kill-session
```
The next visit to `/_term/` will create a fresh `web` session.

### Optional: skip the password prompt on reconnect

By default each new ttyd connection runs a fresh ssh, so jonnosan's linux
password is re-prompted on every reconnect. To make brief disconnects
seamless, enable ssh `ControlMaster` for the ttyd user so the first
authenticated connection is reused for a window of time:

```bash
sudo -u ttyd mkdir -p /var/lib/ttyd/.ssh
sudo -u ttyd tee /var/lib/ttyd/.ssh/config > /dev/null <<'EOF'
Host localhost
    ControlMaster auto
    ControlPath /var/lib/ttyd/.ssh/cm-%r@%h:%p
    ControlPersist 4h
EOF
sudo chmod 700 /var/lib/ttyd/.ssh
sudo chmod 600 /var/lib/ttyd/.ssh/config
```

Behaviour: the first ssh authenticates as normal; subsequent ssh
invocations within 4h reuse the master socket without re-prompting. The
master socket dies on its own after 4h idle, or when the box reboots.

Tradeoff: this slightly weakens the "linux password as third factor"
posture — once the master is up, anyone who can reach ttyd's websocket
(i.e. anyone who clears the gatekeeper layer) gets the shell without
re-proving the password. The gatekeeper layer (OAuth + system_admin +
gatekeeper TOTP) is still the primary gate; you're trading one of the
defences-in-depth for ergonomics. Skip this section if that's not a
trade you want to make.

## Locking it down further

- **Don't use `--writable`** if you only need read-only access (e.g. tailing logs).
- **`--max-clients 4`** caps concurrent terminals; tune as needed.
- **Audit**: ttyd connections are logged via systemd journal; sshd logins are
  in `/var/log/auth.log`. Both also flow through gatekeeper's access log
  with `app_slug="_system"`.
- **Disabling**: set `terminal_enabled: false` in gatekeeper config and reload.
  The `/_auth/verify-system-admin` endpoint then returns 404 for everyone,
  so even a leaked admin session can't reach ttyd.
