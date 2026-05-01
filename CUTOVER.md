# Cutover: bare metal → docker compose

One-time steps to migrate a gatekeeper host from the legacy
`systemd + venv at /home/jonnosan/gatekeeper` setup to the
docker-compose layout. Run on staging first; only promote to prod once
staging has been stable.

## Prerequisites

- Docker + docker compose plugin installed on the host.
- The `jonnosan` user is a member of the `docker` group (or run via sudo).

## 1. Create the host user and data directory

UID 1102 must match the in-container user (vispay=1100, scout=1101,
gatekeeper=1102).

```bash
sudo groupadd -r -g 1102 gatekeeper || true
sudo useradd  -r -u 1102 -g 1102 -s /usr/sbin/nologin -d /srv/gatekeeper gatekeeper || true
sudo mkdir -p /srv/gatekeeper/data
sudo chown -R gatekeeper:gatekeeper /srv/gatekeeper
```

## 2. Move config + DB into the data dir

```bash
# Stop the legacy service first so the DB is quiescent.
sudo systemctl stop gatekeeper

sudo cp /home/jonnosan/gatekeeper/gatekeeper.db /srv/gatekeeper/data/
sudo cp /home/jonnosan/gatekeeper/config.yaml   /srv/gatekeeper/data/
sudo cp -r /home/jonnosan/gatekeeper/config.d   /srv/gatekeeper/data/

sudo chown -R gatekeeper:gatekeeper /srv/gatekeeper/data
```

### 2a. Scrub absolute paths from config.yaml

The bare-metal config commonly has an absolute `database.path` baked in
(e.g. `/home/jonnosan/gatekeeper/gatekeeper.db`). That path doesn't exist
inside the container — the symptom is a startup loop with
`sqlite3.OperationalError: unable to open database file`.

Open `/srv/gatekeeper/data/config.yaml` and **delete the entire
`database:` block**:

```yaml
# DELETE THESE TWO LINES:
database:
  path: "/home/jonnosan/gatekeeper/gatekeeper.db"
```

The default (`gatekeeper.db`, relative) resolves inside the container to
`/app/gatekeeper.db`, which is symlinked to `/app/data/gatekeeper.db` —
i.e. the bind-mounted DB. Same for any other absolute paths that
reference `/home/jonnosan/gatekeeper/...`; they should either be removed
or rewritten relative to `/app/data/`.

## 3. Disable the legacy systemd unit

```bash
sudo systemctl disable gatekeeper
# (Don't remove the unit file yet — keep it as a fallback until docker
# is proven stable.)
```

## 4. Bring up the docker stack

```bash
cd /home/jonnosan/gatekeeper
git pull --ff-only

# IMAGE_TAG matches the git commit count returned by /_auth/version.
IMAGE_TAG="v$(git rev-list --count HEAD)"

IMAGE_TAG=$IMAGE_TAG docker compose build
IMAGE_TAG=$IMAGE_TAG docker compose up -d
```

## 5. Verify

```bash
# Container should be healthy and listening.
docker compose ps
curl -s http://localhost:9100/_auth/health
curl -s http://localhost:9100/_auth/version

# Try a real forward_auth flow end-to-end (sign in to admin UI etc.)
```

Caddy needs no changes — it still `forward_auth`s to `localhost:9100`,
which the container exposes via `127.0.0.1:9100:9100`.

## Snags / known gaps

- **`/_term/` web terminal**: ttyd stays on the host (it does
  `ssh jonnosan@localhost tmux ...`). The forward_auth subrequest from
  the host-side ttyd to `http://localhost:9100/_auth/verify-system-admin`
  still works because the container is bound to localhost. No change
  needed unless you want ttyd containerised too (out of scope here).

- **Cyclops**: the container reaches the cyclops collector via the
  same env vars and network as the bare-metal service today. If cyclops
  is also containerised on the same host, confirm both containers can
  reach each other (default bridge network, or shared compose network).

## Rollback

If something is wrong after step 4:

```bash
docker compose down
sudo systemctl enable gatekeeper
sudo systemctl start gatekeeper
```

The legacy venv + DB at `/home/jonnosan/gatekeeper/` are untouched
(step 2 *copied*, did not move) — the systemd service can resume.
