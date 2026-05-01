#!/usr/bin/env bash
# Deploy gatekeeper to a target server (docker compose).
# Usage: ./deploy.sh <host> [user]
#   e.g. ./deploy.sh linode.callendina.com
#        ./deploy.sh vispay.callendina.com jonnosan
#
# Assumes the host has been cut over from the legacy systemd unit to
# docker compose — see CUTOVER.md for one-time setup steps.

set -euo pipefail

HOST="${1:?Usage: $0 <host> [user]}"
USER="${2:-jonnosan}"

echo "Deploying gatekeeper to ${USER}@${HOST}..."

if ! ssh -o ConnectTimeout=5 "${USER}@${HOST}" true 2>/dev/null; then
    echo "ERROR: Cannot connect to ${USER}@${HOST}" >&2
    exit 1
fi

ssh "${USER}@${HOST}" bash -s <<'EOF'
    set -euo pipefail
    cd "$HOME/gatekeeper"
    echo "  Pulling latest..."
    git pull --ff-only
    # Compute count on the remote *after* pull so it matches what's
    # actually being built. IMAGE_TAG and GATEKEEPER_COMMIT_COUNT both
    # derive from the same number — the tag is human-facing, the env
    # var is baked into the image so /_auth/version reports it.
    COUNT=$(git rev-list --count HEAD)
    IMAGE_TAG="v${COUNT}"
    export GATEKEEPER_COMMIT_COUNT="${COUNT}"
    export IMAGE_TAG
    echo "  Building image (${IMAGE_TAG}, commit_count=${COUNT})..."
    docker compose build
    echo "  Bringing stack up..."
    docker compose up -d --remove-orphans
    echo "  Waiting for health..."
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://localhost:9100/_auth/health >/dev/null 2>&1; then
            echo "  OK: gatekeeper is responding on localhost:9100"
            docker compose ps
            exit 0
        fi
        sleep 1
    done
    echo "  ERROR: gatekeeper did not respond within 10s" >&2
    docker compose ps
    docker compose logs --tail=30 gatekeeper
    exit 1
EOF
