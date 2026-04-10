#!/usr/bin/env bash
# Deploy gatekeeper to a target server.
# Usage: ./deploy.sh <host> [user]
#   e.g. ./deploy.sh vispay-staging.callendina.com
#        ./deploy.sh vispay-prod.callendina.com jonnosan

set -euo pipefail

HOST="${1:?Usage: $0 <host> [user]}"
USER="${2:-jonnosan}"
REMOTE_DIR="/home/${USER}/gatekeeper"

echo "Deploying gatekeeper to ${USER}@${HOST}..."

# Check SSH connectivity
if ! ssh -o ConnectTimeout=5 "${USER}@${HOST}" true 2>/dev/null; then
    echo "ERROR: Cannot connect to ${USER}@${HOST}" >&2
    exit 1
fi

# Pull latest code and restart
ssh "${USER}@${HOST}" bash -s <<EOF
    set -euo pipefail
    cd ${REMOTE_DIR}
    echo "  Pulling latest..."
    git pull --ff-only
    echo "  Restarting gatekeeper..."
    sudo systemctl restart gatekeeper
    sleep 1
    if sudo systemctl is-active --quiet gatekeeper; then
        echo "  OK: gatekeeper is running"
    else
        echo "  ERROR: gatekeeper failed to start" >&2
        sudo journalctl -u gatekeeper --no-pager -n 20
        exit 1
    fi
EOF
