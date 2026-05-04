#!/usr/bin/env python3
"""Gatekeeper management CLI.

Sub-commands:
  provision [--env=prod|staging]   One-shot host setup (Docker, /srv/gatekeeper/data)
  deploy [--env=prod|staging]      git pull + docker compose build + up -d
  set-secret <env> <KEY>           Write a secret to /srv/gatekeeper/data/.env on host
  status [--env=prod|staging]      docker compose ps
  logs [--env=prod|staging]        docker compose logs -f

Replaces deploy.sh. Secrets are written via skeletor.secrets.set_secret() — value is
piped over SSH stdin, never on a command line. Requires NOPASSWD sudo on the host.
"""
import argparse
import getpass
import os
import sys
import textwrap

from jinja2 import Environment, FileSystemLoader
from skeletor import ssh, secrets
from skeletor.ssh import SSHError

_DEPLOY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deploy")


ENV_HOSTS = {
    "prod":    "scout.callendina.com",
    "staging": "staging.callendina.com",
}
SSH_USER = "jonnosan"
REPO_DIR = "/home/jonnosan/gatekeeper"
DATA_DIR = "/srv/gatekeeper/data"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _host(env: str) -> str:
    if env not in ENV_HOSTS:
        print(f"unknown env: {env!r} (must be one of {sorted(ENV_HOSTS)})", file=sys.stderr)
        sys.exit(1)
    return ENV_HOSTS[env]


def _run(host: str, cmd: str) -> None:
    """SSH to host, run cmd, stream output to terminal. Exits on failure."""
    print(f"# {SSH_USER}@{host}: {cmd[:120]}{'...' if len(cmd) > 120 else ''}", flush=True)
    try:
        ssh.run(host, cmd, user=SSH_USER, capture=False)
    except SSHError as e:
        sys.exit(e.result.returncode)


# ─── provision ────────────────────────────────────────────────────────────────

def cmd_provision(env: str) -> None:
    """Idempotent host setup. Safe to re-run."""
    host = _host(env)
    script = textwrap.dedent(f"""\
        set -e

        echo '=== 1. Docker install (idempotent) ==='
        if ! command -v docker >/dev/null 2>&1; then
            sudo bash -c '
                set -e
                apt-get update
                apt-get install -y ca-certificates curl gnupg
                install -m 0755 -d /etc/apt/keyrings
                . /etc/os-release
                curl -fsSL "https://download.docker.com/linux/${{ID}}/gpg" | \\
                    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                chmod a+r /etc/apt/keyrings/docker.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \\
                    https://download.docker.com/linux/${{ID}} \\
                    $(. /etc/os-release && echo $VERSION_CODENAME) stable" \\
                    > /etc/apt/sources.list.d/docker.list
                apt-get update
                apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            '
        else
            echo "  docker present: $(docker --version)"
        fi

        echo '=== 2. Add {SSH_USER} to docker group (idempotent) ==='
        if ! groups {SSH_USER} | grep -qw docker; then
            sudo usermod -aG docker {SSH_USER}
            echo "  added to docker group — re-login required for effect"
        else
            echo "  {SSH_USER} already in docker group"
        fi

        echo '=== 3. Clone repo (idempotent) ==='
        if [ ! -d {REPO_DIR}/.git ]; then
            git clone https://github.com/Callendina/gatekeeper.git {REPO_DIR}
        else
            echo "  repo already cloned at {REPO_DIR}"
        fi

        echo '=== 4. /srv/gatekeeper/data (idempotent) ==='
        sudo bash -c '
            mkdir -p {DATA_DIR}
            chown {SSH_USER}:{SSH_USER} {DATA_DIR}
            chmod 750 {DATA_DIR}
        '

        echo '=== Provision complete ==='
        echo
        echo 'Next steps:'
        echo '  1. Set secrets (example):'
        echo '       python manage.py set-secret {env} SECRET_KEY'
        echo '       python manage.py set-secret {env} TWILIO_ACCOUNT_SID'
        echo '       python manage.py set-secret {env} TWILIO_AUTH_TOKEN'
        echo '       python manage.py set-secret {env} TWILIO_WEBHOOK_SECRET'
        echo '  2. python manage.py deploy --env={env}'
    """)
    _run(host, script)


# ─── deploy ───────────────────────────────────────────────────────────────────

def _deploy_server_config(host: str, env: str) -> None:
    """Render deploy/server.yaml.j2 and upload to /srv/gatekeeper/data/config.yaml."""
    j2 = Environment(loader=FileSystemLoader(_DEPLOY_DIR), keep_trailing_newline=True)
    rendered = j2.get_template("server.yaml.j2").render(env=env)
    print(f"# Deploying server config → {DATA_DIR}/config.yaml", flush=True)
    cmd = (
        f"sudo tee {DATA_DIR}/config.yaml > /dev/null"
        f" && sudo chown gatekeeper:gatekeeper {DATA_DIR}/config.yaml"
        f" && sudo chmod 0640 {DATA_DIR}/config.yaml"
    )
    ssh.run(host, cmd, user=SSH_USER, stdin=rendered)


def cmd_deploy(env: str) -> None:
    """Render + upload server config, then git pull + docker compose build + up -d."""
    host = _host(env)
    _deploy_server_config(host, env)
    script = textwrap.dedent(f"""\
        set -e
        cd {REPO_DIR}
        echo '=== 1. git pull ==='
        git pull --ff-only
        COUNT=$(git rev-list --count HEAD)
        IMAGE_TAG="v${{COUNT}}"
        export GATEKEEPER_COMMIT_COUNT="${{COUNT}}"
        export IMAGE_TAG
        echo "=== 2. docker compose build (${{IMAGE_TAG}}) ==="
        docker compose build
        echo '=== 3. docker compose up -d ==='
        docker compose up -d --remove-orphans
        echo '=== 4. health check ==='
        for i in 1 2 3 4 5 6 7 8 9 10; do
            if curl -sf http://localhost:9100/_auth/health >/dev/null 2>&1; then
                echo "  OK — gatekeeper healthy on :9100"
                docker compose ps
                exit 0
            fi
            sleep 1
        done
        echo "  ERROR: gatekeeper did not respond within 10s" >&2
        docker compose logs --tail=30 gatekeeper
        exit 1
    """)
    _run(host, script)


# ─── set-secret ───────────────────────────────────────────────────────────────

def cmd_set_secret(env: str, key: str) -> None:
    """Prompt for a secret value and write it to /srv/gatekeeper/data/.env on host."""
    host = _host(env)
    value = getpass.getpass(f"{key} ({env}): ")
    if not value.strip():
        print("empty value — aborted", file=sys.stderr)
        sys.exit(1)
    secrets.set_secret(host, key, value, app_slug="gatekeeper", user=SSH_USER)
    print(f"  {key} written to {SSH_USER}@{host}:{DATA_DIR}/.env")


# ─── status / logs ────────────────────────────────────────────────────────────

def cmd_status(env: str) -> None:
    _run(_host(env), f"cd {REPO_DIR} && docker compose ps")


def cmd_logs(env: str, service: str | None) -> None:
    svc = service or ""
    _run(_host(env), f"cd {REPO_DIR} && docker compose logs -f --tail=200 {svc}")


# ─── argparse ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="manage.py",
        description="Gatekeeper management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("provision", help="One-shot host setup")
    p.add_argument("--env", default="prod", choices=list(ENV_HOSTS),
                   help="Target environment (default: prod)")

    p = sub.add_parser("deploy", help="git pull + build + up on the env's host")
    p.add_argument("--env", default="prod", choices=list(ENV_HOSTS),
                   help="Target environment (default: prod)")

    p = sub.add_parser("set-secret", help="Write a secret to /srv/gatekeeper/data/.env")
    p.add_argument("env", choices=list(ENV_HOSTS), help="Target environment")
    p.add_argument("key", metavar="KEY", help="Environment variable name")

    p = sub.add_parser("status", help="docker compose ps")
    p.add_argument("--env", default="prod", choices=list(ENV_HOSTS))

    p = sub.add_parser("logs", help="docker compose logs -f")
    p.add_argument("--env", default="prod", choices=list(ENV_HOSTS))
    p.add_argument("service", nargs="?", default=None,
                   help="Service name (default: all)")

    args = parser.parse_args()

    if args.cmd == "provision":
        cmd_provision(args.env)
    elif args.cmd == "deploy":
        cmd_deploy(args.env)
    elif args.cmd == "set-secret":
        cmd_set_secret(args.env, args.key)
    elif args.cmd == "status":
        cmd_status(args.env)
    elif args.cmd == "logs":
        cmd_logs(args.env, args.service)


if __name__ == "__main__":
    main()
