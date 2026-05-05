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
from skeletor import RemoteError, secrets
from skeletor import workflow as wf

_DEPLOY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deploy")


ENV_HOSTS = {
    # gatekeeper-specific hostnames — currently CNAME to the same VMs as
    # scout but decouple gk's deploy target from scout's so the two can
    # split onto separate VMs later without renaming this file.
    "prod":    "gatekeeper.callendina.com",
    "staging": "gatekeeper-staging.callendina.com",
}
SSH_USER = "skeletor"
REPO_DIR = "/srv/gatekeeper"
DATA_DIR = "/srv/gatekeeper/data"
GITHUB_REPO = "git@github.com:Callendina/gatekeeper.git"
GATEKEEPER_UID = 1102
GATEKEEPER_GID = 1102


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
        wf.run_remote_script(host, cmd, user=SSH_USER)
    except RemoteError as e:
        sys.exit(e.result.returncode)


# ─── provision ────────────────────────────────────────────────────────────────

def cmd_provision(env: str) -> None:
    """Idempotent host setup per CONVENTIONS §1+§2. Safe to re-run."""
    host = _host(env)
    # Standard host setup: docker, gatekeeper user (UID 1102), /srv/gatekeeper/{,data}
    wf.provision_host(host, app="gatekeeper", uid=GATEKEEPER_UID, gid=GATEKEEPER_GID, user=SSH_USER)

    # Bring repo content into /srv/gatekeeper/. Operator must have a
    # deploy key for Callendina/gatekeeper on the host.
    wf.git_clone_or_pull(host, dest=REPO_DIR, repo_url=GITHUB_REPO, user=SSH_USER)

    _run(host, textwrap.dedent(f"""\
        echo '=== Provision complete ==='
        echo
        echo 'Next steps:'
        echo '  1. Set secrets (example):'
        echo '       python manage.py set-secret {env} GK_SECRET_KEY'
        echo '       python manage.py set-secret {env} GOOGLE_CLIENT_SECRET'
        echo '       python manage.py set-secret {env} GITHUB_CLIENT_SECRET'
        echo '       python manage.py set-secret {env} RESEND_API_KEY'
        echo '       python manage.py set-secret {env} TWILIO_ACCOUNT_SID'
        echo '       python manage.py set-secret {env} TWILIO_AUTH_TOKEN'
        echo '  2. python manage.py deploy --env={env}'
    """))


# ─── deploy ───────────────────────────────────────────────────────────────────

def _deploy_server_config(host: str, env: str) -> None:
    """Render deploy/server.yaml.j2 and upload to /srv/gatekeeper/data/config.yaml."""
    j2 = Environment(loader=FileSystemLoader(_DEPLOY_DIR), keep_trailing_newline=True)
    rendered = j2.get_template("server.yaml.j2").render(env=env)
    print(f"# Deploying server config → {DATA_DIR}/config.yaml", flush=True)
    wf.deploy_file(
        host,
        content=rendered,
        dest_path=f"{DATA_DIR}/config.yaml",
        owner="gatekeeper",
        group="gatekeeper",
        mode="0640",
        user=SSH_USER,
    )


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


def cmd_generate_secret(env: str, key: str, bytes_n: int = 32) -> None:
    """Generate a random hex value (token_hex(bytes_n)) and write it to
    /srv/gatekeeper/data/.env on the host. The value is never echoed
    to the local terminal — bypasses the human-paste step that risks
    terminal escape codes contaminating the value.
    """
    import secrets as _secrets_lib
    host = _host(env)
    value = _secrets_lib.token_hex(bytes_n)
    secrets.set_secret(host, key, value, app_slug="gatekeeper", user=SSH_USER)
    print(f"  {key} ({bytes_n*2}-char hex) written to {SSH_USER}@{host}:{DATA_DIR}/.env")


def cmd_copy_secret(src: str, dst: str, key: str) -> None:
    """Copy a single named secret from src env's .env to dst env's .env.
    Per-key by design — callers must name each secret to copy so we
    never silently propagate a new staging key into prod."""
    src_host = _host(src)
    dst_host = _host(dst)
    if src_host == dst_host:
        print("source and destination are the same host — aborted", file=sys.stderr)
        sys.exit(1)

    print(f"# Copying {key} from {src} → {dst}")
    ok = secrets.copy_secret(
        src_host, dst_host, key,
        app_slug="gatekeeper", src_user=SSH_USER, dst_user=SSH_USER,
    )
    if ok:
        print(f"  {key} written to {SSH_USER}@{dst_host}:{DATA_DIR}/.env")
    else:
        print(f"  {key} not present on {src} — nothing written", file=sys.stderr)
        sys.exit(2)


# ─── status / logs ────────────────────────────────────────────────────────────

def cmd_status(env: str) -> None:
    _run(_host(env), f"cd {REPO_DIR} && docker compose ps")


def cmd_admin_reset_totp(env: str, email: str) -> None:
    """Bump key_num + clear confirmed_at for the named user's TOTP row.

    Use this when GK_SECRET_KEY has been rotated (which invalidates the
    derived per-user TOTP secrets — every existing enrollment yields a
    different secret than what's in the user's authenticator). After
    reset, the user re-enrolls on next protected access (new QR code).

    Runs inside the gatekeeper container via `docker compose exec`, so
    the script uses the same ORM the running app uses — no separate
    sqlite3 surface and no risk of schema drift.
    """
    import shlex
    host = _host(env)
    script = textwrap.dedent(f"""\
        import asyncio
        from sqlalchemy import select
        from gatekeeper import database  # rebind read at call time
        from gatekeeper.config import load_config
        from gatekeeper.models import User, UserTOTP, UserAppRole

        async def main():
            cfg = load_config()
            await database.init_db(cfg.database_path)
            async with database.async_session_factory() as s:
                user = await s.scalar(select(User).where(User.email == {email!r}))
                if user is None:
                    raise SystemExit(f"no user with email={email!r}")
                rec = await s.scalar(select(UserTOTP).where(UserTOTP.user_id == user.id))
                if rec is None:
                    print(f"no TOTP enrollment to reset for {email!r}")
                    return
                old_key_num = rec.key_num
                rec.key_num += 1
                rec.confirmed_at = None
                rec.last_counter = 0
                # Also clear per-(user, app) mfa_method bindings so the
                # picker re-runs and the user can re-enroll cleanly.
                rows = (await s.execute(
                    select(UserAppRole).where(UserAppRole.user_id == user.id)
                )).scalars().all()
                for r in rows:
                    r.mfa_method = None
                await s.commit()
                print(f"reset TOTP for {{user.email}} (key_num {{old_key_num}} -> {{rec.key_num}})")

        asyncio.run(main())
        """)
    cmd = (
        f"cd {REPO_DIR} && "
        f"docker compose exec -T gatekeeper python -c {shlex.quote(script)}"
    )
    _run(host, cmd)


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

    p = sub.add_parser(
        "generate-secret",
        help="Generate a random hex value and write it to .env (no paste step)"
    )
    p.add_argument("env", choices=list(ENV_HOSTS), help="Target environment")
    p.add_argument("key", metavar="KEY", help="Environment variable name")
    p.add_argument("--bytes", type=int, default=32, dest="bytes_n",
                   help="Random bytes (default 32 → 64-char hex)")

    p = sub.add_parser(
        "copy-secret",
        help="Copy a single named secret from one env's .env to another's"
    )
    p.add_argument("src", choices=list(ENV_HOSTS), help="Source environment")
    p.add_argument("dst", choices=list(ENV_HOSTS), help="Destination environment")
    p.add_argument("key", metavar="KEY", help="Environment variable name to copy")

    admin_p = sub.add_parser("admin", help="Operator helpers")
    admin_sub = admin_p.add_subparsers(dest="admin_cmd", required=True)
    p = admin_sub.add_parser(
        "reset-totp",
        help="Force re-enrollment for one user (after a GK_SECRET_KEY rotation)"
    )
    p.add_argument("--env", default="prod", choices=list(ENV_HOSTS))
    p.add_argument("email", help="Target user's email")

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
    elif args.cmd == "generate-secret":
        cmd_generate_secret(args.env, args.key, args.bytes_n)
    elif args.cmd == "copy-secret":
        cmd_copy_secret(args.src, args.dst, args.key)
    elif args.cmd == "admin":
        if args.admin_cmd == "reset-totp":
            cmd_admin_reset_totp(args.env, args.email)
    elif args.cmd == "status":
        cmd_status(args.env)
    elif args.cmd == "logs":
        cmd_logs(args.env, args.service)


if __name__ == "__main__":
    main()
