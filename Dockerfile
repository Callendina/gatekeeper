# syntax=docker/dockerfile:1
#
# Gatekeeper — production image
#
# Built once on staging, streamed to prod via:
#   ssh staging "docker save gatekeeper:vN" | ssh prod "docker load"
# Runs as the in-container `gatekeeper` user (UID 1102), matching the
# host `gatekeeper` user that owns the bind-mounted /srv/gatekeeper/data
# directory. UIDs across the fleet: vispay=1100, scout=1101, gatekeeper=1102.

FROM python:3.12-slim

RUN groupadd -r -g 1102 gatekeeper \
    && useradd -r -u 1102 -g 1102 -s /usr/sbin/nologin -d /app gatekeeper

WORKDIR /app

COPY requirements.txt .
# `git` is needed at install time because cyclops ships as a git+ URL in
# requirements.txt; we install it, run pip, then remove it to keep the
# runtime image lean.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Bind-mount target. Symlink config.yaml, config.d/, and the SQLite DB
# into data/ so the app code (which reads relative paths from the working
# directory) works unchanged. The /app/data dir exists at build time so
# symlink targets resolve even before the bind mount is attached.
RUN mkdir -p /app/data \
    && ln -sf data/config.yaml /app/config.yaml \
    && ln -sf data/config.d    /app/config.d \
    && ln -sf data/gatekeeper.db /app/gatekeeper.db \
    && chown -R gatekeeper:gatekeeper /app

USER gatekeeper

EXPOSE 9100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:9100/_auth/health', timeout=3).status == 200 else 1)" \
        || exit 1

CMD ["python", "run.py"]
