#!/usr/bin/env python3
"""
Dev proxy that simulates Caddy's forward_auth behaviour.

Listens on port 8080, and for each request:
1. Calls gatekeeper's /_auth/verify endpoint (like Caddy forward_auth)
2. If 200: proxies to troll (port 8888) with gatekeeper's response headers
3. If /_auth/*: proxies directly to gatekeeper (port 9100)
4. Otherwise: returns gatekeeper's error response (401/403/429)

This lets you test the full flow locally without installing Caddy.

Usage:
    # Terminal 1: python run.py (gatekeeper on :9100)
    # Terminal 2: cd troll && python run.py (troll on :8888)
    # Terminal 3: cd troll && python dev_proxy.py (proxy on :8080)
    # Browser: http://localhost:8080
"""
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
import uvicorn

app = FastAPI()

GATEKEEPER_URL = "http://127.0.0.1:9100"
TROLL_URL = "http://127.0.0.1:8888"

COPY_HEADERS = [
    "x-gatekeeper-user",
    "x-gatekeeper-role",
    "x-gatekeeper-system-admin",
]


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str = ""):
    full_path = f"/{path}"
    if request.url.query:
        full_path += f"?{request.url.query}"

    # Route /_auth/* directly to gatekeeper
    if full_path.startswith("/_auth"):
        return await _proxy_to(GATEKEEPER_URL, full_path, request)

    # Forward auth check
    async with httpx.AsyncClient() as client:
        verify_headers = {
            "x-forwarded-host": "localhost",
            "x-forwarded-uri": full_path,
            "x-forwarded-method": request.method,
            "x-forwarded-for": request.client.host,
        }
        # Forward cookies
        if request.headers.get("cookie"):
            verify_headers["cookie"] = request.headers["cookie"]
        # Forward API key if present
        api_key = request.headers.get("x-api-key")
        if api_key:
            verify_headers["x-forwarded-api-key"] = api_key

        verify_resp = await client.get(
            f"{GATEKEEPER_URL}/_auth/verify",
            headers=verify_headers,
        )

    if verify_resp.status_code != 200:
        # Return gatekeeper's error, but check for login redirect
        login_url = verify_resp.headers.get("x-gatekeeper-login-url")
        if login_url:
            return Response(
                status_code=302,
                headers={"Location": login_url},
            )
        register_url = verify_resp.headers.get("x-gatekeeper-register-url")
        if register_url:
            return Response(
                status_code=302,
                headers={"Location": register_url},
            )
        return Response(
            content=verify_resp.text,
            status_code=verify_resp.status_code,
        )

    # Build extra headers from gatekeeper's response
    extra_headers = {}
    for h in COPY_HEADERS:
        val = verify_resp.headers.get(h)
        if val is not None:
            extra_headers[h] = val

    # Proxy to troll, with gatekeeper headers added
    response = await _proxy_to(TROLL_URL, full_path, request, extra_headers)

    # Copy any set-cookie from gatekeeper's verify response
    for cookie_header in verify_resp.headers.get_list("set-cookie"):
        response.headers.append("set-cookie", cookie_header)

    return response


async def _proxy_to(
    base_url: str,
    path: str,
    request: Request,
    extra_headers: dict = None,
):
    async with httpx.AsyncClient() as client:
        headers = dict(request.headers)
        headers.pop("host", None)
        if extra_headers:
            headers.update(extra_headers)

        body = await request.body()

        resp = await client.request(
            method=request.method,
            url=f"{base_url}{path}",
            headers=headers,
            content=body,
        )

    response = Response(
        content=resp.content,
        status_code=resp.status_code,
    )
    for key, val in resp.headers.items():
        if key.lower() not in ("content-length", "content-encoding", "transfer-encoding"):
            response.headers.append(key, val)

    return response


if __name__ == "__main__":
    print("Dev proxy: http://localhost:8080 -> gatekeeper(:9100) + troll(:8888)")
    print("Make sure gatekeeper and troll are running first.")
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="info")
