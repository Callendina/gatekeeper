"""Troll — a minimal test app for verifying gatekeeper integration.

Displays who's logged in (from gatekeeper headers) and has a single
'Say Hello' button that calls an API endpoint.
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Troll")


def _get_gatekeeper_info(request: Request) -> dict:
    return {
        "user": request.headers.get("x-gatekeeper-user", ""),
        "role": request.headers.get("x-gatekeeper-role", ""),
        "is_system_admin": request.headers.get("x-gatekeeper-system-admin", "") == "true",
        "ip": request.headers.get("x-forwarded-for", request.client.host),
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    info = _get_gatekeeper_info(request)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Troll</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; padding: 2rem; }}
        .container {{ max-width: 600px; margin: 0 auto; }}
        .card {{ background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 2rem; margin-bottom: 1rem; }}
        h1 {{ margin-bottom: 1rem; }}
        .info-row {{ display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #eee; }}
        .info-label {{ font-weight: 600; color: #666; }}
        .info-value {{ font-family: monospace; }}
        .btn {{ display: inline-block; padding: 0.7rem 1.5rem; background: #4a90d9; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-top: 1rem; }}
        .btn:hover {{ background: #3a7bc8; }}
        #greeting {{ margin-top: 1rem; padding: 1rem; background: #f0f7ff; border-radius: 4px; display: none; font-size: 1.1rem; }}
        .auth-links {{ margin-top: 1rem; font-size: 0.9rem; }}
        .auth-links a {{ color: #4a90d9; margin-right: 1rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Troll</h1>
            <p style="color: #666; margin-bottom: 1rem;">Gatekeeper integration test app</p>

            <div class="info-row">
                <span class="info-label">User</span>
                <span class="info-value">{info['user'] or '(anonymous)'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Role</span>
                <span class="info-value">{info['role'] or '(none)'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">System Admin</span>
                <span class="info-value">{'Yes' if info['is_system_admin'] else 'No'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">IP Address</span>
                <span class="info-value">{info['ip']}</span>
            </div>

            <button class="btn" onclick="sayHello()">Say Hello</button>
            <div id="greeting"></div>

            <div class="auth-links">
                {'<a href="/_auth/logout?app=troll-dev">Logout</a>' if info['user'] else '<a href="/_auth/login?app=troll-dev&next=/">Login</a>'}
                <a href="/_auth/admin">Admin</a>
            </div>
        </div>
    </div>
    <script>
        async function sayHello() {{
            const resp = await fetch('/api/hello');
            const data = await resp.json();
            const el = document.getElementById('greeting');
            el.textContent = data.message;
            el.style.display = 'block';
        }}
    </script>
</body>
</html>"""


@app.get("/api/hello")
async def hello(request: Request):
    info = _get_gatekeeper_info(request)
    if info["user"]:
        message = f"Hello {info['user']}!"
    else:
        message = "Hello anonymous person!"
    return JSONResponse({"message": message})
