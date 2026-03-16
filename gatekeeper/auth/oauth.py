from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
from gatekeeper.config import GatekeeperConfig

oauth = OAuth()


def setup_oauth(config: GatekeeperConfig):
    if config.google_client_id:
        oauth.register(
            name="google",
            client_id=config.google_client_id,
            client_secret=config.google_client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )


async def get_google_redirect_url(request: Request, redirect_uri: str) -> str:
    return await oauth.google.authorize_redirect(request, redirect_uri)


async def handle_google_callback(request: Request) -> dict:
    """Returns dict with keys: email, name, sub (Google user ID)."""
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo")
    return {
        "email": userinfo["email"],
        "name": userinfo.get("name", userinfo["email"]),
        "sub": userinfo["sub"],
    }
