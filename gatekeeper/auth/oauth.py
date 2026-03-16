from authlib.integrations.starlette_client import OAuth
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

    if config.github_client_id:
        oauth.register(
            name="github",
            client_id=config.github_client_id,
            client_secret=config.github_client_secret,
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "user:email"},
        )
