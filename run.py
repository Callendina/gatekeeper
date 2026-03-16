#!/usr/bin/env python3
"""Run gatekeeper server."""
import uvicorn
from gatekeeper.config import load_config

config = load_config()
uvicorn.run(
    "gatekeeper.app:app",
    host=config.host,
    port=config.port,
    log_level="info",
)
