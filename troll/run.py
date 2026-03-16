#!/usr/bin/env python3
"""Run the troll test app on port 8888."""
import uvicorn

uvicorn.run("app:app", host="127.0.0.1", port=8888, log_level="info")
