"""Run the local secure notes demonstration."""

from __future__ import annotations

import argparse

import uvicorn

from notes_app import Settings, create_app
from notes_app.config import ConfigurationError


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args()
    try:
        settings = Settings.from_env()
        settings.validate_bind_host(args.host)
    except ConfigurationError as exc:
        parser.error(str(exc))
    uvicorn.run(create_app(settings), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
