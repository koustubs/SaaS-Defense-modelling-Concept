"""Module execution support for ``python -m threat_analyzer``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
