"""Print a fresh development-only NOTES_MASTER_KEY value."""

from __future__ import annotations

import base64
import secrets


def main() -> None:
    encoded = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    print(encoded)


if __name__ == "__main__":
    main()
