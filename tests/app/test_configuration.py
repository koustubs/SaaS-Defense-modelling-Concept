from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from notes_app.config import ConfigurationError, Settings
from notes_app.main import create_app
from scripts import run_demo


@pytest.mark.parametrize(
    ("environment", "expected"),
    [("development", False), ("test", True), ("production", True)],
)
def test_only_development_mode_allows_non_secure_cookies(
    environment: str, expected: bool, tmp_path: Path
) -> None:
    settings = Settings(
        master_key=b"C" * 32,
        environment=environment,
        database_url=f"sqlite+pysqlite:///{(tmp_path / 'cookies.db').as_posix()}",
        argon2_time_cost=1,
        argon2_memory_cost_kib=8_192,
        argon2_parallelism=1,
    )
    app = create_app(settings)

    assert settings.secure_cookies is expected
    try:
        scheme = "https" if expected else "http"
        with TestClient(app, base_url=f"{scheme}://testserver") as client:
            response = client.get("/login")
            csrf_cookie = next(
                item
                for item in response.headers.get_list("set-cookie")
                if item.startswith("notes_csrf=")
            )
            assert ("Secure" in csrf_cookie) is expected
            assert ("strict-transport-security" in response.headers) is expected
    finally:
        app.state.engine.dispose()


def test_non_loopback_binding_requires_production() -> None:
    development = Settings(master_key=b"C" * 32, environment="development")
    test = Settings(master_key=b"C" * 32, environment="test")
    production = Settings(master_key=b"C" * 32, environment="production")

    for host in ("127.0.0.1", "::1", "localhost"):
        development.validate_bind_host(host)
    with pytest.raises(ConfigurationError, match="non-loopback"):
        development.validate_bind_host("0.0.0.0")  # noqa: S104 - validation input
    with pytest.raises(ConfigurationError, match="non-loopback"):
        test.validate_bind_host("192.0.2.10")
    production.validate_bind_host("0.0.0.0")  # noqa: S104 - validation input


def test_launcher_rejects_unsafe_binding_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    encoded_key = base64.urlsafe_b64encode(b"C" * 32).decode("ascii")
    monkeypatch.setenv("NOTES_MASTER_KEY", encoded_key)
    monkeypatch.setenv("NOTES_ENV", "development")
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_demo.py", "--host", "0.0.0.0"],  # noqa: S104 - validation input
    )

    with pytest.raises(SystemExit) as raised:
        run_demo.main()

    assert raised.value.code == 2
    error = capsys.readouterr().err
    assert "non-loopback binding requires NOTES_ENV=production" in error
    assert "Traceback" not in error
