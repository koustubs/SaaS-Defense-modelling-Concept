from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from notes_app.config import Settings
from notes_app.main import create_app

TEST_PASSWORD = "correct horse battery staple"


@dataclass
class FakeClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current

    def advance(self, *, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(datetime(2026, 1, 2, 3, 4, 5))


@pytest.fixture
def database_path(tmp_path: Path) -> Path:
    return tmp_path / "notes-test.db"


@pytest.fixture
def settings(database_path: Path) -> Settings:
    return Settings(
        master_key=b"T" * 32,
        database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
        environment="test",
        session_idle_seconds=10,
        session_absolute_seconds=30,
        login_max_failures=3,
        login_window_seconds=60,
        lockout_seconds=20,
        max_request_bytes=2_048,
        max_notes_per_user=2,
        max_title_chars=40,
        max_note_chars=256,
        page_size=1,
        argon2_time_cost=1,
        argon2_memory_cost_kib=8_192,
        argon2_parallelism=1,
    )


@pytest.fixture
def app(settings: Settings, clock: FakeClock) -> FastAPI:
    application = create_app(settings, clock=clock)
    yield application
    application.state.engine.dispose()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    with TestClient(
        app, base_url="https://testserver", raise_server_exceptions=False
    ) as test_client:
        yield test_client


def csrf(client: TestClient) -> str:
    token = client.cookies.get("notes_csrf")
    assert token
    return token


def register(
    client: TestClient,
    username: str = "alice",
    password: str = TEST_PASSWORD,
) -> None:
    response = client.get("/register")
    assert response.status_code == 200
    response = client.post(
        "/register",
        data={"username": username, "password": password, "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login?registered=1"


def login(
    client: TestClient,
    username: str = "alice",
    password: str = TEST_PASSWORD,
) -> None:
    response = client.get("/login")
    assert response.status_code == 200
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/notes"


def register_and_login(
    client: TestClient,
    username: str = "alice",
    password: str = TEST_PASSWORD,
) -> None:
    register(client, username, password)
    login(client, username, password)


def create_note(client: TestClient, title: str = "First note", body: str = "Private body") -> str:
    response = client.post(
        "/notes",
        data={"title": title, "body": body, "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/notes/")
    return location.removeprefix("/notes/")
