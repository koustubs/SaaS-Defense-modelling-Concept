from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import notes_app.main as main_module
from notes_app.config import Settings
from notes_app.main import create_app
from notes_app.models import AuditEvent, LoginThrottle, User, UserSession
from tests.app.conftest import TEST_PASSWORD, FakeClock, csrf, login, register


def test_registration_stores_argon2id_hash_not_plaintext(client: TestClient, app: FastAPI) -> None:
    register(client)

    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "alice"))
        assert user is not None
        assert user.password_hash != TEST_PASSWORD
        assert user.password_hash.startswith("$argon2id$")


def test_registration_integrity_race_matches_neutral_conflict_and_safe_audit(
    client: TestClient,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    client.get("/register")
    original_flush = Session.flush
    injected = False

    def racing_flush(session: Session, *args, **kwargs):
        nonlocal injected
        if not injected and any(isinstance(item, User) for item in session.new):
            injected = True
            raise IntegrityError(
                "INSERT INTO users (username, password_hash)",
                {"username": "alice", "password": TEST_PASSWORD},
                RuntimeError("UNIQUE constraint failed: users.username"),
            )
        return original_flush(session, *args, **kwargs)

    monkeypatch.setattr(Session, "flush", racing_flush)
    raced = client.post(
        "/register",
        data={"username": "alice", "password": TEST_PASSWORD, "csrf_token": csrf(client)},
    )
    assert raced.status_code == 409
    assert "That username is unavailable." in raced.text
    assert "UNIQUE constraint" not in raced.text
    assert TEST_PASSWORD not in raced.text
    assert "Traceback" not in raced.text

    created = client.post(
        "/register",
        data={"username": "alice", "password": TEST_PASSWORD, "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert created.status_code == 303
    duplicate = client.post(
        "/register",
        data={"username": "alice", "password": TEST_PASSWORD, "csrf_token": csrf(client)},
    )
    assert duplicate.status_code == raced.status_code
    assert duplicate.text == raced.text
    assert TEST_PASSWORD not in caplog.text

    with app.state.session_factory() as db:
        conflicts = db.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "account.registration_conflict")
        ).all()
        assert len(conflicts) == 2
        for event in conflicts:
            assert event.actor_user_id is None
            assert event.target_id is None
            assert event.event_data == '{"reason":"username_unavailable"}'
            assert "alice" not in event.event_data
            assert TEST_PASSWORD not in event.event_data


def test_registration_enforces_username_and_password_policy(client: TestClient) -> None:
    client.get("/register")
    response = client.post(
        "/register",
        data={"username": "not allowed!", "password": "short", "csrf_token": csrf(client)},
    )
    assert response.status_code == 400
    assert "Username must be" in response.text

    response = client.post(
        "/register",
        data={"username": "valid-name", "password": "short", "csrf_token": csrf(client)},
    )
    assert response.status_code == 400
    assert "at least 12 characters" in response.text


def test_successful_login_creates_only_a_hashed_session_token(
    client: TestClient, app: FastAPI
) -> None:
    register(client)
    login(client)
    raw_token = client.cookies.get("notes_session")
    assert raw_token

    with app.state.session_factory() as db:
        session = db.scalar(select(UserSession))
        assert session is not None
        assert len(session.token_hash) == 32
        assert raw_token.encode() not in session.token_hash
        assert session.revoked_at is None


def test_wrong_and_nonexistent_accounts_receive_same_generic_failure(
    client: TestClient,
) -> None:
    register(client)
    client.get("/login")
    wrong_password = client.post(
        "/login",
        data={"username": "alice", "password": "wrong password", "csrf_token": csrf(client)},
    )
    missing_account = client.post(
        "/login",
        data={"username": "nobody", "password": "wrong password", "csrf_token": csrf(client)},
    )

    assert wrong_password.status_code == missing_account.status_code == 401
    assert "Unable to sign in with those credentials." in wrong_password.text
    assert wrong_password.text == missing_account.text
    assert "alice" not in wrong_password.text
    assert "nobody" not in missing_account.text


def test_wrong_real_and_missing_accounts_each_run_one_verifier_call(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    register(client)
    client.get("/login")
    verified_hashes: list[str] = []
    original_verify = main_module.verify_password

    def counted_verify(hasher, stored_hash: str, supplied_password: str) -> bool:
        verified_hashes.append(stored_hash)
        return original_verify(hasher, stored_hash, supplied_password)

    monkeypatch.setattr(main_module, "verify_password", counted_verify)
    real_account = client.post(
        "/login",
        data={"username": "alice", "password": "wrong password", "csrf_token": csrf(client)},
    )
    missing_account = client.post(
        "/login",
        data={"username": "nobody", "password": "wrong password", "csrf_token": csrf(client)},
    )
    assert real_account.status_code == missing_account.status_code == 401
    assert len(verified_hashes) == 2
    assert all(value.startswith("$argon2id$") for value in verified_hashes)
    assert verified_hashes[0] != verified_hashes[1]


def test_xss_shaped_authentication_inputs_are_not_reflected(client: TestClient) -> None:
    payload = '"><svg onload=alert(1)>'
    client.get("/register")
    registration = client.post(
        "/register",
        data={"username": payload, "password": TEST_PASSWORD, "csrf_token": csrf(client)},
    )
    assert registration.status_code == 400
    assert payload not in registration.text
    assert "<svg" not in registration.text

    client.get("/login")
    login_failure = client.post(
        "/login",
        data={"username": payload, "password": "wrong password", "csrf_token": csrf(client)},
    )
    assert login_failure.status_code == 401
    assert payload not in login_failure.text
    assert "<svg" not in login_failure.text
    assert "script-src 'none'" in login_failure.headers["content-security-policy"]


def test_account_and_address_lockout_is_temporary(
    client: TestClient, app: FastAPI, clock: FakeClock
) -> None:
    register(client)
    client.get("/login")
    for _ in range(3):
        response = client.post(
            "/login",
            data={"username": "alice", "password": "wrong password", "csrf_token": csrf(client)},
        )
        assert response.status_code == 401

    locked_correct_attempt = client.post(
        "/login",
        data={"username": "alice", "password": TEST_PASSWORD, "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert locked_correct_attempt.status_code == 401
    assert "Unable to sign in with those credentials." in locked_correct_attempt.text
    with app.state.session_factory() as db:
        scopes = {record.scope for record in db.scalars(select(LoginThrottle)).all()}
        assert scopes == {"account", "address"}

    clock.advance(seconds=21)
    unlocked = client.post(
        "/login",
        data={"username": "alice", "password": TEST_PASSWORD, "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert unlocked.status_code == 303


def test_account_lockout_uses_normalized_username_identifier(client: TestClient) -> None:
    register(client, username="Alice")
    client.get("/login")
    for variant in ("ALICE", " alice ", "Alice"):
        failed = client.post(
            "/login",
            data={"username": variant, "password": "wrong password", "csrf_token": csrf(client)},
        )
        assert failed.status_code == 401

    bypass_attempt = client.post(
        "/login",
        data={"username": "aLiCe", "password": TEST_PASSWORD, "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert bypass_attempt.status_code == 401
    assert "Unable to sign in with those credentials." in bypass_attempt.text


def test_parallel_login_failures_are_serialized_and_bound_password_work(
    settings: Settings,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = create_app(replace(settings, login_max_failures=1), clock=clock)
    request_barrier = threading.Barrier(2)
    count_lock = threading.Lock()
    verifier_calls = 0
    original_verify = main_module.verify_password

    def counted_verify(*args, **kwargs):
        nonlocal verifier_calls
        with count_lock:
            verifier_calls += 1
        return original_verify(*args, **kwargs)

    monkeypatch.setattr(main_module, "verify_password", counted_verify)
    try:
        with (
            TestClient(
                application, base_url="https://testserver", raise_server_exceptions=False
            ) as first_client,
            TestClient(
                application, base_url="https://testserver", raise_server_exceptions=False
            ) as second_client,
        ):
            register(first_client)
            first_client.get("/login")
            second_client.get("/login")

            def fail_login(client: TestClient) -> int:
                request_barrier.wait()
                return client.post(
                    "/login",
                    data={
                        "username": "alice",
                        "password": "wrong password",
                        "csrf_token": csrf(client),
                    },
                ).status_code

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(fail_login, first_client),
                    executor.submit(fail_login, second_client),
                ]
                statuses = [future.result(timeout=10) for future in futures]
            assert statuses == [401, 401]
            assert verifier_calls == 1

            still_locked = first_client.post(
                "/login",
                data={
                    "username": "alice",
                    "password": TEST_PASSWORD,
                    "csrf_token": csrf(first_client),
                },
            )
            assert still_locked.status_code == 401
            assert verifier_calls == 1

            with application.state.session_factory() as db:
                throttles = db.scalars(select(LoginThrottle)).all()
                assert {record.scope for record in throttles} == {"account", "address"}
                assert all(record.failures == 1 for record in throttles)
                assert all(record.locked_until is not None for record in throttles)
    finally:
        application.state.engine.dispose()


def test_login_rotates_existing_authenticated_session(client: TestClient, app: FastAPI) -> None:
    register(client)
    login(client)
    first_raw_token = client.cookies.get("notes_session")

    login(client)
    second_raw_token = client.cookies.get("notes_session")
    assert second_raw_token != first_raw_token
    with app.state.session_factory() as db:
        sessions = db.scalars(select(UserSession).order_by(UserSession.id)).all()
        assert len(sessions) == 2
        assert sessions[0].revoked_at is not None
        assert sessions[1].revoked_at is None
    with TestClient(
        app, base_url="https://testserver", raise_server_exceptions=False
    ) as replay_client:
        replay_client.cookies.set("notes_session", first_raw_token)
        replay = replay_client.get("/notes", follow_redirects=False)
        assert replay.status_code == 303
        assert replay.headers["location"] == "/login"


def test_logout_revokes_session_and_clears_cookie(client: TestClient, app: FastAPI) -> None:
    register(client)
    login(client)
    revoked_raw_token = client.cookies.get("notes_session")
    assert revoked_raw_token
    response = client.post("/logout", data={"csrf_token": csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    assert client.cookies.get("notes_session") is None

    with app.state.session_factory() as db:
        session = db.scalar(select(UserSession))
        assert session is not None
        assert session.revoked_at is not None
        event_types = {event.event_type for event in db.scalars(select(AuditEvent)).all()}
        assert "logout.succeeded" in event_types
    client.cookies.set("notes_session", revoked_raw_token)
    replay = client.get("/notes", follow_redirects=False)
    assert replay.status_code == 303
    assert replay.headers["location"] == "/login"


def test_idle_and_absolute_session_expiry(
    client: TestClient, app: FastAPI, clock: FakeClock
) -> None:
    register(client)
    login(client)
    clock.advance(seconds=11)
    idle_expired = client.get("/notes", follow_redirects=False)
    assert idle_expired.status_code == 303
    assert idle_expired.headers["location"] == "/login"

    login(client)
    for _ in range(3):
        clock.advance(seconds=9)
        assert client.get("/notes", follow_redirects=False).status_code == 200
    clock.advance(seconds=4)
    absolute_expired = client.get("/notes", follow_redirects=False)
    assert absolute_expired.status_code == 303
    with app.state.session_factory() as db:
        records = db.scalars(select(UserSession).order_by(UserSession.id)).all()
        assert all(record.revoked_at is not None for record in records)


def test_login_failures_are_audited_without_submitted_password(
    client: TestClient, app: FastAPI
) -> None:
    register(client)
    client.get("/login")
    submitted_secret = "submitted secret password"
    client.post(
        "/login",
        data={"username": "alice", "password": submitted_secret, "csrf_token": csrf(client)},
    )
    with app.state.session_factory() as db:
        event = db.scalar(
            select(AuditEvent)
            .where(AuditEvent.event_type == "login.failed")
            .order_by(AuditEvent.id.desc())
        )
        assert event is not None
        assert submitted_secret not in event.event_data
        assert "rejected" in event.event_data
