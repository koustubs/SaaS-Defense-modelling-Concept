from __future__ import annotations

import logging
from dataclasses import replace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from notes_app.main import create_app
from notes_app.models import AuditEvent, Note, User, UserSession
from tests.app.conftest import (
    TEST_PASSWORD,
    FakeClock,
    create_note,
    csrf,
    login,
    register,
    register_and_login,
)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/notes"),
        ("GET", "/notes/new"),
        ("POST", "/notes"),
        ("GET", "/notes/00000000-0000-0000-0000-000000000001"),
        ("GET", "/notes/00000000-0000-0000-0000-000000000001/edit"),
        ("POST", "/notes/00000000-0000-0000-0000-000000000001/edit"),
        ("GET", "/notes/00000000-0000-0000-0000-000000000001/delete"),
        ("POST", "/notes/00000000-0000-0000-0000-000000000001/delete"),
        ("POST", "/export"),
        ("GET", "/admin/audit-summary"),
    ],
)
def test_unauthenticated_requests_cannot_reach_protected_routes(
    client: TestClient, method: str, path: str
) -> None:
    response = client.request(method, path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_missing_and_invalid_csrf_are_rejected(client: TestClient) -> None:
    client.get("/register")
    missing = client.post("/register", data={"username": "alice", "password": TEST_PASSWORD})
    invalid = client.post(
        "/register",
        data={"username": "alice", "password": TEST_PASSWORD, "csrf_token": "invalid"},
    )
    assert missing.status_code == invalid.status_code == 403

    register(client)
    client.get("/login")
    missing_login = client.post("/login", data={"username": "alice", "password": TEST_PASSWORD})
    invalid_login = client.post(
        "/login",
        data={"username": "alice", "password": TEST_PASSWORD, "csrf_token": "invalid"},
    )
    assert missing_login.status_code == invalid_login.status_code == 403
    login(client)
    missing_note = client.post("/notes", data={"title": "title", "body": "body"})
    invalid_note = client.post(
        "/notes", data={"title": "title", "body": "body", "csrf_token": "invalid"}
    )
    assert missing_note.status_code == invalid_note.status_code == 403
    assert client.post("/export").status_code == 403
    note_id = create_note(client)
    missing_edit = client.post(f"/notes/{note_id}/edit", data={"title": "edit", "body": "edit"})
    invalid_edit = client.post(
        f"/notes/{note_id}/edit",
        data={"title": "edit", "body": "edit", "csrf_token": "invalid"},
    )
    assert missing_edit.status_code == invalid_edit.status_code == 403
    missing_delete = client.post(f"/notes/{note_id}/delete")
    invalid_delete = client.post(f"/notes/{note_id}/delete", data={"csrf_token": "invalid"})
    assert missing_delete.status_code == invalid_delete.status_code == 403
    assert client.post("/logout").status_code == 403
    assert client.post("/logout", data={"csrf_token": "invalid"}).status_code == 403


def test_normal_user_is_denied_admin_route_and_admin_is_allowed(
    client: TestClient, app: FastAPI
) -> None:
    register_and_login(client)
    denied = client.get("/admin/audit-summary")
    assert denied.status_code == 403
    assert "not permitted" in denied.text
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "alice"))
        assert user is not None
        user.role = "admin"
        db.commit()

    allowed = client.get("/admin/audit-summary")
    assert allowed.status_code == 200
    assert "Administrative audit summary" in allowed.text
    with app.state.session_factory() as db:
        denied_event = db.scalar(
            select(AuditEvent).where(AuditEvent.event_type == "admin.access_denied")
        )
        allowed_event = db.scalar(
            select(AuditEvent).where(AuditEvent.event_type == "admin.access_succeeded")
        )
        assert denied_event is not None
        assert denied_event.outcome == "denied"
        assert allowed_event is not None
        assert allowed_event.outcome == "success"
        assert allowed_event.actor_user_id == denied_event.actor_user_id
        assert allowed_event.target_type == "admin_route"
        assert allowed_event.target_id == "audit-summary"
        assert allowed_event.event_data == '{"role":"admin"}'


def test_authenticated_csrf_token_is_bound_to_its_own_session(app: FastAPI) -> None:
    with (
        TestClient(
            app, base_url="https://testserver", raise_server_exceptions=False
        ) as first_client,
        TestClient(
            app, base_url="https://testserver", raise_server_exceptions=False
        ) as second_client,
    ):
        register_and_login(first_client)
        login(second_client)
        first_session = first_client.cookies.get("notes_session")
        second_csrf = csrf(second_client)
        assert first_session

        with TestClient(
            app, base_url="https://testserver", raise_server_exceptions=False
        ) as forged_client:
            forged_client.cookies.set("notes_session", first_session)
            forged_client.cookies.set("notes_csrf", second_csrf)
            rejected = forged_client.post(
                "/notes",
                data={"title": "forged", "body": "forged", "csrf_token": second_csrf},
            )
            assert rejected.status_code == 403
    with app.state.session_factory() as db:
        assert db.scalar(select(func.count(Note.id))) == 0


def test_note_plaintext_is_absent_from_sqlite_file(
    client: TestClient, database_path, app: FastAPI
) -> None:
    register_and_login(client)
    title = "PLAINTEXT-TITLE-8a4b2613"
    body = "PLAINTEXT-BODY-fda83bb9"
    create_note(client, title, body)
    app.state.engine.dispose()
    database_bytes = database_path.read_bytes()
    assert title.encode() not in database_bytes
    assert body.encode() not in database_bytes


def test_audit_records_exclude_passwords_notes_tokens_and_csrf(
    client: TestClient, app: FastAPI
) -> None:
    register_and_login(client)
    note_title = "audit-secret-title"
    note_body = "audit-secret-body"
    create_note(client, note_title, note_body)
    client.post("/export", data={"csrf_token": csrf(client)})
    session_token = client.cookies.get("notes_session")
    csrf_token = csrf(client)

    with app.state.session_factory() as db:
        events = db.scalars(select(AuditEvent)).all()
        serialized = "\n".join(
            "|".join(
                [
                    event.event_type,
                    event.outcome,
                    event.target_type or "",
                    event.target_id or "",
                    event.event_data,
                    event.client_address_hash,
                ]
            )
            for event in events
        )
    for secret in (TEST_PASSWORD, note_title, note_body, session_token, csrf_token):
        assert secret
        assert secret not in serialized


def test_required_security_events_are_recorded_end_to_end(client: TestClient, app: FastAPI) -> None:
    register(client)
    client.get("/login")
    failed = client.post(
        "/login",
        data={"username": "alice", "password": "wrong password", "csrf_token": csrf(client)},
    )
    assert failed.status_code == 401
    login(client)
    note_id = create_note(client)
    updated = client.post(
        f"/notes/{note_id}/edit",
        data={"title": "updated", "body": "updated", "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert updated.status_code == 303
    assert client.post("/export", data={"csrf_token": csrf(client)}).status_code == 200
    assert client.get("/admin/audit-summary").status_code == 403
    deleted = client.post(
        f"/notes/{note_id}/delete",
        data={"csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert (
        client.post(
            "/logout", data={"csrf_token": csrf(client)}, follow_redirects=False
        ).status_code
        == 303
    )

    with app.state.session_factory() as db:
        event_types = {event.event_type for event in db.scalars(select(AuditEvent)).all()}
    assert {
        "login.failed",
        "login.succeeded",
        "logout.succeeded",
        "note.created",
        "note.updated",
        "note.deleted",
        "notes.exported",
        "admin.access_denied",
    }.issubset(event_types)


def test_corrupted_ciphertext_returns_generic_correlated_error(
    client: TestClient, app: FastAPI
) -> None:
    register_and_login(client)
    note_id = create_note(client)
    with app.state.session_factory() as db:
        note = db.scalar(select(Note).where(Note.public_id == note_id))
        assert note is not None
        note.body_ciphertext = b"invalid ciphertext"
        db.commit()

    response = client.get(f"/notes/{note_id}")
    assert response.status_code == 500
    assert "request could not be completed" in response.text.lower()
    assert "InvalidTag" not in response.text
    assert "Traceback" not in response.text
    assert "SELECT" not in response.text
    assert response.headers["x-correlation-id"] in response.text


def test_internal_exception_logging_omits_attacker_controlled_message(
    client: TestClient, app: FastAPI, caplog
) -> None:
    register_and_login(client)
    note_id = create_note(client)
    secret = "ATTACKER-CONTROLLED-LOG-SENTINEL"

    class ExplodingCipher:
        def decrypt(self, *_args, **_kwargs):
            raise RuntimeError(secret)

    app.state.note_cipher = ExplodingCipher()
    caplog.set_level(logging.ERROR)
    response = client.get(f"/notes/{note_id}")
    assert response.status_code == 500
    assert secret not in response.text
    assert secret not in caplog.text
    assert "RuntimeError" in caplog.text
    assert response.headers["x-correlation-id"] in caplog.text


def test_security_headers_and_cookie_attributes_are_present(client: TestClient) -> None:
    register_and_login(client)
    response = client.get("/notes")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-correlation-id"]

    login_page = client.get("/login")
    raw_cookie_headers = login_page.headers.get_list("set-cookie")
    csrf_cookie = next(value for value in raw_cookie_headers if value.startswith("notes_csrf="))
    assert "HttpOnly" in csrf_cookie
    assert "Secure" in csrf_cookie
    assert "SameSite=lax" in csrf_cookie
    assert login_page.headers["strict-transport-security"].startswith("max-age=")


def test_production_session_and_csrf_cookies_require_https(settings, clock: FakeClock) -> None:
    production_app = create_app(replace(settings, environment="production"), clock=clock)
    try:
        with TestClient(
            production_app,
            base_url="https://testserver",
            raise_server_exceptions=False,
        ) as production_client:
            register(production_client)
            production_client.get("/login")
            response = production_client.post(
                "/login",
                data={
                    "username": "alice",
                    "password": TEST_PASSWORD,
                    "csrf_token": csrf(production_client),
                },
                follow_redirects=False,
            )
            cookies = response.headers.get_list("set-cookie")
            session_cookie = next(value for value in cookies if value.startswith("notes_session="))
            csrf_cookie = next(value for value in cookies if value.startswith("notes_csrf="))
            assert "Secure" in session_cookie and "HttpOnly" in session_cookie
            assert "Secure" in csrf_cookie and "HttpOnly" in csrf_cookie
            assert response.headers["strict-transport-security"].startswith("max-age=")
    finally:
        production_app.state.engine.dispose()


def test_database_contains_session_hash_but_not_raw_cookie(
    client: TestClient, app: FastAPI, database_path
) -> None:
    register_and_login(client)
    raw_token = client.cookies.get("notes_session")
    assert raw_token
    with app.state.session_factory() as db:
        record = db.scalar(select(UserSession))
        assert record is not None
        assert len(record.token_hash) == 32
    app.state.engine.dispose()
    assert raw_token.encode() not in database_path.read_bytes()
