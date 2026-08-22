from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from urllib.parse import urlencode

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select

from notes_app.config import Settings
from notes_app.main import CappedRequestBodyMiddleware, RequestBodyTooLarge, create_app
from notes_app.models import Note, User
from tests.app.conftest import (
    FakeClock,
    create_note,
    csrf,
    login,
    register_and_login,
)


def test_user_can_create_read_update_and_delete_own_note(client: TestClient) -> None:
    register_and_login(client)
    note_id = create_note(client, "Initial title", "Initial body")

    read = client.get(f"/notes/{note_id}")
    assert read.status_code == 200
    assert "Initial title" in read.text
    assert "Initial body" in read.text
    update = client.post(
        f"/notes/{note_id}/edit",
        data={"title": "Updated title", "body": "Updated body", "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert update.status_code == 303
    updated = client.get(f"/notes/{note_id}")
    assert "Updated title" in updated.text
    assert "Updated body" in updated.text
    confirmation = client.get(f"/notes/{note_id}/delete")
    assert confirmation.status_code == 200
    assert "Delete “Updated title”?" in confirmation.text
    deleted = client.post(
        f"/notes/{note_id}/delete",
        data={"csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert client.get(f"/notes/{note_id}").status_code == 404


def test_owner_scope_blocks_cross_user_read_update_delete_and_export(
    app: FastAPI,
) -> None:
    with TestClient(
        app, base_url="https://testserver", raise_server_exceptions=False
    ) as alice_client:
        register_and_login(alice_client, "alice")
        note_id = create_note(alice_client, "Alice secret title", "Alice secret body")

    with TestClient(
        app, base_url="https://testserver", raise_server_exceptions=False
    ) as bob_client:
        register_and_login(bob_client, "bob")
        bob_list = bob_client.get("/notes")
        assert bob_list.status_code == 200
        assert "Alice secret title" not in bob_list.text
        assert "Alice secret body" not in bob_list.text
        assert bob_client.get(f"/notes/{note_id}").status_code == 404
        assert bob_client.get(f"/notes/{note_id}/edit").status_code == 404
        update = bob_client.post(
            f"/notes/{note_id}/edit",
            data={"title": "stolen", "body": "stolen", "csrf_token": csrf(bob_client)},
        )
        assert update.status_code == 404
        assert bob_client.get(f"/notes/{note_id}/delete").status_code == 404
        deletion = bob_client.post(
            f"/notes/{note_id}/delete",
            data={"csrf_token": csrf(bob_client)},
        )
        assert deletion.status_code == 404
        exported = bob_client.post("/export", data={"csrf_token": csrf(bob_client)})
        assert exported.status_code == 200
        assert exported.json()["notes"] == []
        assert "Alice secret" not in exported.text

    with app.state.session_factory() as db:
        alice = db.scalar(select(User).where(User.username == "alice"))
        assert alice is not None
        note = db.scalar(select(Note).where(Note.public_id == note_id, Note.owner_id == alice.id))
        assert note is not None


def test_note_input_limits_quota_and_pagination(client: TestClient, clock: FakeClock) -> None:
    register_and_login(client)
    too_long_title = client.post(
        "/notes",
        data={"title": "x" * 41, "body": "body", "csrf_token": csrf(client)},
    )
    assert too_long_title.status_code == 400
    assert "at most 40 characters" in too_long_title.text
    too_long_body = client.post(
        "/notes",
        data={"title": "valid", "body": "x" * 257, "csrf_token": csrf(client)},
    )
    assert too_long_body.status_code == 400
    assert "at most 256 characters" in too_long_body.text

    create_note(client, "One", "body one")
    clock.advance(seconds=1)
    create_note(client, "Two", "body two")
    page_one = client.get("/notes?page=1")
    page_two = client.get("/notes?page=2")
    assert "Two" in page_one.text and "One" not in page_one.text
    assert "One" in page_two.text and "Two" not in page_two.text
    over_quota = client.post(
        "/notes",
        data={"title": "Three", "body": "body three", "csrf_token": csrf(client)},
    )
    assert over_quota.status_code == 409
    assert "note limit has been reached" in over_quota.text


def test_request_body_size_limit_is_enforced_before_form_processing(client: TestClient) -> None:
    register_and_login(client)
    response = client.post(
        "/notes",
        data={"title": "large", "body": "z" * 3_000, "csrf_token": csrf(client)},
    )
    assert response.status_code == 413
    assert "request is too large" in response.text


def test_chunked_request_without_content_length_is_rejected_before_database_work(
    client: TestClient, app: FastAPI
) -> None:
    register_and_login(client)
    encoded = urlencode(
        {"title": "chunked", "body": "z" * 3_000, "csrf_token": csrf(client)}
    ).encode()

    def body_chunks():
        for offset in range(0, len(encoded), 127):
            yield encoded[offset : offset + 127]

    response = client.post(
        "/notes",
        content=body_chunks(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 413
    with app.state.session_factory() as db:
        assert db.scalar(select(func.count(Note.id))) == 0


def test_capped_receive_stops_consuming_chunks_at_the_boundary() -> None:
    receive_calls = 0
    chunks = iter(
        [
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"456", "more_body": True},
        ]
    )

    async def receive():
        nonlocal receive_calls
        receive_calls += 1
        if receive_calls > 2:
            raise AssertionError("middleware consumed a chunk after exceeding the limit")
        return next(chunks)

    async def downstream(_scope, downstream_receive, _send):
        while True:
            message = await downstream_receive()
            if not message.get("more_body", False):
                return

    async def scenario() -> None:
        middleware = CappedRequestBodyMiddleware(downstream, max_bytes=5)
        with pytest.raises(RequestBodyTooLarge):
            await middleware(
                {"type": "http", "method": "POST", "path": "/", "headers": []},
                receive,
                lambda _message: None,
            )

    asyncio.run(scenario())
    assert receive_calls == 2


def test_single_process_quota_check_is_serialized_for_concurrent_creates(
    settings: Settings, clock: FakeClock
) -> None:
    application = create_app(replace(settings, max_notes_per_user=1), clock=clock)
    barrier = threading.Barrier(2)
    try:
        with (
            TestClient(
                application, base_url="https://testserver", raise_server_exceptions=False
            ) as first_client,
            TestClient(
                application, base_url="https://testserver", raise_server_exceptions=False
            ) as second_client,
        ):
            register_and_login(first_client)
            login(second_client)

            def submit(client: TestClient, title: str) -> int:
                barrier.wait()
                return client.post(
                    "/notes",
                    data={"title": title, "body": title, "csrf_token": csrf(client)},
                    follow_redirects=False,
                ).status_code

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(submit, first_client, "first"),
                    executor.submit(submit, second_client, "second"),
                ]
                statuses = sorted(future.result(timeout=10) for future in futures)
            assert statuses == [303, 409]
            with application.state.session_factory() as db:
                assert db.scalar(select(func.count(Note.id))) == 1
    finally:
        application.state.engine.dispose()


def test_xss_payload_is_escaped_in_title_and_body(client: TestClient) -> None:
    register_and_login(client)
    payload = '<script>alert("owned")</script>'
    note_id = create_note(client, payload, payload)
    response = client.get(f"/notes/{note_id}")
    assert response.status_code == 200
    assert payload not in response.text
    assert "&lt;script&gt;alert" in response.text
    assert "script-src &#39;none&#39;" not in response.text


def test_sql_injection_shaped_values_are_stored_as_note_data(client: TestClient) -> None:
    register_and_login(client)
    title = "'; DROP TABLE users; --"
    body = "1 OR 1=1; SELECT * FROM notes"
    note_id = create_note(client, title, body)
    response = client.get(f"/notes/{note_id}")
    assert response.status_code == 200
    assert "DROP TABLE users" in response.text
    assert "SELECT * FROM notes" in response.text
    assert client.get("/notes").status_code == 200


def test_export_returns_only_current_users_decrypted_notes(client: TestClient) -> None:
    register_and_login(client)
    note_id = create_note(client, "Export title", "Export body")
    response = client.post("/export", data={"csrf_token": csrf(client)})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"] == "attachment; filename=notes-export.json"
    payload = response.json()
    assert payload["schema_version"] == "1.0"
    assert payload["notes"] == [
        {
            "id": note_id,
            "title": "Export title",
            "body": "Export body",
            "created_at": "2026-01-02T03:04:05Z",
            "updated_at": "2026-01-02T03:04:05Z",
        }
    ]


def test_update_and_delete_sql_include_owner_predicate(client: TestClient, app: FastAPI) -> None:
    register_and_login(client)
    note_id = create_note(client)
    statements: list[str] = []

    def capture_statement(
        _connection, _cursor, statement: str, _parameters, _context, _executemany
    ) -> None:  # type: ignore[no-untyped-def]
        statements.append(statement)

    event.listen(app.state.engine, "before_cursor_execute", capture_statement)
    try:
        edited = client.post(
            f"/notes/{note_id}/edit",
            data={"title": "changed", "body": "changed", "csrf_token": csrf(client)},
            follow_redirects=False,
        )
        deleted = client.post(
            f"/notes/{note_id}/delete",
            data={"csrf_token": csrf(client)},
            follow_redirects=False,
        )
    finally:
        event.remove(app.state.engine, "before_cursor_execute", capture_statement)

    assert edited.status_code == deleted.status_code == 303
    update_sql = next(item for item in statements if item.startswith("UPDATE notes"))
    delete_sql = next(item for item in statements if item.startswith("DELETE FROM notes"))
    assert "notes.public_id" in update_sql and "notes.owner_id" in update_sql
    assert "notes.public_id" in delete_sql and "notes.owner_id" in delete_sql
