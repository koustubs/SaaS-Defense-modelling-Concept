"""FastAPI application factory for the secure notes demonstration."""

import json
import logging
import threading
import uuid
from _thread import LockType
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.templating import Jinja2Templates
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from notes_app.audit import record_event
from notes_app.config import Settings, project_root
from notes_app.crypto import (
    DataProtectionError,
    NoteCipher,
    new_signed_csrf,
    random_token,
    valid_signed_csrf,
)
from notes_app.database import create_database, get_db
from notes_app.models import AuditEvent, Note, User
from notes_app.security import (
    GENERIC_LOGIN_ERROR,
    AuthenticatedSession,
    authenticate_session,
    clear_account_throttle,
    create_session,
    csrf_is_valid,
    is_login_locked,
    normalize_username,
    password_hasher,
    password_policy_error,
    record_login_failure,
    revoke_session,
    throttle_keys,
    valid_username,
    verify_password,
)

LOGGER = logging.getLogger("notes_app")


def utc_now() -> datetime:
    """Return naive UTC for consistent SQLite storage and comparison."""
    return datetime.now(UTC).replace(tzinfo=None)


@dataclass(frozen=True, slots=True)
class DecryptedNote:
    public_id: str
    title: str
    body: str
    created_at: datetime
    updated_at: datetime


class RequestBodyTooLarge(RuntimeError):
    """Raised as soon as an unknown-length request crosses the configured limit."""


class CappedRequestBodyMiddleware:
    """Count ASGI request chunks without aggregating an unbounded request body."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        consumed = 0

        async def capped_receive() -> Message:
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > self.max_bytes:
                    # Do not request or retain later chunks after crossing the boundary.
                    raise RequestBodyTooLarge
            return message

        await self.app(scope, capped_receive, send)


def create_app(
    settings: Settings | None = None,
    *,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Build an isolated application instance.

    Passing settings and a clock makes security-boundary tests deterministic. If no
    settings are passed, required configuration is loaded from the environment.
    """
    settings = settings or Settings.from_env()
    root = project_root()
    template_dir = Path(settings.template_dir or root / "templates")
    static_dir = Path(settings.static_dir or root / "static")
    templates = Jinja2Templates(directory=str(template_dir))
    engine, session_factory = create_database(settings.database_url)
    hasher = password_hasher(settings)

    app = FastAPI(
        title="Secure Notes Demonstration",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        debug=False,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.password_hasher = hasher
    app.state.dummy_password_hash = hasher.hash(random_token())
    app.state.note_cipher = NoteCipher(settings.master_key)
    app.state.clock = clock or utc_now
    app.state.templates = templates
    # Fixed stripes avoid an attacker-controlled, ever-growing per-user lock registry.
    note_creation_locks = tuple(threading.Lock() for _ in range(64))
    app.state.note_creation_locks = note_creation_locks
    login_locks = tuple(threading.Lock() for _ in range(64))
    app.state.login_locks = login_locks
    app.add_middleware(CappedRequestBodyMiddleware, max_bytes=settings.max_request_bytes)

    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.middleware("http")
    async def security_envelope(request: Request, call_next: Callable) -> Response:
        request.state.correlation_id = str(uuid.uuid4())
        try:
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = settings.max_request_bytes + 1
                if declared_length > settings.max_request_bytes:
                    response = _generic_error(
                        templates, request, 413, "The submitted request is too large."
                    )
                    _apply_security_headers(response, request.state.correlation_id, settings)
                    return response
            response = await call_next(request)
        except RequestBodyTooLarge:
            response = _generic_error(
                templates, request, 413, "The submitted request is too large."
            )
        except Exception as exc:
            # This is the outer application safety boundary. It deliberately omits
            # exception messages and tracebacks because dependencies may include secrets.
            LOGGER.error(
                "Unhandled application error; correlation_id=%s; error=%s",
                request.state.correlation_id,
                type(exc).__name__,
            )
            response = _generic_error(
                templates, request, 500, "The request could not be completed."
            )
        _apply_security_headers(response, request.state.correlation_id, settings)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _exc: RequestValidationError) -> Response:
        return _generic_error(templates, request, 422, "The request could not be processed.")

    @app.exception_handler(DataProtectionError)
    async def data_protection_error(request: Request, exc: DataProtectionError) -> Response:
        LOGGER.error(
            "Encrypted data validation failed; correlation_id=%s; error=%s",
            request.state.correlation_id,
            type(exc).__name__,
        )
        return _generic_error(templates, request, 500, "The request could not be completed.")

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError) -> Response:
        LOGGER.error(
            "Database operation failed; correlation_id=%s; error=%s",
            request.state.correlation_id,
            type(exc).__name__,
        )
        return _generic_error(templates, request, 500, "The request could not be completed.")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if 300 <= exc.status_code < 400:
            return await http_exception_handler(request, exc)
        messages = {
            401: "Authentication is required.",
            403: "You are not permitted to access this resource.",
            404: "The requested resource was not found.",
            405: "This request method is not allowed.",
        }
        message = messages.get(exc.status_code, "The request could not be completed.")
        return _generic_error(templates, request, exc.status_code, message)

    def require_auth(
        request: Request,
        db: Annotated[Session, Depends(get_db)],
    ) -> AuthenticatedSession:
        authenticated = authenticate_session(
            db,
            settings,
            request.cookies.get(settings.cookie_name),
            app.state.clock(),
        )
        if authenticated is None:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        request.state.authenticated = authenticated
        return authenticated

    _register_public_routes(
        app,
        templates,
        settings,
        hasher,
        login_locks,
        note_creation_locks,
        require_auth,
    )
    return app


def _register_public_routes(
    app: FastAPI,
    templates: Jinja2Templates,
    settings: Settings,
    hasher: PasswordHasher,
    login_locks: tuple[LockType, ...],
    note_creation_locks: tuple[LockType, ...],
    require_auth: Callable[..., AuthenticatedSession],
) -> None:
    Db = Annotated[Session, Depends(get_db)]

    @app.get("/", response_class=HTMLResponse)
    def root_redirect() -> RedirectResponse:
        return RedirectResponse("/notes", status_code=303)

    @app.get("/register", response_class=HTMLResponse)
    def register_page(request: Request) -> Response:
        return _public_form_response(templates, request, settings, "register.html")

    @app.post("/register", response_class=HTMLResponse)
    async def register(request: Request, db: Db) -> Response:
        form = await request.form()
        csrf_token = _form_text(form, "csrf_token")
        csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
        if not csrf_is_valid(settings, None, csrf_cookie, csrf_token):
            raise HTTPException(status_code=403)
        username = normalize_username(_form_text(form, "username"))
        password = _form_text(form, "password")
        error: str | None = None
        if not valid_username(username):
            error = "Username must be 3–64 lowercase letters, digits, dots, dashes, or underscores."
        elif password_error := password_policy_error(password):
            error = password_error
        if error:
            return templates.TemplateResponse(
                request=request,
                name="register.html",
                context={"csrf_token": csrf_token, "error": error},
                status_code=400,
            )
        now = app.state.clock()
        if db.scalar(select(User.id).where(User.username == username)) is not None:
            return _registration_conflict(templates, request, db, now, csrf_token)
        user = User(
            public_id=str(uuid.uuid4()),
            username=username,
            password_hash=hasher.hash(password),
            role="user",
            created_at=now,
        )
        db.add(user)
        try:
            db.flush()
            record_event(
                db,
                request,
                now=now,
                event_type="account.registered",
                outcome="success",
                actor_user_id=user.id,
                target_type="account",
                target_id=user.public_id,
            )
            db.commit()
        except IntegrityError:
            db.rollback()
            return _registration_conflict(templates, request, db, now, csrf_token)
        return RedirectResponse("/login?registered=1", status_code=303)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, registered: bool = False) -> Response:
        return _public_form_response(
            templates,
            request,
            settings,
            "login.html",
            {"registered": registered},
        )

    @app.post("/login", response_class=HTMLResponse)
    async def login(request: Request, db: Db) -> Response:
        form = await request.form()
        csrf_token = _form_text(form, "csrf_token")
        csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
        if not csrf_is_valid(settings, None, csrf_cookie, csrf_token):
            raise HTTPException(status_code=403)
        username = normalize_username(_form_text(form, "username"))
        password = _form_text(form, "password")
        now = app.state.clock()
        keys = throttle_keys(request, username)
        lock_indexes = sorted(
            {
                int.from_bytes(identifier_hash[:4], "big") % len(login_locks)
                for _scope, identifier_hash in keys
            }
        )
        # Account and client-address stripes cover check, verification, and update.
        # Sorted acquisition prevents deadlocks for requests whose stripes overlap.
        with ExitStack() as lock_stack:
            for lock_index in lock_indexes:
                lock_stack.enter_context(login_locks[lock_index])
            locked = is_login_locked(db, keys, now)
            if locked:
                # Do not perform attacker-amplified Argon2 work during a lockout.
                user = None
                password_matches = False
            else:
                user = (
                    db.scalar(select(User).where(User.username == username)) if username else None
                )
                candidate_hash = user.password_hash if user else app.state.dummy_password_hash
                password_matches = verify_password(hasher, candidate_hash, password)
            if locked or user is None or not password_matches:
                if not locked:
                    record_login_failure(db, settings, keys, now)
                record_event(
                    db,
                    request,
                    now=now,
                    event_type="login.failed",
                    outcome="failure",
                    actor_user_id=user.id if user else None,
                    target_type="account",
                    target_id=user.public_id if user else None,
                    data={"reason": "rejected"},
                )
                db.commit()
                return templates.TemplateResponse(
                    request=request,
                    name="login.html",
                    context={"csrf_token": csrf_token, "error": GENERIC_LOGIN_ERROR},
                    status_code=401,
                )
            old_auth = authenticate_session(
                db,
                settings,
                request.cookies.get(settings.cookie_name),
                now,
                touch=False,
            )
            if old_auth:
                revoke_session(db, old_auth.record, now)
            clear_account_throttle(db, settings, username)
            _record, raw_token, authenticated_csrf = create_session(db, settings, user, now)
            record_event(
                db,
                request,
                now=now,
                event_type="login.succeeded",
                outcome="success",
                actor_user_id=user.id,
                target_type="session",
            )
            db.commit()
        response = RedirectResponse("/notes", status_code=303)
        _set_auth_cookies(response, settings, raw_token, authenticated_csrf)
        return response

    @app.post("/logout")
    async def logout(request: Request, db: Db) -> Response:
        form = await request.form()
        now = app.state.clock()
        authenticated = authenticate_session(
            db,
            settings,
            request.cookies.get(settings.cookie_name),
            now,
            touch=False,
        )
        csrf_token = _form_text(form, "csrf_token")
        csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
        if not csrf_is_valid(
            settings,
            authenticated.record if authenticated else None,
            csrf_cookie,
            csrf_token,
        ):
            raise HTTPException(status_code=403)
        if authenticated:
            revoke_session(db, authenticated.record, now)
            record_event(
                db,
                request,
                now=now,
                event_type="logout.succeeded",
                outcome="success",
                actor_user_id=authenticated.user.id,
                target_type="session",
            )
            db.commit()
        response = RedirectResponse("/login", status_code=303)
        _clear_auth_cookies(response, settings)
        return response

    _register_note_routes(app, templates, settings, note_creation_locks, require_auth)


def _register_note_routes(
    app: FastAPI,
    templates: Jinja2Templates,
    settings: Settings,
    note_creation_locks: tuple[LockType, ...],
    require_auth: Callable[..., AuthenticatedSession],
) -> None:
    Auth = Annotated[AuthenticatedSession, Depends(require_auth)]
    Db = Annotated[Session, Depends(get_db)]

    @app.get("/notes", response_class=HTMLResponse)
    def list_notes(
        request: Request,
        auth: Auth,
        db: Db,
        page: Annotated[int, Query(ge=1)] = 1,
    ) -> Response:
        total = db.scalar(select(func.count(Note.id)).where(Note.owner_id == auth.user.id)) or 0
        max_page = max(1, (total + settings.page_size - 1) // settings.page_size)
        page = min(page, max_page)
        note_rows = db.scalars(
            select(Note)
            .where(Note.owner_id == auth.user.id)
            .order_by(Note.updated_at.desc(), Note.public_id.asc())
            .offset((page - 1) * settings.page_size)
            .limit(settings.page_size)
        ).all()
        notes = [_decrypt_note(app.state.note_cipher, note) for note in note_rows]
        return templates.TemplateResponse(
            request=request,
            name="notes.html",
            context={
                "current_user": auth.user,
                "csrf_token": request.cookies.get(settings.csrf_cookie_name, ""),
                "notes": notes,
                "page": page,
                "max_page": max_page,
                "total": total,
            },
        )

    @app.get("/notes/new", response_class=HTMLResponse)
    def new_note_page(request: Request, auth: Auth) -> Response:
        return templates.TemplateResponse(
            request=request,
            name="note_form.html",
            context={
                "current_user": auth.user,
                "csrf_token": request.cookies.get(settings.csrf_cookie_name, ""),
                "note": None,
                "action": "/notes",
                "heading": "Create note",
                "limits": settings,
            },
        )

    @app.post("/notes", response_class=HTMLResponse)
    async def create_note(request: Request, auth: Auth, db: Db) -> Response:
        form = await request.form()
        _require_session_csrf(request, settings, auth, form)
        title = _form_text(form, "title")
        body = _form_text(form, "body")
        validation_error = _validate_note(title, body, settings)
        if validation_error:
            return templates.TemplateResponse(
                request=request,
                name="note_form.html",
                context={
                    "current_user": auth.user,
                    "csrf_token": _form_text(form, "csrf_token"),
                    "note": DecryptedNote("", title, body, app.state.clock(), app.state.clock()),
                    "action": "/notes",
                    "heading": "Create note",
                    "limits": settings,
                    "error": validation_error,
                },
                status_code=400,
            )
        # The demonstration is deliberately single-process. This stripe serializes the
        # count-and-insert sequence for a user inside that scope; a distributed deployment
        # needs a database constraint/transactional quota mechanism instead.
        creation_lock = note_creation_locks[auth.user.id % len(note_creation_locks)]
        with creation_lock:
            note_count = (
                db.scalar(select(func.count(Note.id)).where(Note.owner_id == auth.user.id)) or 0
            )
            if note_count >= settings.max_notes_per_user:
                return templates.TemplateResponse(
                    request=request,
                    name="note_form.html",
                    context={
                        "current_user": auth.user,
                        "csrf_token": _form_text(form, "csrf_token"),
                        "note": DecryptedNote(
                            "", title, body, app.state.clock(), app.state.clock()
                        ),
                        "action": "/notes",
                        "heading": "Create note",
                        "limits": settings,
                        "error": "The per-account note limit has been reached.",
                    },
                    status_code=409,
                )
            note_id = str(uuid.uuid4())
            title_nonce, title_ciphertext = app.state.note_cipher.encrypt(
                title, auth.user.id, note_id, "title"
            )
            body_nonce, body_ciphertext = app.state.note_cipher.encrypt(
                body, auth.user.id, note_id, "body"
            )
            now = app.state.clock()
            note = Note(
                public_id=note_id,
                owner_id=auth.user.id,
                title_nonce=title_nonce,
                title_ciphertext=title_ciphertext,
                body_nonce=body_nonce,
                body_ciphertext=body_ciphertext,
                key_version=app.state.note_cipher.key_version,
                created_at=now,
                updated_at=now,
            )
            db.add(note)
            record_event(
                db,
                request,
                now=now,
                event_type="note.created",
                outcome="success",
                actor_user_id=auth.user.id,
                target_type="note",
                target_id=note_id,
            )
            db.commit()
        return RedirectResponse(f"/notes/{note_id}", status_code=303)

    @app.get("/notes/{note_id}", response_class=HTMLResponse)
    def read_note(request: Request, note_id: str, auth: Auth, db: Db) -> Response:
        note = _owned_note(db, note_id, auth.user.id)
        if note is None:
            raise HTTPException(status_code=404)
        return templates.TemplateResponse(
            request=request,
            name="note_detail.html",
            context={
                "current_user": auth.user,
                "csrf_token": request.cookies.get(settings.csrf_cookie_name, ""),
                "note": _decrypt_note(app.state.note_cipher, note),
            },
        )

    @app.get("/notes/{note_id}/edit", response_class=HTMLResponse)
    def edit_note_page(request: Request, note_id: str, auth: Auth, db: Db) -> Response:
        note = _owned_note(db, note_id, auth.user.id)
        if note is None:
            raise HTTPException(status_code=404)
        return templates.TemplateResponse(
            request=request,
            name="note_form.html",
            context={
                "current_user": auth.user,
                "csrf_token": request.cookies.get(settings.csrf_cookie_name, ""),
                "note": _decrypt_note(app.state.note_cipher, note),
                "action": f"/notes/{note_id}/edit",
                "heading": "Edit note",
                "limits": settings,
            },
        )

    @app.post("/notes/{note_id}/edit", response_class=HTMLResponse)
    async def edit_note(request: Request, note_id: str, auth: Auth, db: Db) -> Response:
        form = await request.form()
        _require_session_csrf(request, settings, auth, form)
        note = _owned_note(db, note_id, auth.user.id)
        if note is None:
            raise HTTPException(status_code=404)
        title = _form_text(form, "title")
        body = _form_text(form, "body")
        validation_error = _validate_note(title, body, settings)
        if validation_error:
            decrypted = _decrypt_note(app.state.note_cipher, note)
            submitted = DecryptedNote(
                decrypted.public_id,
                title,
                body,
                decrypted.created_at,
                decrypted.updated_at,
            )
            return templates.TemplateResponse(
                request=request,
                name="note_form.html",
                context={
                    "current_user": auth.user,
                    "csrf_token": _form_text(form, "csrf_token"),
                    "note": submitted,
                    "action": f"/notes/{note_id}/edit",
                    "heading": "Edit note",
                    "limits": settings,
                    "error": validation_error,
                },
                status_code=400,
            )
        title_nonce, title_ciphertext = app.state.note_cipher.encrypt(
            title, auth.user.id, note_id, "title"
        )
        body_nonce, body_ciphertext = app.state.note_cipher.encrypt(
            body, auth.user.id, note_id, "body"
        )
        now = app.state.clock()
        updated = db.execute(
            update(Note)
            .where(Note.public_id == note_id, Note.owner_id == auth.user.id)
            .values(
                title_nonce=title_nonce,
                title_ciphertext=title_ciphertext,
                body_nonce=body_nonce,
                body_ciphertext=body_ciphertext,
                updated_at=now,
            )
        )
        if updated.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=404)
        record_event(
            db,
            request,
            now=now,
            event_type="note.updated",
            outcome="success",
            actor_user_id=auth.user.id,
            target_type="note",
            target_id=note_id,
        )
        db.commit()
        return RedirectResponse(f"/notes/{note_id}", status_code=303)

    _register_note_delete_export_routes(app, templates, settings, require_auth)


def _register_note_delete_export_routes(
    app: FastAPI,
    templates: Jinja2Templates,
    settings: Settings,
    require_auth: Callable[..., AuthenticatedSession],
) -> None:
    Auth = Annotated[AuthenticatedSession, Depends(require_auth)]
    Db = Annotated[Session, Depends(get_db)]

    @app.get("/notes/{note_id}/delete", response_class=HTMLResponse)
    def delete_note_page(request: Request, note_id: str, auth: Auth, db: Db) -> Response:
        note = _owned_note(db, note_id, auth.user.id)
        if note is None:
            raise HTTPException(status_code=404)
        return templates.TemplateResponse(
            request=request,
            name="delete_confirm.html",
            context={
                "current_user": auth.user,
                "csrf_token": request.cookies.get(settings.csrf_cookie_name, ""),
                "note": _decrypt_note(app.state.note_cipher, note),
            },
        )

    @app.post("/notes/{note_id}/delete")
    async def delete_note(request: Request, note_id: str, auth: Auth, db: Db) -> Response:
        form = await request.form()
        _require_session_csrf(request, settings, auth, form)
        if not _valid_note_id(note_id):
            raise HTTPException(status_code=404)
        deleted = db.execute(
            sa_delete(Note).where(Note.public_id == note_id, Note.owner_id == auth.user.id)
        )
        if deleted.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=404)
        now = app.state.clock()
        record_event(
            db,
            request,
            now=now,
            event_type="note.deleted",
            outcome="success",
            actor_user_id=auth.user.id,
            target_type="note",
            target_id=note_id,
        )
        db.commit()
        return RedirectResponse("/notes", status_code=303)

    @app.post("/export")
    async def export_notes(request: Request, auth: Auth, db: Db) -> Response:
        form = await request.form()
        _require_session_csrf(request, settings, auth, form)
        note_rows = db.scalars(
            select(Note)
            .where(Note.owner_id == auth.user.id)
            .order_by(Note.created_at.asc(), Note.public_id.asc())
        ).all()
        notes = [_decrypt_note(app.state.note_cipher, note) for note in note_rows]
        payload = {
            "schema_version": "1.0",
            "notes": [
                {
                    "id": note.public_id,
                    "title": note.title,
                    "body": note.body,
                    "created_at": note.created_at.isoformat() + "Z",
                    "updated_at": note.updated_at.isoformat() + "Z",
                }
                for note in notes
            ],
        }
        record_event(
            db,
            request,
            now=app.state.clock(),
            event_type="notes.exported",
            outcome="success",
            actor_user_id=auth.user.id,
            target_type="account",
            target_id=auth.user.public_id,
            data={"count": len(notes)},
        )
        db.commit()
        return Response(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=notes-export.json"},
        )

    _register_admin_route(app, templates, settings, require_auth)


def _register_admin_route(
    app: FastAPI,
    templates: Jinja2Templates,
    settings: Settings,
    require_auth: Callable[..., AuthenticatedSession],
) -> None:
    Auth = Annotated[AuthenticatedSession, Depends(require_auth)]
    Db = Annotated[Session, Depends(get_db)]

    @app.get("/admin/audit-summary", response_class=HTMLResponse)
    def admin_audit_summary(request: Request, auth: Auth, db: Db) -> Response:
        if auth.user.role != "admin":
            record_event(
                db,
                request,
                now=app.state.clock(),
                event_type="admin.access_denied",
                outcome="denied",
                actor_user_id=auth.user.id,
                target_type="admin_route",
                target_id="audit-summary",
                data={"role": auth.user.role},
            )
            db.commit()
            raise HTTPException(status_code=403)
        record_event(
            db,
            request,
            now=app.state.clock(),
            event_type="admin.access_succeeded",
            outcome="success",
            actor_user_id=auth.user.id,
            target_type="admin_route",
            target_id="audit-summary",
            data={"role": auth.user.role},
        )
        db.commit()
        user_count = db.scalar(select(func.count(User.id))) or 0
        note_count = db.scalar(select(func.count(Note.id))) or 0
        event_count = db.scalar(select(func.count(AuditEvent.id))) or 0
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={
                "current_user": auth.user,
                "csrf_token": request.cookies.get(settings.csrf_cookie_name, ""),
                "user_count": user_count,
                "note_count": note_count,
                "event_count": event_count,
            },
        )


def _registration_conflict(
    templates: Jinja2Templates,
    request: Request,
    db: Session,
    now: datetime,
    csrf_token: str,
) -> Response:
    record_event(
        db,
        request,
        now=now,
        event_type="account.registration_conflict",
        outcome="denied",
        target_type="account",
        data={"reason": "username_unavailable"},
    )
    db.commit()
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"csrf_token": csrf_token, "error": "That username is unavailable."},
        status_code=409,
    )


def _apply_security_headers(response: Response, correlation_id: str, settings: Settings) -> None:
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Correlation-ID"] = correlation_id
    if settings.secure_cookies:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"


def _generic_error(
    templates: Jinja2Templates,
    request: Request,
    status_code: int,
    message: str,
) -> Response:
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "status_code": status_code,
            "message": message,
            "correlation_id": request.state.correlation_id,
        },
        status_code=status_code,
    )


def _public_form_response(
    templates: Jinja2Templates,
    request: Request,
    settings: Settings,
    template_name: str,
    context: dict[str, object] | None = None,
) -> Response:
    csrf_token = request.cookies.get(settings.csrf_cookie_name)
    if not csrf_token or not valid_signed_csrf(settings.master_key, csrf_token):
        csrf_token = new_signed_csrf(settings.master_key)
    response = templates.TemplateResponse(
        request=request,
        name=template_name,
        context={"csrf_token": csrf_token, **(context or {})},
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )
    return response


def _set_auth_cookies(
    response: Response,
    settings: Settings,
    raw_token: str,
    csrf_token: str,
) -> None:
    cookie_options = {
        "httponly": True,
        "secure": settings.secure_cookies,
        "samesite": "lax",
        "path": "/",
        "max_age": settings.session_absolute_seconds,
    }
    response.set_cookie(settings.cookie_name, raw_token, **cookie_options)
    response.set_cookie(settings.csrf_cookie_name, csrf_token, **cookie_options)


def _clear_auth_cookies(response: Response, settings: Settings) -> None:
    response.delete_cookie(settings.cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")


def _form_text(form: object, key: str) -> str:
    value = form.get(key)  # type: ignore[attr-defined]
    return value if isinstance(value, str) else ""


def _require_session_csrf(
    request: Request,
    settings: Settings,
    auth: AuthenticatedSession,
    form: object,
) -> None:
    if not csrf_is_valid(
        settings,
        auth.record,
        request.cookies.get(settings.csrf_cookie_name),
        _form_text(form, "csrf_token"),
    ):
        raise HTTPException(status_code=403)


def _validate_note(title: str, body: str, settings: Settings) -> str | None:
    if not title.strip():
        return "A title is required."
    if len(title) > settings.max_title_chars:
        return f"Title must contain at most {settings.max_title_chars} characters."
    if len(body) > settings.max_note_chars:
        return f"Note body must contain at most {settings.max_note_chars} characters."
    return None


def _owned_note(db: Session, public_id: str, owner_id: int) -> Note | None:
    if not _valid_note_id(public_id):
        return None
    return db.scalar(select(Note).where(Note.public_id == public_id, Note.owner_id == owner_id))


def _valid_note_id(public_id: str) -> bool:
    try:
        uuid.UUID(public_id)
    except ValueError:
        return False
    return True


def _decrypt_note(cipher: NoteCipher, note: Note) -> DecryptedNote:
    return DecryptedNote(
        public_id=note.public_id,
        title=cipher.decrypt(
            note.title_nonce,
            note.title_ciphertext,
            note.owner_id,
            note.public_id,
            "title",
            note.key_version,
        ),
        body=cipher.decrypt(
            note.body_nonce,
            note.body_ciphertext,
            note.owner_id,
            note.public_id,
            "body",
            note.key_version,
        ),
        created_at=note.created_at,
        updated_at=note.updated_at,
    )
