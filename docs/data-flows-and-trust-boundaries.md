# Data Flows and Trust Boundaries

## Scope

The portfolio separates three kinds of material:

- `original_evidence/` contains curated, byte-identical files from the supplied 2025 archive.
- `src/threat_analyzer/` is a modernized utility for evidence-aware sequence-diagram analysis.
- `src/notes_app/` is a newly created local reference application that demonstrates selected controls.

The two runtime components do not depend on the historical code. The analyzer reads text models and JSON configuration; the notes application handles browser requests and a local database.

## System context

The source diagram is [`diagrams/system-context.puml`](diagrams/system-context.puml). It shows the seven boundaries used throughout the threat model:

| Boundary | Less-trusted side | More-trusted side | Required checks |
|---|---|---|---|
| Browser to application | HTTP client, headers, cookies, paths, bodies, timing | FastAPI request handlers | Body and field limits, parsing, authentication, CSRF, authorization, escaping, generic errors |
| Authentication/session | Anonymous or invalid token | Authenticated server-side session | Password verification, attempt controls, opaque-token hash lookup, revocation and expiry |
| Application to database | Application queries and transaction inputs | Persistent account, session, note, and audit records | Bound parameters, owner scoping, transactions, encrypted note fields, restrictive file access |
| Application to key source | Runtime configuration | AES-GCM key material | Exact decoding and length validation, no fallback production key, no database persistence |
| User to administrator | Normal authenticated account | Narrow administrative capability | Server-side role load and enforcement, audit of denial and success |
| Application to future adapters | Internal audit/notification event | External service | Explicit minimized schema, authentication, failure isolation; not implemented here |
| Development to deployed runtime | Test keys, test DBs, local cookie relaxation | Deployed process | Explicit production mode and `Secure` cookies for non-loopback use, protected configuration, no seeded secrets |

## Notes application flows

### Registration

1. The browser receives a form containing a cryptographically random pre-authentication CSRF value.
2. The browser submits identity and password fields with that value.
3. The application enforces the request-size and field policy, normalizes the identity, and checks uniqueness.
4. The password is converted to an Argon2id hash. The plaintext is not written to the database, application log, or audit record.
5. The account and a metadata-only audit event are committed.
6. The browser receives a bounded validation or neutral conflict response, or a redirect after successful creation. Registration does not confer an administrator role through a client field.

The public registration endpoint is a resource-amplification surface because Argon2 hashing is deliberately expensive. Edge controls are needed for an internet deployment.

### Login and session creation

1. Account and client-address attempt state is checked before expensive verification when safe to do so.
2. The application obtains the account record by normalized identity. An unknown account follows a dummy Argon2 verification path so the external behavior is less useful for enumeration.
3. A failed attempt updates bounded failure state and records a metadata-only audit event. Reaching the configured threshold creates a temporary lockout.
4. A successful login clears applicable failure state and creates fresh random session and CSRF material.
5. Only hashes of the session and CSRF values are persisted with creation time, last-seen time, absolute expiry, and revocation state. Idle expiry is derived during validation from the stored last-seen time and configured idle interval.
6. The raw session token is returned only in an `HttpOnly`, `SameSite=Lax` cookie. Session and CSRF cookies are `Secure` in production mode; development and test modes omit that flag. `NOTES_ENV` defaults to development, and the default loopback binding can be overridden with `--host`, so non-loopback use must explicitly select production mode and HTTPS.

The implementation uses opaque sessions because a single local service can check revocation directly. JWTs would add key, rotation, audience, algorithm, and revocation complexity without a demonstrated benefit here.

### Session validation and logout

Each protected request hashes the cookie and loads the session, account, and role from server-side state. Missing, malformed, revoked, idle-expired, or absolute-expired sessions are rejected before a data operation. Activity updates do not extend the absolute deadline. Logout is a state-changing POST: it requires CSRF validation, marks the server-side session revoked, records an audit event, and expires the browser cookie.

### CSRF validation

Public registration and login forms validate a signed random double-submit value shared by the form and cookie. Authenticated state-changing browser routes additionally compare the submitted token with the hash bound to the current session using constant-time comparison semantics. SameSite cookies are supporting browser policy, not the primary check. GET is not used for deletion or other destructive actions.

### Note creation and update

1. Authentication and CSRF validation run before mutation.
2. Request, title, and body sizes are bounded; creation also checks the per-user note quota.
3. A new public UUID is generated by the server. Updates query by both the UUID and authenticated owner ID.
4. The configured 32-byte key is loaded and validated.
5. Title and body are separately encrypted with AES-GCM and unique nonces. Authenticated additional data binds owner ID, note UUID, field name, and key version.
6. Ciphertext, nonce, key version, and non-sensitive timestamps are committed with a metadata-only audit event.
7. Decrypted content is placed only in an autoescaped server-rendered template.

AES-GCM protects content stored in the database file when the key remains separate. It does not conceal record counts, owners, timestamps, approximate lengths, or access patterns.

### Note list and read

Listing uses an owner-constrained, ordered, paginated query. Only the selected page is decrypted. Reading one note uses a query whose predicate includes both its public UUID and authenticated owner. The application does not fetch a foreign note and decide in the browser whether to hide it. Missing and foreign identifiers follow the same external not-found behavior.

### Delete

The UI presents a confirmation step, then submits a CSRF-protected POST. The delete query or prior lookup is owner-scoped. The audit record identifies the operation and target public ID but never stores deleted content. SQLite and backup erasure semantics are outside the demonstration; deletion is logical application removal, not verified forensic erasure.

### Export

Export requires a current session and is limited to owner-scoped rows. The response is a defined JSON download containing decrypted data for the requester. The application records an export event without the exported content. After download, confidentiality depends on the browser, endpoint, and user storage; the application cannot revoke an existing copy.

### Administrative route

The route first authenticates the session and then compares the server-side account role with the required administrator role. Hiding the navigation link is not an authorization control. Denied access and successful administrative access are audit events. The route is intentionally narrow and does not claim user provisioning, role-management, or global note-reading functionality.

### Error and audit flow

Unhandled failures receive a correlation identifier. The browser receives a generic response without a stack trace, SQL detail, filesystem path, or cryptographic detail. Internal diagnostics may include the correlation identifier and exception class, but not request secrets or note content. Audit event fields are constrained to action, outcome, actor/target metadata, timing, correlation data, and a minimized client address where used.

## Threat analyzer flow

1. A `pathlib.Path` is constructed from the caller's spelling, its exact bytes are read and hashed, and those bytes are decoded as UTF-8. The path is not canonicalized with `Path.resolve()`.
2. The parser processes a declared PlantUML subset line by line, collecting actors, participants, interactions, sections, source line numbers, and warnings for unsupported constructs.
3. The rule loader validates schema version, stable identifiers, categories, threat-register references, contextual selectors, and qualitative risk values.
4. Evaluation tests each interaction and its local context. A control mentioned on an unrelated flow cannot satisfy the evaluated interaction.
5. Findings retain the rule ID, modern threat ID, exact interaction evidence, and a `diagram-indicator` evidence basis.
6. The qualitative likelihood-impact matrix determines severity. Ordering is stable and no rank is forced to a severity.
7. JSON serialization uses a documented schema version and deterministic key and item order. HTML rendering escapes every untrusted field.

The parser does not execute diagram content, invoke PlantUML, upload text, or contact a rendering server. Unsupported syntax is reported rather than silently reinterpreted.

### Supported PlantUML subset

The modern parser recognizes `@startuml`/`@enduml`; single-line titles; `actor`, `participant`, `boundary`, `control`, `entity`, `database`, `collections`, and `queue` declarations; named `== section ==` dividers; common forward and reverse request/response arrows with a message; single-line and block notes; apostrophe comments; and `alt`, `opt`, `loop`, `group`, `par`, `critical`, and `break` blocks with `else`/`end`. Harmless presentation directives such as activate/deactivate, create/destroy, autonumber, newpage, skin parameters, scale, single-line header/footer, and hide-footbox are acknowledged but do not change the analysis model.

Aliases use the parser's documented restricted identifier syntax. Full PlantUML features, includes, macros, styling semantics, component diagrams, and executable rendering are not supported. Non-empty input outside this subset produces a line-numbered warning; malformed open blocks and notes produce explicit closure warnings.

## Historical architecture corrections

The original broad sequence diagram placed several tools in the normal note-content path. The modern design makes these distinctions explicit:

- OWASP ZAP is an authorized out-of-band dynamic testing tool, not a runtime sanitizer and recipient of user notes.
- MISP/TAXII can enrich monitoring with threat intelligence; it is not a normal-content inspection service.
- Kafka and SIEM are possible operational transports, not implemented controls in this repository.
- OAuth/JWT is not inherently required for a compact same-origin demonstration; server-side opaque sessions provide direct revocation with fewer moving parts.
- External notification and monitoring integrations require real adapters, infrastructure, authentication, privacy review, failure handling, and tests before they can be claimed.

## Diagram availability

The repository retains PlantUML source so the architecture is reviewable without a renderer. If a local PlantUML executable is unavailable, the application and analyzer remain fully runnable; no generated diagram image is required.
