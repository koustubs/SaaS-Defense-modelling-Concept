# Implementation Pseudocode

This document restates the modern threat analyzer and notes application as language-independent pseudocode. It is derived from the current implementation under `src/` and does not describe the preserved historical programs under `original_evidence/`.

“Security-failure behavior” describes the implemented fail-closed or warning behavior. It does not imply that every parser warning or diagram observation is a confirmed vulnerability. Analyzer output uses the repository terms “diagram observation,” `Needs validation`, and `diagram-indicator`; likelihood, impact, and severity belong to the modern threat register rather than unvalidated observations.

## Threat analyzer

### 1. PlantUML parsing

| Field | Implementation |
|---|---|
| Inputs | A filesystem path containing PlantUML text, or an in-memory text string with an optional source label. |
| Preconditions | File input must be readable and valid UTF-8. Only the documented supported PlantUML sequence subset is interpreted. |
| Decisions | Each non-empty line is classified in order as a diagram marker, title, participant declaration, numbered section occurrence, interaction, note, comment, control-block marker, supported non-semantic directive, or unsupported syntax. |
| Security-failure behavior | File or decoding failure raises a typed read error. Recoverable structural and unsupported-syntax conditions become parser warnings. A duplicate alias does not replace the first declaration. Unsupported directives are not executed or fetched. |
| Outputs | A diagram containing source identity, exact source SHA-256, title, participants, interactions, numbered section occurrences, annotations, open-block context, and parser warnings. |
| Related threat IDs | AN-001, AN-003, AN-005; the retained context also supports evaluation of the configured `TM-*` rules. |
| Implementation | [`parser.py`](../src/threat_analyzer/parser.py), [`models.py`](../src/threat_analyzer/models.py), and [`exceptions.py`](../src/threat_analyzer/exceptions.py) |

```text
ALGORITHM ParseSequenceDiagram(input, optional source label)
    IF input identifies a file THEN
        READ the exact file bytes
        IF the bytes cannot be read or decoded as UTF-8 THEN
            RAISE a typed diagram-read error
        END IF
        SET text to the decoded bytes
        SET source digest to SHA-256 of the exact bytes
    ELSE
        SET text to the supplied string
        SET source digest to SHA-256 of its UTF-8 encoding
    END IF

    INITIALIZE ordered participants, interactions, sections, annotations, and warnings
    INITIALIZE an empty declared-alias set and open-control-block stack
    INITIALIZE current section occurrence and start/end marker flags

    FOR each source line in order
        IGNORE blank lines

        IF the line starts the diagram THEN
            WARN if a start marker was already seen
            MARK the start marker as seen
        ELSE IF the line ends the diagram THEN
            MARK the end marker as seen
        ELSE IF the line declares a title THEN
            STORE the title
        ELSE IF the line declares a supported participant kind THEN
            DERIVE its display name and alias
            IF the alias was already declared THEN
                WARN and retain the first declaration
            ELSE
                STORE actor declarations as actors
                STORE other supported declarations as system participants
            END IF
        ELSE IF the line starts a section THEN
            CREATE the next numbered section occurrence
            SET it as the current section occurrence
        ELSE IF the line is a supported interaction THEN
            NORMALIZE a reverse arrow to the actual sender and receiver
            CLASSIFY dashed arrows as responses and other arrows as requests
            STORE its line, sequence number, section occurrence, and open blocks
            WARN for every endpoint whose alias was not declared
        ELSE IF the line is a single-line or block note THEN
            STORE its text, explicit participant targets, current section,
                and most recent interaction number
            WARN if a block note has no closing marker
        ELSE IF the line is a comment THEN
            STORE it as an annotation in the current interaction context
        ELSE IF the line opens a supported control block THEN
            PUSH its kind, label, and line onto the block stack
        ELSE IF the line starts an alternative branch THEN
            WARN if no control block is open
        ELSE IF the line closes a control block THEN
            POP one block, or WARN if no block is open
        ELSE IF the line is a supported non-semantic directive THEN
            IGNORE it
        ELSE
            WARN that the line is outside the supported subset
        END IF
    END FOR

    WARN if the start marker or end marker is missing
    WARN for every control block still open
    RETURN the ordered diagram and warnings
END ALGORITHM
```

### 2. Context-aware threat-rule evaluation

| Field | Implementation |
|---|---|
| Inputs | A parsed diagram, strictly validated rule set, and strictly validated modern threat register. |
| Preconditions | Rule IDs are unique and agree with their embedded threat IDs; detector/scope combinations are valid; every referenced threat ID exists in the register. |
| Decisions | An `explicit_evidence` rule matches configured terms directly. A `missing_contextual_control` rule emits evidence only when a trigger term exists and no non-negated control qualifies within the configured attached, same-section, connected-section, or prior-only scope. |
| Security-failure behavior | A rule/register mismatch raises an analysis-configuration error. A control in another section occurrence, later than a prior-only trigger, in another actor-initiated flow, disconnected from the trigger, explicitly negated, or targeted at unrelated participants does not suppress an observation. Diagram absence is described as a review signal rather than implementation proof. |
| Outputs | Stable, deduplicated, severity-free observations ordered by threat ID, rule ID, and observation ID, with line-level evidence and status `Needs validation`. |
| Related threat IDs | AN-001 and AN-002. Current rules target TM-001, TM-002, TM-003, TM-004, TM-005, TM-006, TM-009, TM-010, TM-014, and TM-017. |
| Implementation | [`evaluator.py`](../src/threat_analyzer/evaluator.py), [`rules.py`](../src/threat_analyzer/rules.py), and [`threat_rules.json`](../config/threat_rules.json) |

```text
ALGORITHM EvaluateThreatRules(diagram, rule set, threat register)
    INDEX register entries by threat ID
    IF any rule references an absent register entry THEN
        RAISE an analysis-configuration error
    END IF

    FOR each rule in stable rule-ID order
        IF rule detector is explicit evidence THEN
            FIND case-insensitive match terms in interaction messages and annotations
            CREATE line-level evidence for every match
        ELSE
            FOR each interaction containing a trigger term
                SET control found to FALSE

                IF the trigger message contains a non-negated control term THEN
                    SET control found to TRUE
                END IF

                CHECK annotations attached to the trigger
                IGNORE a targeted annotation unless it names a trigger endpoint
                IF an applicable annotation contains a non-negated control term THEN
                    SET control found to TRUE
                END IF

                IF control is still absent and scope is wider than attached THEN
                    CONSIDER only the same numbered section occurrence
                    EXCLUDE later candidates when the scope is prior-only

                    IF connected context is required THEN
                        NUMBER actor-initiated flows within the section occurrence
                        START a new flow at each request sent by a declared actor
                        REQUIRE candidate and trigger to have the same flow number
                        BUILD an undirected participant graph for that flow
                        REQUIRE a participant path between candidate and trigger
                    END IF

                    ACCEPT only candidate interactions with non-negated control terms
                    ACCEPT a candidate annotation only when its target and attached
                        interaction satisfy the same time, section, flow, and path scope
                END IF

                IF no qualifying control was found THEN
                    CREATE trigger evidence stating that diagram absence is a review signal
                END IF
            END FOR
        END IF

        DEDUPLICATE evidence by line, interaction number, and excerpt
        SORT evidence by line, interaction number, and excerpt

        IF evidence remains THEN
            CREATE a stable observation ID from the rule ID
            COPY only classification from the referenced register entry
            SET status to Needs validation
            SET evidence basis to diagram-indicator
            DO NOT assign likelihood, impact, or severity
        END IF
    END FOR

    SORT and RETURN the observations
END ALGORITHM
```

### 3. Qualitative risk calculation

| Field | Implementation |
|---|---|
| Inputs | Validated qualitative likelihood and impact values: `Low`, `Medium`, or `High`. |
| Preconditions | The register matrix exactly matches the implementation matrix, and likelihood, impact, and supplied severity are supported values. |
| Decisions | Severity is the direct matrix cell for likelihood and impact. Finding count, ordering, rank, classification, and STRIDE category do not modify it. |
| Security-failure behavior | An unsupported value, changed matrix, or declared severity that differs from the matrix causes strict register-schema rejection. Diagram observations are not scored. |
| Outputs | One register severity: `Low`, `Medium`, `High`, or `Critical`. |
| Related threat IDs | AN-002 and AN-003; the calculation applies to rated register scenarios TM-001 through TM-021. |
| Implementation | [`scoring.py`](../src/threat_analyzer/scoring.py) and [`parse_threat_register`](../src/threat_analyzer/rules.py) |

| Likelihood | Low impact | Medium impact | High impact |
|---|---:|---:|---:|
| Low | Low | Low | Medium |
| Medium | Low | Medium | High |
| High | Medium | High | Critical |

```text
ALGORITHM CalculateQualitativeRisk(likelihood, impact)
    REQUIRE likelihood and impact to be supported qualitative values
    SET severity to RISK_MATRIX[likelihood][impact]
    RETURN severity
END ALGORITHM

ALGORITHM ValidateRegisterSeverity(entry)
    SET expected severity to CalculateQualitativeRisk(entry likelihood, entry impact)
    IF entry overall severity differs from expected severity THEN
        REJECT the threat register
    END IF
END ALGORITHM
```

### 4. Safe JSON and HTML report generation

| Field | Implementation |
|---|---|
| Inputs | A typed analysis report and, for file output, a destination path. |
| Preconditions | The report was assembled from a parsed diagram, validated rules, a validated register, and evaluated observations. |
| Decisions | JSON uses a fixed versioned shape, sorted keys, stable ordering, no timestamp, preserved Unicode, and a final newline. HTML passes every dynamic diagram, rule, register, warning, source, observation, and evidence value through one quote-aware escaping boundary. |
| Security-failure behavior | JSON is produced by the standard serializer rather than string interpolation. HTML-active input is emitted as text. File output uses same-directory temporary replacement; a write failure removes the temporary file when possible and raises a typed report-write error. |
| Outputs | Deterministic JSON text, escaped standalone HTML text, or the atomically replaced destination file. |
| Related threat IDs | AN-003, AN-004, AN-005, TM-009, and TM-010. |
| Implementation | [`analyzer.py`](../src/threat_analyzer/analyzer.py), [`reporting.py`](../src/threat_analyzer/reporting.py), and [`exceptions.py`](../src/threat_analyzer/exceptions.py) |

```text
ALGORITHM RenderReport(report, format)
    IF format is JSON THEN
        MAP typed values to the documented schema
        INCLUDE source identity, schema versions, matrix, summaries,
            parser warnings, register entries, and observations
        OMIT timestamps and severity from observations
        SERIALIZE with sorted keys, preserved Unicode, fixed indentation,
            and one final newline
        RETURN JSON text
    END IF

    IF format is HTML THEN
        DEFINE EscapeDynamicValue as markup-and-quote escaping
        ESCAPE every dynamic string before placing it in markup or an identifier
        RENDER source identity, interpretation notice, observations,
            parser warnings, risk matrix, and modern threat register
        RENDER explicit empty-state text when observations or warnings are absent
        RETURN standalone HTML text
    END IF
END ALGORITHM

ALGORITHM WriteReport(destination, rendered text)
    CREATE the destination parent directory
    CREATE a UTF-8, line-feed-normalized temporary file in that directory
    WRITE and flush the complete text
    REPLACE the destination with the temporary file
    IF any filesystem operation fails THEN
        REMOVE the temporary file when possible
        RAISE a typed report-write error
    END IF
    RETURN the destination path
END ALGORITHM
```

## Notes application

All state-changing browser algorithms below run behind the configured request-body cap. Protected routes also use the shared authenticated-session dependency before their route-specific decisions.

### 5. User registration and password hashing

| Field | Implementation |
|---|---|
| Inputs | Registration form, signed public CSRF cookie and form value, validated settings, database session, password hasher, request context, and current time. |
| Preconditions | Request size is within the application limit; public CSRF validation succeeds; the master key and Argon2id settings passed startup validation. |
| Decisions | Normalize the username with NFKC, trimming, and case folding; require 3–64 permitted characters; require a 12–128 character password; reject a known or concurrently inserted duplicate username; assign a random public ID and persisted role `user`. |
| Security-failure behavior | Invalid CSRF returns 403 without creating an account. Policy failure returns 400. Both pre-checked and uniqueness-race conflicts return the same unavailable-username response and safe audit event. Password plaintext is never persisted or added to audit data. Database failures reach the generic error boundary. |
| Outputs | A committed user containing an Argon2id password hash, an `account.registered` audit event, and a redirect to login; otherwise a bounded error response. |
| Related threat IDs | TM-001, TM-004, TM-011, TM-012, TM-017, and TM-019. |
| Implementation | [`register`](../src/notes_app/main.py), [`normalize_username`, `password_policy_error`, and `password_hasher`](../src/notes_app/security.py) |

```text
ALGORITHM RegisterUser(request, form, database, settings, password hasher, now)
    REQUIRE the public CSRF cookie and form value to be valid
    NORMALIZE the submitted username using compatibility normalization,
        trimming, and case folding
    READ the submitted password without logging it

    IF username length or character policy fails THEN
        RETURN status 400 with the documented validation message
    END IF
    IF password length is outside 12 through 128 characters THEN
        RETURN status 400 with the documented password-policy message
    END IF

    IF normalized username already exists THEN
        RECORD account.registration_conflict without password or submitted username
        COMMIT the audit event
        RETURN status 409 with the unavailable-username message
    END IF

    HASH the password with configured Argon2id parameters and a generated salt
    CREATE a user with a random public ID and role user
    TRY to flush the unique username
        RECORD account.registered with the new user and public account ID
        COMMIT the user and audit event together
    ON uniqueness conflict
        ROLL BACK
        RECORD and COMMIT the same registration-conflict event
        RETURN the same status 409 response
    END TRY

    RETURN a redirect to the login page
END ALGORITHM
```

### 6. Login throttling and temporary lockout

| Field | Implementation |
|---|---|
| Inputs | Login request and form, normalized username, supplied password, account/client throttle settings, database session, password hasher, and current time. |
| Preconditions | Public CSRF validation succeeds. Login throttle identifiers can be derived from the normalized username and direct client address using domain-separated keyed hashes. |
| Decisions | Check both account and address throttle rows under sorted fixed lock stripes. Skip Argon2 work while either scope is locked. Otherwise perform exactly one real or dummy password verification. Increment both scopes for an unlocked failure, reset an expired window, and set a temporary lock after the configured threshold. |
| Security-failure behavior | Locked, unknown-user, and wrong-password cases return the same generic 401 response. Unknown users use a dummy hash. Locked requests do not trigger attacker-amplified password hashing. Audit data contains only a fixed rejection reason. Database failures reach the generic boundary. |
| Outputs | On failure, committed throttle/audit state and a generic response. On success, the authenticated user advances to session rotation, the account throttle is cleared, and the address throttle remains. |
| Related threat IDs | TM-001, TM-011, TM-014, and TM-017. |
| Implementation | [`login`](../src/notes_app/main.py), [`throttle_keys`, `is_login_locked`, and `record_login_failure`](../src/notes_app/security.py) |

```text
ALGORITHM VerifyLoginWithThrottle(request, normalized username, password, database, now)
    DERIVE keyed hashes for account and direct client-address scopes
    MAP both hashes to a fixed set of in-process lock stripes
    ACQUIRE the distinct stripes in sorted order

    IF either throttle row has a future locked-until time THEN
        SET login result to rejected
        SKIP user lookup and password verification
    ELSE
        LOOK UP the normalized username
        SELECT the stored password hash, or the application dummy hash if no user exists
        PERFORM one password verification
        SET login result to rejected if user is absent or verification fails
    END IF

    IF login result is rejected THEN
        IF the request was not already locked THEN
            FOR each account and address throttle row
                CREATE the row if absent
                RESET failures and lock if its counting window expired
                INCREMENT failures
                IF failures reach the configured threshold THEN
                    SET locked-until to now plus the lockout duration
                END IF
            END FOR
        END IF
        RECORD login.failed with fixed reason rejected and no password
        COMMIT
        RELEASE the stripes
        RETURN the generic status 401 response
    END IF

    CLEAR only the successful account throttle
    RELEASE the stripes after session rotation and success audit are committed
    RETURN the authenticated user
END ALGORITHM
```

### 7. Session creation, validation, expiry, and logout revocation

| Field | Implementation |
|---|---|
| Inputs | Authenticated user, optional raw session cookie, settings, database session, current time, and for logout the CSRF cookie/form value. |
| Preconditions | A 32-byte master key, positive idle/absolute lifetimes, and idle lifetime not exceeding absolute lifetime. Login must have authenticated the user before session creation. |
| Decisions | Store only a domain-separated keyed hash of a random opaque token; bind a signed CSRF value to the session with another hash; enforce both idle and absolute deadlines; rotate a valid old session at login; update last-seen time when requested; revoke on expiry, missing user, or logout. |
| Security-failure behavior | Missing, unknown, revoked, expired, or orphaned sessions do not authenticate. Expired/orphaned rows are marked revoked. Protected routes redirect to login. Logout with invalid CSRF returns 403 and does not revoke a valid session. Raw session and CSRF values are not stored in audit events. |
| Outputs | A server-side session and raw cookie values at creation; an authenticated user/session pair or no authentication at validation; a revoked row and cleared browser cookies at logout. |
| Related threat IDs | TM-002, TM-003, TM-004, TM-011, TM-017, and TM-019. |
| Implementation | [`create_session`, `authenticate_session`, and `revoke_session`](../src/notes_app/security.py), plus [`login` and `logout`](../src/notes_app/main.py) |

```text
ALGORITHM CreateSession(user, database, settings, now)
    GENERATE a random 32-byte URL-safe opaque token
    GENERATE a random signed CSRF value
    STORE a domain-separated keyed hash of the session token
    STORE a different domain-separated keyed hash of the CSRF value
    STORE user ID, creation time, last-seen time, and absolute expiry
    RETURN the session row, raw token, and raw CSRF value
END ALGORITHM

ALGORITHM ValidateSession(optional raw token, database, settings, now, touch)
    IF raw token is absent THEN RETURN no authentication
    HASH it using the session-token purpose
    QUERY a matching session whose revoked time is empty
    IF no row exists THEN RETURN no authentication

    CALCULATE idle deadline from last-seen time
    IF now reaches either idle or absolute deadline THEN
        MARK the session revoked and COMMIT
        RETURN no authentication
    END IF

    LOAD the session user
    IF the user no longer exists THEN
        MARK the session revoked and COMMIT
        RETURN no authentication
    END IF

    IF touch is requested THEN
        UPDATE last-seen time and COMMIT
    END IF
    RETURN the authenticated user and session row
END ALGORITHM

ALGORITHM Logout(request, database, settings, now)
    VALIDATE the current session without extending last-seen time
    REQUIRE a signed CSRF cookie/form match bound to that session when present
    IF a valid session exists THEN
        MARK it revoked
        RECORD logout.succeeded
        COMMIT both changes
    END IF
    EXPIRE the session and CSRF cookies in the response
    RETURN a redirect to login
END ALGORITHM
```

### 8. CSRF validation

| Field | Implementation |
|---|---|
| Inputs | Master key, optional authenticated session row, CSRF cookie value, and submitted form value. |
| Preconditions | Public forms receive a signed random CSRF value in both an HttpOnly `SameSite=Lax` cookie and server-rendered form field. Authenticated forms receive the value created with the session. |
| Decisions | Require both values, compare them in constant time, verify the signature in constant time, and for authenticated requests compare a domain-separated hash with the session’s stored CSRF hash. |
| Security-failure behavior | Any missing value, mismatch, malformed value, invalid signature, or session-binding mismatch returns false; state-changing routes convert false to 403 before mutation. A public form replaces an absent or invalid cookie with a newly signed value. |
| Outputs | A validation boolean, or a newly signed public-form token when rendering a public form. |
| Related threat IDs | TM-003 and TM-004. |
| Implementation | [`new_signed_csrf` and `valid_signed_csrf`](../src/notes_app/crypto.py), [`csrf_is_valid`](../src/notes_app/security.py), and [`_require_session_csrf`](../src/notes_app/main.py) |

```text
ALGORITHM ValidateCsrf(master key, optional session, cookie value, form value)
    IF cookie or form value is absent THEN RETURN FALSE
    IF constant-time comparison says the two values differ THEN RETURN FALSE
    SPLIT the form value into random part and signature
    IF either part is absent THEN RETURN FALSE
    RECOMPUTE the signature with the CSRF-signature purpose
    IF constant-time signature comparison fails THEN RETURN FALSE

    IF no authenticated session was supplied THEN RETURN TRUE
    HASH the complete form value with the CSRF-session purpose
    RETURN constant-time comparison with the session CSRF hash
END ALGORITHM
```

### 9. Note creation with validation, encryption, and audit logging

| Field | Implementation |
|---|---|
| Inputs | Authenticated session, note title/body form, CSRF values, validated limits, note cipher, database session, request context, and current time. |
| Preconditions | The shared request-body cap and authentication dependency succeed; session-bound CSRF validation succeeds. |
| Decisions | Require a non-blank title, enforce title/body character limits, serialize per-user count-and-insert within one process, enforce the note-count quota, generate a public UUID, and encrypt title/body separately with fresh nonces and field-specific authenticated context. |
| Security-failure behavior | Invalid CSRF returns 403. Invalid fields return 400 without persistence. Quota exhaustion returns 409. Encryption authentication/configuration and database errors reach the generic error boundary. Neither note plaintext nor cryptographic values are placed in the audit event. |
| Outputs | A committed ciphertext-only note and `note.created` audit event, followed by a redirect to the new owner-scoped note. |
| Related threat IDs | TM-002, TM-004, TM-007, TM-008, TM-011, TM-012, TM-013, TM-015, TM-016, and TM-017. |
| Implementation | [`create_note`](../src/notes_app/main.py), [`_validate_note`](../src/notes_app/main.py), and [`NoteCipher`](../src/notes_app/crypto.py) |

```text
ALGORITHM CreateNote(request, authenticated user, form, database, settings, cipher)
    REQUIRE session-bound CSRF validation
    READ title and body as text
    IF title is blank, title is too long, or body is too long THEN
        RETURN status 400 with submitted text rendered through the template boundary
    END IF

    ACQUIRE the fixed creation-lock stripe for the authenticated user
    COUNT notes whose owner ID equals the authenticated user ID
    IF the per-user quota has been reached THEN
        RELEASE the stripe
        RETURN status 409
    END IF

    GENERATE a public note UUID
    ENCRYPT title with a fresh 12-byte nonce and authenticated context
        containing key version, owner ID, note UUID, and field name title
    ENCRYPT body independently with a fresh 12-byte nonce and authenticated context
        containing key version, owner ID, note UUID, and field name body
    CREATE the note row with nonces, ciphertext, key version, and timestamps
    RECORD note.created with actor and note ID but no note content
    COMMIT the note and audit event together
    RELEASE the stripe
    RETURN a redirect to the new note
END ALGORITHM
```

### 10. Owner-scoped note reading, updating, and deletion

| Field | Implementation |
|---|---|
| Inputs | Authenticated user ID, public note ID, database session, and for mutations validated CSRF plus submitted note text or delete intent. |
| Preconditions | Shared authentication succeeds. Mutations also pass request-size and session-bound CSRF checks. |
| Decisions | Validate the public ID as a UUID. Reads select by both public ID and owner ID. Updates perform an owner-scoped lookup, validate and re-encrypt fields, then execute an update with both predicates. Deletes execute a delete with both predicates. Mutations require exactly one affected row. |
| Security-failure behavior | Invalid IDs, missing notes, other users’ notes, and unexpected mutation row counts all return the same 404. Failed mutation counts are rolled back. Validation failure returns 400. No audit success event is written unless the owner-scoped mutation succeeds. |
| Outputs | Decrypted owner-visible note data for a read; committed re-encrypted data and `note.updated` audit event for update; committed removal and `note.deleted` event for deletion. |
| Related threat IDs | TM-002, TM-004, TM-005, TM-008, TM-009, TM-012, TM-013, TM-017, and TM-021. |
| Implementation | [`_owned_note`, `read_note`, `edit_note`, and `delete_note`](../src/notes_app/main.py) |

```text
ALGORITHM ReadOwnedNote(public note ID, authenticated user, database)
    IF public note ID is not a valid UUID THEN RETURN not found
    SELECT the note WHERE public ID matches AND owner ID matches the user
    IF no row exists THEN RETURN not found
    DECRYPT title and body using stored nonces, key version,
        owner ID, note ID, and field names as authenticated context
    RETURN the decrypted note to the autoescaping template
END ALGORITHM

ALGORITHM UpdateOwnedNote(request, public note ID, authenticated user, form, database)
    REQUIRE session-bound CSRF validation
    QUERY the note WHERE public ID and owner ID both match
    IF no row exists THEN RETURN not found
    VALIDATE submitted title and body
    ENCRYPT each field independently with fresh nonce and authenticated context
    UPDATE notes WHERE public ID matches AND owner ID matches the user
    IF affected row count is not exactly one THEN
        ROLL BACK and RETURN not found
    END IF
    RECORD note.updated and COMMIT
    RETURN a redirect to the note
END ALGORITHM

ALGORITHM DeleteOwnedNote(request, public note ID, authenticated user, database)
    REQUIRE session-bound CSRF validation
    IF public note ID is not a valid UUID THEN RETURN not found
    DELETE WHERE public ID matches AND owner ID matches the user
    IF affected row count is not exactly one THEN
        ROLL BACK and RETURN not found
    END IF
    RECORD note.deleted and COMMIT
    RETURN a redirect to the note list
END ALGORITHM
```

### 11. User-scoped export

| Field | Implementation |
|---|---|
| Inputs | Authenticated user, session-bound CSRF values, database session, note cipher, request context, and current time. |
| Preconditions | Authentication, request-size enforcement, and CSRF validation succeed. |
| Decisions | Select only rows whose owner ID equals the authenticated user ID, order them deterministically, decrypt them with authenticated context, and serialize a fixed JSON schema using the standard JSON serializer. |
| Security-failure behavior | Invalid CSRF returns 403. No other user’s row enters the result query. Ciphertext authentication failure or database failure reaches the generic error boundary rather than returning partial or raw internal data. |
| Outputs | A JSON attachment containing only the current user’s note IDs, plaintext titles/bodies, and timestamps, plus a committed `notes.exported` audit event containing only the exported count. |
| Related threat IDs | TM-002, TM-004, TM-005, TM-009, TM-011, TM-017, and TM-021. |
| Implementation | [`export_notes`](../src/notes_app/main.py) and [`_decrypt_note`](../src/notes_app/main.py) |

```text
ALGORITHM ExportCurrentUsersNotes(request, authenticated user, database, cipher)
    REQUIRE session-bound CSRF validation
    SELECT all notes WHERE owner ID equals the authenticated user ID
        ORDER BY creation time then public ID
    FOR each selected note
        DECRYPT title and body with their stored authenticated context
        ADD only ID, title, body, created time, and updated time to the export
    END FOR
    SERIALIZE schema version 1.0 and notes with the standard JSON serializer
        using stable key ordering and preserved Unicode
    RECORD notes.exported with the user ID and note count only
    COMMIT the audit event
    RETURN the JSON attachment
END ALGORITHM
```

### 12. Server-side RBAC

| Field | Implementation |
|---|---|
| Inputs | Server-authenticated user with persisted role, database session, request context, and current time. |
| Preconditions | The shared session dependency has loaded the user from the database. The current administrative surface is the audit-summary route only. |
| Decisions | Compare the persisted role exactly with `admin`; do not trust form, query, cookie, or template state. Audit both denied and successful access before returning the result. |
| Security-failure behavior | A non-admin receives 403 after a committed `admin.access_denied` event. Unauthenticated callers are redirected by the shared session dependency. No administrative data query runs for a denied user. |
| Outputs | For an admin, a count-only summary of users, notes, and audit events plus `admin.access_succeeded`; otherwise no administrative data. |
| Related threat IDs | TM-002, TM-006, TM-017, and TM-018. |
| Implementation | [`admin_audit_summary`](../src/notes_app/main.py) |

```text
ALGORITHM ReadAdminAuditSummary(request, authenticated user, database)
    IF the persisted user role is not exactly admin THEN
        RECORD admin.access_denied with the persisted role
        COMMIT the audit event
        RETURN status 403
    END IF

    RECORD admin.access_succeeded with the persisted role
    COMMIT the audit event
    COUNT users, notes, and audit events
    RETURN the count-only administrative page
END ALGORITHM
```

### 13. Generic error handling

| Field | Implementation |
|---|---|
| Inputs | Request, correlation ID, downstream response or exception, validated settings, and templates. |
| Preconditions | The security-envelope middleware assigns a random correlation ID before calling downstream code. Debug and interactive API documentation are disabled. |
| Decisions | Reject declared or streamed request bodies over the configured cap; map known validation, data-protection, database, and HTTP exceptions to bounded messages; catch other exceptions at the outer boundary; apply security headers to the response. |
| Security-failure behavior | Internal logs contain correlation ID and exception class, not exception message or traceback. Responses omit SQL, paths, secrets, field values, and stack traces. Non-redirect HTTP errors use a safe allow-list of messages; other failures use a generic 500 response. |
| Outputs | A bounded HTML error response with status, safe message, and correlation ID, plus security headers including HSTS outside development mode. |
| Related threat IDs | TM-009, TM-010, TM-011, TM-015, and TM-019. |
| Implementation | [`security_envelope`, exception handlers, `_generic_error`, and `_apply_security_headers`](../src/notes_app/main.py) |

```text
ALGORITHM ExecuteWithinSecurityEnvelope(request, downstream application, settings)
    ASSIGN a random correlation ID

    IF Content-Length is malformed or exceeds the configured limit THEN
        RETURN generic status 413 with security headers
    END IF

    WHILE receiving request-body chunks
        ACCUMULATE only the byte count
        IF the count exceeds the limit THEN
            STOP requesting later chunks and RETURN generic status 413
        END IF
    END WHILE

    TRY downstream processing
        MAP validation errors to generic status 422
        MAP authenticated-encryption or database errors to generic status 500
        MAP 401, 403, 404, and 405 to their fixed safe messages
        PRESERVE framework redirects
    CATCH any other exception
        LOG only correlation ID and exception class
        SET response to the generic status 500 page
    END TRY

    APPLY content security policy, no-sniff, frame denial, no-referrer,
        permissions policy, no-store, and correlation headers
    APPLY HSTS when secure-cookie mode is active
    RETURN the response
END ALGORITHM
```

### 14. Audit-event recording

| Field | Implementation |
|---|---|
| Inputs | Database session, request, current time, event type, outcome, optional actor/target identifiers, and optional structured data. |
| Preconditions | The request has a correlation ID and application settings. The caller owns transaction commit or rollback. |
| Decisions | Accept optional data keys only from `reason`, `role`, `page`, and `count`; ignore forwarded headers and use the direct client address; store only a 24-hex-character keyed address hash; serialize event data with sorted compact JSON. |
| Security-failure behavior | A disallowed data key raises an error before the event is added. Passwords, note content, session tokens, CSRF values, encryption keys, and raw client addresses have no allowed event field. Persistence failure is handled by the caller’s transaction and generic error boundary. |
| Outputs | An audit event added to the current transaction with time, type, outcome, actor, target, keyed client-address hash, correlation ID, and allow-listed JSON data. |
| Related threat IDs | TM-010, TM-011, TM-017, TM-018, and TM-021. |
| Implementation | [`record_event`](../src/notes_app/audit.py) and [`AuditEvent`](../src/notes_app/models.py) |

```text
ALGORITHM RecordAuditEvent(database, request, event fields, optional data)
    SET allowed data keys to reason, role, page, and count
    IF optional data contains any other key THEN
        RAISE a disallowed-audit-field error
    END IF

    READ the direct client address without trusting forwarded headers
    COMPUTE a domain-separated keyed hash of the address
    TRUNCATE its hexadecimal representation to 24 characters
    SERIALIZE allowed data as compact JSON with sorted keys

    CREATE an audit row containing:
        occurrence time, event type, outcome, optional actor,
        optional target type and ID, address hash,
        request correlation ID, and serialized allowed data
    ADD the row to the caller's current database transaction
    RETURN the pending audit event
END ALGORITHM
```

## Verification references

- Analyzer parsing, evaluator, scoring, and rendering behavior is exercised under [`tests/analyzer/`](../tests/analyzer/).
- Registration, authentication, sessions, CSRF, notes, export, RBAC, error handling, cryptography, and audit behavior is exercised under [`tests/app/`](../tests/app/).
- Code-to-test mappings and residual limitations remain authoritative in [`control-traceability.md`](control-traceability.md).
