# Threat Model

## Overview

This repository contains two distinct runtime surfaces:

1. A command-line utility that parses a documented subset of PlantUML sequence diagrams, evaluates contextual threat rules, and writes deterministic JSON and escaped HTML reports.
2. A local, server-rendered notes application that demonstrates authentication, server-side sessions, CSRF protection, owner-scoped authorization, role checks, encrypted note fields, bounded inputs, and security audit records.

The curated files under `original_evidence/` are historical evidence and are not runtime dependencies. Generated historical reports are not current validation results. The notes application is a reference implementation for local review, not a production service.

The primary security objectives are tenant isolation between users, confidentiality and integrity of note content, correct authentication and session handling, server-side authorization before every protected data operation, bounded use of local resources, and useful auditability without recording secrets or note content.

## Threat Model, Trust Boundaries, and Assumptions

### Assets

| Asset | Required property |
|---|---|
| User credentials | Passwords are accepted only over a protected transport in deployment, never logged, and stored only as Argon2id hashes. |
| Password hashes | Protected from disclosure and offline cracking; parameters remain reviewable and upgradeable. |
| Session tokens | Unpredictable, sent only as protected cookies, stored server-side only as hashes, expired and revocable. |
| CSRF tokens | Unpredictable and never logged; public-form values are signed double-submit tokens, while authenticated values are additionally bound to a valid server-side session. |
| Note titles and bodies | Visible only to their owner, escaped on output, encrypted at rest, and integrity-protected. |
| Encryption keys | Supplied outside the repository and database, limited to the runtime, and replaceable through explicit key-version handling. |
| User identifiers and minimal profile data | Used only for application identity and authorization; not exposed across user boundaries. |
| Exported note data | Contains only the requesting user's notes and is protected in transit and after download by the user's environment. |
| Audit records | Structured for local investigation and free of secrets and note bodies; database custody is trusted because the local store is not immutable. |
| Administrator privileges | Granted deliberately and checked on the server for every administrative operation. |
| Application configuration | Required key material fails closed; operators explicitly select production mode for non-loopback use; secrets are not committed. |

### Actors

| Actor | Capabilities and trust |
|---|---|
| Anonymous internet user | Controls registration/login inputs, headers, cookies, paths, query strings, request timing, and request volume. Untrusted. |
| Authenticated user | Can create legitimate application state and submit malicious identifiers or content. Trusted only for their own data. |
| Malicious authenticated user | Attempts cross-user access, stored XSS, quota exhaustion, session abuse, and role escalation. Untrusted across every tenant and role boundary. |
| Administrator | May use the protected administrative route. Privileged but still subject to authentication, session, CSRF, audit, and data-minimization controls. |
| Application operator | Controls runtime environment, database location, TLS termination, file permissions, key injection, backups, and process lifecycle. Operationally trusted. |
| Developer | Controls source and test changes. Trusted only through review, dependency controls, and separation of development from deployed configuration. |
| Compromised dependency or build input | May execute during build, test, or runtime and can undermine application controls. Untrusted despite appearing in the software supply chain. |
| Attacker with database-file access | Can read or copy password hashes, hashed session records, account metadata, ciphertext, and audit records; cannot be assumed to have the encryption key. |

### Trust boundaries

1. **Browser to application.** All HTTP inputs are attacker-controlled. HTTPS termination is an operator responsibility outside local development.
2. **Authentication and session boundary.** Anonymous requests become authenticated only after password verification and creation of a new opaque server-side session. Possession of a cookie is not sufficient after revocation or expiry.
3. **Application to database.** SQLAlchemy parameterization, owner-scoped queries, transaction behavior, database-file permissions, and encrypted note fields protect this boundary.
4. **Application to encryption-key source.** The database does not contain the master key. Environment configuration is trusted only when supplied and protected by the operator.
5. **Normal user to administrative functions.** Role claims are loaded from server-side state and enforced on the server, not accepted from form fields or cookies.
6. **Application to external monitoring or notification adapter.** No external adapter is enabled by default. A future adapter would receive a deliberately minimized event schema rather than note bodies or credentials.
7. **Development/testing to deployed runtime.** Development cookie settings, ephemeral keys, test databases, verbose test failures, and seeded state must not migrate silently into a deployed process.

### Attacker-controlled inputs

The application treats registration and login fields; note titles and bodies; note public identifiers; form fields and JSON bodies; cookies and CSRF headers; request headers; export requests; URL paths and query parameters; and repeated or oversized requests as hostile. The analyzer likewise treats diagram text, rule files, names, messages, and report fields as untrusted content. Operator-controlled environment values and developer-controlled dependencies are separate privileged inputs and require validation appropriate to their boundary.

### Security invariants

- A protected request maps to one active, unexpired, non-revoked server-side session whose stored token hash matches the presented opaque token.
- Authentication creates fresh session state; logout revokes it; idle and absolute expiry are enforced by the server.
- Public registration and login forms require a signed random double-submit CSRF token. Every authenticated state-changing browser request requires a token additionally bound to the authenticated session.
- Every note read, update, delete, and export query is constrained by the authenticated owner identifier in the database operation itself.
- Administrative access requires a server-side role check in addition to ordinary authentication and CSRF requirements where applicable.
- Note title and body plaintext are encrypted before persistence and output is escaped before HTML rendering.
- The encryption nonce is unique for each encryption operation, and authenticated additional data binds ciphertext to its owner, note identity, field, and key version.
- Passwords, raw session or CSRF tokens, encryption keys, and note bodies never enter audit records or ordinary application logs.
- Request size, field length, login attempts, note count, and listing size are bounded.
- Analyzer observations state what a diagram supports; absence of a control in a diagram is not presented as proof that source code lacks it.
- Report renderers escape every model- or diagram-derived field before inserting it into HTML.

### Assumptions and exclusions

The demonstration assumes one application process, a locally protected SQLite database, a correctly supplied 32-byte master key, and TLS outside loopback development. `NOTES_ENV` defaults to `development`; test and production modes use `Secure` cookies and HSTS. The launcher rejects non-loopback development or test bindings. The operator must protect environment configuration, database backups, filesystem permissions, and TLS termination. A database-file attacker is modeled separately from an attacker who also obtains the key; compromise of both defeats application-layer note confidentiality.

The repository does not claim distributed rate limiting, production KMS or HSM integration, production email delivery, full disaster recovery, multi-region deployment, an enterprise SIEM, Kafka, MISP/TAXII, a production OAuth provider, formal penetration testing, CAPTCHA, automated incident response, or production-ready operations. MFA is a future control unless a complete enrollment, verification, recovery, and test flow is present. OWASP ZAP belongs in an out-of-band test workflow and is not a runtime note sanitizer.

### Threat register cross-reference

The authoritative scenarios, ratings, evidence states, and residual risks are in the [modern threat register](threat-register.md); implementation and verification links are in [control traceability](control-traceability.md).

| ID | Primary topic | ID | Primary topic |
|---|---|---|---|
| `TM-001` | Credential attacks | `TM-012` | Database-file compromise |
| `TM-002` | Authentication bypass | `TM-013` | Encryption-key compromise |
| `TM-003` | Session lifecycle and replay | `TM-014` | Request and authentication exhaustion |
| `TM-004` | Cross-site request forgery | `TM-015` | Oversized request bodies |
| `TM-005` | Cross-user note authorization | `TM-016` | Storage quota exhaustion |
| `TM-006` | Server-side role enforcement | `TM-017` | Repudiation and auditability |
| `TM-007` | Stored or reflected script execution | `TM-018` | Administrator misuse |
| `TM-008` | SQL injection | `TM-019` | Unsafe deployment configuration |
| `TM-009` | Destination-specific output encoding | `TM-020` | Dependency and build compromise |
| `TM-010` | Error-detail disclosure | `TM-021` | Retention, deletion, and export privacy |
| `TM-011` | Sensitive logging |  |  |

## Attack Surface, Mitigations, and Attacker Stories

### Authentication and credentials

An anonymous attacker can automate credential stuffing or brute-force attempts, use account names to seek enumeration differences, or attempt malformed registration and login inputs. Argon2id hashing, a password policy, generic login failures, dummy password verification for unknown accounts, account- and client-address attempt controls, temporary lockout, request limits, and audit events reduce these risks. Throttle records persist in the local database across ordinary process restarts, but their check/update serialization is process-local and does not coordinate across application instances or defeat distributed clients. It is not a substitute for an edge control.

Authentication bypass would be material if a route accepted a client identity, role, or user identifier without validating a current session. Protected dependencies must reject missing, malformed, expired, revoked, or unknown tokens before business logic runs.

### Sessions and CSRF

An attacker may steal a cookie through endpoint compromise, local malware, transport misconfiguration, or a browser vulnerability; attempt fixation or replay; or rely on a session surviving password authentication, logout, or expiry. Fresh opaque tokens, hash-only storage, cookie flags, idle and absolute expiry, and explicit revocation limit replay. The application cannot protect a token already stolen from a fully compromised browser during its remaining valid lifetime.

A malicious site may induce a logged-in browser to submit a write. SameSite cookies reduce ambient cross-site delivery but do not replace session-bound CSRF validation on create, update, delete, export actions with side effects, logout, or administrative writes.

### Note authorization and administrative privileges

A malicious authenticated user can replace a public note UUID, manipulate paths or form fields, or call a route directly to attempt broken object-level authorization. Unpredictable UUIDs reduce casual guessing but do not provide authorization. Database queries must include both the public identifier and authenticated owner identifier; a missing row and a foreign row should not reveal different sensitive details.

A normal user can call administrative URLs directly or submit a forged role value. Roles must come from server-side account state and be enforced at the route boundary. Administrative activity remains a risk even when authorized: excessive data access, privilege misuse, and compromised administrator sessions require minimal capabilities and auditable actions. The compact demonstration provides only a narrow administrative view and does not implement a full privileged-access-management system.

### Injection and unsafe rendering

Attackers control note text, identities, diagram labels, report descriptions, and identifiers. Stored or reflected XSS becomes realistic if any of these values bypass Jinja2 autoescaping or are inserted into HTML by a report generator without escaping. The application renders note content as text through escaped templates, and the analyzer escapes all report fields.

SQL-injection-shaped input must remain data. SQLAlchemy expressions and bound parameters protect normal queries; constructing SQL from note identifiers, sort fields, or filters would violate the invariant. Unsafe output rendering also includes spreadsheet-formula interpretation in downstream tools and active HTML in downloaded data; exports should use a defined JSON content type rather than executable markup.

### Errors, logging, and repudiation

Detailed database, cryptographic, template, or stack errors can expose schema, paths, identifiers, or configuration. External responses use generic messages and correlation identifiers while internal logging retains useful diagnostics. Correlation data and audit metadata must not become a secondary disclosure channel.

Users may deny creating, updating, deleting, or exporting data; attackers may deny failed authentication or denied administrative requests. Structured audit events provide actor, action, target metadata, result, client address where appropriate, and correlation data without passwords, tokens, keys, CSRF values, or note bodies. An attacker or operator with database write access can still alter local audit rows; append-only remote logging is outside scope.

### Data at rest, keys, and privacy

Database-file access exposes account metadata, Argon2id hashes, ciphertext sizes and timing, hashed session records, and audit metadata. AES-GCM protects note title and body confidentiality and integrity when the master key remains separate. It does not conceal that a user has notes, their approximate ciphertext lengths, access times, or relationship metadata. Key compromise combined with database access exposes note plaintext; the local environment-key design has no managed rotation, escrow, hardware protection, or per-tenant envelope keys.

Exported data is plaintext for the authenticated requester and moves outside application control after download. Retention, secure deletion from SQLite pages and backups, user erasure workflows, and jurisdiction-specific privacy obligations are not fully implemented. These are documented privacy risks rather than hidden behind an encryption claim.

### Availability and resource use

An attacker can send large bodies, long fields, repeated login attempts, expensive password verifications, many note writes, large exports, or high-cardinality client addresses. Middleware body limits, field limits, per-user note quotas, pagination, authentication throttles, and owner-scoped exports reduce local impact. Under ordinary application use the note quota indirectly bounds export row count, but the export query has no separate row cap. SQLite locking, process-local critical-section locks around database-backed throttle updates, one process, and a shared Argon2 workload remain constraints. Distributed denial of service requires infrastructure controls outside this repository.

### Configuration and supply chain

Weak or missing keys, development cookie settings in a deployed environment, permissive file permissions, debug mode, stale dependencies, or an unreviewed dependency can invalidate application controls. Configuration parsing fails closed for malformed key material; test and production modes enable `Secure` cookies, and the launcher blocks non-loopback development or test bindings. Operators must still provide HTTPS and the external controls required for non-loopback production use. Lockfiles, isolated builds, vulnerability monitoring, signed releases, and provenance verification are operational improvements not demonstrated here. A compromised package with runtime code execution can read plaintext and keys inside the application process.

### Analyzer-specific attack surface

PlantUML and JSON rule files may contain malformed, enormous, or HTML-active text. The parser supports a deliberate subset, emits warnings for unsupported constructs, preserves line-level evidence, validates stable identifiers and enums, and orders results deterministically. It does not execute PlantUML, contact a rendering service, or infer a confirmed implementation vulnerability solely from omitted diagram text.

## Severity Calibration

Severity combines realistic likelihood and impact for this repository after considering verified controls; STRIDE category and match count do not determine severity. The modern register uses a documented qualitative matrix. Analyzer observations remain unvalidated and have no assigned severity. Historical DREAD values remain evidence of the earlier method, not objective vulnerability scores.

### Critical

Critical means a reachable failure enables broad, systemic compromise with little containment. Examples include an authentication bypass that exposes every user's decrypted notes and administrative functions, or a path that lets a remote attacker obtain both the active encryption key and the database at scale. A missing defense-in-depth header or an absent diagram annotation is never Critical by itself.

### High

High means a realistic attacker can cross a major confidentiality or privilege boundary. Examples include exploitable owner-scope omission allowing cross-user note reads or writes, server-side role bypass, stored XSS that steals active sessions broadly, SQL injection reaching account and ciphertext records, or remote session-token forgery. The attack must be reachable in the implementation, not merely hypothesized from a sequence diagram.

### Medium

Medium covers meaningful but constrained compromise or availability impact. Examples include a CSRF weakness requiring an already authenticated victim and affecting only their data, repeatable local resource exhaustion bounded to one process, sensitive stack detail without credentials or keys, an audit gap that materially impairs investigation, or lockout behavior that permits targeted account denial. Context can raise or lower these when scale or prerequisites change.

### Low

Low covers limited exposure, hard-to-exploit defense-in-depth gaps, and observations with small direct security impact. Examples include a non-sensitive header omission with no practical exploit chain, overly precise but non-confidential validation wording, or incomplete audit metadata that does not prevent attribution of important actions. Autosave and delete-confirmation presentation are usability or safety observations and are not counted as vulnerabilities without a concrete security impact.

## Repository Identity

The final snapshot identifier is generated deterministically from every regular file in the handoff folder, excluding the outer ZIP. Relative POSIX-style paths are sorted ordinally, each file is hashed with SHA-256, and UTF-8 records in the form `<file-sha256>  <relative-path>\n` are concatenated and hashed again. For this document only, the trailing `Repository:` and `Version:` lines and their preceding blank line are omitted from its per-file hash to avoid self-reference. The exact identity lines are appended during final packaging.

Repository: notes-threat-model-portfolio
Version: snapshot-sha256:bbe32eaa3e2226a13ededf1e6a17e301a9adebeee9a8a7c08019dc6df48459e2
