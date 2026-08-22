# Security Policy

## System and Scope

This policy covers the modernized code in `src/threat_analyzer/` and `src/notes_app/`, their configuration, templates, scripts, and tests. Files in `original_evidence/` are preserved historical artifacts and are not maintained runtime code. Historical reports may contain insecure examples and must not be treated as deployment guidance.

The supported runtime scope is a single-process local demonstration using FastAPI, server-rendered pages, and SQLite. The launcher binds to loopback by default and rejects non-loopback development or test bindings. `NOTES_ENV` defaults to `development`; test and production modes set the cookie `Secure` flag and HSTS. A deployment beyond loopback must explicitly select production mode and add correctly configured HTTPS termination, protected environment configuration, restrictive database and backup permissions, supervised process management, and infrastructure-level traffic controls.

Important assets are user credentials and password hashes, opaque session and CSRF tokens, note titles and bodies, encryption keys, user and role identifiers, exported notes, audit records, administrator privileges, and runtime configuration. The repository-wide context is defined in [`docs/threat-model.md`](docs/threat-model.md).

## Threat Model and Trust Boundaries

The principal boundaries are browser-to-application, anonymous-to-authenticated session, application-to-database, application-to-encryption-key source, normal-user-to-administrator, development-to-deployed runtime, and any future external monitoring or notification adapter.

Registration and login fields, note content and identifiers, forms and JSON, cookies and CSRF headers, request headers, URL paths, query parameters, export requests, PlantUML text, JSON rule files, and repeated or oversized requests are attacker-controlled. Environment configuration and dependency/build inputs are privileged operator- or developer-controlled inputs and are validated separately.

The threat model assumes that the operator protects the 32-byte note-encryption key and TLS configuration. An attacker who obtains both the database and active key can decrypt notes. A dependency executing inside the application process can access plaintext and key material and is therefore inside the effective confidentiality boundary.

## Security Invariants

- Passwords are never stored or logged in plaintext and are verified with Argon2id.
- Login responses do not reveal whether an account exists.
- A protected request requires an active, unexpired, non-revoked opaque session; only a hash of its token is stored.
- Authentication creates fresh session state, and logout revokes the current session.
- Public registration and login forms validate a signed random double-submit CSRF token. Every authenticated state-changing browser request validates a random token that is additionally bound to the current server-side session.
- Every note operation is scoped by both authenticated owner ID and note public ID in the database query.
- Role checks use server-side account state and protect administrative routes independently of UI visibility.
- Note title and body plaintext are AES-GCM encrypted before database persistence using a unique nonce and owner/note/field-bound authenticated data.
- HTML reports and application templates escape untrusted values.
- SQL is generated through SQLAlchemy expressions and bound parameters, not string concatenation of request values.
- Passwords, full note content, raw session or CSRF tokens, and encryption keys never enter audit records or ordinary logs.
- Request bodies, note fields, note counts, listing sizes, and authentication attempts are bounded.
- Analyzer output describes diagram indicators and does not turn an omitted control into a confirmed source-code vulnerability.

## Reportable Findings and Severity Context

Reportable classes include authentication bypass; session fixation, forgery, replay after revocation, or expiry bypass; CSRF on state-changing actions; cross-user note access or mutation; role escalation; stored or reflected XSS; SQL or command injection; plaintext note persistence; AES-GCM nonce or authenticated-data misuse; exposure of keys, passwords, or raw tokens; audit leakage of secrets or note bodies; unsafe report rendering; unbounded remotely reachable resource use; insecure deployed defaults; and supply-chain behavior that crosses a documented boundary.

A finding should identify a reachable path, attacker prerequisites, the broken invariant, concrete impact, and a reproducible validation method. Absence of a control from a diagram, historical DREAD rank, scanner label, or keyword count alone is insufficient.

Critical and High ratings require a realistic path across a major confidentiality, integrity, authentication, or privilege boundary. Medium covers constrained compromise, material investigation loss, or bounded service impact. Low covers limited defense-in-depth gaps. Privacy, resilience, and usability observations should be labeled separately unless they support a concrete security impact.

## Out of Scope, Exclusions, and Accepted Risk

The following are known demonstration exclusions, not claims that the associated risks do not matter:

- Distributed rate limiting or denial-of-service protection.
- Production KMS/HSM storage, managed key rotation, and envelope encryption.
- Production email, CAPTCHA, OAuth provider, MFA, Kafka, SIEM, MISP/TAXII, or automated response integrations.
- Multi-region operation, high availability, disaster recovery, and secure backup deletion.
- Formal penetration testing or certification.
- Protection after full compromise of the application process, browser, operator account, or both the database and active encryption key.
- Long-term privacy retention and verified erasure from SQLite free pages or backups.

OWASP ZAP may be used out of band for authorized testing; it is not part of the runtime data path. Authentication throttle records are database-backed, but their check/update critical section is serialized only inside one application process; this is not a distributed or edge rate limiter. SQLite metadata, ciphertext size, account metadata, and local audit rows remain visible to a database-file attacker.

## Known Limitations and Compensating Controls

The repository favors a small auditable design over production infrastructure. Opaque server-side sessions avoid unnecessary JWT key and revocation complexity. Owner-scoped queries, UUID public identifiers, short session lifetimes, CSRF validation, local quotas, structured audit records, and field encryption provide testable controls within the supported scope. They do not replace TLS, filesystem hardening, backups, edge traffic controls, dependency maintenance, centralized monitoring, or managed key custody.

## Reporting a Security Issue

Use the private vulnerability-reporting mechanism of the repository hosting service if one is configured. Otherwise, contact the repository owner privately through the hosting platform before sharing exploit details. Include the affected path and version, prerequisites, impact, a minimal reproduction, and any suggested remediation. Do not place credentials, personal note data, active tokens, encryption keys, or destructive proof-of-concept data in a public issue.
