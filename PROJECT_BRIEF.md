# Project Brief

## Context

The supplied `DFD.zip` contains a 2025 proof of concept for parsing PlantUML sequence diagrams, applying threat rules, scoring findings with DREAD, generating JSON and HTML reports, and presenting countermeasure ideas for a sample notes SaaS design. It also contains generated reports, mitigation figures, duplicate reports, nested ZIPs, and Python bytecode.

The portfolio handoff preserves what the archive proves while separating it from present modernization work. It does not infer authorship, deployment, employer endorsement, or implementation history that the archive cannot establish.

## Problem

The original material demonstrates a useful end-to-end idea, but its organization and analysis are not sufficient for an experienced technical review:

- Source, generated output, screenshots, duplicate files, caches, and nested archives were mixed.
- Parser and matcher logic depended on regular-expression and broad keyword heuristics without source-line context.
- A control appearing anywhere in a diagram could suppress an unrelated flow.
- DREAD mappings drifted from rule semantics, and the first two ranked findings were forced to Critical below the stated threshold.
- Usability observations were counted alongside security vulnerabilities.
- Report fields were inserted into HTML without systematic escaping.
- Reusable modules printed errors or exited the process, and tests were primarily demonstrations rather than assertions.
- The broad design gave runtime roles to ZAP and threat-intelligence components that do not match their normal architectural use.

## Original approach

The general parser extracted quoted actors and participants, request and response arrows, sections, and a title. A notes-specific matcher applied selected rule IDs through handwritten keyword checks. STRIDE supplied the core taxonomy, additional SaaS categories extended it, DREAD supplied historical ranking, and report modules produced HTML and JSON. Countermeasure records and eight figures documented possible mitigations.

The archive's nine-finding JSON is preserved unchanged. It is historical generated output, not nine independently validated vulnerabilities. In particular, two availability entries use the same evidence, the session-timeout entry cites missing audit logging, the privilege entry treats ordinary delete/export language as administrative, and password feedback/new-device notification are better separated from directly exploitable findings.

## Main threat-modeling methods

- Data-flow and sequence-diagram review across explicit trust boundaries.
- Identification of attacker-controlled browser, form, cookie, identifier, export, and repeated-request inputs.
- STRIDE-oriented discovery, with separate security, privacy, resilience, and usability classifications.
- Historical DREAD traceability without treating the score as an objective probability.
- A modern qualitative likelihood-impact matrix with documented prerequisites, impact, residual risk, validation method, and status.
- Stable threat and rule identifiers connecting diagrams, reports, implementation controls, and tests.

## Important risk themes

The modern register emphasizes credential attacks; authentication and session lifecycle; CSRF; broken object-level authorization; role escalation; stored/reflected XSS; SQL injection; unsafe output; error and log disclosure; database and key compromise; request, authentication, and storage exhaustion; repudiation; administrative misuse; deployment configuration; supply-chain integrity; and retention/privacy.

Severity is not derived from STRIDE category or number of matches. The register has no Critical item. Credential attacks remain High because password reuse can cross an account boundary despite local throttling and no MFA is implemented; other controlled or operational scenarios are Medium or Low. Unvalidated analyzer observations receive no severity.

## Modernization decisions

The handoff uses a byte-preserving evidence curation rather than rewriting originals. Every ZIP entry has a disposition, and exact duplicates are identified by SHA-256.

The analyzer is separated into parsing, schema validation, contextual evaluation, risk scoring, and rendering. It retains source line and interaction evidence, reports unsupported syntax, raises typed exceptions from reusable code, orders output deterministically, and labels matches as diagram indicators. The HTML renderer escapes all dynamic content.

The reference application uses a compact server-rendered FastAPI design. Opaque server-side sessions were selected over JWTs because direct expiry and revocation are simpler for one local service. SQLAlchemy provides parameterized queries, SQLite keeps the demonstration runnable, Argon2id protects passwords, and AES-GCM protects note title/body fields with per-operation nonces and owner/note/field-bound authenticated data.

OWASP ZAP is treated as an out-of-band authorized test tool. Kafka, SIEM, MISP/TAXII, OAuth providers, production notification delivery, and production key services are not claimed.

## Demonstrated mitigations

- Registration and login with a documented password policy, Argon2id hashes, generic authentication failure, account/client throttling, and temporary lockout.
- Fresh opaque sessions stored only as hashes, `HttpOnly`/`SameSite` cookies, `Secure` cookies in test and production modes, rotation at authentication, idle/absolute expiry, and logout revocation.
- Signed double-submit CSRF tokens on public authentication forms and session-bound values on authenticated browser mutations.
- Owner-scoped note list/read/update/delete/export queries and server-side role enforcement.
- AES-GCM encryption of title and body with unique nonces, authenticated additional data, and key-version metadata.
- Request, title, body, note-count, export-scope, and pagination bounds.
- Autoescaped pages, escaped analyzer HTML, generic error responses, correlation IDs, and security headers.
- Structured audit records for authentication, logout, note actions, export, and administrative denial without note bodies or secrets.

## Verification status

The handoff is verified with full Pytest and Ruff runs from the repository root, deterministic report regeneration, an evidence-manifest reconciliation, a local Uvicorn HTTP smoke test, and final secret/cache/claim searches. Exact commands, tool versions, results, and unavailable optional tools are recorded in [`docs/verification.md`](docs/verification.md). The control-to-implementation-to-test mapping is in [`docs/control-traceability.md`](docs/control-traceability.md).

## Limitations

The application is a local single-process reference implementation. It does not demonstrate distributed throttling, production key management or rotation, MFA, production email, OAuth provider integration, external security telemetry, high availability, disaster recovery, formal penetration testing, or verified retention and backup erasure. SQLite metadata, password hashes, audit rows, and ciphertext sizes remain visible to a database-file attacker. A compromised application process or combined key-and-database compromise defeats note confidentiality.

These limits are part of the threat model rather than omitted claims. Implementation detail is documented in [`docs/implementation-decisions.md`](docs/implementation-decisions.md), and unresolved operational risk is listed in [`docs/limitations.md`](docs/limitations.md).
