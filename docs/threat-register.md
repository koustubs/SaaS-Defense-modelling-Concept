# Threat Register

## Purpose and evidence states

This register describes repository-scoped risks for the modern analyzer and local notes reference application. Its machine-readable source is [`config/threat_register.json`](../config/threat_register.json), which is schema-validated and embedded by the report generator. Stable threat IDs are used by analyzer rules, implementation traceability, and tests.

A diagram-derived observation is a review indicator. Absence of a control from a diagram is not proof that source code lacks the control, and a control label is not proof that an implementation works. Status therefore refers to the modern repository evidence:

| Status | Meaning |
|---|---|
| Demonstrated | The named local control is implemented and has an automated verification path. |
| Partially demonstrated | A local control is implemented and tested, but production or distributed aspects remain outside scope. |
| Planned | The control is documented but is not claimed as implemented. |

Security, privacy, resilience, and usability classifications remain separate. The modern vulnerability count does not include a usability observation merely because it relates to a security decision.

## Qualitative likelihood-impact matrix

Likelihood records realistic reachability and prerequisites after accounting for controls verified in the current repository. Impact records the affected asset, security property, and scope. Neither STRIDE category, keyword count, evidence count, historical DREAD value, nor finding rank changes the matrix result. A diagram observation is unvalidated and receives no severity; the ratings below apply to the threat scenario. Each entry's status describes the implementation evidence for its control.

| Likelihood \ Impact | Low | Medium | High |
|---|---:|---:|---:|
| Low | Low | Low | Medium |
| Medium | Low | Medium | High |
| High | Medium | High | Critical |

The current register contains no Critical entry. Critical is reserved for a reachable, systemic compromise such as a remote authentication bypass exposing all users and administrator capability, not an automatically promoted top-ranked item.

## Modern register

### TM-001 — An internet attacker uses credential stuffing or repeated password guesses to take over an account

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Spoofing |
| Affected asset | User credentials and accounts |
| Threat scenario | An internet attacker uses credential stuffing or repeated password guesses to take over an account. |
| Preconditions | A valid account identifier is known or guessed and password authentication is reachable. |
| Trust boundary | Browser to application and authentication/session boundary |
| Evidence source | The original sequence model explicitly shows repeated failed logins and no lockout; this is design evidence, not source-code verification. |
| Likelihood | Medium |
| Impact | High |
| Overall severity | High |
| Existing control / historical state | The historical model includes credential validation but does not establish throttling or lockout for the affected flow. |
| Planned or demonstrated control | Generic authentication failures, per-account and per-client throttling, temporary lockout, and strong password hashing. |
| Residual risk | Distributed low-rate attempts and reuse of passwords compromised elsewhere remain possible. |
| Validation method | Automated login-failure, rate-limit, lockout, and generic-response tests. |
| Status | Partially demonstrated |

### TM-002 — A caller reaches a protected note operation without a valid authenticated session

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Spoofing |
| Affected asset | Session-protected notes and user identity |
| Threat scenario | A caller reaches a protected note operation without a valid authenticated session. |
| Preconditions | A protected route omits or incorrectly performs server-side session validation. |
| Trust boundary | Authentication/session boundary |
| Evidence source | The original insecure model includes an unauthenticated notes request; absence of a check in a diagram is not proof of an implementation defect. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | Token validation is modeled for sync but not consistently for every notes flow. |
| Planned or demonstrated control | Central server-side session validation on every protected route with fail-closed behavior. |
| Residual risk | Authentication middleware defects or accidentally unprotected future routes remain possible. |
| Validation method | Unauthenticated access tests for each protected route and route-inventory review. |
| Status | Demonstrated |

### TM-003 — A stolen, fixed, replayed, or non-revoked session token is used to impersonate a user

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Spoofing |
| Affected asset | Opaque session tokens |
| Threat scenario | A stolen, fixed, replayed, or non-revoked session token is used to impersonate a user. |
| Preconditions | An attacker obtains a token or the application fails to rotate, expire, or revoke it. |
| Trust boundary | Browser to application and authentication/session boundary |
| Evidence source | The historical model returns and stores an auth token without documenting storage, rotation, expiry, or revocation properties. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | The diagram names an auth token but does not establish secure lifecycle controls. |
| Planned or demonstrated control | Opaque random tokens, server-side token hashes, secure cookie attributes, rotation, idle and absolute expiry, and logout revocation. |
| Residual risk | A token stolen from a compromised browser remains usable until detected, revoked, or expired. |
| Validation method | Session creation, rotation, idle and absolute expiry, and logout-revocation tests. |
| Status | Demonstrated |

### TM-004 — A malicious site causes an authenticated browser to submit an unwanted state-changing request

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Tampering |
| Affected asset | Notes, account state, and session state |
| Threat scenario | A malicious site causes an authenticated browser to submit an unwanted state-changing request. |
| Preconditions | Cookie-authenticated state-changing endpoints accept requests without a valid anti-CSRF token. |
| Trust boundary | Browser to application |
| Evidence source | The original sequence model contains browser POST and DELETE requests but does not model CSRF validation; this is a review gap, not confirmation. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | No anti-CSRF property is established by the historical diagram. |
| Planned or demonstrated control | Cryptographically random session-bound CSRF tokens validated on every state-changing browser request. |
| Residual risk | Cross-site scripting or a compromised browser can bypass token-based CSRF protection. |
| Validation method | Missing and invalid CSRF-token rejection tests plus valid-token state-changing request tests. |
| Status | Demonstrated |

### TM-005 — A malicious authenticated user changes a note identifier or export request to read or modify another user's data

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Information Disclosure |
| Affected asset | Other users' note titles, bodies, and exports |
| Threat scenario | A malicious authenticated user changes a note identifier or export request to read or modify another user's data. |
| Preconditions | A data query uses a public note ID without also constraining the authenticated owner ID. |
| Trust boundary | Authenticated user to application and application to database |
| Evidence source | The insecure historical model queries all notes and does not model object ownership checks. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | No object-level authorization is established in the original insecure sequence. |
| Planned or demonstrated control | Owner-scoped database queries for every read, update, delete, list, and export operation. |
| Residual risk | Authorization regressions in new query paths remain a high-consequence risk. |
| Validation method | Cross-user read, update, delete, and export denial tests. |
| Status | Demonstrated |

### TM-006 — A normal user invokes an administrative operation or changes effective role state

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Elevation of Privilege |
| Affected asset | Administrator privileges and user administration |
| Threat scenario | A normal user invokes an administrative operation or changes effective role state. |
| Preconditions | An administrative route trusts client state or omits a server-side role check. |
| Trust boundary | Normal-user to administrative functions |
| Evidence source | The original model includes administrator actions without showing role enforcement at each action. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | An Admin actor is named, but actor naming alone is not an authorization control. |
| Planned or demonstrated control | Server-side role checks on all administrative routes with denied-access audit events. |
| Residual risk | Compromise of a legitimate administrator account still grants intended administrative authority. |
| Validation method | Normal-user denial and intended-admin success tests. |
| Status | Demonstrated |

### TM-007 — Attacker-controlled note content executes script when stored or reflected into a page

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Tampering |
| Affected asset | Browser sessions and rendered note content |
| Threat scenario | Attacker-controlled note content executes script when stored or reflected into a page. |
| Preconditions | Untrusted text reaches an HTML execution context without context-appropriate escaping. |
| Trust boundary | Browser to application and application to browser |
| Evidence source | The historical model notes missing input validation but does not establish an exploitable rendering path. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | No output-rendering guarantee can be inferred from the sequence model. |
| Planned or demonstrated control | Template autoescaping, text-only rendering, a restrictive content security policy, and no unsafe HTML insertion. |
| Residual risk | Future rich-text features or unsafe template changes could introduce execution contexts. |
| Validation method | Stored XSS-shaped payload rendering tests plus template review. |
| Status | Demonstrated |

### TM-008 — SQL-shaped attacker input changes a database query rather than being treated as data

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Tampering |
| Affected asset | Database records and authentication data |
| Threat scenario | SQL-shaped attacker input changes a database query rather than being treated as data. |
| Preconditions | Application input is concatenated into SQL or an unsafe raw query. |
| Trust boundary | Application to database |
| Evidence source | The historical sequence model does not contain source-level database query evidence, so implementation status requires code review and tests. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | No source implementation is assessed by the diagram analyzer. |
| Planned or demonstrated control | Parameterized ORM queries, constrained raw-SQL use, and treatment of SQL-shaped strings as ordinary note data. |
| Residual risk | Future hand-written queries or unsafe migration tooling can reintroduce injection paths. |
| Validation method | SQL-injection-shaped input tests and static review for query construction. |
| Status | Demonstrated |

### TM-009 — Attacker-controlled output is inserted into HTML, CSV, or another active context without safe encoding

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Information Disclosure |
| Affected asset | Note content and browser security context |
| Threat scenario | Attacker-controlled output is inserted into HTML, CSV, or another active context without safe encoding. |
| Preconditions | A renderer treats untrusted text as markup or fails to encode for the destination context. |
| Trust boundary | Application to browser and export boundary |
| Evidence source | The original flow displays notes but does not document output encoding; diagram absence is only a review signal. |
| Likelihood | Low |
| Impact | Medium |
| Overall severity | Low |
| Existing control / historical state | No output-encoding property is established by the historical sequence diagram. |
| Planned or demonstrated control | Context-appropriate escaping in HTML reports, templates, and exports with no direct untrusted HTML interpolation. |
| Residual risk | New output formats require their own encoding and formula-injection analysis. |
| Validation method | Malicious report-field and note-output escaping tests. |
| Status | Demonstrated |

### TM-010 — An error response exposes secrets, database detail, stack traces, or sensitive field names

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Information Disclosure |
| Affected asset | Credentials, internal schema, and implementation details |
| Threat scenario | An error response exposes secrets, database detail, stack traces, or sensitive field names. |
| Preconditions | An attacker can trigger a failure whose internal detail is returned externally. |
| Trust boundary | Application to browser |
| Evidence source | The original insecure model explicitly returns an error naming a password field and labels it sensitive. |
| Likelihood | Low |
| Impact | Medium |
| Overall severity | Low |
| Existing control / historical state | The historical insecure flow demonstrates the disclosure rather than a mitigation. |
| Planned or demonstrated control | Generic external errors with correlation IDs and separately protected internal diagnostic logging. |
| Residual risk | Operational logs can still disclose sensitive context if log fields are not curated. |
| Validation method | Failure-path tests that reject stack traces, SQL detail, and sensitive values in responses. |
| Status | Demonstrated |

### TM-011 — Sensitive values are written to application or audit logs and exposed to operators or log systems

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Information Disclosure |
| Affected asset | Passwords, note bodies, keys, CSRF values, and session tokens |
| Threat scenario | Sensitive values are written to application or audit logs and exposed to operators or log systems. |
| Preconditions | Logging captures raw requests, secrets, note content, or exception context without redaction. |
| Trust boundary | Application to monitoring or notification adapter |
| Evidence source | The archive models security logging but does not prove field-level redaction or a runnable external adapter. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | Historical logging concepts do not establish what data is logged. |
| Planned or demonstrated control | Structured allow-listed audit fields that exclude passwords, note bodies, keys, tokens, and CSRF values. |
| Residual risk | Unexpected exception text or future fields can bypass an incomplete redaction policy. |
| Validation method | Audit-record content tests and logging-field review. |
| Status | Demonstrated |

### TM-012 — An attacker with database-file access reads sensitive stored data or alters security state

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Information Disclosure |
| Affected asset | Encrypted notes, password hashes, user identifiers, and audit records |
| Threat scenario | An attacker with database-file access reads sensitive stored data or alters security state. |
| Preconditions | The database file, backup, or storage volume is copied or exposed. |
| Trust boundary | Application to database |
| Evidence source | Database compromise is an explicit repository threat-model assumption; the sequence diagram alone cannot validate storage controls. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | The historical notes database is named but its at-rest protection is not established. |
| Planned or demonstrated control | Authenticated encryption for note titles and bodies, hardened password hashes, and restricted database-file access. |
| Residual risk | Metadata, audit records, and password hashes remain exposed; offline password guessing remains possible. |
| Validation method | SQLite plaintext-absence and cryptographic tests plus documented deployment file-custody review. |
| Status | Partially demonstrated |

### TM-013 — An attacker obtains or replaces the encryption key and decrypts or corrupts stored notes

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Information Disclosure |
| Affected asset | Note-encryption master key and decrypted note content |
| Threat scenario | An attacker obtains or replaces the encryption key and decrypts or corrupts stored notes. |
| Preconditions | Runtime environment configuration, deployment secrets, or host memory is compromised. |
| Trust boundary | Application to encryption-key source |
| Evidence source | The compact reference scope requires an environment-provided key and explicitly excludes production KMS or HSM integration. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | No production key-management integration is claimed. |
| Planned or demonstrated control | A 32-byte environment-provided key, AES-GCM with unique nonces and associated data, plus key-version metadata. |
| Residual risk | Host or environment compromise exposes the active key; rotation is operational rather than automated. |
| Validation method | Configuration validation, nonce/associated-data tests, and documented production key-management review. |
| Status | Partially demonstrated |

### TM-014 — Repeated requests consume CPU, database connections, or endpoint capacity until legitimate work is delayed

| Field | Value |
|---|---|
| Classification | resilience |
| STRIDE category | Denial of Service |
| Affected asset | Application availability and authentication capacity |
| Threat scenario | Repeated requests consume CPU, database connections, or endpoint capacity until legitimate work is delayed. |
| Preconditions | An attacker can make sustained requests and controls are absent or only single-keyed. |
| Trust boundary | Browser to application |
| Evidence source | The historical model explicitly labels an export flow as lacking rate limiting. |
| Likelihood | Medium |
| Impact | Medium |
| Overall severity | Medium |
| Existing control / historical state | No distributed infrastructure is present; the original insecure flow documents missing throttling. |
| Planned or demonstrated control | Login-specific per-account and per-client throttles, bounded request bodies, and per-user note quotas in one process. |
| Residual risk | Database-backed throttle state persists, but check/update serialization is process-local and is not a distributed or edge rate limiter. |
| Validation method | Login-throttle burst and concurrency tests plus production design review for distributed limiting. |
| Status | Partially demonstrated |

### TM-015 — An attacker sends an oversized request body that consumes memory, parsing time, or storage

| Field | Value |
|---|---|
| Classification | resilience |
| STRIDE category | Denial of Service |
| Affected asset | Application memory, request workers, and storage |
| Threat scenario | An attacker sends an oversized request body that consumes memory, parsing time, or storage. |
| Preconditions | The HTTP stack or application accepts bodies larger than the intended note limits. |
| Trust boundary | Browser to application |
| Evidence source | Large-body behavior is in the modern threat scope but is not represented by the historical sequence diagram. |
| Likelihood | Low |
| Impact | Medium |
| Overall severity | Low |
| Existing control / historical state | No request-body limit can be inferred from diagram evidence. |
| Planned or demonstrated control | Reject requests above a documented maximum before expensive parsing or database work. |
| Residual risk | Upstream servers may buffer bodies before application code sees them. |
| Validation method | Maximum and oversized request-body tests plus deployment proxy configuration review. |
| Status | Demonstrated |

### TM-016 — A user creates excessive notes or large cumulative content to exhaust storage and degrade queries

| Field | Value |
|---|---|
| Classification | resilience |
| STRIDE category | Denial of Service |
| Affected asset | Per-user note storage and database capacity |
| Threat scenario | A user creates excessive notes or large cumulative content to exhaust storage and degrade queries. |
| Preconditions | An authenticated user can create notes without count, length, or storage constraints. |
| Trust boundary | Authenticated user to application and application to database |
| Evidence source | The original flow creates notes without documenting a quota; absence in a sequence diagram is not confirmation. |
| Likelihood | Medium |
| Impact | Medium |
| Overall severity | Medium |
| Existing control / historical state | No quota property is established by the historical sequence model. |
| Planned or demonstrated control | Title/body length limits, a per-user note-count quota, bounded pagination, and user-scoped exports. |
| Residual risk | Many accounts can collectively consume storage; the count quota is application-level and is not a database-enforced atomic quota across multiple workers. |
| Validation method | Boundary-length, per-user quota, pagination, and export-scope tests. |
| Status | Demonstrated |

### TM-017 — A user or administrator denies a sensitive action and the operator lacks a trustworthy event record

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Repudiation |
| Affected asset | Audit records and accountability for sensitive actions |
| Threat scenario | A user or administrator denies a sensitive action and the operator lacks a trustworthy event record. |
| Preconditions | Authentication or note operations are not recorded with actor, action, outcome, and correlation context. |
| Trust boundary | Application to database or audit adapter |
| Evidence source | The historical insecure model explicitly labels note creation as having no audit logging. |
| Likelihood | Low |
| Impact | Medium |
| Overall severity | Low |
| Existing control / historical state | Some historical diagrams mention security logs, but the insecure notes flow explicitly lacks an audit event. |
| Planned or demonstrated control | Structured records for authentication, logout, note changes, export, and denied admin access without sensitive payloads. |
| Residual risk | Local audit records can be altered by a host or database administrator and are not an external immutable log. |
| Validation method | Action-to-audit tests and inspection that forbidden secret fields are absent. |
| Status | Demonstrated |

### TM-018 — A legitimate or compromised administrator performs excessive access or destructive actions beyond operational need

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Elevation of Privilege |
| Affected asset | Administrator privileges, user data, and audit visibility |
| Threat scenario | A legitimate or compromised administrator performs excessive access or destructive actions beyond operational need. |
| Preconditions | An administrator account is compromised or administrative authority is too broad and weakly monitored. |
| Trust boundary | Normal-user to administrative functions and operator boundary |
| Evidence source | The historical architecture includes an Admin actor with provisioning and security-tool actions but no least-privilege analysis. |
| Likelihood | Low |
| Impact | Low |
| Overall severity | Low |
| Existing control / historical state | A distinct Admin actor is modeled; this does not prove least privilege or monitoring. |
| Planned or demonstrated control | Narrow server-side RBAC, explicit administrative routes, and audit events for access and denials. |
| Residual risk | The demonstration has a simple role model and does not implement approval workflows or privileged-access management. |
| Validation method | Admin authorization tests, denied-access audit tests, and manual least-privilege review. |
| Status | Partially demonstrated |

### TM-019 — Unsafe configuration enables debug disclosure, insecure cookies, weak limits, or accidental use of development secrets

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Elevation of Privilege |
| Affected asset | Application configuration, cookie policy, debug state, and secrets |
| Threat scenario | Unsafe configuration enables debug disclosure, insecure cookies, weak limits, or accidental use of development secrets. |
| Preconditions | Deployment accepts missing, malformed, or unsafe environment settings. |
| Trust boundary | Development/testing environment to deployed runtime |
| Evidence source | Deployment configuration is not represented by the historical sequence model and must be assessed in code and runtime settings. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | The analyzer makes no claim about deployment configuration state. |
| Planned or demonstrated control | Fail-fast configuration validation, `Secure` cookies in test and production modes, rejection of non-loopback development or test bindings, no committed real key, and debug disabled. |
| Residual risk | Operators can still select unsafe settings or expose environment configuration at the host layer. |
| Validation method | Master-key rejection and production-cookie tests plus deployment checklist review. |
| Status | Partially demonstrated |

### TM-020 — A compromised dependency or build input executes malicious code or alters security behavior

| Field | Value |
|---|---|
| Classification | security |
| STRIDE category | Tampering |
| Affected asset | Application source, dependencies, build inputs, and runtime integrity |
| Threat scenario | A compromised dependency or build input executes malicious code or alters security behavior. |
| Preconditions | A trusted package, source input, or build environment is compromised or insufficiently reviewed. |
| Trust boundary | Development/testing environment to deployed runtime |
| Evidence source | Supply-chain risk is part of the modern repository scope and is not asserted as a historical finding. |
| Likelihood | Low |
| Impact | High |
| Overall severity | Medium |
| Existing control / historical state | No production build or dependency-monitoring system is claimed by this portfolio demonstration. |
| Planned or demonstrated control | A bounded dependency list, review of updates, and optional vulnerability scanning when available. |
| Residual risk | A trusted upstream release or developer environment can still be compromised. |
| Validation method | Dependency inventory, lock/declaration review, and recorded scanner execution when tools are available. |
| Status | Planned |

### TM-021 — Personal data is retained longer than intended, included unnecessarily in exports or logs, or not deleted consistently

| Field | Value |
|---|---|
| Classification | privacy |
| STRIDE category | Information Disclosure |
| Affected asset | Note content, exports, identifiers, profile data, and audit records |
| Threat scenario | Personal data is retained longer than intended, included unnecessarily in exports or logs, or not deleted consistently. |
| Preconditions | Retention rules are undefined, deletion is incomplete, or exports include data beyond the requesting user's scope. |
| Trust boundary | Application to database and user-scoped export boundary |
| Evidence source | The archive contains cleanup and export concepts but does not establish a retention policy or verified deletion semantics. |
| Likelihood | Medium |
| Impact | Medium |
| Overall severity | Medium |
| Existing control / historical state | A timed cleanup participant exists historically, but its policy and implementation are not verified. |
| Planned or demonstrated control | User-scoped export and deletion behavior, data minimization, and an explicit production retention decision outside the demo scope. |
| Residual risk | Backups, audit retention, and legal deletion requirements are not implemented by the compact local demonstration. |
| Validation method | User-scoped export tests, deletion tests, and documented retention-policy review. |
| Status | Partially demonstrated |

## Historical DREAD appendix

The following values are copied from the byte-identical [historical nine-finding JSON](../original_evidence/reports/threat_report_20250710_152215.json). They are retained for traceability and were not recalculated. In the historical scorer, the first two ranked findings were forced to `Critical` even though both weighted scores were 7.27 and the declared Critical threshold began at 8.0. These values are not objective probabilities or current severity decisions.

| Historical ID | Rule ID | Title | Weighted DREAD | Normal DREAD | Historical severity | Current interpretation |
|---|---|---|---:|---:|---|---|
| TF-SD-003 | STRIDE-D-002 | Resource exhaustion through unlimited operations | 7.27 | 7.2 | Critical | Security/resilience; overlaps TF-SD-002 and reuses the same rate-limit evidence. |
| TF-SD-004 | STRIDE-E-001 | User can access admin functions without proper authorization | 7.27 | 7 | Critical | Security; authorization concern is important, but ordinary delete/export actions were overgeneralized as administrative. |
| TF-SD-002 | STRIDE-D-001 | No rate limiting on API endpoints | 7.18 | 7.4 | High | Security/resilience; one explicit missing-rate-limit annotation was extended heuristically to many flows. |
| TF-SD-005 | STRIDE-E-002 | Session management without proper timeout | 6.55 | 6.4 | High | Security; the session-timeout title is supported by audit-logging evidence, so the historical match is semantically misaligned. |
| TF-SD-001 | STRIDE-I-001 | Sensitive data exposed in error messages | 6 | 5.8 | High | Security/privacy; the model shows excessive field detail, though no password value is disclosed. |
| TF-SD-006 | SAAS-NOTES-008 | No multi-factor authentication (MFA) option | 6 | 5.8 | High | Security hardening; the diagram explicitly says no 2FA, but implementation status was not established. |
| TF-SD-007 | SAAS-NOTES-009 | No account lockout after repeated failed logins | 5.73 | 5.8 | Medium | Security; repeated failures and absence of lockout are explicitly modeled. |
| TF-SD-009 | SAAS-NOTES-018 | No password strength indicator | 5.73 | 5.8 | Medium | Usability with security relevance; a strength indicator is not server-side password enforcement. |
| TF-SD-008 | SAAS-NOTES-017 | No new device login notification | 3.91 | 4 | Low | Detection/resilience/usability; a notification can aid detection but its absence is not authentication bypass. |

See [original-work-assessment.md](original-work-assessment.md) for the full technical assessment and [control-traceability.md](control-traceability.md) for modern code and test evidence.
