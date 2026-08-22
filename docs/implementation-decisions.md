# Implementation Decisions

## Evidence is immutable and separate

The original archive is not edited. Relevant distinct artifacts are copied byte-for-byte into `original_evidence/`, while `MANIFEST.json` records every original ZIP entry, including directories, caches, duplicates, and nested archives. Excluded entries remain accountable through their original path, hash, classification, and exclusion reason. This prevents modernization work from being misrepresented as 2025 source.

## A constrained parser instead of a general PlantUML engine

The analyzer supports only the declaration, section, note, and request/response constructs it can represent with line-level evidence. A security rule engine should not silently invent semantics for an unfamiliar diagram construct. Warnings make coverage limits visible, and the CLI never sends a diagram to a network renderer.

## Contextual rule evaluation

The historical matcher often searched the entire diagram for a control keyword. That can let a rate-limit annotation on one endpoint suppress a finding on every endpoint. Modern rules select an interaction and examine evidence local to that interaction or explicitly linked context. Findings are described as diagram indicators, because a diagram omission is not implementation proof.

## Qualitative likelihood and impact

The modern register uses a fixed matrix rather than automatically changing the first ranked findings to Critical. Likelihood documents prerequisites and realistic reachability; impact documents the affected security property and scope. STRIDE remains a discovery taxonomy. Historical DREAD values are preserved only with historical evidence and are not recomputed as authoritative scores.

## Server-rendered FastAPI application

Server-rendered Jinja2 pages keep the demonstration small and make browser security boundaries visible. A JavaScript framework would add a second dependency and rendering surface without improving the controls being demonstrated. Templates rely on autoescaping, and destructive actions use forms rather than GET requests.

## Opaque server-side sessions

Opaque random tokens are simpler than JWTs for one service with a local database. The database stores only a token hash and authoritative expiry/revocation state. This permits immediate logout revocation and avoids token algorithm, audience, signing-key, and stale-claim failure modes. It does add a database lookup per protected request, which is acceptable for the demonstration.

## Argon2id password hashing

Argon2id is deliberately memory-hard and is provided by `argon2-cffi`. Parameters are encoded with each hash so they can be reviewed and upgraded. The application uses a dummy verification path for an unknown identity and a generic external failure message. Local attempt controls bound repeated work but do not replace an edge service in production.

## AES-GCM field encryption

Titles and bodies are encrypted separately so listing can decrypt only required data, and each operation receives a unique random nonce. Authenticated additional data binds the ciphertext to owner, note public identifier, field, and key version. Moving ciphertext to another record or field therefore fails authentication. The 32-byte key comes from environment configuration and is never committed. Production key custody, envelope encryption, and managed rotation remain outside scope.

## Owner scoping in database queries

Every single-note query includes both public UUID and authenticated owner ID. This keeps the authorization condition at the shared data-access boundary. UUIDs reduce accidental enumeration but are explicitly not treated as authorization.

## Local roles and a narrow admin surface

Roles are stored with the account and read by the server. The demonstration includes one intentionally limited administrative endpoint so RBAC can be tested without inventing a full administration product. UI link visibility is only presentation; direct-route tests verify the server-side boundary.

## SQLite for a reproducible demonstration

SQLite makes the project runnable without external infrastructure and enables a direct test that note plaintext is absent from the database file. It does not provide production concurrency, centralized access controls, remote audit durability, or managed backups. SQLAlchemy keeps query construction parameterized and allows a future database change without changing the core authorization rule.

## Structured local audit records

Audit events are stored locally with constrained metadata. This makes security decisions and tests visible without claiming SIEM forwarding. The schema excludes passwords, note bodies, keys, raw session tokens, and CSRF values. A database administrator can modify the rows; append-only remote storage is a future operational control.

## Deterministic reports and snapshots

Analyzer fixtures and generated reports omit wall-clock timestamps. Stable identifiers, sorted collections, explicit schema versions, and canonical JSON settings make changes reviewable. The final repository identity is derived from sorted relative paths and SHA-256 hashes rather than a fabricated Git commit.

