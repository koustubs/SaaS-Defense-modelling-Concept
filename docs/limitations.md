# Limitations

## Demonstration scope

The notes application is intended for local technical review in a single process. It has not undergone formal penetration testing and is not described as production-ready. An internet deployment needs HTTPS termination, process supervision, restrictive service and filesystem identities, secure backups, edge request controls, dependency operations, centralized monitoring, and a managed secret/key service.

## Authentication

- MFA is not implemented. A real addition would require enrollment verification, TOTP secret protection, recovery codes, replay handling, step-up policy, reset flows, and tests.
- CAPTCHA, breached-password checking, production email, new-device notification, and account-recovery delivery are not implemented.
- Local account and client-address throttles use database-backed state with process-local serialization. The state survives an ordinary process restart but is lost if the local database is replaced; it does not coordinate safely across replicas or defeat a distributed attack.
- A targeted attacker may deliberately trigger temporary lockout for a known account. Production policy must balance brute-force resistance with account-denial risk.

## Sessions and browsers

- A stolen session can be replayed until it expires or is revoked. The application cannot defend a fully compromised browser or endpoint.
- `Secure` cookies require HTTPS and are enabled in test and production modes; only development mode omits the flag for loopback HTTP. Correct environment selection, TLS, and proxy configuration remain operator responsibilities.
- SameSite policy and CSRF tokens address ordinary browser requests; unusual embedded or cross-origin deployment models would need a separate review.

## Encryption and storage

- One environment-provided master key protects all note fields. There is key-version metadata but no managed KMS/HSM, envelope encryption, automated rotation, escrow, or per-tenant key.
- An attacker with both database and active key can decrypt notes. A compromised application process can observe plaintext during legitimate use.
- Encryption does not hide account metadata, note ownership, timestamps, ciphertext sizes, access patterns, or audit metadata.
- SQLite deletion does not prove that plaintext-derived or ciphertext bytes are gone from free pages, journal files, filesystem snapshots, or backups. Verified retention and erasure are outside scope.
- Exports are plaintext for the authenticated user and leave application control after download.

## Availability and scale

- SQLite and a single process are not a high-availability or high-concurrency design.
- Body, field, note-count, and pagination limits reduce local abuse but do not stop volumetric denial of service.
- Login has local account and client-address throttles. Registration and ordinary application routes have no separate request-rate limit, and audit/session/account rows have no retention quota; non-local deployment requires edge limits and operational retention controls.
- A request without a trustworthy `Content-Length` is counted one ASGI chunk at a time and consumption stops after crossing the application limit. The HTTP server has already allocated each delivered chunk, so a production server or reverse proxy must also enforce its own streaming limit before large chunks or bodies reach the application.
- The per-user note quota uses an application-level count in the supported single process. It is not a database-enforced atomic quota across multiple workers and must be redesigned before horizontally scaling the service.
- Full disaster recovery, multi-region deployment, backup restore testing, and capacity benchmarks were not performed.

## Audit and operations

- Audit records share the application database and are not append-only against an operator or database attacker.
- No Kafka, SIEM, MISP/TAXII, pager, production email, or automated incident-response adapter is implemented.
- Correlation identifiers aid local diagnosis but do not provide distributed tracing.

## Threat analyzer

- The parser implements a documented PlantUML subset rather than the full language. Warnings require reviewer attention.
- The local CLI does not impose a separate adversarial file-size limit on diagram or JSON inputs. Do not expose it directly as an unauthenticated upload service without adding bounded streaming and deployment controls.
- Rule evaluation is heuristic. A match indicates diagram evidence worth review, not a confirmed source-code vulnerability.
- A missing control in a sequence diagram may reflect modeling scope rather than missing implementation. Conversely, a control label does not prove correct implementation.
- Qualitative ratings depend on documented assumptions and should be revisited when exposure, deployment, or controls change.
- Historical DREAD scores are preserved for traceability but are not objective probabilities or current severity decisions.

## External tools and validation

PlantUML image rendering is optional and not required to run either package. OWASP ZAP belongs in a separately authorized dynamic-test environment. Optional dependency and static-analysis tools are reported only when actually run; their absence is not presented as a pass.
