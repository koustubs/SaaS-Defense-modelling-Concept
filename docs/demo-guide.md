# Demonstration Guide

This walkthrough is designed for a short technical review. Run commands from the repository root in PowerShell after completing the setup in `README.md`.

## 1. Inspect the original evidence

Open [`../original_evidence/README.md`](../original_evidence/README.md) and [`../original_evidence/MANIFEST.json`](../original_evidence/MANIFEST.json).

Point out that:

- The source ZIP digest was recomputed before curation.
- All 51 entries remain represented in the disposition manifest.
- The 27 retained artifacts are byte-identical; duplicates, caches, and repeating nested ZIPs are recorded rather than silently deleted.
- The modern code is outside `original_evidence/` and is not presented as 2025 work.

## 2. Open the historical report

Open [`../original_evidence/reports/threat_report.html`](../original_evidence/reports/threat_report.html) or inspect the preserved [`threat_report_20250710_152215.json`](../original_evidence/reports/threat_report_20250710_152215.json).

Explain that the nine entries are historical generated observations, not nine independently validated vulnerabilities. The first two were forced to Critical by rank even though their weighted DREAD values were below the declared Critical threshold. The exact calibration is in [`original-work-assessment.md`](original-work-assessment.md).

Historical HTML files were not rewritten, so an image link that assumed the old directory layout may not resolve. The authoritative figures remain in `original_evidence/figures/`.

## 3. Explain one original insecure flow

Open [`diagrams/original-insecure-flow.puml`](diagrams/original-insecure-flow.puml) beside the preserved [`../original_evidence/models/sample_notes_app.uml`](../original_evidence/models/sample_notes_app.uml).

Use the unauthenticated listing as the example:

1. The browser sends `GET /api/notes` without credentials.
2. The notes service queries notes without an owner constraint being shown.
3. The database returns all notes.

The defensible conclusion is that the historical diagram intentionally models missing authentication and owner scope. It is not evidence about an unseen deployed codebase.

## 4. Run the modern analyzer

```powershell
& .\.venv\Scripts\python.exe -m threat_analyzer analyze `
  docs\diagrams\original-insecure-flow.puml `
  --rules config\threat_rules.json `
  --json reports\updated-threat-report.json `
  --html reports\updated-threat-report.html
```

The shipped inputs produce nine diagram observations, embed all 21 modern register entries, and produce no parser warning or Critical observation. Open `reports/updated-threat-report.html` and show:

- Stable `OBS-*`, `RULE-*`, and `TM-*` identifiers.
- Exact source line and interaction evidence.
- The `diagram-indicator` evidence basis and non-confirmation notice.
- Separate security/resilience classification.
- Escaped HTML and the absence of rank-forced severity.

The CLI loads `config/threat_register.json` automatically because it is beside the rules file. `--register` can select another validated register explicitly.

## 5. Start the notes application

```powershell
$env:NOTES_MASTER_KEY = & .\.venv\Scripts\python.exe scripts\generate_development_key.py
$env:NOTES_ENV = "development"
& .\.venv\Scripts\python.exe scripts\run_demo.py
```

Open `http://127.0.0.1:8000/register`. Keep the server terminal visible for the remainder of the browser demonstration. No account is pre-seeded.

## 6. Demonstrate registration and login

Register a temporary username with a password of at least 12 characters, then sign in. Explain the server-side controls:

- Argon2id password hashing.
- Generic login rejection for both unknown users and bad passwords.
- Account- and client-address failure tracking with temporary lockout.
- A fresh opaque session token whose database representation is only an HMAC digest.
- `HttpOnly` and `SameSite=Lax` cookies, with `Secure` enabled in test and production modes.
- Idle and absolute server-side expiry plus logout revocation.

Do not use a real personal password in the demonstration.

## 7. Demonstrate note CRUD

Create a note containing a recognizable temporary title and body. Then:

1. Return to the paginated list.
2. Read the note.
3. Edit both fields.
4. Select Delete and show the confirmation page.
5. Cancel once, then confirm deletion with the POST action.
6. Create another temporary note and use Export.

Explain that every single-note database query includes both note public UUID and authenticated owner ID. The UUID is not treated as authorization. State-changing forms carry a token bound to the current server-side session, and Jinja2 renders note content as escaped text.

## 8. Demonstrate cross-user denial

The fastest reproducible demonstration is the focused assertion that creates Alice's encrypted note, signs in as Bob, and checks list, read, edit, delete, and export isolation:

```powershell
& .\.venv\Scripts\python.exe -m pytest -q `
  tests\app\test_notes.py::test_owner_scope_blocks_cross_user_read_update_delete_and_export
```

The test expects Bob's list and export to omit Alice's note, neutral not-found responses for direct foreign-note operations, and an unchanged Alice-owned database row.

## 9. Demonstrate login lockout

```powershell
& .\.venv\Scripts\python.exe -m pytest -q `
  tests\app\test_authentication.py::test_account_and_address_lockout_is_temporary
```

The deterministic clock test submits repeated bad passwords, verifies that correct credentials are rejected during the temporary lockout using the same generic response, advances past the configured deadline, and verifies successful login.

## 10. Show encrypted note storage

```powershell
& .\.venv\Scripts\python.exe -m pytest -q `
  tests\app\test_security_controls.py::test_note_plaintext_is_absent_from_sqlite_file `
  tests\app\test_security_controls.py::test_corrupted_ciphertext_returns_generic_correlated_error `
  tests\app\test_crypto.py
```

The storage test writes unique plaintext sentinels and confirms neither appears in the SQLite bytes. The cryptographic unit tests verify random nonce variation, owner/note/field/version authenticated-data binding, and exact key configuration validation. The corrupted-ciphertext route test verifies that altered ciphertext is rejected through a generic correlated error. This demonstrates application-layer field encryption, not production key custody.

## 11. Show control traceability

Open [`control-traceability.md`](control-traceability.md). Select one high-risk boundary, such as `TM-005`, and follow it across:

1. Original diagram evidence.
2. The modern threat-register entry.
3. Owner-scoped implementation code.
4. The cross-user test.
5. Residual regression risk.

The same pattern covers analyzer controls such as contextual matching and HTML escaping.

## 12. Explain limitations accurately

Finish with [`limitations.md`](limitations.md) and the exclusions in [`../SECURITY.md`](../SECURITY.md). Emphasize:

- Single-process throttling and quota behavior are not distributed infrastructure controls.
- Application body checks do not replace an edge/server streaming limit for chunked uploads.
- The environment key is not a production KMS/HSM or automated rotation design.
- MFA, production email, Kafka, SIEM, MISP/TAXII, OAuth, multi-region recovery, and formal penetration testing are not claimed.
- SQLite deletion does not prove erasure from free pages, snapshots, or backups.
- A compromised process, or compromise of both database and active key, defeats note confidentiality.

Stop the application with `Ctrl+C`. Delete `notes-demo.db` and clear the temporary `NOTES_MASTER_KEY` from the shell when the local review is complete.
