# Notes Threat Model Portfolio

This repository preserves a 2025 sequence-diagram threat-modeling prototype, corrects its main analytical weaknesses, and adds a separate runnable notes application that demonstrates selected controls. Historical files remain byte-identical under `original_evidence/`; modern code and reports are clearly separated from that evidence.

## What is included

- A complete 51-entry archive disposition manifest and hashes for 27 retained artifacts.
- A typed, deterministic PlantUML threat analyzer with contextual rules, schema validation, line-level evidence, qualitative risk scoring, JSON output, and escaped HTML output.
- A FastAPI/SQLite notes application with Argon2id passwords, hashed opaque sessions, CSRF protection, owner-scoped CRUD/export, server-side RBAC, AES-GCM note encryption, bounded inputs, local throttling, security headers, and structured audit records.
- Automated tests and a control-to-code-to-test traceability table.

The notes application and modern analyzer are new reference implementations. They are not presented as code from the original internship-era archive.

## Repository layout

| Path | Purpose |
|---|---|
| `original_evidence/` | Curated byte-identical historical source, models, reports, figures, and complete disposition manifests |
| `src/threat_analyzer/` | Modern parser, rule evaluator, risk model, reporters, and CLI |
| `src/notes_app/` | Secure notes reference application |
| `config/` | Validated threat rules and the machine-readable modern register |
| `docs/` | Assessment, threat model, flows, register, decisions, traceability, demo guide, and diagrams |
| `tests/` | Analyzer and application security assertions |
| `reports/` | Regenerated deterministic JSON and HTML analysis |

## Setup on Windows

Python 3.12 or newer is required. From the repository root in PowerShell:

```powershell
py -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

The application reads process environment variables directly; `.env.example` is a reference rather than an automatically loaded secrets file.

## Run the threat analyzer

```powershell
& .\.venv\Scripts\python.exe -m threat_analyzer analyze `
  docs\diagrams\original-insecure-flow.puml `
  --rules config\threat_rules.json `
  --json reports\updated-threat-report.json `
  --html reports\updated-threat-report.html
```

The report schema is version `1.1`. Observations are diagram-derived review indicators: an omitted control is not reported as a confirmed source-code vulnerability, and unvalidated observations are not assigned the threat register's scenario severity. The parser supports a documented subset and reports unsupported syntax as warnings. Unless `--register` is supplied, the CLI loads `threat_register.json` beside the `--rules` file.

## Run the notes application

Generate an ephemeral local key and start the app from the repository root:

```powershell
$env:NOTES_MASTER_KEY = & .\.venv\Scripts\python.exe scripts\generate_development_key.py
$env:NOTES_ENV = "development"
& .\.venv\Scripts\python.exe scripts\run_demo.py
```

Open `http://127.0.0.1:8000/register`. The default database is `notes-demo.db` in the current directory. Stop the process with `Ctrl+C`, then remove the local database when it is no longer needed.

No accounts or passwords are seeded. Register a local user through the UI. The administrative boundary is deliberately narrow and is verified with an ephemeral admin role in the automated RBAC test; no reusable admin credential is included.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `NOTES_MASTER_KEY` | Required | URL-safe base64 value decoding to exactly 32 bytes |
| `NOTES_DATABASE_URL` | `sqlite+pysqlite:///notes-demo.db` | SQLAlchemy database URL |
| `NOTES_ENV` | `development` | `development`, `test`, or `production`; test and production enable `Secure` cookies and HSTS |
| `NOTES_SESSION_IDLE_SECONDS` | `900` | Server-side idle lifetime |
| `NOTES_SESSION_ABSOLUTE_SECONDS` | `28800` | Maximum session lifetime |
| `NOTES_LOGIN_MAX_FAILURES` | `5` | Account and client-address failure threshold |
| `NOTES_LOCKOUT_SECONDS` | `900` | Temporary lockout duration |
| `NOTES_MAX_REQUEST_BYTES` | `20000` | Application request-body limit |
| `NOTES_MAX_NOTES_PER_USER` | `100` | Per-user note-count quota |

`NOTES_ENV` defaults to `development`; only that mode omits the cookie `Secure` flag for the documented loopback HTTP demonstration. Test and production modes require HTTPS-capable clients. The launcher rejects a non-loopback development or test binding. Any non-local use requires HTTPS, an explicit `NOTES_ENV=production`, and the operational controls described in `SECURITY.md`.

## Run verification

```powershell
& .\.venv\Scripts\python.exe -m pytest -q
& .\.venv\Scripts\ruff.exe check .
& .\.venv\Scripts\ruff.exe format --check .
```

The same checks run on Python 3.12 and 3.13 in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

Actual handoff results and the smoke-test method are recorded in [`docs/verification.md`](docs/verification.md).

## Security scope and limitations

This is a single-process local demonstration, not a production deployment. It does not implement distributed rate limiting, MFA, production KMS/HSM custody, production email, OAuth, Kafka, SIEM, MISP/TAXII, multi-region operation, disaster recovery, or verified retention/backup erasure. A database-file attacker cannot read note plaintext without the key, but database metadata remains visible; an attacker with both database and key can decrypt notes.

Start with the [repository threat model](docs/threat-model.md), [modern threat register](docs/threat-register.md), [control traceability table](docs/control-traceability.md), [implementation pseudocode](docs/pseudocode.md), and [five-to-ten-minute demo guide](docs/demo-guide.md). Vulnerability-reporting scope and security invariants are in [SECURITY.md](SECURITY.md).
