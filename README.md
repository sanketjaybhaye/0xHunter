# 0xHunter

Bug bounty and ethical hacking workspace: targets, findings, notes, methodology checklist, recon scratchpad, payloads, and report generation.

## Requirements

- Python 3.10+
- See [requirements.txt](requirements.txt)

## Setup

```bash
cd 0xHunter
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
python init_db.py
python create_admin.py admin your-secure-password
```

## Run (development)

```bash
set SECRET_KEY=your-random-secret
set FLASK_DEBUG=1
python app.py
```

Open http://127.0.0.1:5000 and sign in.

## Production

```bash
set SECRET_KEY=long-random-secret
set FLASK_DEBUG=0
set DATABASE_PATH=/path/to/database.sqlite
gunicorn -w 2 -b 0.0.0.0:5000 app:app
```

Use HTTPS behind a reverse proxy (nginx, Caddy). The v1 auth model is a **shared team workspace** (same data for all logged-in users), not per-user isolation.

## Features

- **Targets** — programs, scope, platform filters, edit/delete
- **Findings** — list + Kanban board, CSV export, severity filters, link to program
- **Notes** — autosave, search, categories
- **Checklist** — 70+ methodology items across 6 categories
- **Recon** — per-target asset list with status
- **Hunt Kit** — HTTP client + curl, security header analyzer, Google/Shodan dorks, open-redirect tester, cookie parser, URL deduper, subdomain generator, diff tool, CVE quick reference
- **Bookmarks** — save program URLs and docs (included in export)
- **Scope checker** — in/out of scope against active targets
- **Report generator** — Markdown export
- **Utilities** — encoders, JWT decode, hashes, regex, wordlists, payloads
- **Global search** — top bar search across targets, findings, notes

## Backup

Use **Export** in the sidebar for JSON backup. **Import** replaces all workspace data in the database.

## Environment variables

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Flask session signing key (required in production) |
| `FLASK_DEBUG` | `1` for debug mode, `0` for production |
| `DATABASE_PATH` | SQLite file path (default: `database.sqlite`) |
| `PORT` | HTTP port (default: `5000`) |
