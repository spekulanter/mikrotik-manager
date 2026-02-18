# MikroTik Manager - Codex AGENTS Guide

This file defines how Codex should work in this repository.
Project facts are shared with Claude and come from `CLAUDE.md`.

## Source of Truth

1. `AGENTS.md` - Codex workflow and execution rules
2. `CLAUDE.md` - project architecture, security model, API behavior, deployment notes
3. Source code (especially `app.py`) - final implementation truth

Conflict resolution:
- Codex working style/process -> follow `AGENTS.md`
- Project behavior/security/contracts -> follow `CLAUDE.md` and code

## Project Snapshot

- App: Flask-based MikroTik RouterOS manager (single main app in `app.py`)
- Core modules: device management, backups, monitoring (ICMP + SNMP), notifications
- Auth: username/password + mandatory TOTP 2FA flow
- Data: SQLite database in `/var/lib/mikrotik-manager/data`
- Secrets: `secret.key` and `encryption.key` stored in data dir (chmod 600)
- Frontend: server-rendered HTML templates + vanilla JS + Chart.js

For full details (DB schema, routes, settings keys, deployment, troubleshooting), read `CLAUDE.md`.

## Codex Workflow For This Repo

1. Read only relevant sections from `CLAUDE.md` before edits.
2. Keep changes minimal and targeted; avoid broad refactors in `app.py` unless required.
3. Preserve security invariants:
   - do not weaken auth/2FA
   - do not store plaintext credentials
   - do not bypass encryption helpers
4. For database changes:
   - prepare migration-safe edits
   - preserve compatibility with existing `init_database()` behavior
5. Prefer existing project patterns:
   - `add_log()` for persistent logs
   - SocketIO emits for real-time frontend updates
   - parameterized SQL queries
6. Validate impacted flows after edits (manual smoke tests):
   - login + 2FA
   - add/edit device
   - backup trigger
   - monitoring data endpoints/UI

## Files To Treat Carefully

Do not manually edit runtime secrets/data files:
- `/var/lib/mikrotik-manager/data/secret.key`
- `/var/lib/mikrotik-manager/data/encryption.key`
- `/var/lib/mikrotik-manager/data/mikrotik_manager.db` (except deliberate migrations)

Safe to modify when required:
- `app.py`
- `*.html`
- `static/js/*`
- `requirements.txt`
- `template/*` (Android template)

## Sync Policy (CLAUDE <-> AGENTS)

- Canonical shared documentation: `CLAUDE.md`
- Codex-specific delta and workflow: `AGENTS.md`
- After updating `CLAUDE.md`, run:

`bash sync-agents.sh`

This regenerates `AGENTS.md` with updated metadata and keeps both docs aligned without duplicating full content.

## Metadata

- Synced on: 2026-02-18
- Source file: `CLAUDE.md`
- Source SHA256: `84443098a679e20098ebf489cfa65050f7e68cb56e79f9c34059797b5e5c27e3`
