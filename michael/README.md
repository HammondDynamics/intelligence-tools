# Archangel

Multi-node early warning system with automated threat detection and hardware failsafe alerts.

## Architecture

- **Multi-node deployment** — runs simultaneously on laptop and mobile (Termux) with automatic node detection
- **Redundant target arrays** — dual-method reachability testing (HTTP + raw TCP socket on port 53)
- **Tiered alert system** — GREEN / YELLOW / ORANGE / RED with escalating response actions
- **Hardware failsafe** — infinite-loop physical alarm (audio + visual + vibration) when software alerts cannot be delivered
- **Emergency mode** — dynamic polling frequency that increases automatically when threats are detected

## Features

- Automated data collection from multiple independent sources
- Cross-referencing and correlation across data streams to reduce false positives
- Persistent memory with atomic writes (crash-safe JSON state management)
- Duplicate suppression across polling cycles
- Connection pooling via shared `requests.Session()`
- Rotating log files (2MB, 3 backups)
- Daily heartbeat / proof-of-life reporting
- Telegram alerting with multi-user broadcast and rate-limit retry handling
- Platform-aware hardware alarms (Windows: system-modal dialog + TTS / Android: torch strobe + vibration loop)

## Alert Logic

The system monitors multiple independent data streams. Each stream is a binary tripwire. The number of simultaneous trips determines the alert level:

| Trips | Level | Behavior |
|-------|-------|----------|
| 0 | GREEN | Silent. No alert. |
| 1 | YELLOW | Telegram alert. Normal polling continues. |
| 2 | ORANGE | Telegram alert. Emergency polling activated. |
| 3 | RED | Telegram alert. Emergency polling activated. |
| Alerting unreachable | BLACK | Hardware alarm triggered. Infinite loop until manual abort. |

## Infrastructure Canary

The network diagnostic uses a split-horizon approach with two independent target arrays:

**Targets:**
- Array A: 5x HTTP endpoints
- Array B: 5x HTTP endpoints + 2x raw TCP port 53

**Cross-reference logic:**

| Array A | Array B | Diagnosis |
|---------|---------|-----------|
| ✅ UP | ✅ UP | Normal — all routes operational |
| ❌ DOWN | ✅ UP | Network partition detected → Hardware alarm |
| ❌ DOWN | ❌ DOWN | Device offline → Silent (no false alarm) |
| ✅ UP | ❌ DOWN | Routing anomaly → Alert |

## Tech Stack

- Python 3.10+
- `requests` / `beautifulsoup4` / `python-dotenv`
- Telegram Bot API
- Platform-specific alerting (`winsound` + `ctypes` on Windows, `termux-api` on Android)

## Deployment

Designed for always-on operation via `tmux` (mobile) or background process (laptop). Auto-detects platform and adjusts node name and alarm method accordingly.

Credentials are loaded from `.env` (not hardcoded). Memory state is persisted in JSON with atomic writes to prevent corruption on power loss.
