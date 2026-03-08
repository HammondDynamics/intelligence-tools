# Gabriel

Automated strategic monitoring system that aggregates multiple data sources into a scored threat assessment delivered on a fixed schedule.

## Architecture

- **Server-deployed daemon** — runs on VPS via systemd (auto-restart, boot persistence)
- **4-desk pipeline** — each desk independently scores its domain, results are aggregated into a composite threat score
- **Sleep-calculated scheduler** — computes exact seconds until next event and sleeps once (no CPU-burning poll loops)
- **Sensor failure awareness** — distinguishes between "everything is fine" and "we can't see anything" to prevent false reassurance

## Desks

| Desk | Source | Scoring |
|------|--------|---------|
| Alpha | REST API (raw JSON, no library dependencies) | 0-40 points based on configurable thresholds |
| Bravo | 4x RSS feeds with regex keyword matching | 0-50 points, pre-filtered feeds scored as single signal to prevent inflation |
| Charlie | REST API | Informational (no score contribution) |
| Delta | REST API — 5 monitored routes | 0-30 points based on week-over-week variance |

## Threat Scoring

| Score | Level |
|-------|-------|
| 0-34 | NOMINAL |
| 35-64 | ELEVATED |
| 65+ | HIGH RISK |
| 5+ sensors offline | DEGRADED (SENSOR FAILURE) |

The DEGRADED state is critical — it prevents the system from reporting NOMINAL when data sources are actually dead. A score of 0 with failed sensors means "we can't see" not "everything is fine."

## Pre-filtered Feed Handling

RSS feeds with search terms baked into the URL are guaranteed to match keywords on every article. Scoring each article individually would max out the signal score every cycle regardless of actual conditions.

**Solution:** Feeds marked `pre_filtered: True` contribute a maximum of 1 hit (10 points) regardless of how many articles match. Non-pre-filtered feeds score per-article as normal.

| Feed Type | Scoring |
|-----------|---------|
| General RSS | 10 points per matching article (capped at 50) |
| Pre-filtered RSS | 10 points total (single confirmation signal) |

## Scheduler

| Event | Day | Time | Content |
|-------|-----|------|---------|
| Full briefing | Monday | 08:00 UTC | All 4 desks + composite score + directive |
| Full briefing | Thursday | 08:00 UTC | All 4 desks + composite score + directive |
| Boot briefing | On startup | Immediate | Tests all connections, sets baselines |

No polling. No wasted CPU cycles. One `time.sleep()` call per cycle.

## Features

- Composite threat scoring across multiple independent data domains
- Pre-filtered feed detection to prevent score inflation
- Persistent baselines with atomic writes for week-over-week comparison
- Telegram delivery with rate-limit retry and multi-user broadcast
- Rotating log files (2MB, 3 backups)
- Connection pooling via shared `requests.Session()`
- Auto node detection (Windows / Linux / Android)
- Graceful degradation when optional API tokens are missing

## Tech Stack

- Python 3.10+
- `requests` / `beautifulsoup4` / `python-dotenv` / `feedparser`
- Telegram Bot API
- systemd for process management

## Deployment

Runs as a systemd service on Linux. Credentials loaded from `.env`. Memory state persisted in JSON with atomic writes. Designed to run indefinitely with zero maintenance.
