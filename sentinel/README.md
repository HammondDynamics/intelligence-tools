# SENTINEL

Real-time CVE monitoring daemon that watches public vulnerability databases for threats targeting a defined technology stack. Sends instant alerts to Telegram when critical vulnerabilities are disclosed.

Built for personal operational security. Runs 24/7 on a Hetzner VPS in production.

---

## What It Does

SENTINEL polls the NIST National Vulnerability Database (NVD) API on a fixed schedule, cross-references every new CVE against a configurable list of technologies, and pushes formatted alerts directly to Telegram based on severity.

- **CRITICAL / HIGH** (CVSS 7.0+) → Immediate Telegram alert
- **MEDIUM** (CVSS 4.0–6.9) → Queued into a daily digest
- **LOW** → Ignored

CVEs flagged in CISA's Known Exploited Vulnerabilities catalog are detected automatically via NVD metadata and marked as actively exploited in the alert.

---

## Architecture

    ┌──────────────────────────────────────────────────┐
    │                  HETZNER VPS                      │
    │              (Debian / systemd)                   │
    │                                                   │
    │   ┌───────────┐       ┌──────────────────────┐   │
    │   │ SENTINEL  │──────▶│  NVD API 2.0         │   │
    │   │ daemon    │◀──────│  (NIST)              │   │
    │   │           │       └──────────────────────┘   │
    │   │           │                                   │
    │   │           │──────▶ Telegram Bot API ─────▶ 📱 │
    │   │           │                                   │
    │   │           │◀─────▶ sentinel_memory.json       │
    │   └───────────┘       (persistent state)          │
    └──────────────────────────────────────────────────┘

---

## Alert Examples

### Critical CVE Alert

    🔴 SENTINEL: CRITICAL CVE DETECTED

    CVE-2026-XXXXX
    CVSS: 9.8 (CRITICAL)
    Product: OpenSSH
    Vendor: OpenBSD

    DESCRIPTION:
    Remote code execution vulnerability in OpenSSH allows
    unauthenticated attackers to execute arbitrary code...

    🚨 CISA KEV: YES (Actively Exploited)
    Patch Deadline: 2026-04-01
    Required Action: Apply vendor patch.

    Matched: openssh, rce, remote code execution
    Source: NVD

    🔗 CVE-2026-XXXXX Details

### Daily Digest

    🛡️ SENTINEL DAILY DIGEST

    New CVEs in last 24h affecting your stack: 3
    - 🟠 CVE-2026-1111 (HIGH 7.5) — nginx: buffer overflow
    - 🟠 CVE-2026-2222 (HIGH 8.1) — Linux Kernel: privilege escalation
    - 🟡 CVE-2026-3333 (MEDIUM 6.5) — Python: urllib SSRF

    CISA KEV additions: 0

    ✅ All systems nominal. No critical patches required.

---

## Monitored Stack

| Category | Technologies |
|----------|-------------|
| Operating Systems | Windows 10/11, Ubuntu 24.04, Linux kernel, Android |
| Services | OpenSSH, Nginx, Node.js |
| Languages / Packages | Python (CPython), pip, npm |
| Network | Mullvad VPN, WireGuard, Telegram API |
| Threat Terms | zero-day, RCE, privilege escalation, actively exploited |

Technologies are matched using two methods:
1. **CPE prefix matching** — precise product identification using NVD's Common Platform Enumeration data
2. **Keyword matching** — fallback for CVEs where CPE data is incomplete or missing

A configurable blocklist filters out noise from unrelated projects that happen to share keyword matches.

---

## Design

| Component | Detail |
|-----------|--------|
| Data source | NVD API 2.0 (NIST) — sole source, no API key required |
| CISA KEV detection | Via NVD metadata fields (cisaExploitAdd, cisaActionDue) |
| Polling interval | Every 4 hours |
| Daily digest | 09:00 UTC |
| State management | JSON file with atomic writes (write to .tmp, then os.replace) |
| Duplicate suppression | Seen CVE IDs persisted to disk, capped at 10,000 entries |
| Deployment | systemd service with auto-restart and boot persistence |
| Alerting | Telegram Bot API with 429 rate-limit handling and retry logic |
| Failure handling | API failures logged and skipped; 24h outage triggers offline alert |

---

## Deployment

Runs as a systemd daemon on a Hetzner cloud VPS. The service auto-restarts on failure and survives reboots.

**Requirements:**
- Python 3.10+
- requests
- python-dotenv
- Telegram bot token

---

## Status

**In production.** Running 24/7 since March 2026.

---

## Related

This is one component of a broader personal intelligence platform:

- **GABRIEL** — Strategic OSINT monitoring and alerting system
- **ARCHANGEL** — Mobile tactical tripwire running on Android

All three systems share a common alerting pipeline and code architecture.
