#!/usr/bin/env python3
"""
SENTINEL — CVE / Vulnerability Alert Daemon
Monitors CISA KEV and NVD for vulnerabilities affecting the operator's stack.
Sends real-time Telegram alerts for HIGH/CRITICAL findings.
Sends a daily digest at 09:00 UTC.

Consistent with Archangel (radar.py) and Gabriel (gabriel.py) code patterns.
"""

import json
import logging
import os
import platform
import socket
import sys
import time
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from dotenv import load_dotenv

# ──────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────

MEMORY_FILE = Path(__file__).parent / "sentinel_memory.json"
LOG_FILE = Path(__file__).parent / "sentinel.log"
ENV_FILE = Path(__file__).parent / ".env"


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Polling intervals (seconds)
NVD_INTERVAL_HOURS = 4
DIGEST_HOUR_UTC = 9  # 09:00 UTC daily digest

# CVSS thresholds
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0

# NVD rate limiting: 5 requests per 30 seconds without key,
# 50 per 30 seconds with key.
NVD_REQUEST_DELAY_NO_KEY = 6.5   # seconds between NVD requests (no key)
NVD_REQUEST_DELAY_WITH_KEY = 0.7  # seconds between NVD requests (with key)

# Telegram retry
TELEGRAM_RETRY_WAIT = 60  # seconds

# Sensor-offline threshold
SENSOR_OFFLINE_HOURS = 24

# ──────────────────────────────────────────────────────────────────────
# MONITORED TECHNOLOGY STACK
# ──────────────────────────────────────────────────────────────────────

MONITORED_KEYWORDS: Dict[str, List[str]] = {
    "os": ["windows 10", "windows 11", "windows", "ubuntu", "linux kernel",
           "android"],
    "server": ["nginx", "openssh", "node.js", "nodejs", "node js"],
    "language": ["python", "pip", "npm"],
    "network": ["mullvad", "wireguard", "openvpn", "telegram"],
    "app": ["termux", "big-agi", "big agi"],
    "critical_terms": [
        "zero-day", "0-day", "zero day",
        "remote code execution", "rce",
        "privilege escalation",
        "actively exploited",
    ],
}

# Flattened lowercase keyword set for fast matching
_ALL_KEYWORDS: Set[str] = set()
for _group in MONITORED_KEYWORDS.values():
    for _kw in _group:
        _ALL_KEYWORDS.add(_kw.lower())
# Products to ignore even if they match a keyword
IGNORED_PRODUCTS = {
    "ormar", "psd-tools", "psd_tools", "langflow", "agenta",
    "n8n", "yt-dlp", "yt_dlp", "label-studio", "label_studio",
    "gradio", "streamlit", "mlflow", "airflow", "prefect",
    "dbt", "great_expectations", "kedro", "bentoml", "ray",
}
MONITORED_CPES: List[str] = [
    "cpe:2.3:o:microsoft:windows",
    "cpe:2.3:o:canonical:ubuntu",
    "cpe:2.3:o:linux:linux_kernel",
    "cpe:2.3:a:openbsd:openssh",
    "cpe:2.3:a:f5:nginx",
    "cpe:2.3:a:nginx:nginx",
    "cpe:2.3:a:python:python",
    "cpe:2.3:a:python_software_foundation:python",
    "cpe:2.3:a:nodejs:node.js",
    "cpe:2.3:a:openjs_foundation:node.js",
    "cpe:2.3:o:google:android",
    "cpe:2.3:a:mullvad:mullvad_vpn",
    "cpe:2.3:a:telegram:telegram",
]

# ──────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────

logger = logging.getLogger("sentinel")
logger.setLevel(logging.DEBUG)

_fmt = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_fh = RotatingFileHandler(
    LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(_fmt)
logger.addHandler(_fh)

_ch = logging.StreamHandler(sys.stdout)
_ch.setLevel(logging.INFO)
_ch.setFormatter(_fmt)
logger.addHandler(_ch)

# ──────────────────────────────────────────────────────────────────────
# ENVIRONMENT VALIDATION
# ──────────────────────────────────────────────────────────────────────

load_dotenv(ENV_FILE)

SENTINEL_TOKEN: str = os.getenv("SENTINEL_TOKEN", "")
YOUR_CHAT_ID: str = os.getenv("YOUR_CHAT_ID", "")
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

if not SENTINEL_TOKEN:
    logger.critical("SENTINEL_TOKEN not set in .env — aborting.")
    sys.exit(1)

if not YOUR_CHAT_ID:
    logger.critical("YOUR_CHAT_ID not set in .env — aborting.")
    sys.exit(1)

CHAT_IDS: List[str] = [cid.strip() for cid in YOUR_CHAT_ID.split(",") if cid.strip()]

if NVD_API_KEY:
    logger.info("NVD API key loaded — using higher rate limits.")
    NVD_REQUEST_DELAY = NVD_REQUEST_DELAY_WITH_KEY
else:
    logger.info("No NVD API key — using conservative rate limits.")
    NVD_REQUEST_DELAY = NVD_REQUEST_DELAY_NO_KEY

NODE_NAME = f"{platform.system()}/{socket.gethostname()}"

# ──────────────────────────────────────────────────────────────────────
# HTTP SESSION
# ──────────────────────────────────────────────────────────────────────

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
})

TELEGRAM_BASE = f"https://api.telegram.org/bot{SENTINEL_TOKEN}"

# ──────────────────────────────────────────────────────────────────────
# MEMORY MANAGEMENT
# ──────────────────────────────────────────────────────────────────────

DEFAULT_MEMORY: Dict[str, Any] = {
    "last_kev_count": 0,
    "seen_cve_ids": [],
    "last_nvd_check": None,
    "last_cisa_check": None,
    "last_cisa_success": None,
    "last_nvd_success": None,
    "last_digest_date": None,
    "digest_queue": [],
}


def load_memory() -> Dict[str, Any]:
    """Load memory from disk, returning defaults if missing or corrupt."""
    if not MEMORY_FILE.exists():
        logger.info("No memory file found — starting fresh.")
        return dict(DEFAULT_MEMORY)
    try:
        with open(MEMORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Ensure all keys exist (forward-compatible)
        for key, default in DEFAULT_MEMORY.items():
            if key not in data:
                data[key] = default if not isinstance(default, list) else list(default)
        logger.info(
            "Memory loaded: %d seen CVEs, last KEV count %d.",
            len(data["seen_cve_ids"]),
            data["last_kev_count"],
        )
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Corrupt memory file, resetting: %s", exc)
        return dict(DEFAULT_MEMORY)


def save_memory(memory: Dict[str, Any]) -> None:
    """Atomic write: tmp file then os.replace."""
    tmp_path = MEMORY_FILE.with_suffix(".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(memory, f, indent=2, default=str)
        os.replace(tmp_path, MEMORY_FILE)
        logger.debug("Memory saved (%d seen CVEs).", len(memory["seen_cve_ids"]))
    except OSError as exc:
        logger.error("Failed to save memory: %s", exc)


# ──────────────────────────────────────────────────────────────────────
# TELEGRAM
# ──────────────────────────────────────────────────────────────────────

def send_telegram(text: str, parse_mode: str = "HTML") -> bool:
    """Send a message to all configured chat IDs. Handles 429 rate limits."""
    success = True
    for chat_id in CHAT_IDS:
        sent = _send_single(chat_id, text, parse_mode)
        if not sent:
            success = False
    return success


def _send_single(chat_id: str, text: str, parse_mode: str) -> bool:
    """Send to one chat ID with retry on 429."""
    
    if len(text) > 4000:
        text = text[:3997] + "..."

    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }

    for attempt in range(2):
        try:
            resp = session.post(
                f"{TELEGRAM_BASE}/sendMessage",
                json=payload,
                timeout=30,
            )
            if resp.status_code == 200:
                logger.debug("Telegram message sent to %s.", chat_id)
                return True
            if resp.status_code == 429:
                retry_after = resp.json().get("parameters", {}).get(
                    "retry_after", TELEGRAM_RETRY_WAIT
                )
                logger.warning(
                    "Telegram 429 — waiting %d seconds (attempt %d).",
                    retry_after, attempt + 1,
                )
                time.sleep(retry_after)
                continue
            logger.error(
                "Telegram error %d: %s", resp.status_code, resp.text[:300]
            )
            if attempt == 0:
                time.sleep(TELEGRAM_RETRY_WAIT)
                continue
            return False
        except requests.RequestException as exc:
            logger.error("Telegram request failed: %s", exc)
            if attempt == 0:
                time.sleep(TELEGRAM_RETRY_WAIT)
                continue
            return False
    return False


# ──────────────────────────────────────────────────────────────────────
# CVE MATCHING LOGIC
# ──────────────────────────────────────────────────────────────────────

def matches_stack_keywords(text: str) -> List[str]:
    """Return list of matched keywords found in text."""
    if not text:
        return []
    text_lower = text.lower()
    matched = []
    for kw in _ALL_KEYWORDS:
        if kw in text_lower:
            matched.append(kw)
    return matched


def matches_stack_cpe(cpe_nodes: List[Dict]) -> List[str]:
    """Walk NVD CPE configuration nodes and return matched CPE prefixes."""
    matched = []
    cpe_strings = _extract_cpe_strings(cpe_nodes)
    for cpe_str in cpe_strings:
        cpe_lower = cpe_str.lower()
        for prefix in MONITORED_CPES:
            if cpe_lower.startswith(prefix):
                matched.append(prefix)
    return list(set(matched))


def _extract_cpe_strings(nodes: List[Dict]) -> List[str]:
    """Recursively extract all CPE match strings from NVD configuration nodes."""
    results: List[str] = []
    for node in nodes:
        for cpe_match in node.get("cpeMatch", []):
            criteria = cpe_match.get("criteria", "")
            if criteria:
                results.append(criteria)
        # Recurse into nested nodes
        for child_node in node.get("nodes", []):
            results.extend(_extract_cpe_strings([child_node]))
    return results


def extract_cvss_score(metrics: Dict) -> Tuple[float, str]:
    """Extract the highest CVSS score from NVD metrics. Returns (score, version)."""
    best_score = 0.0
    best_version = "N/A"

    # Try CVSS v3.1 first, then v3.0, then v2.0
    for key, ver in [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]:
        metric_list = metrics.get(key, [])
        for m in metric_list:
            cvss_data = m.get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            if score > best_score:
                best_score = score
                best_version = ver

    return best_score, best_version


def severity_label(score: float) -> str:
    """Return human-readable severity label."""
    if score >= CVSS_CRITICAL:
        return "CRITICAL"
    if score >= CVSS_HIGH:
        return "HIGH"
    if score >= CVSS_MEDIUM:
        return "MEDIUM"
    return "LOW"


def severity_emoji(score: float) -> str:
    """Return severity emoji."""
    if score >= CVSS_CRITICAL:
        return "🔴"
    if score >= CVSS_HIGH:
        return "🟠"
    if score >= CVSS_MEDIUM:
        return "🟡"
    return "⚪"



# ──────────────────────────────────────────────────────────────────────
# NVD API
# ──────────────────────────────────────────────────────────────────────

def check_nvd(memory: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Query NVD for recently published CVEs matching our stack.
    Uses keyword search batches to stay within rate limits.
    Returns new relevant CVEs. Updates memory in-place.
    """
    logger.info("Checking NVD for new CVEs...")

    # Determine time window
    last_check_str = memory.get("last_nvd_check")
    if last_check_str:
        try:
            start_dt = datetime.fromisoformat(last_check_str)
        except (ValueError, TypeError):
            start_dt = datetime.now(timezone.utc) - timedelta(hours=NVD_INTERVAL_HOURS)
    else:
        # First run: look back 24 hours
        start_dt = datetime.now(timezone.utc) - timedelta(hours=24)

    # Ensure timezone-aware
    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=timezone.utc)

    end_dt = datetime.now(timezone.utc)

    # NVD API date format: 2026-03-09T00:00:00.000
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    pub_start = start_dt.strftime(fmt)
    pub_end = end_dt.strftime(fmt)

    now_iso = end_dt.isoformat()
    memory["last_nvd_check"] = now_iso

    # Search keywords
    search_terms = [
        "openssh",
        "nginx",
        "linux kernel",
        "cpython",
        "node.js",
        "android",
        "windows",
        "ubuntu",
        "mullvad",
        "telegram",
        "termux",
    ]

    seen_ids: Set[str] = set(memory["seen_cve_ids"])
    all_new: List[Dict[str, Any]] = []
    seen_this_run: Set[str] = set()  # Deduplicate across search terms

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    any_success = False

    for term in search_terms:
        params = {
            "keywordSearch": term,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": 100,
            "startIndex": 0,
        }

        try:
            resp = session.get(
                NVD_API_URL, params=params, headers=headers, timeout=60
            )
            if resp.status_code == 403:
                logger.warning("NVD 403 (rate limited) on term '%s' — skipping.", term)
                time.sleep(NVD_REQUEST_DELAY * 3)
                continue
            resp.raise_for_status()
            any_success = True
        except requests.RequestException as exc:
            logger.warning("NVD query failed for '%s': %s", term, exc)
            time.sleep(NVD_REQUEST_DELAY)
            continue

        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("NVD JSON parse failed for '%s': %s", term, exc)
            time.sleep(NVD_REQUEST_DELAY)
            continue

        vulnerabilities = data.get("vulnerabilities", [])
        logger.debug(
            "NVD term '%s': %d results (total: %s).",
            term,
            len(vulnerabilities),
            data.get("totalResults", "?"),
        )

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")

            if not cve_id or cve_id in seen_ids or cve_id in seen_this_run:
                continue

            seen_this_run.add(cve_id)

            # Extract description (English preferred)
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # Extract CVSS
            metrics = cve_data.get("metrics", {})
            cvss_score, cvss_version = extract_cvss_score(metrics)

            # Skip LOW severity
            if cvss_score > 0 and cvss_score < CVSS_MEDIUM:
                seen_ids.add(cve_id)
                continue

            # CPE matching
            configurations = cve_data.get("configurations", [])
            cpe_nodes = []
            for config in configurations:
                cpe_nodes.extend(config.get("nodes", []))
            matched_cpes = matches_stack_cpe(cpe_nodes)

            # Keyword matching (fallback or supplement)
            searchable = f"{description} {term}"
            matched_kw = matches_stack_keywords(searchable)

            if not matched_cpes and not matched_kw:
                
                seen_ids.add(cve_id)
                continue

            # Filter out noise
            searchable_lower = searchable.lower()
            if any(ignored in searchable_lower for ignored in IGNORED_PRODUCTS):
                if not matched_cpes:  # CPE match overrides blocklist
                    seen_ids.add(cve_id)
                    continue

            # Extract affected product info from CPE or description
            vendor_product = _extract_vendor_product(cpe_nodes, matched_cpes)

            # Check if NVD flags this CVE as CISA KEV
            cisa_exploit_add = cve_data.get("cisaExploitAdd", "")
            cisa_action_due = cve_data.get("cisaActionDue", "")
            cisa_required_action = cve_data.get("cisaRequiredAction", "")
            cisa_vuln_name = cve_data.get("cisaVulnerabilityName", "")
            is_kev = bool(cisa_exploit_add or cisa_action_due)

            # References
            references = cve_data.get("references", [])
            ref_url = ""
            for ref in references:
                ref_url = ref.get("url", "")
                break

            all_new.append({
                "cve_id": cve_id,
                "vendor": vendor_product.get("vendor", "Unknown"),
                "product": vendor_product.get("product", "Unknown"),
                "description": description,
                "cvss_score": cvss_score,
                "cvss_version": cvss_version,
                "source": "NVD",
                "matched_keywords": matched_kw,
                "matched_cpes": matched_cpes,
                "is_kev": is_kev,
                "due_date": cisa_action_due,
                "cisa_required_action": cisa_required_action,
                "cisa_vuln_name": cisa_vuln_name,
                "reference_url": ref_url or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve_data.get("published", ""),
            })
            seen_ids.add(cve_id)

        # Rate limiting between requests
        time.sleep(NVD_REQUEST_DELAY)

    if any_success:
        memory["last_nvd_success"] = now_iso

    memory["seen_cve_ids"] = list(seen_ids)

    logger.info("NVD: %d new CVEs match monitored stack.", len(all_new))
    return all_new


def _extract_vendor_product(
    cpe_nodes: List[Dict], matched_cpes: List[str]
) -> Dict[str, str]:
    """Try to extract a human-readable vendor/product from CPE data."""
    if matched_cpes:
        # Parse from first matched CPE prefix
        parts = matched_cpes[0].split(":")
        vendor = parts[3] if len(parts) > 3 else "Unknown"
        product = parts[4] if len(parts) > 4 else "Unknown"
        return {
            "vendor": vendor.replace("_", " ").title(),
            "product": product.replace("_", " ").title(),
        }
    return {"vendor": "Unknown", "product": "Unknown"}


# ──────────────────────────────────────────────────────────────────────
# ALERT FORMATTING
# ──────────────────────────────────────────────────────────────────────

def format_alert(vuln: Dict[str, Any]) -> str:
    """Format a single CVE alert for Telegram (HTML)."""
    cve_id = vuln["cve_id"]
    score = vuln.get("cvss_score")
    emoji = severity_emoji(score) if score else "⚠️"
    sev = severity_label(score) if score else "UNKNOWN"
    vendor = vuln.get("vendor", "Unknown")
    product = vuln.get("product", "Unknown")
    description = vuln.get("description", "No description available.")
    is_kev = vuln.get("is_kev", False)
    source = vuln.get("source", "")

    # Truncate description for readability
    if len(description) > 500:
        description = description[:497] + "..."

    score_str = f"{score:.1f}" if score else "N/A"
    ref_url = vuln.get(
        "reference_url", f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    )

    matched_kw = vuln.get("matched_keywords", [])
    match_str = ", ".join(matched_kw[:5]) if matched_kw else "CPE match"

    lines = [
        f"{emoji} <b>SENTINEL: {sev} CVE DETECTED</b>",
        "",
        f"<b>{cve_id}</b>",
        f"CVSS: {score_str} ({sev})",
        f"Product: {product}",
        f"Vendor: {vendor}",
        "",
        f"<b>DESCRIPTION:</b>",
        f"{description}",
        "",
    ]

    if is_kev:
        lines.append("🚨 <b>CISA KEV: YES (Actively Exploited)</b>")
        due = vuln.get("due_date", "")
        if due:
            lines.append(f"Patch Deadline: {due}")
        cisa_action = vuln.get("cisa_required_action", "")
        if cisa_action:
            lines.append(f"Required Action: {cisa_action}")
    else:
        lines.append("CISA KEV: No")

    lines.extend([
        "",
        f"Matched: {match_str}",
        f"Source: {source}",
        "",
        f"🔗 <a href=\"{ref_url}\">{cve_id} Details</a>",
    ])

    return "\n".join(lines)


def format_digest(
    high_critical: List[Dict[str, Any]],
    medium: List[Dict[str, Any]],
    kev_additions: int,
) -> str:
    """Format the daily digest message."""
    total = len(high_critical) + len(medium)

    lines = [
        "🛡️ <b>SENTINEL DAILY DIGEST</b>",
        "",
        f"New CVEs in last 24h affecting your stack: <b>{total}</b>",
    ]

    if high_critical:
        lines.append("")
        lines.append("<b>HIGH / CRITICAL:</b>")
        for v in high_critical[:15]:
            score = v.get("cvss_score", 0)
            score_str = f"{score:.1f}" if score else "N/A"
            sev = severity_label(score) if score else "?"
            emoji = severity_emoji(score) if score else "⚠️"
            product = v.get("product", "Unknown")
            desc_short = v.get("description", "")[:80]
            lines.append(
                f"{emoji} {v['cve_id']} ({sev} {score_str}) — {product}: {desc_short}"
            )

    if medium:
        lines.append("")
        lines.append("<b>MEDIUM:</b>")
        for v in medium[:10]:
            score = v.get("cvss_score", 0)
            score_str = f"{score:.1f}" if score else "N/A"
            product = v.get("product", "Unknown")
            lines.append(f"🟡 {v['cve_id']} ({score_str}) — {product}")

    lines.extend([
        "",
        f"CISA KEV additions: <b>{kev_additions}</b>",
        "",
    ])

    if not high_critical and not medium:
        lines.append("✅ All systems nominal. No relevant patches required.")
    elif high_critical:
        lines.append("⚠️ Action required — review HIGH/CRITICAL items above.")
    else:
        lines.append("ℹ️ Medium-severity items for awareness only.")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
# SENSOR HEALTH CHECK
# ──────────────────────────────────────────────────────────────────────

def check_sensor_health(memory: Dict[str, Any]) -> None:
    """Alert if NVD has been unreachable for 24+ hours."""
    now = datetime.now(timezone.utc)

    last_nvd = memory.get("last_nvd_success")

    if not last_nvd:
        return

    try:
        dt = datetime.fromisoformat(last_nvd)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        nvd_offline = (now - dt) > timedelta(hours=SENSOR_OFFLINE_HOURS)
    except (ValueError, TypeError):
        return

    if nvd_offline:
        logger.error("NVD sensor offline for 24+ hours!")
        send_telegram(
            "⚠️ <b>SENTINEL SENSOR OFFLINE</b>\n\n"
            f"NVD has been unreachable for over {SENSOR_OFFLINE_HOURS} hours.\n\n"
            "Vulnerability monitoring is offline. "
            "Check network connectivity and API status.\n\n"
            f"Node: {NODE_NAME}"
        )


# ──────────────────────────────────────────────────────────────────────
# SCHEDULER HELPERS
# ──────────────────────────────────────────────────────────────────────

def seconds_until_next(last_check_iso: Optional[str], interval_hours: int) -> float:
    """
    Calculate seconds until the next check is due.
    Returns 0 if overdue or never checked.
    """
    if not last_check_iso:
        return 0.0

    try:
        last_dt = datetime.fromisoformat(last_check_iso)
    except (ValueError, TypeError):
        return 0.0

    if last_dt.tzinfo is None:
        last_dt = last_dt.replace(tzinfo=timezone.utc)

    next_dt = last_dt + timedelta(hours=interval_hours)
    now = datetime.now(timezone.utc)
    delta = (next_dt - now).total_seconds()
    return max(0.0, delta)


def seconds_until_digest() -> float:
    """Calculate seconds until next 09:00 UTC."""
    now = datetime.now(timezone.utc)
    target = now.replace(hour=DIGEST_HOUR_UTC, minute=0, second=0, microsecond=0)
    if now >= target:
        target += timedelta(days=1)
    return (target - now).total_seconds()


# ──────────────────────────────────────────────────────────────────────
# MEMORY PRUNING
# ──────────────────────────────────────────────────────────────────────

MAX_SEEN_CVES = 10000  # Prevent unbounded growth


def prune_memory(memory: Dict[str, Any]) -> None:
    """Keep only the most recent CVE IDs to prevent unbounded memory growth."""
    seen = memory.get("seen_cve_ids", [])
    if len(seen) > MAX_SEEN_CVES:
        # Keep the most recent entries (end of list)
        memory["seen_cve_ids"] = seen[-MAX_SEEN_CVES:]
        logger.info(
            "Pruned seen CVE list from %d to %d entries.",
            len(seen), MAX_SEEN_CVES,
        )

    digest_queue = memory.get("digest_queue", [])
    if len(digest_queue) > 200:
        memory["digest_queue"] = digest_queue[-200:]


# ──────────────────────────────────────────────────────────────────────
# MAIN LOOP
# ──────────────────────────────────────────────────────────────────────

def process_alerts(
    vulns: List[Dict[str, Any]], memory: Dict[str, Any]
) -> Tuple[int, int]:
    """
    Process a list of new vulnerabilities.
    Sends immediate alerts for HIGH/CRITICAL.
    Queues MEDIUM for daily digest.
    Returns (alerts_sent, queued_count).
    """
    alerts_sent = 0
    queued = 0

    for vuln in vulns:
        score = vuln.get("cvss_score")

        # CISA KEV entries are always high priority regardless of CVSS
        is_kev = vuln.get("is_kev", False) or vuln.get("source") == "CISA_KEV"

        if is_kev or (score is not None and score >= CVSS_HIGH):
            # Immediate alert
            msg = format_alert(vuln)
            if send_telegram(msg):
                alerts_sent += 1
            else:
                logger.error(
                    "Failed to send alert for %s.", vuln.get("cve_id")
                )
            # Small delay between alerts to avoid Telegram rate limits
            if alerts_sent > 0 and alerts_sent % 5 == 0:
                time.sleep(2)

        elif score is not None and score >= CVSS_MEDIUM:
            # Queue for daily digest
            memory.setdefault("digest_queue", []).append({
                "cve_id": vuln["cve_id"],
                "cvss_score": score,
                "product": vuln.get("product", "Unknown"),
                "description": vuln.get("description", "")[:120],
                "vendor": vuln.get("vendor", "Unknown"),
                "source": vuln.get("source", ""),
            })
            queued += 1

        elif score is None and not is_kev:
            # No CVSS score and not KEV — queue for digest with a note
            memory.setdefault("digest_queue", []).append({
                "cve_id": vuln["cve_id"],
                "cvss_score": 0,
                "product": vuln.get("product", "Unknown"),
                "description": vuln.get("description", "")[:120],
                "vendor": vuln.get("vendor", "Unknown"),
                "source": vuln.get("source", ""),
            })
            queued += 1

    return alerts_sent, queued


def send_daily_digest(memory: Dict[str, Any]) -> None:
    """Send the daily digest if it hasn't been sent today."""
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    last_digest = memory.get("last_digest_date")

    if last_digest == today_str:
        return  # Already sent today

    digest_queue = memory.get("digest_queue", [])

    # Separate by severity
    high_critical = [
        v for v in digest_queue
        if v.get("cvss_score", 0) >= CVSS_HIGH
    ]
    medium = [
        v for v in digest_queue
        if CVSS_MEDIUM <= v.get("cvss_score", 0) < CVSS_HIGH
    ]

    # Count KEV additions (from last 24h — approximate)
    kev_count = sum(
        1 for v in digest_queue if v.get("source") == "CISA_KEV"
    )

    msg = format_digest(high_critical, medium, kev_count)
    send_telegram(msg)

    # Clear the queue
    memory["digest_queue"] = []
    memory["last_digest_date"] = today_str
    logger.info("Daily digest sent for %s.", today_str)


def send_boot_message(memory: Dict[str, Any]) -> None:
    """Send a boot confirmation message."""
    seen_count = len(memory.get("seen_cve_ids", []))
    kev_count = memory.get("last_kev_count", 0)

    keyword_count = len(_ALL_KEYWORDS)
    cpe_count = len(MONITORED_CPES)

    lines = [
        "🛡️ <b>SENTINEL ONLINE</b>",
        "",
        f"Node: <code>{NODE_NAME}</code>",
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        f"Monitoring {keyword_count} keywords + {cpe_count} CPE prefixes",
        f"Previously seen CVEs: {seen_count}",
        f"Last KEV catalog size: {kev_count}",
        "",
        f"NVD check: every {NVD_INTERVAL_HOURS}h",
        "CISA KEV: detected via NVD metadata",
        f"Daily digest: {DIGEST_HOUR_UTC:02d}:00 UTC",
        "",
        f"NVD API key: {'✅ loaded' if NVD_API_KEY else '❌ not set (rate-limited)'}",
        "",
        "All sensors active. Watching for threats.",
    ]

    send_telegram("\n".join(lines))


def main() -> None:
    """Main daemon loop."""
    logger.info("=" * 60)
    logger.info("SENTINEL starting on %s", NODE_NAME)
    logger.info("=" * 60)

    memory = load_memory()

    # Boot message
    send_boot_message(memory)

    # Initial checks on first boot
    first_run = True

    while True:
        try:
            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()

            # ── Determine what needs to run ──────────────────────────
            nvd_due = seconds_until_next(
                memory.get("last_nvd_check"), NVD_INTERVAL_HOURS
            )
            digest_due = seconds_until_digest()

            run_nvd = nvd_due == 0 or first_run
            run_digest = digest_due <= 60  # Within 1 minute of digest time

            total_alerts = 0
            total_queued = 0

            # ── NVD Check ────────────────────────────────────────────
            if run_nvd:
                try:
                    nvd_vulns = check_nvd(memory)
                    if nvd_vulns:
                        alerts, queued = process_alerts(nvd_vulns, memory)
                        total_alerts += alerts
                        total_queued += queued
                        logger.info(
                            "NVD: %d alerts sent, %d queued.", alerts, queued
                        )
                except Exception as exc:
                    logger.error("NVD check error: %s", exc, exc_info=True)

                save_memory(memory)

            # ── Daily Digest ─────────────────────────────────────────
            if run_digest:
                try:
                    send_daily_digest(memory)
                except Exception as exc:
                    logger.error("Digest error: %s", exc, exc_info=True)

                save_memory(memory)

            # ── Sensor Health ────────────────────────────────────────
            if not first_run:
                try:
                    check_sensor_health(memory)
                except Exception as exc:
                    logger.error("Health check error: %s", exc, exc_info=True)

            # ── Prune Memory ─────────────────────────────────────────
            prune_memory(memory)
            save_memory(memory)

            first_run = False

            # ── Calculate sleep duration ─────────────────────────────
            nvd_wait = seconds_until_next(
                memory.get("last_nvd_check"), NVD_INTERVAL_HOURS
            )
            digest_wait = seconds_until_digest()

            # Sleep until the next event
            sleep_secs = max(60.0, min(nvd_wait, digest_wait))

            # Cap at 1 hour to ensure periodic health checks
            sleep_secs = min(sleep_secs, 3600.0)

            next_event = "NVD" if nvd_wait <= digest_wait else "DIGEST"

            logger.info(
                "Sleeping %.0f seconds (%.1f hours) until next event (%s).",
                sleep_secs, sleep_secs / 3600, next_event,
            )

            time.sleep(sleep_secs)

        except KeyboardInterrupt:
            logger.info("Shutdown requested (KeyboardInterrupt).")
            save_memory(memory)
            send_telegram(
                "🛡️ <b>SENTINEL OFFLINE</b>\n\n"
                f"Daemon stopped on {NODE_NAME}.\n"
                f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
            break
        except Exception as exc:
            logger.critical(
                "Unhandled exception in main loop: %s", exc, exc_info=True
            )
            # Never crash — sleep and retry
            time.sleep(300)


if __name__ == "__main__":
    main()
