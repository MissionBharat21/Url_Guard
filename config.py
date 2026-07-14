"""
config.py
=========
Central configuration for URL Guard.

Every other module imports settings from here instead of hardcoding
values. Edit this file to set API keys, timeouts, thresholds, and
file locations.
"""

import os
from pathlib import Path
from typing import List


class Config:
    """Static configuration container for URL Guard."""

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------
    BASE_DIR: Path = Path(__file__).resolve().parent
    REPORTS_DIR: Path = BASE_DIR / "reports"
    LOGS_DIR: Path = BASE_DIR / "logs"
    LOG_FILE: Path = LOGS_DIR / "scan_history.log"

    # ------------------------------------------------------------------
    # Network behaviour
    # ------------------------------------------------------------------
    REQUEST_TIMEOUT: int = 10          # seconds, per HTTP request
    MAX_REDIRECTS: int = 15            # hard cap to avoid infinite loops
    USER_AGENT: str = (
        "Mozilla/5.0 (X11; Linux x86_64) URLGuard/1.0 "
        "(+https://github.com/urlguard) SecurityScanner"
    )

    # ------------------------------------------------------------------
    # API keys (set via environment variables, never hardcode secrets)
    # ------------------------------------------------------------------
    VT_API_KEY: str = os.getenv("URLGUARD_VT_API_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("URLGUARD_GSB_API_KEY", "")
    PHISHTANK_API_KEY: str = os.getenv("URLGUARD_PHISHTANK_API_KEY", "")

    # Optional path to a local MaxMind GeoLite2-City.mmdb file.
    # If unset, GeoIP module falls back to the free ip-api.com HTTP API.
    GEOIP_DB_PATH: str = os.getenv("URLGUARD_GEOIP_DB", "")

    # ------------------------------------------------------------------
    # Risk scoring thresholds (0-100 scale)
    # ------------------------------------------------------------------
    RISK_THRESHOLD_LOW: int = 30       # score < 30  -> LOW RISK
    RISK_THRESHOLD_MEDIUM: int = 60    # 30 <= score < 60 -> MEDIUM RISK
    RISK_THRESHOLD_HIGH: int = 80      # 60 <= score < 80 -> HIGH RISK
    # score >= 80 -> CRITICAL RISK

    # Domain age (days) below which a domain is flagged "newly registered"
    NEWLY_REGISTERED_DAYS: int = 90

    # SSL certificate expiry warning window (days)
    SSL_EXPIRY_WARNING_DAYS: int = 15

    # ------------------------------------------------------------------
    # Known URL shortener domains (expanded automatically)
    # ------------------------------------------------------------------
    SHORTENER_DOMAINS: List[str] = [
        "bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly",
        "is.gd", "goo.gl", "ow.ly", "buff.ly", "shorte.st",
        "adf.ly", "bl.ink", "rebrand.ly", "s.id", "v.gd",
    ]

    # ------------------------------------------------------------------
    # Heuristic keyword list used to flag suspicious paths/query strings
    # ------------------------------------------------------------------
    SUSPICIOUS_KEYWORDS: List[str] = [
        "login", "signin", "verify", "account", "update", "secure",
        "banking", "confirm", "password", "credential", "wallet",
        "suspend", "unlock", "invoice", "billing", "webscr",
        "reset", "authorize", "security-alert", "support",
    ]

    # Well-known brand names commonly targeted by typosquatting.
    # Used only as a heuristic hint list, not an exhaustive database.
    COMMON_BRANDS: List[str] = [
        "google", "facebook", "apple", "microsoft", "amazon", "paypal",
        "netflix", "instagram", "whatsapp", "bankofamerica", "chase",
        "wellsfargo", "linkedin", "twitter", "dropbox", "github",
    ]

    @classmethod
    def ensure_directories(cls) -> None:
        """Create reports/ and logs/ directories if they do not exist."""
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)
