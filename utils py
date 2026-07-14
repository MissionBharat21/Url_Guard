"""
utils.py
========
Shared helper functions used across URL Guard modules:
- URL normalization/validation
- Domain extraction
- Logging setup
- JSON persistence helpers

Every module that needs these primitives imports from here to avoid
duplicated logic.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import tldextract
import validators

from config import Config


def setup_logger(name: str = "url_guard") -> logging.Logger:
    """
    Configure and return a logger that writes to logs/scan_history.log
    and echoes warnings/errors to stderr.
    """
    Config.ensure_directories()
    logger = logging.getLogger(name)

    if logger.handlers:
        # Already configured (e.g. imported multiple times) - reuse it.
        return logger

    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(Config.LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(file_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def normalize_url(raw_url: str) -> str:
    """
    Normalize a user-supplied URL string:
    - Strips whitespace.
    - Prepends https:// if no scheme is present.

    Args:
        raw_url: The raw string typed/pasted by the user.

    Returns:
        A normalized URL string ready for validation.
    """
    url = raw_url.strip()
    if not url:
        return url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url

    return url


def is_valid_url(url: str) -> bool:
    """
    Validate that a URL is well-formed.

    Args:
        url: A normalized URL (scheme already present).

    Returns:
        True if the URL passes format validation, False otherwise.
    """
    try:
        result = validators.url(url)
        return bool(result is True)
    except Exception:
        return False


def extract_domain(url: str) -> str:
    """
    Extract the registrable domain (e.g. 'example.co.uk') from a URL.

    Args:
        url: A full URL.

    Returns:
        The domain string, or an empty string if extraction fails.
    """
    try:
        extracted = tldextract.extract(url)
        if extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return extracted.domain
    except Exception:
        return ""


def extract_hostname(url: str) -> str:
    """Return the full hostname (including subdomains) from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def extract_subdomain(url: str) -> str:
    """Return only the subdomain portion of a URL's hostname."""
    try:
        extracted = tldextract.extract(url)
        return extracted.subdomain
    except Exception:
        return ""


def save_json(path: Path, data: Dict[str, Any]) -> None:
    """Serialize a dictionary to disk as pretty-printed JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=4, default=str, ensure_ascii=False)


def timestamp_slug() -> str:
    """Return a filesystem-safe timestamp string, e.g. 20260714_153000."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_filename_from_url(url: str) -> str:
    """Turn a URL into a safe filename fragment."""
    domain = extract_domain(url) or "unknown"
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", domain)


def days_between(date_a: Optional[datetime], date_b: Optional[datetime]) -> Optional[int]:
    """Return whole days between two datetimes, or None if either is missing."""
    if date_a is None or date_b is None:
        return None
    try:
        return abs((date_b - date_a).days)
    except Exception:
        return None
