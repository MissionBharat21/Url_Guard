"""
whois_check.py
==============
WHOIS lookup wrapper around python-whois. Extracts registrar,
creation/expiration/updated dates, name servers, and organization
details, and flags newly-registered domains (a common phishing
indicator).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

import whois

from config import Config
from utils import setup_logger, days_between

logger = setup_logger(__name__)


class WhoisChecker:
    """Retrieves and normalizes WHOIS data for a domain."""

    def __init__(self, domain: str) -> None:
        """
        Args:
            domain: The registrable domain to look up (e.g. 'example.com').
        """
        self.domain = domain

    @staticmethod
    def _first(value: Union[Any, List[Any], None]) -> Optional[Any]:
        """WHOIS libraries often return lists; take the first usable value."""
        if isinstance(value, list):
            return value[0] if value else None
        return value

    def lookup(self) -> Dict[str, Any]:
        """
        Perform the WHOIS query.

        Returns:
            A dictionary with normalized WHOIS fields. On failure,
            returns a dict with 'error' set and all other fields None.
        """
        result: Dict[str, Any] = {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "country": None,
            "organization": None,
            "domain_age_days": None,
            "is_newly_registered": False,
            "error": None,
        }

        try:
            data = whois.whois(self.domain)
        except Exception as exc:
            logger.warning(f"WHOIS lookup failed for {self.domain}: {exc}")
            result["error"] = str(exc)
            return result

        if data is None or not getattr(data, "domain_name", None):
            result["error"] = "No WHOIS record returned (privacy-protected or unregistered)."
            return result

        creation_date = self._first(getattr(data, "creation_date", None))
        expiration_date = self._first(getattr(data, "expiration_date", None))
        updated_date = self._first(getattr(data, "updated_date", None))

        result["registrar"] = getattr(data, "registrar", None)
        result["creation_date"] = creation_date
        result["expiration_date"] = expiration_date
        result["updated_date"] = updated_date

        name_servers = getattr(data, "name_servers", None) or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        result["name_servers"] = sorted({ns.lower() for ns in name_servers if ns})

        result["country"] = self._first(getattr(data, "country", None))
        result["organization"] = self._first(getattr(data, "org", None))

        if isinstance(creation_date, datetime):
            age_days = days_between(creation_date, datetime.now())
            result["domain_age_days"] = age_days
            if age_days is not None and age_days < Config.NEWLY_REGISTERED_DAYS:
                result["is_newly_registered"] = True

        return result
