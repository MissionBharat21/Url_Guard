"""
vt.py
=====
VirusTotal API v3 integration. Submits a URL for analysis (or fetches
an existing report) and normalizes the malicious/suspicious/harmless
detection counts. Requires Config.VT_API_KEY to be set; if it is not
set, this module reports itself as unavailable rather than failing.
"""

import base64
import time
from typing import Any, Dict

import requests

from config import Config
from utils import setup_logger

logger = setup_logger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    """Thin wrapper around the VirusTotal v3 URL analysis endpoints."""

    def __init__(self, api_key: str = None, timeout: int = None) -> None:
        """
        Args:
            api_key: VirusTotal API key. Falls back to Config.VT_API_KEY.
            timeout: HTTP timeout in seconds.
        """
        self.api_key = api_key or Config.VT_API_KEY
        self.timeout = timeout or Config.REQUEST_TIMEOUT

    @property
    def is_configured(self) -> bool:
        """Whether an API key is available to use this client."""
        return bool(self.api_key)

    @staticmethod
    def _url_id(url: str) -> str:
        """VirusTotal identifies URLs by URL-safe base64 (no padding)."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key}

    def _submit_url(self, url: str) -> bool:
        """Submit a URL for fresh analysis. Returns True on success."""
        try:
            resp = requests.post(
                f"{VT_BASE_URL}/urls",
                headers=self._headers(),
                data={"url": url},
                timeout=self.timeout,
            )
            return resp.status_code == 200
        except requests.RequestException as exc:
            logger.warning(f"VirusTotal: submission failed: {exc}")
            return False

    def scan(self, url: str) -> Dict[str, Any]:
        """
        Fetch (or trigger + fetch) a VirusTotal report for a URL.

        Returns:
            Dict with keys: available, malicious, suspicious, harmless,
            undetected, total_engines, community_score, permalink, error.
        """
        result: Dict[str, Any] = {
            "available": False,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "community_score": None,
            "permalink": None,
            "error": None,
        }

        if not self.is_configured:
            result["error"] = "VirusTotal API key not configured (set URLGUARD_VT_API_KEY)."
            return result

        url_id = self._url_id(url)

        try:
            resp = requests.get(
                f"{VT_BASE_URL}/urls/{url_id}",
                headers=self._headers(),
                timeout=self.timeout,
            )

            if resp.status_code == 404:
                # Not yet analyzed - submit it, then poll briefly for a result.
                submitted = self._submit_url(url)
                if not submitted:
                    result["error"] = "Failed to submit URL to VirusTotal."
                    return result
                time.sleep(3)
                resp = requests.get(
                    f"{VT_BASE_URL}/urls/{url_id}",
                    headers=self._headers(),
                    timeout=self.timeout,
                )

            if resp.status_code != 200:
                result["error"] = f"VirusTotal returned HTTP {resp.status_code}."
                return result

            payload = resp.json()
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            votes = attributes.get("total_votes", {})

            result["available"] = True
            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"] = stats.get("harmless", 0)
            result["undetected"] = stats.get("undetected", 0)
            result["total_engines"] = sum(stats.values()) if stats else 0
            result["community_score"] = {
                "harmless_votes": votes.get("harmless", 0),
                "malicious_votes": votes.get("malicious", 0),
            }
            result["permalink"] = f"https://www.virustotal.com/gui/url/{url_id}"

        except requests.RequestException as exc:
            logger.warning(f"VirusTotal: request failed: {exc}")
            result["error"] = f"Request to VirusTotal failed: {exc}"

        return result
