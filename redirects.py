"""
redirects.py
============
Follows HTTP redirect chains manually (one hop at a time, rather than
letting requests auto-follow) so we can:
- Record every hop in order.
- Detect infinite/looping redirects.
- Detect a shortener domain and expand it.
- Warn when the final domain differs from the original.
"""

from typing import Any, Dict, List

import requests

from config import Config
from utils import setup_logger, extract_domain

logger = setup_logger(__name__)


class RedirectAnalyzer:
    """Follows and records a URL's redirect chain."""

    def __init__(self, start_url: str, max_hops: int = None, timeout: int = None) -> None:
        """
        Args:
            start_url: The initial URL to analyze.
            max_hops: Maximum redirects to follow before aborting.
            timeout: Per-request timeout in seconds.
        """
        self.start_url = start_url
        self.max_hops = max_hops or Config.MAX_REDIRECTS
        self.timeout = timeout or Config.REQUEST_TIMEOUT
        self.headers = {"User-Agent": Config.USER_AGENT}

    def is_shortener(self, url: str) -> bool:
        """Return True if the URL's domain matches a known shortener service."""
        domain = extract_domain(url).lower()
        return domain in Config.SHORTENER_DOMAINS

    def follow(self) -> Dict[str, Any]:
        """
        Walk the redirect chain hop by hop.

        Returns:
            Dict with keys:
                chain: List[Dict] each with 'url' and 'status_code'
                final_url: str
                hop_count: int
                loop_detected: bool
                domain_changed: bool
                shortener_used: bool
                error: Optional[str]
        """
        chain: List[Dict[str, Any]] = []
        visited = set()
        current_url = self.start_url
        loop_detected = False
        error = None
        shortener_used = self.is_shortener(self.start_url)

        session = requests.Session()

        for hop in range(self.max_hops + 1):
            if current_url in visited:
                loop_detected = True
                break
            visited.add(current_url)

            try:
                response = session.get(
                    current_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.exceptions.SSLError as exc:
                error = f"SSL error while fetching {current_url}: {exc}"
                break
            except requests.exceptions.ConnectionError as exc:
                error = f"Connection error while fetching {current_url}: {exc}"
                break
            except requests.exceptions.Timeout:
                error = f"Timed out while fetching {current_url}"
                break
            except requests.exceptions.RequestException as exc:
                error = f"Request failed for {current_url}: {exc}"
                break

            chain.append({"url": current_url, "status_code": response.status_code})

            if response.is_redirect or response.is_permanent_redirect:
                next_url = response.headers.get("Location")
                if not next_url:
                    error = "Redirect response missing Location header."
                    break
                # Resolve relative redirects against the current URL.
                next_url = requests.compat.urljoin(current_url, next_url)
                current_url = next_url
                continue
            else:
                # Not a redirect - this is the final destination.
                break
        else:
            # Loop exhausted max_hops without settling.
            error = f"Exceeded maximum redirect limit ({self.max_hops})."

        final_url = chain[-1]["url"] if chain else self.start_url
        original_domain = extract_domain(self.start_url)
        final_domain = extract_domain(final_url)

        return {
            "chain": chain,
            "final_url": final_url,
            "hop_count": max(len(chain) - 1, 0),
            "loop_detected": loop_detected,
            "domain_changed": bool(original_domain and final_domain and original_domain != final_domain),
            "shortener_used": shortener_used,
            "error": error,
        }
