"""
heuristics.py
=============
Rule-based phishing/malware heuristics. Each check inspects the URL
(and, where relevant, data already gathered by other modules) and
contributes a weighted flag toward the overall risk score.

The engine is intentionally conservative: individual heuristics are
signals, not proof. The final verdict is a weighted aggregate.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import tldextract

from config import Config
from utils import extract_domain, extract_hostname, extract_subdomain


@dataclass
class HeuristicFlag:
    """A single triggered heuristic finding."""
    name: str
    description: str
    weight: int  # contribution to risk score, 0-100 scale


@dataclass
class HeuristicResult:
    """Aggregated heuristic findings for a URL."""
    flags: List[HeuristicFlag] = field(default_factory=list)

    @property
    def total_weight(self) -> int:
        return sum(flag.weight for flag in self.flags)


class HeuristicsEngine:
    """Runs all phishing/malware heuristic checks against a URL."""

    def __init__(self, url: str, redirect_info: Optional[Dict[str, Any]] = None,
                 whois_info: Optional[Dict[str, Any]] = None) -> None:
        """
        Args:
            url: The URL under analysis (original, as typed/normalized).
            redirect_info: Output from RedirectAnalyzer.follow(), if available.
            whois_info: Output from WhoisChecker.lookup(), if available.
        """
        self.url = url
        self.redirect_info = redirect_info or {}
        self.whois_info = whois_info or {}
        self.parsed = urlparse(url)
        self.hostname = extract_hostname(url)
        self.domain = extract_domain(url)
        self.subdomain = extract_subdomain(url)

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_ip_as_host(self) -> Optional[HeuristicFlag]:
        """Flag URLs that use a raw IP address instead of a domain name."""
        try:
            ipaddress.ip_address(self.hostname)
            return HeuristicFlag(
                name="ip_as_host",
                description="URL uses a raw IP address instead of a domain name.",
                weight=20,
            )
        except (ValueError, TypeError):
            return None

    def _check_url_length(self) -> Optional[HeuristicFlag]:
        """Flag excessively long URLs, often used to obscure the real target."""
        length = len(self.url)
        if length > 150:
            return HeuristicFlag(
                name="long_url",
                description=f"URL is unusually long ({length} characters).",
                weight=10,
            )
        return None

    def _check_redirect_count(self) -> Optional[HeuristicFlag]:
        """Flag URLs with an excessive number of redirect hops."""
        hop_count = self.redirect_info.get("hop_count", 0)
        if hop_count >= 4:
            return HeuristicFlag(
                name="excessive_redirects",
                description=f"URL redirects {hop_count} times before settling.",
                weight=15,
            )
        return None

    def _check_redirect_loop(self) -> Optional[HeuristicFlag]:
        """Flag detected infinite redirect loops."""
        if self.redirect_info.get("loop_detected"):
            return HeuristicFlag(
                name="redirect_loop",
                description="A redirect loop was detected.",
                weight=25,
            )
        return None

    def _check_domain_change(self) -> Optional[HeuristicFlag]:
        """Flag when the final destination domain differs from the original."""
        if self.redirect_info.get("domain_changed"):
            return HeuristicFlag(
                name="domain_changed_on_redirect",
                description="Final destination domain differs from the original URL.",
                weight=10,
            )
        return None

    def _check_subdomain_count(self) -> Optional[HeuristicFlag]:
        """Flag domains with an excessive number of subdomain labels."""
        if not self.subdomain:
            return None
        label_count = len(self.subdomain.split("."))
        if label_count >= 3:
            return HeuristicFlag(
                name="excessive_subdomains",
                description=f"Hostname has {label_count} subdomain labels ({self.hostname}).",
                weight=10,
            )
        return None

    def _check_suspicious_keywords(self) -> Optional[HeuristicFlag]:
        """Flag presence of common phishing-related keywords in path/query."""
        haystack = (self.parsed.path + " " + self.parsed.query).lower()
        matches = [kw for kw in Config.SUSPICIOUS_KEYWORDS if kw in haystack]
        if matches:
            return HeuristicFlag(
                name="suspicious_keywords",
                description=f"Suspicious keyword(s) found: {', '.join(sorted(set(matches)))}.",
                weight=10 + min(len(matches) * 2, 15),
            )
        return None

    def _check_punycode(self) -> Optional[HeuristicFlag]:
        """Flag punycode (xn--) domains, often used for homograph attacks."""
        if "xn--" in self.hostname.lower():
            return HeuristicFlag(
                name="punycode_domain",
                description="Domain uses punycode encoding (possible homograph attack).",
                weight=25,
            )
        return None

    def _check_unicode_homograph(self) -> Optional[HeuristicFlag]:
        """Flag hostnames containing non-ASCII characters (raw, pre-punycode)."""
        try:
            self.hostname.encode("ascii")
            return None
        except UnicodeEncodeError:
            return HeuristicFlag(
                name="unicode_homograph",
                description="Hostname contains non-ASCII (Unicode) characters.",
                weight=25,
            )

    def _check_typosquatting(self) -> Optional[HeuristicFlag]:
        """
        Flag domains that closely resemble a well-known brand but are not
        an exact match (simple edit-distance heuristic, not a full lookup).
        """
        domain_root = tldextract.extract(self.url).domain.lower()

        def levenshtein(a: str, b: str) -> int:
            if len(a) < len(b):
                a, b = b, a
            previous_row = range(len(b) + 1)
            for i, char_a in enumerate(a, start=1):
                current_row = [i]
                for j, char_b in enumerate(b, start=1):
                    insertions = previous_row[j] + 1
                    deletions = current_row[j - 1] + 1
                    substitutions = previous_row[j - 1] + (char_a != char_b)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            return previous_row[-1]

        for brand in Config.COMMON_BRANDS:
            if domain_root == brand:
                continue  # exact match to a real brand, not typosquatting
            distance = levenshtein(domain_root, brand)
            if 0 < distance <= 2 and len(domain_root) >= 4:
                return HeuristicFlag(
                    name="possible_typosquatting",
                    description=f"Domain '{domain_root}' closely resembles brand '{brand}'.",
                    weight=25,
                )
        return None

    def _check_mixed_scheme(self) -> Optional[HeuristicFlag]:
        """Flag plain HTTP URLs (no encryption in transit)."""
        if self.parsed.scheme == "http":
            return HeuristicFlag(
                name="insecure_scheme",
                description="URL uses plain HTTP instead of HTTPS.",
                weight=10,
            )
        return None

    def _check_suspicious_query_params(self) -> Optional[HeuristicFlag]:
        """Flag query parameters that look like embedded redirect/URL payloads."""
        query = parse_qs(self.parsed.query)
        redirect_param_names = {"redirect", "url", "next", "target", "dest", "continue", "return"}
        for key, values in query.items():
            if key.lower() in redirect_param_names:
                for value in values:
                    if value.startswith("http") or "%2f%2f" in value.lower():
                        return HeuristicFlag(
                            name="suspicious_query_redirect",
                            description=f"Query parameter '{key}' embeds another URL.",
                            weight=15,
                        )
        return None

    def _check_newly_registered(self) -> Optional[HeuristicFlag]:
        """Flag domains registered very recently (per WHOIS data, if available)."""
        if self.whois_info.get("is_newly_registered"):
            age = self.whois_info.get("domain_age_days")
            return HeuristicFlag(
                name="newly_registered_domain",
                description=f"Domain was registered only {age} day(s) ago.",
                weight=20,
            )
        return None

    def _check_fake_login_page_hint(self) -> Optional[HeuristicFlag]:
        """
        Lightweight combined hint: a login-related keyword paired with a
        subdomain or path structure that is not the brand's own domain.
        """
        haystack = (self.parsed.path + " " + self.subdomain).lower()
        login_terms = {"login", "signin", "secure", "account", "verify"}
        if any(term in haystack for term in login_terms) and self.subdomain:
            return HeuristicFlag(
                name="possible_fake_login_page",
                description=(
                    f"Login-related term found on subdomain '{self.subdomain}.{self.domain}', "
                    "which does not match the apparent target brand."
                ),
                weight=15,
            )
        return None

    # ------------------------------------------------------------------
    # Runner
    # ------------------------------------------------------------------

    def run_all(self) -> HeuristicResult:
        """Execute every heuristic check and collect triggered flags."""
        checks = [
            self._check_ip_as_host,
            self._check_url_length,
            self._check_redirect_count,
            self._check_redirect_loop,
            self._check_domain_change,
            self._check_subdomain_count,
            self._check_suspicious_keywords,
            self._check_punycode,
            self._check_unicode_homograph,
            self._check_typosquatting,
            self._check_mixed_scheme,
            self._check_suspicious_query_params,
            self._check_newly_registered,
            self._check_fake_login_page_hint,
        ]

        result = HeuristicResult()
        for check in checks:
            flag = check()
            if flag:
                result.flags.append(flag)

        return result
