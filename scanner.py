"""
scanner.py
==========
Orchestrator module. URLGuardScanner ties every other module together
into a single scan() call:

    utils        -> validation/normalization
    redirects    -> chain following + shortener expansion
    ssl_check    -> HTTPS/certificate inspection
    dns_check    -> DNS record lookups
    whois_check  -> registration data
    geoip        -> IP resolution + geolocation
    heuristics   -> phishing/malware rule checks
    vt           -> VirusTotal reputation lookup

The result of scan() is a single nested dict that report.py knows how
to render and export, and that main.py logs to logs/scan_history.log.
"""

from datetime import datetime
from typing import Any, Dict

from config import Config
from utils import (
    setup_logger,
    normalize_url,
    is_valid_url,
    extract_domain,
    extract_hostname,
)
from redirects import RedirectAnalyzer
from ssl_check import SSLChecker
from dns_check import DNSChecker
from whois_check import WhoisChecker
from geoip import GeoIPLookup, resolve_ips
from heuristics import HeuristicsEngine
from vt import VirusTotalClient

logger = setup_logger(__name__)


class InvalidURLError(Exception):
    """Raised when a supplied URL fails format validation."""


class URLGuardScanner:
    """Runs a complete security scan against a single URL."""

    def __init__(self, raw_url: str) -> None:
        """
        Args:
            raw_url: The URL as typed by the user (scheme optional).

        Raises:
            InvalidURLError: If the URL cannot be normalized/validated.
        """
        self.raw_url = raw_url
        self.url = normalize_url(raw_url)

        if not self.url or not is_valid_url(self.url):
            raise InvalidURLError(f"'{raw_url}' is not a valid URL.")

        self.domain = extract_domain(self.url)
        self.hostname = extract_hostname(self.url)

    def _score_risk(self, heuristic_weight: int, vt_result: Dict[str, Any],
                     ssl_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Combine heuristic weights, VirusTotal detections, and SSL issues
        into a single 0-100 risk score with a verdict label.
        """
        score = heuristic_weight

        if vt_result.get("available"):
            malicious = vt_result.get("malicious", 0)
            suspicious = vt_result.get("suspicious", 0)
            score += min(malicious * 8, 50)
            score += min(suspicious * 3, 20)

        if ssl_info.get("https_enabled") is False:
            score += 10
        elif ssl_info.get("valid") is False:
            score += 15
        elif ssl_info.get("self_signed"):
            score += 15

        days_remaining = ssl_info.get("days_remaining")
        if isinstance(days_remaining, int) and 0 <= days_remaining <= Config.SSL_EXPIRY_WARNING_DAYS:
            score += 5

        score = max(0, min(100, score))

        if score >= Config.RISK_THRESHOLD_HIGH:
            verdict = "CRITICAL RISK"
        elif score >= Config.RISK_THRESHOLD_MEDIUM:
            verdict = "HIGH RISK"
        elif score >= Config.RISK_THRESHOLD_LOW:
            verdict = "MEDIUM RISK"
        else:
            verdict = "LOW RISK"

        return {"score": score, "verdict": verdict}

    def scan(self) -> Dict[str, Any]:
        """
        Execute the full scan pipeline.

        Returns:
            A nested dict containing every module's findings, plus the
            aggregated risk score and verdict.
        """
        logger.info(f"Starting scan for {self.url}")

        # 1. Redirect analysis (also detects/expands shorteners)
        redirect_analyzer = RedirectAnalyzer(self.url)
        redirect_info = redirect_analyzer.follow()
        final_hostname = extract_hostname(redirect_info["final_url"]) or self.hostname
        final_domain = extract_domain(redirect_info["final_url"]) or self.domain

        # 2. SSL/HTTPS inspection (against the final destination host)
        ssl_checker = SSLChecker(final_hostname)
        ssl_info = ssl_checker.inspect()

        # 3. DNS analysis (against the final domain)
        dns_checker = DNSChecker(final_domain)
        dns_info = dns_checker.run_all()

        # 4. WHOIS lookup
        whois_checker = WhoisChecker(final_domain)
        whois_info = whois_checker.lookup()

        # 5. IP resolution + GeoIP
        ip_info = resolve_ips(final_hostname)
        geo_info: Dict[str, Any] = {}
        if ip_info.get("ipv4"):
            geo_info = GeoIPLookup(ip_info["ipv4"]).lookup()
        elif ip_info.get("ipv6"):
            geo_info = GeoIPLookup(ip_info["ipv6"]).lookup()

        # 6. Phishing heuristics (against the original URL + gathered context)
        heuristics_engine = HeuristicsEngine(self.url, redirect_info=redirect_info, whois_info=whois_info)
        heuristics_result = heuristics_engine.run_all()

        # 7. Reputation check (VirusTotal)
        vt_client = VirusTotalClient()
        vt_result = vt_client.scan(redirect_info["final_url"])

        # 8. Aggregate risk score
        risk = self._score_risk(heuristics_result.total_weight, vt_result, ssl_info)

        result: Dict[str, Any] = {
            "original_url": self.raw_url,
            "normalized_url": self.url,
            "scan_time": datetime.now().isoformat(timespec="seconds"),
            "redirects": redirect_info,
            "ssl": ssl_info,
            "dns": dns_info,
            "whois": whois_info,
            "ip_info": ip_info,
            "geoip": geo_info,
            "heuristics": {
                "flags": [
                    {"name": f.name, "description": f.description, "weight": f.weight}
                    for f in heuristics_result.flags
                ],
                "total_weight": heuristics_result.total_weight,
            },
            "virustotal": vt_result,
            "risk": risk,
        }

        logger.info(
            f"Scan complete for {self.url} | Score={risk['score']} | Verdict={risk['verdict']}"
        )

        return result
