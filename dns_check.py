"""
dns_check.py
============
Performs DNS record lookups for a given domain: A, AAAA, MX, NS, TXT,
CNAME, and reverse DNS (PTR). Used by scanner.py to enrich a scan
report and by heuristics.py indirectly (via the resolved IPs).
"""

from typing import Dict, List

import dns.resolver
import dns.reversename
import dns.exception

from utils import setup_logger

logger = setup_logger(__name__)


class DNSChecker:
    """Resolves DNS records for a domain with graceful failure handling."""

    def __init__(self, domain: str, timeout: int = 5) -> None:
        """
        Args:
            domain: The domain name to query (no scheme, no path).
            timeout: Per-query timeout in seconds.
        """
        self.domain = domain
        try:
            self.resolver = dns.resolver.Resolver()
        except Exception:
            self.resolver = dns.resolver.Resolver(configure=False)

        if not self.resolver.nameservers:
            self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _query(self, record_type: str) -> List[str]:
        """
        Run a single DNS query and return record values as strings.
        Returns an empty list on any resolution failure.
        """
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            return [answer.to_text().strip('"') for answer in answers]
        except dns.resolver.NXDOMAIN:
            logger.info(f"DNS: {self.domain} does not exist (NXDOMAIN)")
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.exception.Timeout:
            logger.warning(f"DNS: timeout resolving {record_type} for {self.domain}")
            return []
        except Exception as exc:
            logger.warning(f"DNS: error resolving {record_type} for {self.domain}: {exc}")
            return []

    def get_a_records(self) -> List[str]:
        """Return IPv4 (A) addresses."""
        return self._query("A")

    def get_aaaa_records(self) -> List[str]:
        """Return IPv6 (AAAA) addresses."""
        return self._query("AAAA")

    def get_mx_records(self) -> List[str]:
        """Return mail exchange (MX) records."""
        return self._query("MX")

    def get_ns_records(self) -> List[str]:
        """Return name server (NS) records."""
        return self._query("NS")

    def get_txt_records(self) -> List[str]:
        """Return TXT records (SPF, DKIM hints, verification tokens, etc.)."""
        return self._query("TXT")

    def get_cname_records(self) -> List[str]:
        """Return CNAME records, if any."""
        return self._query("CNAME")

    def get_reverse_dns(self, ip_address: str) -> List[str]:
        """
        Perform a reverse DNS (PTR) lookup for a given IP address.

        Args:
            ip_address: An IPv4 or IPv6 address string.

        Returns:
            List of PTR hostnames, or empty list if none found.
        """
        try:
            rev_name = dns.reversename.from_address(ip_address)
            answers = self.resolver.resolve(rev_name, "PTR")
            return [answer.to_text() for answer in answers]
        except Exception as exc:
            logger.info(f"DNS: reverse lookup failed for {ip_address}: {exc}")
            return []

    def run_all(self) -> Dict[str, List[str]]:
        """
        Run every DNS lookup and bundle results together.

        Returns:
            Dict with keys: A, AAAA, MX, NS, TXT, CNAME, PTR.
        """
        a_records = self.get_a_records()
        results: Dict[str, List[str]] = {
            "A": a_records,
            "AAAA": self.get_aaaa_records(),
            "MX": self.get_mx_records(),
            "NS": self.get_ns_records(),
            "TXT": self.get_txt_records(),
            "CNAME": self.get_cname_records(),
            "PTR": [],
        }

        if a_records:
            results["PTR"] = self.get_reverse_dns(a_records[0])

        return results
