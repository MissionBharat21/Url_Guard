"""
ssl_check.py
============
Inspects a domain's HTTPS/SSL configuration: whether HTTPS is
reachable, certificate validity window, issuer, days remaining until
expiry, and self-signed certificate detection.
"""

import socket
import ssl
from datetime import datetime
from typing import Any, Dict

from config import Config
from utils import setup_logger

logger = setup_logger(__name__)

CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


class SSLChecker:
    """Connects to a host on port 443 and inspects its TLS certificate."""

    def __init__(self, hostname: str, port: int = 443, timeout: int = None) -> None:
        """
        Args:
            hostname: The domain/host to connect to (no scheme).
            port: TCP port for the TLS handshake (default 443).
            timeout: Socket timeout in seconds.
        """
        self.hostname = hostname
        self.port = port
        self.timeout = timeout or Config.REQUEST_TIMEOUT

    def _get_certificate_dict(self) -> Dict[str, Any]:
        """Open a TLS connection and return the peer certificate dict."""
        context = ssl.create_default_context()
        with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                return ssock.getpeercert()

    def _get_certificate_dict_insecure(self) -> Dict[str, Any]:
        """
        Fallback: connect without verifying the chain, so we can still
        report on self-signed or otherwise invalid certificates instead
        of failing outright.
        """
        context = ssl._create_unverified_context()
        with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                return ssock.getpeercert()

    @staticmethod
    def _issuer_to_str(issuer_tuple) -> str:
        """Flatten the tuple-of-tuples issuer/subject structure to a string."""
        try:
            parts = []
            for rdn in issuer_tuple:
                for key, value in rdn:
                    parts.append(f"{key}={value}")
            return ", ".join(parts)
        except Exception:
            return "Unknown"

    def inspect(self) -> Dict[str, Any]:
        """
        Run the full SSL inspection.

        Returns:
            Dict with keys: https_enabled, valid, self_signed, issuer,
            subject, not_before, not_after, days_remaining, error.
        """
        result: Dict[str, Any] = {
            "https_enabled": False,
            "valid": False,
            "self_signed": False,
            "issuer": None,
            "subject": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "error": None,
        }

        cert = None
        verified = True
        try:
            cert = self._get_certificate_dict()
        except ssl.SSLCertVerificationError as exc:
            verified = False
            logger.info(f"SSL: certificate did not verify for {self.hostname}: {exc}")
            try:
                cert = self._get_certificate_dict_insecure()
            except Exception as inner_exc:
                result["error"] = f"Certificate verification and fallback both failed: {inner_exc}"
                return result
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
            result["error"] = f"Could not establish HTTPS connection: {exc}"
            return result
        except Exception as exc:
            result["error"] = f"Unexpected SSL error: {exc}"
            return result

        if not cert:
            result["error"] = "No certificate data returned by server."
            return result

        result["https_enabled"] = True
        result["valid"] = verified

        issuer = self._issuer_to_str(cert.get("issuer", ()))
        subject = self._issuer_to_str(cert.get("subject", ()))
        result["issuer"] = issuer
        result["subject"] = subject

        # Self-signed heuristic: issuer and subject fields match.
        result["self_signed"] = bool(issuer) and (issuer == subject)

        not_before_raw = cert.get("notBefore")
        not_after_raw = cert.get("notAfter")

        try:
            if not_before_raw:
                result["not_before"] = datetime.strptime(not_before_raw, CERT_DATE_FORMAT)
            if not_after_raw:
                not_after = datetime.strptime(not_after_raw, CERT_DATE_FORMAT)
                result["not_after"] = not_after
                result["days_remaining"] = (not_after - datetime.now()).days
        except ValueError as exc:
            logger.warning(f"SSL: could not parse certificate dates: {exc}")

        return result
